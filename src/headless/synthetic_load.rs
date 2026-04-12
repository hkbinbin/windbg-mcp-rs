use windows::{
    Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_ADDSYNTHMOD_DEFAULT, DEBUG_ANY_ID, DEBUG_BREAKPOINT_ADDER_ONLY,
        DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED, DEBUG_BREAKPOINT_GO_ONLY,
        DEBUG_BREAKPOINT_ONE_SHOT, DEBUG_VALUE, IDebugBreakpoint, IDebugControl, IDebugDataSpaces,
        IDebugRegisters, IDebugSymbols3,
    },
    core::{PCSTR, PCWSTR, Result as WinResult},
};

use crate::headless::module_match::module_selector_matches;

const LOADER_BREAK_EXPRESSION: &[u8] = b"nt!MmLoadSystemImage\0";
const RCX_REGISTER_NAME: &[u8] = b"rcx\0";
const UNICODE_STRING_HEADER_LEN: usize = 16;
const MAX_SYNTHETIC_PATH_BYTES: usize = 1024;
const LOADER_ARG5_STACK_OFFSET: u64 = 0x28;
const LOADER_OUT_PARAM_COUNT: usize = 2;
const DOS_HEADER_LEN: usize = 0x40;
const PE_HEADER_PROBE_LEN: usize = 0x80;
const DOS_MAGIC: [u8; 2] = [b'M', b'Z'];
const PE_MAGIC: [u8; 4] = [b'P', b'E', 0, 0];
const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const PE_OPTIONAL_HEADER_OFFSET: usize = 24;
const PE_ENTRY_POINT_RVA_OFFSET: usize = PE_OPTIONAL_HEADER_OFFSET + 0x10;
const PE_IMAGE_SIZE_OFFSET: usize = PE_OPTIONAL_HEADER_OFFSET + 0x38;

#[derive(Debug)]
pub(crate) enum SyntheticLoadDecision {
    NotHandled,
    Continue,
    Break { module_path: Option<String> },
}

#[derive(Default)]
pub(crate) struct SyntheticLoadState {
    entry_breakpoint_id: Option<u32>,
    pending_return_breakpoint_id: Option<u32>,
    pending_entry_breakpoint_id: Option<u32>,
    pending_module_path: Option<String>,
    pending_out_params: Option<LoaderOutParamPointers>,
}

impl SyntheticLoadState {
    pub(crate) fn sync_breakpoint(
        &mut self,
        control: &IDebugControl,
        break_enabled: bool,
    ) -> WinResult<()> {
        if !break_enabled {
            tracing::debug!("synthetic module-load breakpoint is disabled; clearing state");
            self.clear(control)?;
            return Ok(());
        }

        if self.entry_breakpoint_id.is_some() {
            tracing::trace!(
                breakpoint_id = self.entry_breakpoint_id,
                "synthetic module-load entry breakpoint already exists"
            );
            return Ok(());
        }

        self.entry_breakpoint_id = Some(add_code_breakpoint_at_expression(
            control,
            LOADER_BREAK_EXPRESSION,
            DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_GO_ONLY | DEBUG_BREAKPOINT_ADDER_ONLY,
        )?);
        tracing::debug!(
            breakpoint_id = self.entry_breakpoint_id,
            "installed synthetic module-load entry breakpoint"
        );
        Ok(())
    }

    pub(crate) fn handle_breakpoint(
        &mut self,
        breakpoint: &IDebugBreakpoint,
        control: &IDebugControl,
        registers: &IDebugRegisters,
        data_spaces: &IDebugDataSpaces,
        debug_symbols: &IDebugSymbols3,
        selector: Option<&str>,
    ) -> WinResult<SyntheticLoadDecision> {
        let breakpoint_id = unsafe { breakpoint.GetId() }?;

        if self.pending_entry_breakpoint_id == Some(breakpoint_id) {
            tracing::debug!(
                breakpoint_id,
                module_path = self.pending_module_path.as_deref().unwrap_or("<unknown>"),
                "synthetic module-load entry-point breakpoint matched"
            );
            self.pending_entry_breakpoint_id = None;
            return Ok(SyntheticLoadDecision::Break {
                module_path: self.pending_module_path.take(),
            });
        }

        if self.pending_return_breakpoint_id == Some(breakpoint_id) {
            tracing::debug!(
                breakpoint_id,
                module_path = self.pending_module_path.as_deref().unwrap_or("<unknown>"),
                "synthetic module-load return breakpoint matched"
            );
            self.pending_return_breakpoint_id = None;
            if let Some(image_info) = self.resolve_loaded_image_info(data_spaces)? {
                self.register_synthetic_module(debug_symbols, image_info);
                self.arm_entry_breakpoint(control, image_info)?;
                return Ok(SyntheticLoadDecision::Continue);
            }

            tracing::debug!(
                module_path = self.pending_module_path.as_deref().unwrap_or("<unknown>"),
                "synthetic module-load return breakpoint could not resolve an image base; breaking at return"
            );
            return Ok(SyntheticLoadDecision::Break {
                module_path: self.pending_module_path.take(),
            });
        }

        if self.entry_breakpoint_id != Some(breakpoint_id) {
            return Ok(SyntheticLoadDecision::NotHandled);
        }

        let module_path = read_loader_module_path(registers, data_spaces)?;
        tracing::debug!(
            breakpoint_id,
            module_path = module_path.as_deref().unwrap_or("<unknown>"),
            selector = selector.unwrap_or("<any>"),
            "synthetic module-load entry breakpoint hit"
        );
        let matches_selector = match selector {
            None => true,
            Some(selector) => module_path
                .as_deref()
                .map(|value| module_selector_matches(selector, value))
                .unwrap_or(true),
        };

        if !matches_selector {
            tracing::debug!(
                breakpoint_id,
                module_path = module_path.as_deref().unwrap_or("<unknown>"),
                selector = selector.unwrap_or("<any>"),
                "synthetic module-load entry breakpoint did not match selector"
            );
            return Ok(SyntheticLoadDecision::Continue);
        }

        let return_address = read_return_address(registers, data_spaces)?;
        let Some(return_address) = return_address else {
            tracing::debug!(
                breakpoint_id,
                module_path = module_path.as_deref().unwrap_or("<unknown>"),
                "synthetic module-load entry breakpoint could not read return address; breaking immediately"
            );
            return Ok(SyntheticLoadDecision::Break { module_path });
        };

        let out_params = read_loader_out_param_pointers(registers, data_spaces)?;
        tracing::debug!(
            breakpoint_id,
            arg5_out = out_params.arg5_out,
            arg6_out = out_params.arg6_out,
            "synthetic module-load captured MmLoadSystemImage out-parameter slots"
        );
        self.arm_return_breakpoint(control, return_address, module_path, out_params)?;
        Ok(SyntheticLoadDecision::Continue)
    }

    fn arm_return_breakpoint(
        &mut self,
        control: &IDebugControl,
        return_address: u64,
        module_path: Option<String>,
        out_params: LoaderOutParamPointers,
    ) -> WinResult<()> {
        self.remove_pending_return_breakpoint(control)?;
        self.pending_return_breakpoint_id = Some(add_code_breakpoint_at_offset(
            control,
            return_address,
            DEBUG_BREAKPOINT_ENABLED
                | DEBUG_BREAKPOINT_GO_ONLY
                | DEBUG_BREAKPOINT_ADDER_ONLY
                | DEBUG_BREAKPOINT_ONE_SHOT,
        )?);
        self.pending_module_path = module_path;
        self.pending_out_params = Some(out_params);
        tracing::debug!(
            breakpoint_id = self.pending_return_breakpoint_id,
            return_address,
            module_path = self.pending_module_path.as_deref().unwrap_or("<unknown>"),
            "armed synthetic module-load return breakpoint"
        );
        Ok(())
    }

    fn clear(&mut self, control: &IDebugControl) -> WinResult<()> {
        self.remove_pending_return_breakpoint(control)?;
        self.remove_pending_entry_breakpoint(control)?;
        if let Some(id) = self.entry_breakpoint_id.take() {
            remove_breakpoint_by_id(control, id)?;
        }
        self.pending_module_path = None;
        self.pending_out_params = None;
        Ok(())
    }

    fn remove_pending_return_breakpoint(&mut self, control: &IDebugControl) -> WinResult<()> {
        if let Some(id) = self.pending_return_breakpoint_id.take() {
            remove_breakpoint_by_id(control, id)?;
        }
        self.pending_out_params = None;
        Ok(())
    }

    fn remove_pending_entry_breakpoint(&mut self, control: &IDebugControl) -> WinResult<()> {
        if let Some(id) = self.pending_entry_breakpoint_id.take() {
            remove_breakpoint_by_id(control, id)?;
        }
        Ok(())
    }

    fn resolve_loaded_image_info(
        &self,
        data_spaces: &IDebugDataSpaces,
    ) -> WinResult<Option<LoadedImageInfo>> {
        let Some(out_params) = self.pending_out_params else {
            return Ok(None);
        };

        for (slot_name, out_pointer) in
            [("arg5", out_params.arg5_out), ("arg6", out_params.arg6_out)]
        {
            let Some(out_pointer) = out_pointer.filter(|value| *value != 0) else {
                continue;
            };

            let candidate = read_virtual_pointer(data_spaces, out_pointer)?;
            let Some(candidate) = candidate.filter(|value| *value != 0) else {
                tracing::debug!(
                    slot_name,
                    out_pointer,
                    "synthetic module-load out-parameter slot was null"
                );
                continue;
            };

            let Some(image_info) = read_pe_image_info(data_spaces, candidate)? else {
                tracing::debug!(
                    slot_name,
                    out_pointer,
                    candidate,
                    "synthetic module-load out-parameter did not resolve to a PE image base"
                );
                continue;
            };

            tracing::debug!(
                slot_name,
                out_pointer,
                image_base = candidate,
                image_size = image_info.image_size,
                entry_point = image_info.entry_point,
                module_path = self.pending_module_path.as_deref().unwrap_or("<unknown>"),
                "synthetic module-load resolved image base and entry point"
            );
            return Ok(Some(image_info));
        }

        Ok(None)
    }

    fn arm_entry_breakpoint(
        &mut self,
        control: &IDebugControl,
        image_info: LoadedImageInfo,
    ) -> WinResult<()> {
        self.remove_pending_entry_breakpoint(control)?;
        self.pending_entry_breakpoint_id = Some(add_code_breakpoint_at_offset(
            control,
            image_info.entry_point,
            DEBUG_BREAKPOINT_ENABLED
                | DEBUG_BREAKPOINT_GO_ONLY
                | DEBUG_BREAKPOINT_ADDER_ONLY
                | DEBUG_BREAKPOINT_ONE_SHOT,
        )?);
        tracing::debug!(
            breakpoint_id = self.pending_entry_breakpoint_id,
            image_base = image_info.image_base,
            entry_point = image_info.entry_point,
            module_path = self.pending_module_path.as_deref().unwrap_or("<unknown>"),
            "armed synthetic module-load entry-point breakpoint"
        );
        Ok(())
    }

    fn register_synthetic_module(
        &self,
        debug_symbols: &IDebugSymbols3,
        image_info: LoadedImageInfo,
    ) {
        let Some(module_path) = self.pending_module_path.as_deref() else {
            return;
        };

        let module_name = synthetic_module_name_from_path(module_path);
        let image_path_wide = wide_null(module_path);
        let module_name_wide = wide_null(&module_name);
        match unsafe {
            debug_symbols.AddSyntheticModuleWide(
                image_info.image_base,
                image_info.image_size,
                PCWSTR(image_path_wide.as_ptr()),
                PCWSTR(module_name_wide.as_ptr()),
                DEBUG_ADDSYNTHMOD_DEFAULT,
            )
        } {
            Ok(()) => tracing::debug!(
                image_base = image_info.image_base,
                image_size = image_info.image_size,
                entry_point = image_info.entry_point,
                module_path,
                module_name,
                "registered synthetic module for synthetic load breakpoint"
            ),
            Err(error) => tracing::debug!(
                ?error,
                image_base = image_info.image_base,
                image_size = image_info.image_size,
                entry_point = image_info.entry_point,
                module_path,
                module_name,
                "failed to register synthetic module for synthetic load breakpoint"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct LoaderOutParamPointers {
    arg5_out: Option<u64>,
    arg6_out: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct LoadedImageInfo {
    image_base: u64,
    image_size: u32,
    entry_point: u64,
}

fn add_code_breakpoint_at_expression(
    control: &IDebugControl,
    expression: &[u8],
    flags: u32,
) -> WinResult<u32> {
    let breakpoint = unsafe { control.AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID) }?;
    unsafe {
        breakpoint.SetOffsetExpression(PCSTR(expression.as_ptr()))?;
        breakpoint.SetFlags(flags)?;
        breakpoint.GetId()
    }
}

fn add_code_breakpoint_at_offset(
    control: &IDebugControl,
    offset: u64,
    flags: u32,
) -> WinResult<u32> {
    let breakpoint = unsafe { control.AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID) }?;
    unsafe {
        breakpoint.SetOffset(offset)?;
        breakpoint.SetFlags(flags)?;
        breakpoint.GetId()
    }
}

fn remove_breakpoint_by_id(control: &IDebugControl, breakpoint_id: u32) -> WinResult<()> {
    match unsafe { control.GetBreakpointById(breakpoint_id) } {
        Ok(breakpoint) => unsafe { control.RemoveBreakpoint(&breakpoint) },
        Err(error) => {
            tracing::debug!(
                breakpoint_id,
                ?error,
                "synthetic load breakpoint was already gone"
            );
            Ok(())
        }
    }
}

fn read_return_address(
    registers: &IDebugRegisters,
    data_spaces: &IDebugDataSpaces,
) -> WinResult<Option<u64>> {
    let stack_offset = unsafe { registers.GetStackOffset() }?;
    if stack_offset == 0 {
        return Ok(None);
    }

    let mut pointers = [0u64; 1];
    unsafe { data_spaces.ReadPointersVirtual(stack_offset, &mut pointers) }?;
    Ok((pointers[0] != 0).then_some(pointers[0]))
}

fn read_loader_out_param_pointers(
    registers: &IDebugRegisters,
    data_spaces: &IDebugDataSpaces,
) -> WinResult<LoaderOutParamPointers> {
    let stack_offset = unsafe { registers.GetStackOffset() }?;
    if stack_offset == 0 {
        return Ok(LoaderOutParamPointers::default());
    }

    let mut pointers = [0u64; LOADER_OUT_PARAM_COUNT];
    unsafe {
        data_spaces.ReadPointersVirtual(stack_offset + LOADER_ARG5_STACK_OFFSET, &mut pointers)
    }?;
    Ok(LoaderOutParamPointers {
        arg5_out: (pointers[0] != 0).then_some(pointers[0]),
        arg6_out: (pointers[1] != 0).then_some(pointers[1]),
    })
}

fn read_loader_module_path(
    registers: &IDebugRegisters,
    data_spaces: &IDebugDataSpaces,
) -> WinResult<Option<String>> {
    let unicode_string_ptr = read_register_u64(registers, RCX_REGISTER_NAME)?;
    if unicode_string_ptr == 0 {
        return Ok(None);
    }

    let header = read_virtual_exact::<UNICODE_STRING_HEADER_LEN>(data_spaces, unicode_string_ptr)?;
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer_ptr = u64::from_le_bytes([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14],
        header[15],
    ]);
    if length == 0 || buffer_ptr == 0 || length > MAX_SYNTHETIC_PATH_BYTES || (length % 2) != 0 {
        return Ok(None);
    }

    let mut utf16_bytes = vec![0u8; length];
    unsafe {
        data_spaces.ReadVirtual(
            buffer_ptr,
            utf16_bytes.as_mut_ptr().cast(),
            utf16_bytes.len() as u32,
            None,
        )?;
    }

    let utf16: Vec<u16> = utf16_bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let module_path = String::from_utf16_lossy(&utf16);
    if module_path.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(module_path))
    }
}

fn read_register_u64(registers: &IDebugRegisters, register_name: &[u8]) -> WinResult<u64> {
    let register_index = unsafe { registers.GetIndexByName(PCSTR(register_name.as_ptr())) }?;
    let mut value = DEBUG_VALUE::default();
    unsafe { registers.GetValue(register_index, &mut value) }?;
    Ok(unsafe { value.Anonymous.Anonymous.I64 })
}

fn read_virtual_exact<const N: usize>(
    data_spaces: &IDebugDataSpaces,
    address: u64,
) -> WinResult<[u8; N]> {
    let mut buffer = [0u8; N];
    unsafe {
        data_spaces.ReadVirtual(
            address,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            None,
        )?;
    }
    Ok(buffer)
}

fn read_virtual_pointer(data_spaces: &IDebugDataSpaces, address: u64) -> WinResult<Option<u64>> {
    let mut pointers = [0u64; 1];
    unsafe { data_spaces.ReadPointersVirtual(address, &mut pointers) }?;
    Ok((pointers[0] != 0).then_some(pointers[0]))
}

fn read_pe_image_info(
    data_spaces: &IDebugDataSpaces,
    image_base: u64,
) -> WinResult<Option<LoadedImageInfo>> {
    let dos_header = match read_virtual_exact::<DOS_HEADER_LEN>(data_spaces, image_base) {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!(
                image_base,
                ?error,
                "synthetic module-load could not read DOS header"
            );
            return Ok(None);
        }
    };
    if dos_header[0..2] != DOS_MAGIC {
        return Ok(None);
    }

    let pe_offset = u32::from_le_bytes([
        dos_header[0x3c],
        dos_header[0x3d],
        dos_header[0x3e],
        dos_header[0x3f],
    ]) as usize;
    let pe_header =
        match read_virtual_exact::<PE_HEADER_PROBE_LEN>(data_spaces, image_base + pe_offset as u64)
        {
            Ok(value) => value,
            Err(error) => {
                tracing::debug!(
                    image_base,
                    pe_offset,
                    ?error,
                    "synthetic module-load could not read PE header"
                );
                return Ok(None);
            }
        };

    if pe_header[0..4] != PE_MAGIC {
        return Ok(None);
    }

    let optional_magic = u16::from_le_bytes([
        pe_header[PE_OPTIONAL_HEADER_OFFSET],
        pe_header[PE_OPTIONAL_HEADER_OFFSET + 1],
    ]);
    if !matches!(optional_magic, PE32_MAGIC | PE32_PLUS_MAGIC) {
        return Ok(None);
    }

    let entry_rva = u32::from_le_bytes([
        pe_header[PE_ENTRY_POINT_RVA_OFFSET],
        pe_header[PE_ENTRY_POINT_RVA_OFFSET + 1],
        pe_header[PE_ENTRY_POINT_RVA_OFFSET + 2],
        pe_header[PE_ENTRY_POINT_RVA_OFFSET + 3],
    ]) as u64;
    let image_size = u32::from_le_bytes([
        pe_header[PE_IMAGE_SIZE_OFFSET],
        pe_header[PE_IMAGE_SIZE_OFFSET + 1],
        pe_header[PE_IMAGE_SIZE_OFFSET + 2],
        pe_header[PE_IMAGE_SIZE_OFFSET + 3],
    ]);
    if entry_rva == 0 || image_size == 0 {
        return Ok(None);
    }

    Ok(Some(LoadedImageInfo {
        image_base,
        image_size,
        entry_point: image_base + entry_rva,
    }))
}

fn synthetic_module_name_from_path(module_path: &str) -> String {
    module_path
        .rsplit(['\\', '/'])
        .find(|segment| !segment.is_empty())
        .unwrap_or("synthetic.sys")
        .to_string()
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
