use std::{
    ffi::CString,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use windows::{
    Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_CSS_LOADS, DEBUG_CSS_UNLOADS, DEBUG_EVENT_BREAKPOINT,
        DEBUG_EVENT_CHANGE_DEBUGGEE_STATE, DEBUG_EVENT_CHANGE_ENGINE_STATE,
        DEBUG_EVENT_CHANGE_SYMBOL_STATE, DEBUG_EVENT_EXCEPTION, DEBUG_EVENT_LOAD_MODULE,
        DEBUG_EVENT_SESSION_STATUS, DEBUG_EVENT_SYSTEM_ERROR, DEBUG_EVENT_UNLOAD_MODULE,
        IDebugBreakpoint, IDebugControl, IDebugDataSpaces, IDebugEventCallbacks,
        IDebugEventCallbacks_Impl, IDebugRegisters, IDebugSymbols, IDebugSymbols3,
    },
    core::{Error as WinError, HRESULT, PCSTR, Result as WinResult, implement},
};

use crate::headless::{
    module_match::{module_selector_matches, normalize_module_name},
    synthetic_load::{SyntheticLoadDecision, SyntheticLoadState},
};

const STATUS_BREAKPOINT: u32 = 0x8000_0003;

#[derive(Default)]
pub(crate) struct HeadlessEventControl {
    suppress_next_breakpoint: AtomicBool,
    suppressed_breakpoint_seen: AtomicBool,
    mirrored_filters: Mutex<MirroredSpecificFilters>,
}

impl HeadlessEventControl {
    pub(crate) fn suppress_one_breakpoint(&self) {
        self.suppress_next_breakpoint.store(true, Ordering::SeqCst);
    }

    pub(crate) fn take_pending_breakpoint_suppression(&self) -> bool {
        self.suppress_next_breakpoint.swap(false, Ordering::SeqCst)
    }

    pub(crate) fn should_suppress_breakpoint(&self) -> bool {
        self.suppress_next_breakpoint.swap(false, Ordering::SeqCst)
    }

    pub(crate) fn mark_suppressed_breakpoint_seen(&self) {
        self.suppressed_breakpoint_seen
            .store(true, Ordering::SeqCst);
    }

    pub(crate) fn take_suppressed_breakpoint_seen(&self) -> bool {
        self.suppressed_breakpoint_seen
            .swap(false, Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub(crate) fn mirror_specific_filter_command(&self, command: &str) {
        let mut mirrored_filters = self
            .mirrored_filters
            .lock()
            .expect("headless event mirror lock poisoned");
        mirrored_filters.apply_command(command);
    }

    pub(crate) fn refresh_module_load_watch(
        &self,
        command: &str,
        control: &IDebugControl,
        debug_symbols: &IDebugSymbols,
    ) {
        let mut mirrored_filters = self
            .mirrored_filters
            .lock()
            .expect("headless event mirror lock poisoned");
        mirrored_filters.apply_command(command);
        mirrored_filters.refresh_module_load_watch(debug_symbols);
        if let Err(error) = mirrored_filters.sync_synthetic_load_breakpoint(control) {
            tracing::warn!(
                ?error,
                "failed to synchronize synthetic module-load breakpoint state"
            );
        }
    }

    fn should_break_module_event(
        &self,
        kind: ModuleEventKind,
        module_name: &str,
        image_name: &str,
    ) -> bool {
        let mirrored_filters = self
            .mirrored_filters
            .lock()
            .expect("headless event mirror lock poisoned");
        mirrored_filters.should_break(kind, module_name, image_name)
    }

    fn should_break_on_symbol_state(
        &self,
        kind: ModuleEventKind,
        debug_symbols: &IDebugSymbols,
    ) -> bool {
        let mirrored_filters = self
            .mirrored_filters
            .lock()
            .expect("headless event mirror lock poisoned");
        mirrored_filters.should_break_on_symbol_state(kind, debug_symbols)
    }

    pub(crate) fn has_pending_module_load_watch(&self) -> bool {
        let mirrored_filters = self
            .mirrored_filters
            .lock()
            .expect("headless event mirror lock poisoned");
        mirrored_filters.has_pending_module_load_watch()
    }

    pub(crate) fn poll_module_load_watch(&self, debug_symbols: &IDebugSymbols) -> bool {
        let mut mirrored_filters = self
            .mirrored_filters
            .lock()
            .expect("headless event mirror lock poisoned");
        mirrored_filters.poll_module_load_watch(debug_symbols)
    }

    fn handle_synthetic_load_breakpoint(
        &self,
        breakpoint: &IDebugBreakpoint,
        control: &IDebugControl,
        registers: &IDebugRegisters,
        data_spaces: &IDebugDataSpaces,
        debug_symbols: &IDebugSymbols3,
    ) -> WinResult<SyntheticLoadDecision> {
        let mut mirrored_filters = self
            .mirrored_filters
            .lock()
            .expect("headless event mirror lock poisoned");
        mirrored_filters.handle_synthetic_load_breakpoint(
            breakpoint,
            control,
            registers,
            data_spaces,
            debug_symbols,
        )
    }
}

#[implement(IDebugEventCallbacks)]
pub(crate) struct HeadlessEventCallbacks {
    control: Arc<HeadlessEventControl>,
    debugger_control: IDebugControl,
    debug_data_spaces: IDebugDataSpaces,
    debug_registers: IDebugRegisters,
    debug_symbols: IDebugSymbols,
    debug_symbols3: IDebugSymbols3,
}

impl HeadlessEventCallbacks {
    pub(crate) fn new(
        control: Arc<HeadlessEventControl>,
        debugger_control: IDebugControl,
        debug_data_spaces: IDebugDataSpaces,
        debug_registers: IDebugRegisters,
        debug_symbols: IDebugSymbols,
        debug_symbols3: IDebugSymbols3,
    ) -> Self {
        Self {
            control,
            debugger_control,
            debug_data_spaces,
            debug_registers,
            debug_symbols,
            debug_symbols3,
        }
    }
}

fn request_break() -> WinResult<()> {
    tracing::debug!("headless event callback requested break");
    Err(WinError::from_hresult(HRESULT(6)))
}

fn request_go() -> WinResult<()> {
    tracing::debug!("headless event callback requested go");
    Err(WinError::from_hresult(HRESULT(1)))
}

impl IDebugEventCallbacks_Impl for HeadlessEventCallbacks_Impl {
    fn GetInterestMask(&self) -> WinResult<u32> {
        tracing::trace!("event callback GetInterestMask");
        Ok(DEBUG_EVENT_BREAKPOINT
            | DEBUG_EVENT_EXCEPTION
            | DEBUG_EVENT_SESSION_STATUS
            | DEBUG_EVENT_SYSTEM_ERROR
            | DEBUG_EVENT_CHANGE_DEBUGGEE_STATE
            | DEBUG_EVENT_CHANGE_ENGINE_STATE
            | DEBUG_EVENT_CHANGE_SYMBOL_STATE
            | DEBUG_EVENT_LOAD_MODULE
            | DEBUG_EVENT_UNLOAD_MODULE)
    }

    fn Breakpoint(&self, _bp: windows::core::Ref<IDebugBreakpoint>) -> WinResult<()> {
        let Some(breakpoint) = _bp.as_ref() else {
            tracing::debug!("event callback: breakpoint without breakpoint payload");
            return request_break();
        };

        match self.control.handle_synthetic_load_breakpoint(
            breakpoint,
            &self.debugger_control,
            &self.debug_registers,
            &self.debug_data_spaces,
            &self.debug_symbols3,
        )? {
            SyntheticLoadDecision::NotHandled => {
                tracing::debug!("event callback: breakpoint");
                request_break()
            }
            SyntheticLoadDecision::Continue => {
                tracing::debug!("event callback: synthetic module-load breakpoint will continue");
                request_go()
            }
            SyntheticLoadDecision::Break { module_path } => {
                tracing::debug!(
                    module_path = module_path.as_deref().unwrap_or("<unknown>"),
                    "event callback: synthetic module-load breakpoint matched"
                );
                request_break()
            }
        }
    }

    fn Exception(
        &self,
        exception: *const windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD64,
        firstchance: u32,
    ) -> WinResult<()> {
        let code = unsafe { exception.as_ref().map(|value| value.ExceptionCode) };
        tracing::debug!(?code, firstchance, "event callback: exception");
        if code
            == Some(windows::Win32::Foundation::NTSTATUS(
                STATUS_BREAKPOINT as i32,
            ))
            && firstchance == 1
            && self.control.should_suppress_breakpoint()
        {
            tracing::debug!("suppressing synthetic first-chance breakpoint after resume");
            self.control.mark_suppressed_breakpoint_seen();
            return request_go();
        }
        request_break()
    }

    fn CreateThread(&self, _handle: u64, _dataoffset: u64, _startoffset: u64) -> WinResult<()> {
        tracing::trace!("event callback: create thread");
        Ok(())
    }

    fn ExitThread(&self, _exitcode: u32) -> WinResult<()> {
        tracing::trace!("event callback: exit thread");
        Ok(())
    }

    fn CreateProcessA(
        &self,
        _imagefilehandle: u64,
        _handle: u64,
        _baseoffset: u64,
        _modulesize: u32,
        _modulename: &PCSTR,
        _imagename: &PCSTR,
        _checksum: u32,
        _timedatestamp: u32,
        _initialthreadhandle: u64,
        _threaddataoffset: u64,
        _startoffset: u64,
    ) -> WinResult<()> {
        tracing::debug!("event callback: create process");
        Ok(())
    }

    fn ExitProcess(&self, _exitcode: u32) -> WinResult<()> {
        tracing::debug!("event callback: exit process");
        Ok(())
    }

    fn LoadModule(
        &self,
        _imagefilehandle: u64,
        _baseoffset: u64,
        _modulesize: u32,
        modulename: &PCSTR,
        imagename: &PCSTR,
        _checksum: u32,
        _timedatestamp: u32,
    ) -> WinResult<()> {
        let module_name = pcstr_to_string(modulename);
        let image_name = pcstr_to_string(imagename);
        tracing::debug!(%module_name, %image_name, "event callback: load module");
        if self
            .control
            .should_break_module_event(ModuleEventKind::Load, &module_name, &image_name)
        {
            return request_break();
        }
        Ok(())
    }

    fn UnloadModule(&self, imagebasename: &PCSTR, _baseoffset: u64) -> WinResult<()> {
        let image_name = pcstr_to_string(imagebasename);
        tracing::debug!(%image_name, "event callback: unload module");
        if self
            .control
            .should_break_module_event(ModuleEventKind::Unload, &image_name, &image_name)
        {
            return request_break();
        }
        Ok(())
    }

    fn SystemError(&self, _error: u32, _level: u32) -> WinResult<()> {
        tracing::debug!("event callback: system error");
        request_break()
    }

    fn SessionStatus(&self, _status: u32) -> WinResult<()> {
        tracing::debug!("event callback: session status");
        Ok(())
    }

    fn ChangeDebuggeeState(&self, _flags: u32, _argument: u64) -> WinResult<()> {
        tracing::debug!("event callback: change debuggee state");
        Ok(())
    }

    fn ChangeEngineState(&self, _flags: u32, _argument: u64) -> WinResult<()> {
        tracing::debug!("event callback: change engine state");
        Ok(())
    }

    fn ChangeSymbolState(&self, flags: u32, _argument: u64) -> WinResult<()> {
        tracing::debug!(flags, "event callback: change symbol state");
        if (flags & DEBUG_CSS_LOADS) != 0
            && self
                .control
                .should_break_on_symbol_state(ModuleEventKind::Load, &self.debug_symbols)
        {
            return request_break();
        }
        if (flags & DEBUG_CSS_UNLOADS) != 0
            && self
                .control
                .should_break_on_symbol_state(ModuleEventKind::Unload, &self.debug_symbols)
        {
            return request_break();
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ModuleEventKind {
    Load,
    Unload,
}

#[derive(Default)]
struct MirroredSpecificFilters {
    load_module: MirroredModuleFilter,
    unload_module: MirroredModuleFilter,
}

impl MirroredSpecificFilters {
    fn apply_command(&mut self, command: &str) {
        for segment in command.split([';', '\n', '\r']) {
            self.apply_segment(segment.trim());
        }
    }

    fn apply_segment(&mut self, command: &str) {
        if command.is_empty() {
            return;
        }

        let mut parts = command.split_whitespace();
        let token = parts.next().unwrap_or_default().to_ascii_lowercase();
        match token.as_str() {
            "sxr" => {
                self.load_module = MirroredModuleFilter::default();
                self.unload_module = MirroredModuleFilter::default();
            }
            "sxe" | "sxd" | "sxn" | "sxi" | "sx-" => {
                let Some(filter_spec) = parts.next() else {
                    return;
                };
                let (filter_name, argument) =
                    filter_spec.split_once(':').unwrap_or((filter_spec, ""));
                let target = match filter_name.to_ascii_lowercase().as_str() {
                    "ld" => Some(&mut self.load_module),
                    "ud" => Some(&mut self.unload_module),
                    _ => None,
                };
                let Some(target) = target else {
                    return;
                };
                match token.as_str() {
                    "sxe" => {
                        target.break_enabled = true;
                        target.selector = selector_argument(argument);
                    }
                    "sx-" => *target = MirroredModuleFilter::default(),
                    _ => {
                        target.break_enabled = false;
                        target.selector = selector_argument(argument);
                    }
                }
            }
            _ => {}
        }
    }

    fn should_break(&self, kind: ModuleEventKind, module_name: &str, image_name: &str) -> bool {
        let rule = match kind {
            ModuleEventKind::Load => &self.load_module,
            ModuleEventKind::Unload => &self.unload_module,
        };
        if !rule.break_enabled {
            return false;
        }
        let Some(selector) = rule.selector.as_deref() else {
            return true;
        };
        module_selector_matches(selector, module_name)
            || module_selector_matches(selector, image_name)
    }

    fn should_break_on_symbol_state(
        &self,
        kind: ModuleEventKind,
        debug_symbols: &IDebugSymbols,
    ) -> bool {
        let rule = match kind {
            ModuleEventKind::Load => &self.load_module,
            ModuleEventKind::Unload => &self.unload_module,
        };
        if !rule.break_enabled {
            return false;
        }
        let Some(selector) = rule.selector.as_deref() else {
            return true;
        };
        module_is_loaded(debug_symbols, selector)
    }

    fn refresh_module_load_watch(&mut self, debug_symbols: &IDebugSymbols) {
        self.load_module.refresh_watch(debug_symbols);
    }

    fn has_pending_module_load_watch(&self) -> bool {
        self.load_module.watch_pending
    }

    fn poll_module_load_watch(&mut self, debug_symbols: &IDebugSymbols) -> bool {
        self.load_module.poll_watch(debug_symbols)
    }

    fn sync_synthetic_load_breakpoint(&mut self, control: &IDebugControl) -> WinResult<()> {
        self.load_module.sync_synthetic_load_breakpoint(control)
    }

    fn handle_synthetic_load_breakpoint(
        &mut self,
        breakpoint: &IDebugBreakpoint,
        control: &IDebugControl,
        registers: &IDebugRegisters,
        data_spaces: &IDebugDataSpaces,
        debug_symbols: &IDebugSymbols3,
    ) -> WinResult<SyntheticLoadDecision> {
        self.load_module.handle_synthetic_breakpoint(
            breakpoint,
            control,
            registers,
            data_spaces,
            debug_symbols,
        )
    }
}

#[derive(Default)]
struct MirroredModuleFilter {
    break_enabled: bool,
    selector: Option<String>,
    watch_pending: bool,
    last_loaded: bool,
    synthetic_load_state: SyntheticLoadState,
}

impl MirroredModuleFilter {
    fn refresh_watch(&mut self, debug_symbols: &IDebugSymbols) {
        if !self.break_enabled {
            self.watch_pending = false;
            self.last_loaded = false;
            return;
        }
        let Some(selector) = self.selector.as_deref() else {
            self.watch_pending = false;
            self.last_loaded = false;
            return;
        };

        let loaded = module_is_loaded(debug_symbols, selector);
        self.last_loaded = loaded;
        self.watch_pending = !loaded;
    }

    fn poll_watch(&mut self, debug_symbols: &IDebugSymbols) -> bool {
        if !self.watch_pending {
            return false;
        }
        let Some(selector) = self.selector.as_deref() else {
            return false;
        };

        let loaded = module_is_loaded(debug_symbols, selector);
        let should_break = loaded && !self.last_loaded;
        self.last_loaded = loaded;
        if should_break {
            self.watch_pending = false;
        }
        should_break
    }

    fn sync_synthetic_load_breakpoint(&mut self, control: &IDebugControl) -> WinResult<()> {
        self.synthetic_load_state
            .sync_breakpoint(control, self.break_enabled)
    }

    fn handle_synthetic_breakpoint(
        &mut self,
        breakpoint: &IDebugBreakpoint,
        control: &IDebugControl,
        registers: &IDebugRegisters,
        data_spaces: &IDebugDataSpaces,
        debug_symbols: &IDebugSymbols3,
    ) -> WinResult<SyntheticLoadDecision> {
        self.synthetic_load_state.handle_breakpoint(
            breakpoint,
            control,
            registers,
            data_spaces,
            debug_symbols,
            self.selector.as_deref(),
        )
    }
}

fn selector_argument(argument: &str) -> Option<String> {
    let argument = argument.trim();
    if argument.is_empty() {
        None
    } else {
        Some(argument.to_string())
    }
}

fn module_is_loaded(debug_symbols: &IDebugSymbols, selector: &str) -> bool {
    let selector = normalize_module_name(selector);
    if selector.is_empty() || selector.contains('*') || selector.contains('?') {
        return false;
    }

    let Ok(selector) = CString::new(selector) else {
        return false;
    };
    let mut base = 0u64;
    unsafe {
        debug_symbols
            .GetModuleByModuleName(PCSTR(selector.as_ptr() as _), 0, None, Some(&mut base))
            .is_ok()
    }
}

fn pcstr_to_string(value: &PCSTR) -> String {
    if value.is_null() {
        return String::new();
    }
    unsafe { value.to_string() }.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{MirroredSpecificFilters, ModuleEventKind};
    use crate::headless::module_match::{module_selector_matches, normalize_module_name};

    #[test]
    fn normalizes_loaded_module_names() {
        assert_eq!(
            normalize_module_name(r"\??\C:\ShadowGate\ShadowGateSys.sys"),
            "shadowgatesys"
        );
        assert_eq!(normalize_module_name("ShadowGateSys"), "shadowgatesys");
    }

    #[test]
    fn matches_exact_module_name_and_image_path() {
        assert!(module_selector_matches("ShadowGateSys", "ShadowGateSys"));
        assert!(module_selector_matches(
            "ShadowGateSys",
            r"\??\C:\ShadowGate\ShadowGateSys.sys"
        ));
    }

    #[test]
    fn matches_wildcard_module_patterns() {
        assert!(module_selector_matches("shadowgate*", "ShadowGateSys"));
        assert!(module_selector_matches(
            "shadowgate*.sys",
            "ShadowGateSys.sys"
        ));
        assert!(!module_selector_matches("shadowx*", "ShadowGateSys"));
    }

    #[test]
    fn mirrored_filters_break_only_for_selected_driver_loads() {
        let mut filters = MirroredSpecificFilters::default();
        filters.apply_command("sxe ld:ShadowGateSys");
        assert!(filters.should_break(
            ModuleEventKind::Load,
            "ShadowGateSys",
            r"\??\C:\ShadowGate\ShadowGateSys.sys"
        ));
        assert!(!filters.should_break(
            ModuleEventKind::Load,
            "otherdriver",
            r"\SystemRoot\System32\drivers\otherdriver.sys"
        ));
    }

    #[test]
    fn mirrored_filters_reset_to_ignore() {
        let mut filters = MirroredSpecificFilters::default();
        filters.apply_command("sxe ld:ShadowGateSys");
        filters.apply_command("sxr");
        assert!(!filters.should_break(
            ModuleEventKind::Load,
            "ShadowGateSys",
            r"\??\C:\ShadowGate\ShadowGateSys.sys"
        ));
    }
}
