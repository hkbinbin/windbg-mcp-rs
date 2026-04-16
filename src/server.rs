use std::{fs, path::PathBuf, process::Command, time::Duration};

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, handler::server::common::schema_for_type,
    model::*, schemars::JsonSchema, service::RequestContext,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    catalog::{Catalog, CatalogEntry, CatalogResourceKind, CatalogSection},
    executor::{CommandDispatcher, CommandExecutionResult, ExecutionError},
    resources::{GUIDE_URI, render_compact_command, render_full_command, render_guide},
    session_manager::HeadlessSessionManager,
};

#[cfg(test)]
use crate::executor::build_command;

#[derive(Debug, Deserialize, JsonSchema)]
struct ExecuteRawArgs {
    command: String,
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct InterruptTargetArgs {
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ResumeTargetArgs {
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct RecoverSessionArgs {
    session_id: Option<String>,
    resume_if_broken: Option<bool>,
    interrupt_if_running: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct GetExecutionStateArgs {
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct GetOutputArgs {
    session_id: Option<String>,
    cursor: Option<u64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct PrepareSymbolsArgs {
    session_id: Option<String>,
    module: Option<String>,
    symbol_cache: Option<String>,
    symbol_server: Option<String>,
    force_mismatched: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct DiagnoseExtensionsArgs {
    session_id: Option<String>,
    extension: Option<String>,
    probe_command: Option<String>,
    prepare_symbols: Option<bool>,
    module: Option<String>,
    symbol_cache: Option<String>,
    symbol_server: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct DbgPrintArgs {
    session_id: Option<String>,
    lines: Option<u32>,
    include_raw_output: Option<bool>,
    load_extension: Option<bool>,
    prepare_symbols: Option<bool>,
    symbol_cache: Option<String>,
    symbol_server: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ListBreakpointsArgs {
    session_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetBreakpointArgs {
    session_id: Option<String>,
    location: String,
    kind: Option<String>,
    one_shot: Option<bool>,
    pass_count: Option<u32>,
    command: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetHardwareBreakpointArgs {
    session_id: Option<String>,
    address: String,
    access: Option<String>,
    size: Option<u32>,
    one_shot: Option<bool>,
    pass_count: Option<u32>,
    command: Option<String>,
    process_name: Option<String>,
    pid: Option<String>,
    eprocess: Option<String>,
    ethread: Option<String>,
    prepare_symbols: Option<bool>,
    match_index: Option<usize>,
    set_context: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindProcessArgs {
    session_id: Option<String>,
    name: Option<String>,
    pid: Option<String>,
    prepare_symbols: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetProcessBreakpointArgs {
    session_id: Option<String>,
    location: String,
    process_name: Option<String>,
    pid: Option<String>,
    eprocess: Option<String>,
    ethread: Option<String>,
    kind: Option<String>,
    one_shot: Option<bool>,
    pass_count: Option<u32>,
    command: Option<String>,
    prepare_symbols: Option<bool>,
    match_index: Option<usize>,
    set_context: Option<bool>,
    allow_user_software: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetSyscallBreakpointArgs {
    session_id: Option<String>,
    syscall: String,
    process_name: Option<String>,
    pid: Option<String>,
    eprocess: Option<String>,
    one_shot: Option<bool>,
    command: Option<String>,
    prepare_symbols: Option<bool>,
    match_index: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ClearBreakpointArgs {
    session_id: Option<String>,
    breakpoint: Option<String>,
    safe: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ReadRegistersArgs {
    session_id: Option<String>,
    registers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct WriteRegisterArgs {
    session_id: Option<String>,
    register: String,
    value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadMemoryArgs {
    session_id: Option<String>,
    address: String,
    format: Option<String>,
    count: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct DisassembleArgs {
    session_id: Option<String>,
    address: Option<String>,
    count: Option<u32>,
    before: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct BacktraceArgs {
    session_id: Option<String>,
    format: Option<String>,
    count: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct SnapshotMemoryArgs {
    address: String,
    format: Option<String>,
    count: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct BreakpointSnapshotArgs {
    session_id: Option<String>,
    stack_format: Option<String>,
    stack_count: Option<u32>,
    disassemble_count: Option<u32>,
    stack_memory_count: Option<u32>,
    memory: Option<Vec<SnapshotMemoryArgs>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TraceBreakpointArgs {
    session_id: Option<String>,
    location: String,
    kind: Option<String>,
    hardware: Option<bool>,
    access: Option<String>,
    size: Option<u32>,
    process_name: Option<String>,
    pid: Option<String>,
    eprocess: Option<String>,
    ethread: Option<String>,
    prepare_symbols: Option<bool>,
    match_index: Option<usize>,
    set_context: Option<bool>,
    hits: Option<u32>,
    timeout_secs: Option<u64>,
    poll_interval_millis: Option<u64>,
    settle_millis: Option<u64>,
    require_stable_break: Option<bool>,
    commands: Option<Vec<String>>,
    include_default_snapshot: Option<bool>,
    auto_resume: Option<bool>,
    clear_after: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ContinueUntilBreakArgs {
    session_id: Option<String>,
    timeout_secs: Option<u64>,
    poll_interval_millis: Option<u64>,
    settle_millis: Option<u64>,
    require_stable_break: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct StepExecutionArgs {
    session_id: Option<String>,
    timeout_secs: Option<u64>,
    poll_interval_millis: Option<u64>,
    settle_millis: Option<u64>,
    require_stable_break: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EvaluateExpressionArgs {
    session_id: Option<String>,
    expression: String,
    evaluator: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ListModulesArgs {
    session_id: Option<String>,
    pattern: Option<String>,
    verbose: Option<bool>,
    unloaded: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchSymbolsArgs {
    session_id: Option<String>,
    pattern: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct InspectDriverArgs {
    session_id: Option<String>,
    name: String,
    flags: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetDriverLoadBreakpointArgs {
    session_id: Option<String>,
    image: String,
    clear_existing: Option<bool>,
    prepare_symbols: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DriverSummaryArgs {
    session_id: Option<String>,
    name: String,
    device: Option<String>,
    module_pattern: Option<String>,
    prepare_symbols: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetDriverDispatchBreakpointsArgs {
    session_id: Option<String>,
    driver: String,
    functions: Option<Vec<String>>,
    include_default_handlers: Option<bool>,
    one_shot: Option<bool>,
    command: Option<String>,
    prepare_symbols: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct DriverDispatchSnapshotArgs {
    session_id: Option<String>,
    irp: Option<String>,
    driver_object: Option<String>,
    stack_count: Option<u32>,
    memory_count: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct IoctlSnapshotArgs {
    session_id: Option<String>,
    irp: Option<String>,
    system_buffer: Option<String>,
    stack_location: Option<String>,
    auto_detect: Option<bool>,
    candidate_irps: Option<Vec<String>>,
    buffer_count: Option<u32>,
    irp_memory_count: Option<u32>,
    stack_count: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct MinifilterMessageSnapshotArgs {
    session_id: Option<String>,
    input_buffer: Option<String>,
    input_length: Option<String>,
    output_buffer: Option<String>,
    output_length: Option<String>,
    return_length_ptr: Option<String>,
    input_count: Option<u32>,
    output_count: Option<u32>,
    stack_count: Option<u32>,
    backtrace_count: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchCatalogArgs {
    query: String,
    section: Option<CatalogSection>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct OpenSessionArgs {
    connection: String,
    session_id: Option<String>,
    startup_command: Option<String>,
    attach_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CloseSessionArgs {
    session_id: String,
    shutdown_timeout_secs: Option<u64>,
    resume_before_close: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SwitchSessionArgs {
    session_id: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ListSessionsArgs {}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct CurrentSessionArgs {}

#[derive(Debug, Clone, Serialize)]
struct ProcessInfo {
    eprocess: String,
    pid: Option<String>,
    image: Option<String>,
    summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct DriverDispatchRoutine {
    index: Option<String>,
    major_function: String,
    target: String,
    symbol: Option<String>,
    raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IoctlStackArgsSummary {
    output_buffer_length: u64,
    input_buffer_length: u64,
    ioctl_code: u64,
    type3_input_buffer: u64,
    raw_values: Vec<String>,
}

#[derive(Clone)]
enum ServerBackend {
    AttachedSession { dispatcher: CommandDispatcher },
    Headless { sessions: HeadlessSessionManager },
}

#[derive(Clone)]
pub struct WindbgMcpServer {
    backend: ServerBackend,
}

struct PdbInfo {
    name: String,
    guid: String,
    age: u32,
}

impl PdbInfo {
    fn symbol_server_index(&self) -> String {
        format!(
            "{}{:X}",
            self.guid.replace('-', "").to_ascii_uppercase(),
            self.age
        )
    }
}

fn render_execution_result(execution: CommandExecutionResult) -> Value {
    json!({
        "command": execution.command,
        "output": execution.output,
        "state_before": execution.state_before,
        "state_after": execution.state_after,
    })
}

fn parse_lmi_pdb_info(output: &str) -> Option<PdbInfo> {
    let guid = output
        .lines()
        .find_map(|line| line.split_once("GUID:").map(|(_, value)| value.trim()))?
        .trim_matches('{')
        .trim_matches('}')
        .to_string();

    let age_line = output.lines().find(|line| line.contains("Age:"))?;
    let age_text = age_line.split_once("Age:")?.1.split(',').next()?.trim();
    let age = age_text.parse::<u32>().ok()?;
    let name = age_line.split_once("Pdb:")?.1.trim().to_string();
    if guid.is_empty() || name.is_empty() {
        return None;
    }

    Some(PdbInfo { name, guid, age })
}

fn classify_symbol_status(lmv_output: &str) -> &'static str {
    if lmv_output.contains("(pdb symbols)") {
        "pdb"
    } else if lmv_output.contains("(export symbols)") {
        "export"
    } else {
        "unknown"
    }
}

fn output_indicates_symbol_problem(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("symbols are incorrect")
        || lower.contains("symbol file could not be found")
        || (lower.contains("mismatched") && lower.contains("symbol"))
        || lower.contains("doesn't have full symbol information")
        || lower.contains("doesnt have full symbol information")
        || (lower.contains("cannot find") && lower.contains("type"))
}

fn output_indicates_extension_problem(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("unable to load extension")
        || lower.contains("could not load")
        || lower.contains("failed to load")
        || lower.contains("no export")
        || lower.contains("extension dll")
}

fn chain_contains_extension(chain_output: &str, extension: &str) -> bool {
    let chain = chain_output.to_ascii_lowercase();
    let extension = extension
        .trim_start_matches(".load")
        .trim()
        .trim_end_matches(".dll")
        .to_ascii_lowercase();
    !extension.is_empty()
        && (chain.contains(&extension) || chain.contains(&format!("{extension}.dll")))
}

fn tail_output_lines(output: &str, limit: u32) -> (Vec<String>, usize, bool) {
    let lines: Vec<String> = output
        .lines()
        .map(|line| line.trim_end_matches('\r').to_string())
        .collect();
    let total = lines.len();
    let limit = limit.max(1) as usize;
    let truncated = total > limit;
    if truncated {
        (lines[total - limit..].to_vec(), total, true)
    } else {
        (lines, total, false)
    }
}

fn quote_debugger_command(command: &str) -> String {
    format!("\"{}\"", command.replace('"', "\\\""))
}

fn trimmed_nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn debugger_atom(value: &str, field: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if value
        .chars()
        .any(|ch| matches!(ch, ';' | '"' | '\r' | '\n'))
    {
        return Err(format!(
            "{field} cannot contain command separators, quotes, or newlines"
        ));
    }
    Ok(value.to_string())
}

fn clamp_count(value: Option<u32>, default: u32, max: u32) -> u32 {
    value.unwrap_or(default).clamp(1, max)
}

fn parse_debugger_u64(value: &str) -> Option<u64> {
    let mut value = value.trim().trim_end_matches(':').replace('`', "");
    if value.is_empty() {
        return None;
    }
    let radix = if let Some(stripped) = value.strip_prefix("0n") {
        value = stripped.to_string();
        10
    } else {
        value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(&value)
            .to_string();
        16
    };
    u64::from_str_radix(&value, radix).ok()
}

fn irp_output_looks_valid(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("irp is active")
        || lower.contains("irp stack trace")
        || lower.contains("irp_mj_")
}

fn parse_irp_system_buffer(output: &str) -> Option<String> {
    for line in output.lines() {
        let Some((_, rest)) = line.split_once("System buffer=") else {
            continue;
        };
        let pointer = rest
            .trim()
            .trim_end_matches(':')
            .split(|ch: char| ch.is_whitespace() || ch == ':')
            .next()
            .unwrap_or("")
            .trim();
        if parse_debugger_u64(pointer).is_some() {
            return Some(pointer.to_string());
        }
    }
    None
}

fn parse_ioctl_stack_args(output: &str) -> Option<IoctlStackArgsSummary> {
    for line in output.lines() {
        let Some((_, args)) = line.split_once("Args:") else {
            continue;
        };
        let raw_values: Vec<String> = args
            .split_whitespace()
            .take(4)
            .map(|value| value.trim().to_string())
            .collect();
        if raw_values.len() < 4 {
            continue;
        }
        return Some(IoctlStackArgsSummary {
            output_buffer_length: parse_debugger_u64(&raw_values[0])?,
            input_buffer_length: parse_debugger_u64(&raw_values[1])?,
            ioctl_code: parse_debugger_u64(&raw_values[2])?,
            type3_input_buffer: parse_debugger_u64(&raw_values[3])?,
            raw_values,
        });
    }
    None
}

fn parse_db_bytes(output: &str, max_bytes: usize) -> Vec<String> {
    let mut bytes = Vec::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let _address = parts.next();
        for token in parts {
            for value in token.split('-') {
                if value.len() == 2 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    bytes.push(value.to_ascii_lowercase());
                    if bytes.len() >= max_bytes {
                        return bytes;
                    }
                }
            }
        }
    }
    bytes
}

fn parse_le_u32_from_hex_bytes(bytes: &[String], offset: usize) -> Option<u32> {
    let window = bytes.get(offset..offset + 4)?;
    let mut value = 0u32;
    for (index, byte) in window.iter().enumerate() {
        let parsed = u8::from_str_radix(byte, 16).ok()? as u32;
        value |= parsed << (index * 8);
    }
    Some(value)
}

fn contiguous_hex(bytes: &[String]) -> Option<String> {
    (!bytes.is_empty()).then(|| bytes.join(""))
}

fn parse_evaluator_u64(output: &str) -> Option<u64> {
    for line in output.lines().rev() {
        let value_text = line
            .split_once('=')
            .map(|(_, value)| value)
            .unwrap_or(line)
            .trim();
        for token in value_text.split_whitespace().rev() {
            let token = token.trim_matches(|ch: char| ch == ',' || ch == ';');
            if let Some(value) = parse_debugger_u64(token) {
                return Some(value);
            }
        }
    }
    None
}

fn blocked_unsafe_debugger_command(command: &str) -> Option<String> {
    for segment in command.split([';', '\n', '\r']) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if disables_load_event_filter(segment) {
            return Some(format!(
                "blocked unsafe WinDbg command `{segment}`: this dbgeng headless path has been observed to access-violate when disabling `ld` filters after a module-load event. Leave the load filter in the short-lived session, clear normal breakpoints with `windbg_clear_breakpoint`, then resume or close the session."
            ));
        }
        if looks_like_fragile_multi_register_read(segment) {
            return Some(format!(
                "blocked fragile WinDbg command `{segment}`: raw `r <reg> <reg> ...` subset reads have produced transient dbgeng `0x80040205` states in headless mode. Use `windbg_read_registers` with a `registers` array instead; it reads each register as an isolated command."
            ));
        }
    }
    None
}

fn looks_like_fragile_multi_register_read(segment: &str) -> bool {
    let mut parts = segment.split_whitespace();
    let Some(verb) = parts.next() else {
        return false;
    };
    if !verb.eq_ignore_ascii_case("r") {
        return false;
    }

    let registers = parts.collect::<Vec<_>>();
    registers.len() > 1 && registers.iter().all(|part| !part.contains('='))
}

fn disables_load_event_filter(segment: &str) -> bool {
    let mut parts = segment.split_whitespace();
    let Some(verb) = parts.next() else {
        return false;
    };
    if !verb.eq_ignore_ascii_case("sxd") {
        return false;
    }
    let Some(filter_spec) = parts.next() else {
        return false;
    };
    let filter_name = filter_spec
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or(filter_spec)
        .to_ascii_lowercase();
    matches!(filter_name.as_str(), "ld" | "ld*")
}

fn build_breakpoint_command(
    kind: Option<&str>,
    location: &str,
    one_shot: Option<bool>,
    process: Option<&str>,
    thread: Option<&str>,
    pass_count: Option<u32>,
    command_string: Option<&str>,
) -> Result<String, String> {
    let location = location.trim();
    if location.is_empty() {
        return Err("breakpoint location cannot be empty".to_string());
    }

    let kind = kind
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("bp")
        .to_ascii_lowercase();
    if !matches!(kind.as_str(), "bp" | "bu" | "bm") {
        return Err("breakpoint kind must be `bp`, `bu`, or `bm`".to_string());
    }

    let mut command = kind;
    if one_shot.unwrap_or(false) {
        command.push_str(" /1");
    }
    if let Some(process) = trimmed_nonempty(process) {
        command.push_str(" /p ");
        command.push_str(&debugger_atom(process, "eprocess")?);
    }
    if let Some(thread) = trimmed_nonempty(thread) {
        command.push_str(" /t ");
        command.push_str(&debugger_atom(thread, "ethread")?);
    }
    command.push(' ');
    command.push_str(location);
    if let Some(pass_count) = pass_count {
        command.push(' ');
        command.push_str(&pass_count.to_string());
    }
    if let Some(command_string) = trimmed_nonempty(command_string) {
        command.push(' ');
        command.push_str(&quote_debugger_command(command_string));
    }

    Ok(command)
}

fn normalize_hardware_access(access: Option<&str>) -> Result<&'static str, String> {
    let access = access
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("execute")
        .to_ascii_lowercase();

    match access.as_str() {
        "e" | "exec" | "execute" | "execution" => Ok("e"),
        "r" | "read" => Ok("r"),
        "w" | "write" => Ok("w"),
        "i" | "io" | "i/o" => Ok("i"),
        _ => Err(
            "hardware breakpoint access must be execute/e, read/r, write/w, or io/i".to_string(),
        ),
    }
}

fn normalize_hardware_size(access: &str, size: Option<u32>) -> Result<u32, String> {
    let size = size.unwrap_or(1);
    if !matches!(size, 1 | 2 | 4 | 8) {
        return Err("hardware breakpoint size must be 1, 2, 4, or 8 bytes".to_string());
    }
    if access == "e" && size != 1 {
        return Err("execute hardware breakpoints must use size 1".to_string());
    }
    Ok(size)
}

fn build_hardware_breakpoint_command(
    access: Option<&str>,
    size: Option<u32>,
    address: &str,
    one_shot: Option<bool>,
    process: Option<&str>,
    thread: Option<&str>,
    pass_count: Option<u32>,
    command_string: Option<&str>,
) -> Result<String, String> {
    let access = normalize_hardware_access(access)?;
    let size = normalize_hardware_size(access, size)?;
    let address = debugger_atom(address, "address")?;

    let mut command = format!("ba {access} {size}");
    if one_shot.unwrap_or(false) {
        command.push_str(" /1");
    }
    if let Some(process) = trimmed_nonempty(process) {
        command.push_str(" /p ");
        command.push_str(&debugger_atom(process, "eprocess")?);
    }
    if let Some(thread) = trimmed_nonempty(thread) {
        command.push_str(" /t ");
        command.push_str(&debugger_atom(thread, "ethread")?);
    }
    command.push(' ');
    command.push_str(&address);
    if let Some(pass_count) = pass_count {
        command.push(' ');
        command.push_str(&pass_count.to_string());
    }
    if let Some(command_string) = trimmed_nonempty(command_string) {
        command.push(' ');
        command.push_str(&quote_debugger_command(command_string));
    }

    Ok(command)
}

fn parse_breakpoint_ids(output: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in output.lines() {
        let Some(token) = line.split_whitespace().next() else {
            continue;
        };
        let token = token.trim_end_matches(':');
        if !token.is_empty()
            && token.chars().all(|ch| ch.is_ascii_digit())
            && !ids.iter().any(|existing| existing == token)
        {
            ids.push(token.to_string());
        }
    }
    ids
}

fn new_breakpoint_ids(before: &str, after: &str) -> Vec<String> {
    let before_ids = parse_breakpoint_ids(before);
    parse_breakpoint_ids(after)
        .into_iter()
        .filter(|id| !before_ids.iter().any(|before_id| before_id == id))
        .collect()
}

fn output_indicates_breakpoint_failure(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("couldn't resolve error")
        || lower.contains("could not resolve")
        || lower.contains("unable to resolve")
        || lower.contains("symbol not found")
        || lower.contains("syntax error")
        || lower.contains("breakpoint expression")
        || lower.contains("ambiguous symbol")
}

fn validate_created_breakpoints(
    command: &str,
    output: &str,
    created_breakpoints: &[String],
) -> Result<(), String> {
    if output_indicates_breakpoint_failure(output) {
        return Err(format!(
            "breakpoint command `{command}` failed in WinDbg: {}",
            output.trim()
        ));
    }
    if created_breakpoints.is_empty() {
        return Err(format!(
            "breakpoint command `{command}` did not create a new breakpoint; verify the address/symbol and inspect `bl` output"
        ));
    }
    Ok(())
}

fn looks_like_user_mode_address(value: &str) -> bool {
    let value = value.trim().trim_start_matches('@');
    let Some(address) = parse_debugger_u64(value) else {
        return false;
    };
    address != 0 && address < 0x0000_8000_0000_0000
}

fn default_trace_commands() -> Vec<String> {
    vec![
        ".lastevent".to_string(),
        "r".to_string(),
        "u @rip L16".to_string(),
        "kv 16".to_string(),
        "bl".to_string(),
    ]
}

fn memory_command(
    address: &str,
    format: Option<&str>,
    count: Option<u32>,
) -> Result<String, String> {
    let address = address.trim();
    if address.is_empty() {
        return Err("memory address cannot be empty".to_string());
    }

    let format = format.unwrap_or("qwords").trim().to_ascii_lowercase();
    let command = match format.as_str() {
        "b" | "byte" | "bytes" | "db" => {
            format!("db {address} L{}", clamp_count(count, 64, 4096))
        }
        "w" | "word" | "words" | "dw" => {
            format!("dw {address} L{}", clamp_count(count, 32, 2048))
        }
        "d" | "dword" | "dwords" | "dd" => {
            format!("dd {address} L{}", clamp_count(count, 32, 2048))
        }
        "q" | "qword" | "qwords" | "dq" | "pointer" | "pointers" => {
            format!("dq {address} L{}", clamp_count(count, 16, 1024))
        }
        "ascii" | "a" | "da" => format!("da {address}"),
        "unicode" | "u16" | "du" => format!("du {address}"),
        "poi" | "deref" => format!("dq poi({address}) L{}", clamp_count(count, 16, 1024)),
        _ => {
            return Err(format!(
                "unsupported memory format `{format}`; expected bytes, words, dwords, qwords, ascii, unicode, or poi"
            ));
        }
    };
    Ok(command)
}

fn backtrace_command(format: Option<&str>, count: Option<u32>) -> Result<String, String> {
    let requested = trimmed_nonempty(format).unwrap_or("kv");
    let command = match requested {
        value if value.eq_ignore_ascii_case("k") => "k",
        value if value.eq_ignore_ascii_case("kb") => "kb",
        "kP" => "kP",
        value if value.eq_ignore_ascii_case("kp") => "kp",
        value if value.eq_ignore_ascii_case("kv") => "kv",
        _ => {
            return Err(format!(
                "unsupported backtrace format `{requested}`; expected k, kb, kp, kP, or kv"
            ));
        }
    };
    Ok(format!("{} {}", command, clamp_count(count, 32, 512)))
}

fn parse_processes(output: &str) -> Vec<ProcessInfo> {
    #[derive(Default)]
    struct Builder {
        eprocess: String,
        pid: Option<String>,
        image: Option<String>,
        lines: Vec<String>,
    }

    impl Builder {
        fn finish(self) -> Option<ProcessInfo> {
            if self.eprocess.is_empty() {
                return None;
            }
            Some(ProcessInfo {
                eprocess: self.eprocess,
                pid: self.pid,
                image: self.image,
                summary: self.lines.join("\n"),
            })
        }
    }

    let mut processes = Vec::new();
    let mut current: Option<Builder> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("PROCESS ") {
            if let Some(builder) = current.take().and_then(Builder::finish) {
                processes.push(builder);
            }
            let eprocess = rest.split_whitespace().next().unwrap_or("").to_string();
            current = Some(Builder {
                eprocess,
                lines: vec![trimmed.to_string()],
                ..Builder::default()
            });
        } else if let Some(builder) = current.as_mut() {
            builder.lines.push(line.to_string());
        }

        if let Some(builder) = current.as_mut() {
            if let Some(pid) = parse_process_field(trimmed, "Cid:") {
                builder.pid = Some(pid);
            }
            if let Some(image) = parse_process_field(trimmed, "Image:") {
                builder.image = Some(image);
            }
        }
    }

    if let Some(builder) = current.take().and_then(Builder::finish) {
        processes.push(builder);
    }

    processes
}

fn parse_process_field(line: &str, label: &str) -> Option<String> {
    let start = line.find(label)? + label.len();
    line[start..]
        .split_whitespace()
        .next()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_output_pid(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok()
}

fn parse_user_pid(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(decimal) = value.strip_prefix("0n") {
        return decimal.parse().ok();
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse().ok()
}

fn process_matches(process: &ProcessInfo, name: Option<&str>, pid: Option<&str>) -> bool {
    if let Some(name) = trimmed_nonempty(name) {
        let Some(image) = process.image.as_deref() else {
            return false;
        };
        if !wildcard_match_case_insensitive(name, image) {
            return false;
        }
    }

    if let Some(pid) = trimmed_nonempty(pid) {
        let Some(actual) = process.pid.as_deref().and_then(parse_output_pid) else {
            return false;
        };
        let Some(expected) = parse_user_pid(pid) else {
            return false;
        };
        if actual != expected {
            return false;
        }
    }

    true
}

fn wildcard_match_case_insensitive(pattern: &str, value: &str) -> bool {
    fn inner(pattern: &[u8], value: &[u8]) -> bool {
        match (pattern.split_first(), value.split_first()) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some((&b'*', rest)), _) => {
                inner(rest, value) || (!value.is_empty() && inner(pattern, &value[1..]))
            }
            (Some((&b'?', rest)), Some(_)) => inner(rest, &value[1..]),
            (Some((&p, rest)), Some((&v, value_rest))) if p == v => inner(rest, value_rest),
            _ => false,
        }
    }

    inner(
        pattern.to_ascii_lowercase().as_bytes(),
        value.to_ascii_lowercase().as_bytes(),
    )
}

fn normalize_syscall_location(syscall: &str) -> Result<String, String> {
    let syscall = syscall.trim();
    if syscall.is_empty() {
        return Err("syscall cannot be empty".to_string());
    }
    if syscall.contains('!') {
        return Ok(syscall.to_string());
    }

    let name = match syscall.to_ascii_lowercase().as_str() {
        "createfile" | "ntcreatefile" => "NtCreateFile",
        "deviceiocontrol" | "deviceiocontrolfile" | "ntdeviceiocontrolfile" => {
            "NtDeviceIoControlFile"
        }
        _ => syscall,
    };
    Ok(format!("nt!{name}"))
}

fn driver_short_name(name: &str) -> &str {
    let short_name = name
        .trim()
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .trim();
    if short_name.to_ascii_lowercase().ends_with(".sys") {
        &short_name[..short_name.len() - 4]
    } else {
        short_name
    }
}

fn parse_driver_dispatch_routines(output: &str) -> Vec<DriverDispatchRoutine> {
    let mut routines = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("IRP_MJ_") {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(major_index) = tokens.iter().position(|token| token.contains("IRP_MJ_")) else {
            continue;
        };

        let major_function = tokens[major_index]
            .trim_matches(|ch| matches!(ch, ':' | ',' | ';'))
            .to_string();
        let Some(target) = tokens
            .get(major_index + 1)
            .map(|value| value.trim_matches(|ch| matches!(ch, ':' | ',' | ';')))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let symbol = tokens
            .get(major_index + 2)
            .map(|value| value.trim_matches(|ch| matches!(ch, ':' | ',' | ';')))
            .filter(|value| !value.is_empty() && !value.starts_with('+'))
            .map(str::to_string);
        let index = tokens[..major_index].iter().find_map(|token| {
            let token = token.trim();
            token
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .map(str::to_string)
        });

        routines.push(DriverDispatchRoutine {
            index,
            major_function,
            target: target.to_string(),
            symbol,
            raw: trimmed.to_string(),
        });
    }

    routines
}

fn normalize_dispatch_filter(value: &str) -> String {
    let value = value
        .trim()
        .trim_matches(['[', ']'])
        .replace(['-', ' '], "_");
    let upper = value.to_ascii_uppercase();
    if upper.starts_with("IRP_MJ_") {
        upper
    } else if upper.starts_with("MJ_") {
        format!("IRP_{upper}")
    } else {
        format!("IRP_MJ_{upper}")
    }
}

fn dispatch_filter_matches(routine: &DriverDispatchRoutine, filter: &str) -> bool {
    let filter = filter.trim();
    if filter.is_empty() {
        return false;
    }

    let index_filter = filter
        .trim_matches(['[', ']'])
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if routine
        .index
        .as_deref()
        .is_some_and(|index| index.eq_ignore_ascii_case(index_filter))
    {
        return true;
    }

    routine
        .major_function
        .eq_ignore_ascii_case(&normalize_dispatch_filter(filter))
}

fn is_default_dispatch_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.contains("iopinvaliddevicerequest") || lower == "0" || lower == "00000000"
}

fn is_default_dispatch_routine(routine: &DriverDispatchRoutine) -> bool {
    is_default_dispatch_target(&routine.target)
        || routine
            .symbol
            .as_deref()
            .is_some_and(is_default_dispatch_target)
        || routine
            .raw
            .to_ascii_lowercase()
            .contains("iopinvaliddevicerequest")
}

fn default_symbol_cache_dir() -> PathBuf {
    std::env::var_os("WINDBG_MCP_SYMBOL_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Symbols"))
}

fn download_symbol_file(url: &str, destination: &PathBuf) -> Result<(), String> {
    let parent = destination.parent().ok_or_else(|| {
        format!(
            "symbol destination has no parent: {}",
            destination.display()
        )
    })?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($Uri, $OutFile) $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile }",
        ])
        .arg(url)
        .arg(destination)
        .output()
        .map_err(|error| format!("failed to start powershell symbol download: {error}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to download `{url}` to `{}`: {}{}",
            destination.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

impl WindbgMcpServer {
    pub fn new(dispatcher: CommandDispatcher) -> Self {
        Self {
            backend: ServerBackend::AttachedSession { dispatcher },
        }
    }

    pub fn headless(sessions: HeadlessSessionManager) -> Self {
        Self {
            backend: ServerBackend::Headless { sessions },
        }
    }

    fn is_headless(&self) -> bool {
        matches!(self.backend, ServerBackend::Headless { .. })
    }

    fn catalog(&self) -> &'static Catalog {
        Catalog::global()
    }

    fn parse_arguments<T>(&self, arguments: Option<JsonObject>) -> Result<T, McpError>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
            .map_err(|error| McpError::invalid_params(error.to_string(), None))
    }

    fn generic_command_tool(&self) -> Tool {
        Tool::new(
            "windbg_execute_command",
            "Execute a WinDbg command string through dbgeng. Query state first and interrupt explicitly when needed. In headless mode, `session_id` routes the call to a specific attached session.",
            schema_for_type::<ExecuteRawArgs>(),
        )
        .with_title("Execute WinDbg command")
    }

    fn state_tool(&self) -> Tool {
        Tool::new(
            "windbg_get_execution_state",
            "Query the current debugger execution state before deciding whether to interrupt, resume, or execute a command. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<GetExecutionStateArgs>(),
        )
        .with_title("Get debugger execution state")
    }

    fn output_tool(&self) -> Tool {
        Tool::new(
            "windbg_get_output",
            "Read the buffered debugger command output history for the current session. Pass the last returned `next_cursor` to fetch only newer entries. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<GetOutputArgs>(),
        )
        .with_title("Get debugger output")
    }

    fn prepare_symbols_tool(&self) -> Tool {
        Tool::new(
            "windbg_prepare_symbols",
            "Prepare exact PDB symbols for a loaded module, defaulting to `nt`. The tool reads `!lmi`, downloads the module PDB from the Microsoft symbol server into a local cache, appends the exact PDB directory to `.sympath`, and reloads the module.",
            schema_for_type::<PrepareSymbolsArgs>(),
        )
        .with_title("Prepare debugger symbols")
    }

    fn diagnose_extensions_tool(&self) -> Tool {
        Tool::new(
            "windbg_diagnose_extensions",
            "Collect extension-loading diagnostics. The tool returns `.extpath`, `.chain`, optional symbol preparation, extension load output, probe command output, and remediation hints.",
            schema_for_type::<DiagnoseExtensionsArgs>(),
        )
        .with_title("Diagnose debugger extensions")
    }

    fn dbgprint_tool(&self) -> Tool {
        Tool::new(
            "windbg_dbgprint",
            "Read kernel DbgPrint output with the `!dbgprint` extension command. Returns a bounded tail by default, with optional `kdexts` loading, symbol preparation, and full raw output.",
            schema_for_type::<DbgPrintArgs>(),
        )
        .with_title("Read DbgPrint output")
    }

    fn set_breakpoint_tool(&self) -> Tool {
        Tool::new(
            "windbg_set_breakpoint",
            "Set a code breakpoint with `bp`, `bu`, or `bm`, then return the updated `bl` listing. Supports one-shot breakpoints, pass counts, and WinDbg command strings.",
            schema_for_type::<SetBreakpointArgs>(),
        )
        .with_title("Set breakpoint")
    }

    fn set_hardware_breakpoint_tool(&self) -> Tool {
        Tool::new(
            "windbg_set_hardware_breakpoint",
            "Set a hardware breakpoint/watchpoint with WinDbg `ba`. Supports execute/read/write/io access, byte sizes 1/2/4/8, one-shot/pass-count/command strings, and optional process/thread scoping.",
            schema_for_type::<SetHardwareBreakpointArgs>(),
        )
        .with_title("Set hardware breakpoint")
    }

    fn find_process_tool(&self) -> Tool {
        Tool::new(
            "windbg_find_process",
            "Find kernel processes with `!process`, returning parsed EPROCESS, PID, image name, and raw summary blocks. Prepares `nt` symbols by default so process lookup keeps working after fresh KDNET attaches.",
            schema_for_type::<FindProcessArgs>(),
        )
        .with_title("Find kernel process")
    }

    fn set_process_breakpoint_tool(&self) -> Tool {
        Tool::new(
            "windbg_set_process_breakpoint",
            "Resolve a kernel process by image name or PID, then set a process-scoped breakpoint using WinDbg's native `bp /p <EPROCESS>` support.",
            schema_for_type::<SetProcessBreakpointArgs>(),
        )
        .with_title("Set process-scoped breakpoint")
    }

    fn set_syscall_breakpoint_tool(&self) -> Tool {
        Tool::new(
            "windbg_set_syscall_breakpoint",
            "Set a process-scoped syscall breakpoint for symbols such as `NtCreateFile` or `NtDeviceIoControlFile`, reducing global kernel breakpoint noise.",
            schema_for_type::<SetSyscallBreakpointArgs>(),
        )
        .with_title("Set process-scoped syscall breakpoint")
    }

    fn list_breakpoints_tool(&self) -> Tool {
        Tool::new(
            "windbg_list_breakpoints",
            "List debugger breakpoints using `bl`.",
            schema_for_type::<ListBreakpointsArgs>(),
        )
        .with_title("List breakpoints")
    }

    fn clear_breakpoint_tool(&self) -> Tool {
        Tool::new(
            "windbg_clear_breakpoint",
            "Clear a breakpoint using `bc`. Omit `breakpoint` to clear all breakpoints.",
            schema_for_type::<ClearBreakpointArgs>(),
        )
        .with_title("Clear breakpoint")
    }

    fn read_registers_tool(&self) -> Tool {
        Tool::new(
            "windbg_read_registers",
            "Read registers using `r`. Omit `registers` for the standard register set.",
            schema_for_type::<ReadRegistersArgs>(),
        )
        .with_title("Read registers")
    }

    fn write_register_tool(&self) -> Tool {
        Tool::new(
            "windbg_write_register",
            "Write one register using `r <register>=<value>` and return the resulting register output.",
            schema_for_type::<WriteRegisterArgs>(),
        )
        .with_title("Write register")
    }

    fn read_memory_tool(&self) -> Tool {
        Tool::new(
            "windbg_read_memory",
            "Read target memory. Supported formats: bytes/db, words/dw, dwords/dd, qwords/dq, ascii/da, unicode/du, and poi/deref.",
            schema_for_type::<ReadMemoryArgs>(),
        )
        .with_title("Read memory")
    }

    fn disassemble_tool(&self) -> Tool {
        Tool::new(
            "windbg_disassemble",
            "Disassemble around an address using `u` or `ub`. Omit `address` to disassemble at the current instruction pointer.",
            schema_for_type::<DisassembleArgs>(),
        )
        .with_title("Disassemble")
    }

    fn backtrace_tool(&self) -> Tool {
        Tool::new(
            "windbg_backtrace",
            "Show a stack backtrace using `k`, `kb`, `kp`, or `kv`.",
            schema_for_type::<BacktraceArgs>(),
        )
        .with_title("Backtrace")
    }

    fn breakpoint_snapshot_tool(&self) -> Tool {
        Tool::new(
            "windbg_breakpoint_snapshot",
            "Collect a common breakpoint-hit snapshot: `.lastevent`, registers, backtrace, disassembly at RIP, stack memory, breakpoint list, and optional extra memory reads.",
            schema_for_type::<BreakpointSnapshotArgs>(),
        )
        .with_title("Breakpoint snapshot")
    }

    fn trace_breakpoint_tool(&self) -> Tool {
        Tool::new(
            "windbg_trace_breakpoint",
            "Set a temporary software or hardware breakpoint, continue until stable hit(s), run synchronous capture commands, then optionally clear and resume. This replaces fragile command-breakpoint tracing such as `bp addr \".echo; r; g\"` in headless mode.",
            schema_for_type::<TraceBreakpointArgs>(),
        )
        .with_title("Trace breakpoint")
    }

    fn continue_until_break_tool(&self) -> Tool {
        Tool::new(
            "windbg_continue_until_break",
            "Resume the target with `windbg_resume_target` and poll execution state until the target breaks again or a timeout expires.",
            schema_for_type::<ContinueUntilBreakArgs>(),
        )
        .with_title("Continue until break")
    }

    fn step_tool(&self) -> Tool {
        Tool::new(
            "windbg_step",
            "Single-step into one instruction with `t`, then poll until a stable command-ready break is available.",
            schema_for_type::<StepExecutionArgs>(),
        )
        .with_title("Step into")
    }

    fn step_over_tool(&self) -> Tool {
        Tool::new(
            "windbg_step_over",
            "Step over one instruction/call with `p`, then poll until a stable command-ready break is available.",
            schema_for_type::<StepExecutionArgs>(),
        )
        .with_title("Step over")
    }

    fn go_up_tool(&self) -> Tool {
        Tool::new(
            "windbg_go_up",
            "Run until the current function returns with `gu`, then poll until a stable command-ready break is available.",
            schema_for_type::<StepExecutionArgs>(),
        )
        .with_title("Go up")
    }

    fn evaluate_expression_tool(&self) -> Tool {
        Tool::new(
            "windbg_evaluate_expression",
            "Evaluate a debugger expression with the MASM `?` evaluator by default, or C++ `??` when `evaluator` is `cpp`.",
            schema_for_type::<EvaluateExpressionArgs>(),
        )
        .with_title("Evaluate expression")
    }

    fn list_modules_tool(&self) -> Tool {
        Tool::new(
            "windbg_list_modules",
            "List loaded or unloaded modules using `lm`, with optional `pattern`, `verbose`, and `unloaded` flags.",
            schema_for_type::<ListModulesArgs>(),
        )
        .with_title("List modules")
    }

    fn search_symbols_tool(&self) -> Tool {
        Tool::new(
            "windbg_search_symbols",
            "Search symbols with `x <pattern>`, for example `nt!*CreateFile*` or `ShadowGate*!*`.",
            schema_for_type::<SearchSymbolsArgs>(),
        )
        .with_title("Search symbols")
    }

    fn inspect_driver_tool(&self) -> Tool {
        Tool::new(
            "windbg_inspect_driver",
            "Inspect a kernel driver object with `!drvobj <name> <flags>`. Defaults to flags `7`.",
            schema_for_type::<InspectDriverArgs>(),
        )
        .with_title("Inspect driver object")
    }

    fn set_driver_load_breakpoint_tool(&self) -> Tool {
        Tool::new(
            "windbg_set_driver_load_breakpoint",
            "Prepare kernel symbols by default, then break when a kernel driver image loads by configuring `sxe ld:<image>` and returning the event filter list.",
            schema_for_type::<SetDriverLoadBreakpointArgs>(),
        )
        .with_title("Set driver load breakpoint")
    }

    fn driver_summary_tool(&self) -> Tool {
        Tool::new(
            "windbg_driver_summary",
            "Collect a driver-oriented summary: module listing, `!drvobj <name> 7`, object checks, optional device object checks, and parsed IRP dispatch routines.",
            schema_for_type::<DriverSummaryArgs>(),
        )
        .with_title("Driver summary")
    }

    fn set_driver_dispatch_breakpoints_tool(&self) -> Tool {
        Tool::new(
            "windbg_set_driver_dispatch_breakpoints",
            "Parse `!drvobj <driver> 7` and set breakpoints on selected IRP_MJ dispatch routines, defaulting to create/close/device-control when available.",
            schema_for_type::<SetDriverDispatchBreakpointsArgs>(),
        )
        .with_title("Set driver dispatch breakpoints")
    }

    fn driver_dispatch_snapshot_tool(&self) -> Tool {
        Tool::new(
            "windbg_driver_dispatch_snapshot",
            "Collect a dispatch breakpoint snapshot: last event, registers, IRP details, driver object details, stack, RIP disassembly, memory, and breakpoints.",
            schema_for_type::<DriverDispatchSnapshotArgs>(),
        )
        .with_title("Driver dispatch snapshot")
    }

    fn ioctl_snapshot_tool(&self) -> Tool {
        Tool::new(
            "windbg_ioctl_snapshot",
            "Collect an IOCTL-focused IRP snapshot with auto IRP-register detection, parsed IOCTL/input/output lengths, SystemBuffer byte summary, IRP memory, registers, backtrace, and current disassembly.",
            schema_for_type::<IoctlSnapshotArgs>(),
        )
        .with_title("IOCTL snapshot")
    }

    fn minifilter_message_snapshot_tool(&self) -> Tool {
        Tool::new(
            "windbg_minifilter_message_snapshot",
            "Collect a Filter Manager communication-port MessageNotifyCallback snapshot: registers, stack arguments, input/output buffer bytes, parsed message header, backtrace, disassembly, and breakpoint list. Defaults match x64 minifilter callbacks where InputBuffer is @rdx and InputBufferLength is @r8.",
            schema_for_type::<MinifilterMessageSnapshotArgs>(),
        )
        .with_title("Minifilter message snapshot")
    }

    fn interrupt_tool(&self) -> Tool {
        Tool::new(
            "windbg_interrupt_target",
            "Request a debugger break into the currently running target and wait until debugger commands are accepted again. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<InterruptTargetArgs>(),
        )
        .with_title("Interrupt running target")
    }

    fn resume_tool(&self) -> Tool {
        Tool::new(
            "windbg_resume_target",
            "Resume the current target without issuing a text command. This is the safe headless equivalent of continuing execution after an initial break. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<ResumeTargetArgs>(),
        )
        .with_title("Resume target")
    }

    fn recover_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_recover_session",
            "Recover a headless session into a safer operational state. By default it resumes a broken target so the VM is not left paused; set `interrupt_if_running` to true to break into a running target instead.",
            schema_for_type::<RecoverSessionArgs>(),
        )
        .with_title("Recover headless session")
    }

    fn search_tool(&self) -> Tool {
        Tool::new(
            "windbg_search_catalog",
            "Search the static debugger command catalog extracted from debugger.chm and return the best low-context resources to read before execution.",
            schema_for_type::<SearchCatalogArgs>(),
        )
        .with_title("Search WinDbg catalog")
    }

    fn open_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_open_session",
            "Open a headless kernel-debug session using the same connection options you would pass to `-k`, for example `net:port=50000,key=...`. Full launcher strings like `windbgx -k net:...` are also accepted.",
            schema_for_type::<OpenSessionArgs>(),
        )
        .with_title("Open headless session")
    }

    fn close_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_close_session",
            "Close a headless debugger session and detach the owned dbgeng client from the target. By default this tries to resume a broken target before closing; set `resume_before_close` to false to skip that. `shutdown_timeout_secs` bounds teardown so a live KDNET detach cannot hang the MCP server indefinitely.",
            schema_for_type::<CloseSessionArgs>(),
        )
        .with_title("Close headless session")
    }

    fn switch_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_switch_session",
            "Set the default headless session used when `session_id` is omitted from tool calls.",
            schema_for_type::<SwitchSessionArgs>(),
        )
        .with_title("Switch default session")
    }

    fn list_sessions_tool(&self) -> Tool {
        Tool::new(
            "windbg_list_sessions",
            "List all headless debugger sessions managed by this MCP server.",
            schema_for_type::<ListSessionsArgs>(),
        )
        .with_title("List headless sessions")
    }

    fn current_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_current_session",
            "Show the current default headless debugger session.",
            schema_for_type::<CurrentSessionArgs>(),
        )
        .with_title("Get current headless session")
    }

    fn syntax_preview(&self, entry: &CatalogEntry) -> Option<String> {
        let syntax = entry.syntax_block()?;
        let syntax = syntax.trim();
        if syntax.is_empty() {
            return None;
        }

        let preview = syntax
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or(syntax);
        let preview = preview.trim();
        if preview.len() <= 160 {
            Some(preview.to_string())
        } else {
            Some(format!("{}...", &preview[..157]))
        }
    }

    fn base_tools(&self) -> Vec<Tool> {
        vec![
            self.generic_command_tool(),
            self.state_tool(),
            self.output_tool(),
            self.prepare_symbols_tool(),
            self.diagnose_extensions_tool(),
            self.dbgprint_tool(),
            self.set_breakpoint_tool(),
            self.set_hardware_breakpoint_tool(),
            self.find_process_tool(),
            self.set_process_breakpoint_tool(),
            self.set_syscall_breakpoint_tool(),
            self.list_breakpoints_tool(),
            self.clear_breakpoint_tool(),
            self.read_registers_tool(),
            self.write_register_tool(),
            self.read_memory_tool(),
            self.disassemble_tool(),
            self.backtrace_tool(),
            self.breakpoint_snapshot_tool(),
            self.trace_breakpoint_tool(),
            self.continue_until_break_tool(),
            self.step_tool(),
            self.step_over_tool(),
            self.go_up_tool(),
            self.evaluate_expression_tool(),
            self.list_modules_tool(),
            self.search_symbols_tool(),
            self.inspect_driver_tool(),
            self.set_driver_load_breakpoint_tool(),
            self.driver_summary_tool(),
            self.set_driver_dispatch_breakpoints_tool(),
            self.driver_dispatch_snapshot_tool(),
            self.ioctl_snapshot_tool(),
            self.minifilter_message_snapshot_tool(),
            self.search_tool(),
            self.interrupt_tool(),
            self.resume_tool(),
        ]
    }

    fn management_tools(&self) -> Vec<Tool> {
        if !self.is_headless() {
            return Vec::new();
        }

        vec![
            self.open_session_tool(),
            self.close_session_tool(),
            self.switch_session_tool(),
            self.list_sessions_tool(),
            self.current_session_tool(),
            self.recover_session_tool(),
        ]
    }

    fn map_execution_error(error: ExecutionError) -> McpError {
        match error {
            ExecutionError::Session(_) | ExecutionError::InvalidVariant { .. } => {
                McpError::invalid_params(error.to_string(), None)
            }
            _ => McpError::internal_error(error.to_string(), None),
        }
    }

    async fn execute_command(
        &self,
        session_id: Option<&str>,
        command: String,
    ) -> Result<Value, McpError> {
        let execution = self
            .execute_debugger_command(session_id, command.clone())
            .await?;

        Ok(render_execution_result(execution))
    }

    async fn execute_debugger_command(
        &self,
        session_id: Option<&str>,
        command: String,
    ) -> Result<CommandExecutionResult, McpError> {
        if let Some(message) = blocked_unsafe_debugger_command(&command) {
            return Err(McpError::invalid_params(message, None));
        }

        let execution = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .execute(command.clone())
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .execute_command(session_id, command.clone())
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(execution)
    }

    async fn prepare_symbols(&self, args: PrepareSymbolsArgs) -> Result<Value, McpError> {
        let module = args
            .module
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("nt")
            .to_string();
        let symbol_cache = args
            .symbol_cache
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_symbol_cache_dir);
        let symbol_server = args
            .symbol_server
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("https://msdl.microsoft.com/download/symbols")
            .trim_end_matches('/')
            .to_string();

        let mut steps = Vec::new();
        let lmi_command = format!("!lmi {module}");
        let lmi = self
            .execute_debugger_command(args.session_id.as_deref(), lmi_command)
            .await?;
        let pdb = parse_lmi_pdb_info(&lmi.output).ok_or_else(|| {
            McpError::internal_error(
                format!("could not find CodeView PDB information in `!lmi {module}` output"),
                None,
            )
        })?;
        steps.push(render_execution_result(lmi));

        let pdb_index = pdb.symbol_server_index();
        let pdb_dir = symbol_cache.join(&pdb.name).join(&pdb_index);
        let pdb_path = pdb_dir.join(&pdb.name);
        let symbol_url = format!("{symbol_server}/{}/{}/{}", pdb.name, pdb_index, pdb.name);
        let downloaded = if pdb_path.is_file() {
            false
        } else {
            let destination = pdb_path.clone();
            let url = symbol_url.clone();
            tokio::task::spawn_blocking(move || download_symbol_file(&url, &destination))
                .await
                .map_err(|error| {
                    McpError::internal_error(format!("symbol download task failed: {error}"), None)
                })?
                .map_err(|error| McpError::internal_error(error, None))?;
            true
        };

        let sympath = self
            .execute_debugger_command(
                args.session_id.as_deref(),
                format!(".sympath+ {}", pdb_dir.display()),
            )
            .await?;
        steps.push(render_execution_result(sympath));

        let reload_switch = if args.force_mismatched.unwrap_or(false) {
            "/i /f"
        } else {
            "/f"
        };
        let reload = self
            .execute_debugger_command(
                args.session_id.as_deref(),
                format!(".reload {reload_switch} {module}"),
            )
            .await?;
        steps.push(render_execution_result(reload));

        let lmv = self
            .execute_debugger_command(args.session_id.as_deref(), format!("lmv m {module}"))
            .await?;
        let symbol_status = classify_symbol_status(&lmv.output);
        steps.push(render_execution_result(lmv));

        Ok(json!({
            "module": module,
            "pdb": {
                "name": pdb.name,
                "guid": pdb.guid,
                "age": pdb.age,
                "symbol_server_index": pdb_index,
                "url": symbol_url,
                "local_path": pdb_path,
                "downloaded": downloaded,
            },
            "symbol_cache": symbol_cache,
            "symbol_status": symbol_status,
            "success": symbol_status == "pdb",
            "steps": steps,
        }))
    }

    async fn diagnostic_command_step(
        &self,
        session_id: Option<&str>,
        command: &str,
    ) -> (Value, String) {
        match self
            .execute_debugger_command(session_id, command.to_string())
            .await
        {
            Ok(execution) => {
                let output = execution.output.clone();
                (render_execution_result(execution), output)
            }
            Err(error) => (
                json!({
                    "command": command,
                    "error": format!("{error:?}"),
                }),
                String::new(),
            ),
        }
    }

    async fn diagnose_extensions(&self, args: DiagnoseExtensionsArgs) -> Result<Value, McpError> {
        let extension = args
            .extension
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("kdexts")
            .to_string();
        let probe_command = args
            .probe_command
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("!process 0 0")
            .to_string();
        let module = args
            .module
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("nt")
            .to_string();

        let mut steps = Vec::new();
        let mut recommendations = Vec::new();

        let (extpath_step, extpath_output) = self
            .diagnostic_command_step(args.session_id.as_deref(), ".extpath")
            .await;
        steps.push(extpath_step);

        let (chain_before_step, chain_before_output) = self
            .diagnostic_command_step(args.session_id.as_deref(), ".chain")
            .await;
        steps.push(chain_before_step);

        let mut symbol_status = "not_checked".to_string();
        if args.prepare_symbols.unwrap_or(false) {
            match self
                .prepare_symbols(PrepareSymbolsArgs {
                    session_id: args.session_id.clone(),
                    module: Some(module.clone()),
                    symbol_cache: args.symbol_cache.clone(),
                    symbol_server: args.symbol_server.clone(),
                    force_mismatched: None,
                })
                .await
            {
                Ok(payload) => {
                    symbol_status = payload["symbol_status"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    steps.push(json!({
                        "tool": "windbg_prepare_symbols",
                        "result": payload,
                    }));
                }
                Err(error) => {
                    symbol_status = "prepare_failed".to_string();
                    recommendations.push(
                        "Symbol preparation failed; inspect `!lmi nt`, network access to the symbol server, and the configured symbol cache.".to_string(),
                    );
                    steps.push(json!({
                        "tool": "windbg_prepare_symbols",
                        "error": format!("{error:?}"),
                    }));
                }
            }
        }

        let load_command = if extension.starts_with(".load") {
            extension.clone()
        } else {
            format!(".load {extension}")
        };
        let (load_step, load_output) = self
            .diagnostic_command_step(args.session_id.as_deref(), &load_command)
            .await;
        steps.push(load_step);

        let (chain_after_step, chain_after_output) = self
            .diagnostic_command_step(args.session_id.as_deref(), ".chain")
            .await;
        steps.push(chain_after_step);

        let (probe_step, probe_output) = self
            .diagnostic_command_step(args.session_id.as_deref(), &probe_command)
            .await;
        steps.push(probe_step);

        let extension_loaded = chain_contains_extension(&chain_before_output, &extension)
            || chain_contains_extension(&chain_after_output, &extension)
            || chain_contains_extension(&load_output, &extension);
        let symbol_problem = output_indicates_symbol_problem(&probe_output)
            || output_indicates_symbol_problem(&load_output);

        if extpath_output.trim().is_empty() {
            recommendations.push(
                "The effective extension path is empty or unavailable; check WinDbg Preview discovery/cache setup and `_NT_DEBUGGER_EXTENSION_PATH`.".to_string(),
            );
        }
        if !extension_loaded {
            recommendations.push(format!(
                "`{extension}` was not visible in `.chain`; inspect `.extpath` and try loading the cached DLL path explicitly."
            ));
        }
        if symbol_problem {
            recommendations.push(format!(
                "`{probe_command}` reported a symbol problem; run `windbg_prepare_symbols` for `{module}` and retry."
            ));
        }
        if recommendations.is_empty() {
            recommendations.push(
                "Extension path, extension chain, and probe command did not expose an obvious failure.".to_string(),
            );
        }

        Ok(json!({
            "extension": extension,
            "probe_command": probe_command,
            "module": module,
            "extension_loaded": extension_loaded,
            "symbol_status": symbol_status,
            "symbol_problem": symbol_problem,
            "recommendations": recommendations,
            "steps": steps,
        }))
    }

    async fn dbgprint(&self, args: DbgPrintArgs) -> Result<Value, McpError> {
        let line_limit = clamp_count(args.lines, 200, 5000);
        let mut steps = Vec::new();
        let mut recommendations = Vec::new();
        let mut symbol_status = "not_checked".to_string();
        let mut load_output = String::new();

        if args.prepare_symbols.unwrap_or(false) {
            match self
                .prepare_symbols(PrepareSymbolsArgs {
                    session_id: args.session_id.clone(),
                    module: Some("nt".to_string()),
                    symbol_cache: args.symbol_cache.clone(),
                    symbol_server: args.symbol_server.clone(),
                    force_mismatched: None,
                })
                .await
            {
                Ok(payload) => {
                    symbol_status = payload["symbol_status"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    steps.push(json!({
                        "tool": "windbg_prepare_symbols",
                        "result": payload,
                    }));
                }
                Err(error) => {
                    symbol_status = "prepare_failed".to_string();
                    recommendations.push(
                        "`windbg_prepare_symbols` failed while preparing `nt`; inspect symbol cache and symbol-server reachability.".to_string(),
                    );
                    steps.push(json!({
                        "tool": "windbg_prepare_symbols",
                        "error": format!("{error:?}"),
                    }));
                }
            }
        }

        if args.load_extension.unwrap_or(true) {
            let (load_step, output) = self
                .diagnostic_command_step(args.session_id.as_deref(), ".load kdexts")
                .await;
            load_output = output;
            steps.push(load_step);
        }

        let execution = self
            .execute_debugger_command(args.session_id.as_deref(), "!dbgprint".to_string())
            .await?;
        let raw_output = execution.output.clone();
        let (lines, line_count, truncated) = tail_output_lines(&raw_output, line_limit);
        let output = lines.join("\n");
        let symbol_problem = output_indicates_symbol_problem(&raw_output)
            || output_indicates_symbol_problem(&load_output);
        let extension_problem = output_indicates_extension_problem(&raw_output)
            || output_indicates_extension_problem(&load_output);

        if extension_problem {
            recommendations.push(
                "`!dbgprint` or `.load kdexts` reported an extension-loading problem; call `windbg_diagnose_extensions` or retry with `load_extension:true`.".to_string(),
            );
        }
        if symbol_problem {
            recommendations.push(
                "`!dbgprint` reported a symbol problem; retry with `prepare_symbols:true` or call `windbg_prepare_symbols {\"module\":\"nt\"}` first.".to_string(),
            );
        }
        if raw_output.trim().is_empty() {
            recommendations.push(
                "`!dbgprint` returned no text. The kernel DbgPrint buffer may be empty, filtered by component masks, or the target may not have emitted DbgPrint output yet.".to_string(),
            );
        }
        if recommendations.is_empty() {
            recommendations.push(
                "`!dbgprint` completed without obvious extension or symbol errors.".to_string(),
            );
        }

        let mut payload = json!({
            "command": execution.command,
            "source": "!dbgprint",
            "line_limit": line_limit,
            "line_count": line_count,
            "returned_line_count": lines.len(),
            "truncated": truncated,
            "lines": lines,
            "output": output,
            "state_before": execution.state_before,
            "state_after": execution.state_after,
            "symbol_status": symbol_status,
            "symbol_problem": symbol_problem,
            "extension_problem": extension_problem,
            "recommendations": recommendations,
            "steps": steps,
        });

        if args.include_raw_output.unwrap_or(false) {
            if let Some(object) = payload.as_object_mut() {
                object.insert("raw_output".to_string(), json!(raw_output));
            }
        }

        Ok(payload)
    }

    async fn set_breakpoint(&self, args: SetBreakpointArgs) -> Result<Value, McpError> {
        let command = build_breakpoint_command(
            args.kind.as_deref(),
            &args.location,
            args.one_shot,
            None,
            None,
            args.pass_count,
            args.command.as_deref(),
        )
        .map_err(|error| McpError::invalid_params(error, None))?;

        let before_list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let before_output = before_list.output.clone();
        let set = self
            .execute_debugger_command(args.session_id.as_deref(), command)
            .await?;
        let list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let created_breakpoints = new_breakpoint_ids(&before_output, &list.output);
        validate_created_breakpoints(&set.command, &set.output, &created_breakpoints)
            .map_err(|error| McpError::invalid_params(error, None))?;

        Ok(json!({
            "breakpoints_before": render_execution_result(before_list),
            "created_breakpoints": created_breakpoints,
            "breakpoint": render_execution_result(set),
            "breakpoints": render_execution_result(list),
        }))
    }

    async fn set_hardware_breakpoint(
        &self,
        args: SetHardwareBreakpointArgs,
    ) -> Result<Value, McpError> {
        let has_process_selector = trimmed_nonempty(args.eprocess.as_deref()).is_some()
            || trimmed_nonempty(args.process_name.as_deref()).is_some()
            || trimmed_nonempty(args.pid.as_deref()).is_some();
        let (mut steps, process, candidates) = if has_process_selector {
            let selector = SetProcessBreakpointArgs {
                session_id: args.session_id.clone(),
                location: args.address.clone(),
                process_name: args.process_name.clone(),
                pid: args.pid.clone(),
                eprocess: args.eprocess.clone(),
                ethread: args.ethread.clone(),
                kind: None,
                one_shot: args.one_shot,
                pass_count: args.pass_count,
                command: args.command.clone(),
                prepare_symbols: args.prepare_symbols,
                match_index: args.match_index,
                set_context: args.set_context,
                allow_user_software: None,
            };
            let (steps, process, candidates) =
                self.resolve_process_for_breakpoint(&selector).await?;
            (steps, Some(process), candidates)
        } else {
            (Vec::new(), None, Vec::new())
        };

        let ethread = match trimmed_nonempty(args.ethread.as_deref()) {
            Some(value) => Some(
                debugger_atom(value, "ethread")
                    .map_err(|error| McpError::invalid_params(error, None))?,
            ),
            None => None,
        };
        let user_mode_address = looks_like_user_mode_address(&args.address);
        let set_context = process
            .as_ref()
            .map(|_| args.set_context.unwrap_or(user_mode_address))
            .unwrap_or(false);
        if set_context {
            if let Some(process) = &process {
                let context_command = format!(".process /p /r {}", process.eprocess);
                let context = self
                    .execute_debugger_command(args.session_id.as_deref(), context_command.clone())
                    .await?;
                steps.push(json!({
                    "tool": "windbg_set_hardware_breakpoint",
                    "phase": "set_process_context",
                    "command": context_command,
                    "result": render_execution_result(context),
                }));
            }
        }
        let command = build_hardware_breakpoint_command(
            args.access.as_deref(),
            args.size,
            &args.address,
            args.one_shot,
            process.as_ref().map(|process| process.eprocess.as_str()),
            ethread.as_deref(),
            args.pass_count,
            args.command.as_deref(),
        )
        .map_err(|error| McpError::invalid_params(error, None))?;

        let before_list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let before_output = before_list.output.clone();
        let set = self
            .execute_debugger_command(args.session_id.as_deref(), command.clone())
            .await?;
        let list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let created_breakpoints = new_breakpoint_ids(&before_output, &list.output);
        validate_created_breakpoints(&set.command, &set.output, &created_breakpoints)
            .map_err(|error| McpError::invalid_params(error, None))?;
        steps.push(json!({
            "tool": "windbg_set_hardware_breakpoint",
            "command": command,
        }));

        Ok(json!({
            "process": process,
            "candidates": candidates,
            "steps": steps,
            "set_context": set_context,
            "user_mode_address": user_mode_address,
            "breakpoints_before": render_execution_result(before_list),
            "created_breakpoints": created_breakpoints,
            "hardware_breakpoint": render_execution_result(set),
            "breakpoints": render_execution_result(list),
        }))
    }

    async fn lookup_processes(
        &self,
        session_id: Option<&str>,
        name: Option<&str>,
        pid: Option<&str>,
        prepare_symbols: Option<bool>,
    ) -> Result<(Vec<Value>, Vec<ProcessInfo>), McpError> {
        if let Some(name) = trimmed_nonempty(name) {
            debugger_atom(name, "process_name")
                .map_err(|error| McpError::invalid_params(error, None))?;
        }
        if let Some(pid) = trimmed_nonempty(pid) {
            if parse_user_pid(pid).is_none() {
                return Err(McpError::invalid_params(
                    "pid must be decimal, 0n-prefixed decimal, or 0x-prefixed hex",
                    None,
                ));
            }
        }

        let command = if let Some(name) = trimmed_nonempty(name) {
            let name = debugger_atom(name, "process_name")
                .map_err(|error| McpError::invalid_params(error, None))?;
            format!("!process 0 0 {name}")
        } else {
            "!process 0 0".to_string()
        };

        let mut steps = Vec::new();
        let (step, output) = self.diagnostic_command_step(session_id, &command).await;
        steps.push(step);
        let mut matches = parse_processes(&output)
            .into_iter()
            .filter(|process| process_matches(process, name, pid))
            .collect::<Vec<_>>();

        if (matches.is_empty() || output_indicates_symbol_problem(&output))
            && prepare_symbols.unwrap_or(true)
        {
            match self
                .prepare_symbols(PrepareSymbolsArgs {
                    session_id: session_id.map(str::to_string),
                    module: Some("nt".to_string()),
                    symbol_cache: None,
                    symbol_server: None,
                    force_mismatched: None,
                })
                .await
            {
                Ok(payload) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "result": payload,
                })),
                Err(error) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "error": format!("{error:?}"),
                })),
            }

            let (retry_step, retry_output) =
                self.diagnostic_command_step(session_id, &command).await;
            steps.push(retry_step);
            matches = parse_processes(&retry_output)
                .into_iter()
                .filter(|process| process_matches(process, name, pid))
                .collect();
        }

        Ok((steps, matches))
    }

    async fn find_process(&self, args: FindProcessArgs) -> Result<Value, McpError> {
        let (steps, matches) = self
            .lookup_processes(
                args.session_id.as_deref(),
                args.name.as_deref(),
                args.pid.as_deref(),
                args.prepare_symbols,
            )
            .await?;

        Ok(json!({
            "matches": matches,
            "steps": steps,
        }))
    }

    async fn resolve_process_for_breakpoint(
        &self,
        args: &SetProcessBreakpointArgs,
    ) -> Result<(Vec<Value>, ProcessInfo, Vec<ProcessInfo>), McpError> {
        if let Some(eprocess) = trimmed_nonempty(args.eprocess.as_deref()) {
            return Ok((
                Vec::new(),
                ProcessInfo {
                    eprocess: debugger_atom(eprocess, "eprocess")
                        .map_err(|error| McpError::invalid_params(error, None))?,
                    pid: args.pid.clone(),
                    image: args.process_name.clone(),
                    summary: "Provided directly by caller.".to_string(),
                },
                Vec::new(),
            ));
        }

        if trimmed_nonempty(args.process_name.as_deref()).is_none()
            && trimmed_nonempty(args.pid.as_deref()).is_none()
        {
            return Err(McpError::invalid_params(
                "provide `eprocess`, `process_name`, or `pid` for a process-scoped breakpoint",
                None,
            ));
        }

        let (steps, matches) = self
            .lookup_processes(
                args.session_id.as_deref(),
                args.process_name.as_deref(),
                args.pid.as_deref(),
                args.prepare_symbols,
            )
            .await?;
        if matches.is_empty() {
            return Err(McpError::invalid_params(
                "no process matched the provided process_name/pid; use windbg_find_process to inspect candidates",
                None,
            ));
        }

        let selected_index = args.match_index.unwrap_or(0);
        let Some(selected) = matches.get(selected_index).cloned() else {
            return Err(McpError::invalid_params(
                format!(
                    "match_index {selected_index} is out of range for {} matched process(es)",
                    matches.len()
                ),
                None,
            ));
        };

        Ok((steps, selected, matches))
    }

    async fn set_process_breakpoint(
        &self,
        args: SetProcessBreakpointArgs,
    ) -> Result<Value, McpError> {
        let (mut steps, process, candidates) = self.resolve_process_for_breakpoint(&args).await?;
        let user_mode_address = looks_like_user_mode_address(&args.location);
        if user_mode_address && !args.allow_user_software.unwrap_or(false) {
            return Err(McpError::invalid_params(
                "software `bp /p <EPROCESS> <user_va>` can create a breakpoint ID without hitting reliably in live KDNET headless sessions. Use `windbg_set_hardware_breakpoint` with `access: execute`, `size: 1`, and the same process selector, or pass `allow_user_software: true` for an explicit experiment.",
                None,
            ));
        }
        let set_context = args.set_context.unwrap_or(user_mode_address);
        if set_context {
            let context_command = format!(".process /p /r {}", process.eprocess);
            let context = self
                .execute_debugger_command(args.session_id.as_deref(), context_command.clone())
                .await?;
            steps.push(json!({
                "tool": "windbg_set_process_breakpoint",
                "phase": "set_process_context",
                "command": context_command,
                "result": render_execution_result(context),
            }));
        }
        let ethread = match trimmed_nonempty(args.ethread.as_deref()) {
            Some(value) => Some(
                debugger_atom(value, "ethread")
                    .map_err(|error| McpError::invalid_params(error, None))?,
            ),
            None => None,
        };
        let command = build_breakpoint_command(
            args.kind.as_deref(),
            &args.location,
            args.one_shot,
            Some(&process.eprocess),
            ethread.as_deref(),
            args.pass_count,
            args.command.as_deref(),
        )
        .map_err(|error| McpError::invalid_params(error, None))?;

        let before_list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let before_output = before_list.output.clone();
        let set = self
            .execute_debugger_command(args.session_id.as_deref(), command.clone())
            .await?;
        let list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let created_breakpoints = new_breakpoint_ids(&before_output, &list.output);
        validate_created_breakpoints(&set.command, &set.output, &created_breakpoints)
            .map_err(|error| McpError::invalid_params(error, None))?;
        steps.push(json!({
            "tool": "windbg_set_process_breakpoint",
            "command": command,
        }));

        Ok(json!({
            "process": process,
            "candidates": candidates,
            "steps": steps,
            "set_context": set_context,
            "breakpoints_before": render_execution_result(before_list),
            "created_breakpoints": created_breakpoints,
            "breakpoint": render_execution_result(set),
            "breakpoints": render_execution_result(list),
        }))
    }

    async fn set_syscall_breakpoint(
        &self,
        args: SetSyscallBreakpointArgs,
    ) -> Result<Value, McpError> {
        let location = normalize_syscall_location(&args.syscall)
            .map_err(|error| McpError::invalid_params(error, None))?;
        self.set_process_breakpoint(SetProcessBreakpointArgs {
            session_id: args.session_id,
            location,
            process_name: args.process_name,
            pid: args.pid,
            eprocess: args.eprocess,
            ethread: None,
            kind: Some("bp".to_string()),
            one_shot: args.one_shot,
            pass_count: None,
            command: args.command,
            prepare_symbols: args.prepare_symbols,
            match_index: args.match_index,
            set_context: None,
            allow_user_software: None,
        })
        .await
    }

    async fn list_breakpoints(&self, args: ListBreakpointsArgs) -> Result<Value, McpError> {
        self.execute_command(args.session_id.as_deref(), "bl".to_string())
            .await
    }

    async fn clear_breakpoint(&self, args: ClearBreakpointArgs) -> Result<Value, McpError> {
        let breakpoint = trimmed_nonempty(args.breakpoint.as_deref()).unwrap_or("*");
        let safe = args.safe.unwrap_or(true);
        let mut steps = Vec::new();
        if safe {
            let disable = self
                .execute_debugger_command(args.session_id.as_deref(), format!("bd {breakpoint}"))
                .await?;
            steps.push(json!({
                "phase": "disable_before_clear",
                "result": render_execution_result(disable),
            }));
        }
        let clear = self
            .execute_debugger_command(args.session_id.as_deref(), format!("bc {breakpoint}"))
            .await?;
        let list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;

        Ok(json!({
            "safe": safe,
            "steps": steps,
            "clear": render_execution_result(clear),
            "breakpoints": render_execution_result(list),
        }))
    }

    async fn read_registers(&self, args: ReadRegistersArgs) -> Result<Value, McpError> {
        let session_id = args.session_id.clone();
        let command = match args.registers {
            Some(registers) => {
                let registers: Result<Vec<String>, String> = registers
                    .into_iter()
                    .map(|value| debugger_atom(&value, "register"))
                    .collect();
                let registers: Vec<String> = registers
                    .map_err(|error| McpError::invalid_params(error, None))?
                    .into_iter()
                    .filter(|value| !value.is_empty())
                    .collect();
                if registers.is_empty() {
                    "r".to_string()
                } else if registers.len() == 1 {
                    format!("r {}", registers[0])
                } else {
                    let mut steps = Vec::new();
                    let mut output = String::new();
                    let mut commands = Vec::new();
                    for register in registers {
                        let command = format!("r {register}");
                        let execution = self
                            .execute_debugger_command(session_id.as_deref(), command.clone())
                            .await?;
                        output.push_str(&execution.output);
                        if !output.ends_with('\n') {
                            output.push('\n');
                        }
                        commands.push(command);
                        steps.push(render_execution_result(execution));
                    }
                    return Ok(json!({
                        "command": commands.join("; "),
                        "output": output,
                        "steps": steps,
                        "note": "multiple registers were read as isolated commands to avoid fragile raw `r <reg> <reg>` dbgeng states",
                    }));
                }
            }
            None => "r".to_string(),
        };

        self.execute_command(session_id.as_deref(), command).await
    }

    async fn write_register(&self, args: WriteRegisterArgs) -> Result<Value, McpError> {
        let register = debugger_atom(&args.register, "register")
            .map_err(|error| McpError::invalid_params(error, None))?;
        let value = debugger_atom(&args.value, "value")
            .map_err(|error| McpError::invalid_params(error, None))?;

        self.execute_command(
            args.session_id.as_deref(),
            format!("r {register}={value}; r {register}"),
        )
        .await
    }

    async fn read_memory(&self, args: ReadMemoryArgs) -> Result<Value, McpError> {
        let command = memory_command(&args.address, args.format.as_deref(), args.count)
            .map_err(|error| McpError::invalid_params(error, None))?;
        self.execute_command(args.session_id.as_deref(), command)
            .await
    }

    async fn disassemble(&self, args: DisassembleArgs) -> Result<Value, McpError> {
        let verb = if args.before.unwrap_or(false) {
            "ub"
        } else {
            "u"
        };
        let address = trimmed_nonempty(args.address.as_deref()).unwrap_or(".");
        let count = clamp_count(args.count, 16, 512);
        self.execute_command(
            args.session_id.as_deref(),
            format!("{verb} {address} L{count}"),
        )
        .await
    }

    async fn backtrace(&self, args: BacktraceArgs) -> Result<Value, McpError> {
        let command = backtrace_command(args.format.as_deref(), args.count)
            .map_err(|error| McpError::invalid_params(error, None))?;
        self.execute_command(args.session_id.as_deref(), command)
            .await
    }

    async fn breakpoint_snapshot(&self, args: BreakpointSnapshotArgs) -> Result<Value, McpError> {
        let mut commands = vec![
            ".lastevent".to_string(),
            "r".to_string(),
            backtrace_command(args.stack_format.as_deref(), args.stack_count)
                .map_err(|error| McpError::invalid_params(error, None))?,
            format!("u rip L{}", clamp_count(args.disassemble_count, 16, 512)),
            format!("dq rsp L{}", clamp_count(args.stack_memory_count, 32, 1024)),
            "bl".to_string(),
        ];

        for memory in args.memory.unwrap_or_default() {
            commands.push(
                memory_command(&memory.address, memory.format.as_deref(), memory.count)
                    .map_err(|error| McpError::invalid_params(error, None))?,
            );
        }

        let mut steps = Vec::new();
        for command in commands {
            let (step, _) = self
                .diagnostic_command_step(args.session_id.as_deref(), &command)
                .await;
            steps.push(step);
        }

        Ok(json!({ "steps": steps }))
    }

    async fn trace_breakpoint(&self, args: TraceBreakpointArgs) -> Result<Value, McpError> {
        let hit_limit = args.hits.unwrap_or(1).clamp(1, 100);
        let timeout_secs = args.timeout_secs.unwrap_or(30).clamp(1, 3600);
        let poll_interval =
            Duration::from_millis(args.poll_interval_millis.unwrap_or(250).clamp(50, 10_000));
        let settle_millis = args.settle_millis.unwrap_or(350).clamp(0, 5_000);
        let require_stable_break = args.require_stable_break.unwrap_or(true);
        let auto_resume = args.auto_resume.unwrap_or(true);
        let clear_after = args.clear_after.unwrap_or(true);
        let hardware = args.hardware.unwrap_or(false);

        let has_process_selector = trimmed_nonempty(args.eprocess.as_deref()).is_some()
            || trimmed_nonempty(args.process_name.as_deref()).is_some()
            || trimmed_nonempty(args.pid.as_deref()).is_some();
        let (mut setup_steps, process, candidates) = if has_process_selector {
            let selector = SetProcessBreakpointArgs {
                session_id: args.session_id.clone(),
                location: args.location.clone(),
                process_name: args.process_name.clone(),
                pid: args.pid.clone(),
                eprocess: args.eprocess.clone(),
                ethread: args.ethread.clone(),
                kind: args.kind.clone(),
                one_shot: Some(false),
                pass_count: None,
                command: None,
                prepare_symbols: args.prepare_symbols,
                match_index: args.match_index,
                set_context: args.set_context,
                allow_user_software: Some(true),
            };
            let (steps, process, candidates) =
                self.resolve_process_for_breakpoint(&selector).await?;
            (steps, Some(process), candidates)
        } else {
            (Vec::new(), None, Vec::new())
        };

        let ethread = match trimmed_nonempty(args.ethread.as_deref()) {
            Some(value) => Some(
                debugger_atom(value, "ethread")
                    .map_err(|error| McpError::invalid_params(error, None))?,
            ),
            None => None,
        };
        let set_context = process
            .as_ref()
            .map(|_| {
                args.set_context
                    .unwrap_or_else(|| looks_like_user_mode_address(&args.location))
            })
            .unwrap_or(false);
        if set_context {
            if let Some(process) = &process {
                let context_command = format!(".process /p /r {}", process.eprocess);
                let context = self
                    .execute_debugger_command(args.session_id.as_deref(), context_command.clone())
                    .await?;
                setup_steps.push(json!({
                    "tool": "windbg_trace_breakpoint",
                    "phase": "set_process_context",
                    "command": context_command,
                    "result": render_execution_result(context),
                }));
            }
        }

        let breakpoint_command = if hardware {
            build_hardware_breakpoint_command(
                args.access.as_deref(),
                args.size,
                &args.location,
                Some(false),
                process.as_ref().map(|process| process.eprocess.as_str()),
                ethread.as_deref(),
                None,
                None,
            )
        } else {
            build_breakpoint_command(
                args.kind.as_deref(),
                &args.location,
                Some(false),
                process.as_ref().map(|process| process.eprocess.as_str()),
                ethread.as_deref(),
                None,
                None,
            )
        }
        .map_err(|error| McpError::invalid_params(error, None))?;

        let before_list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let before_output = before_list.output.clone();
        setup_steps.push(json!({
            "phase": "breakpoints_before_trace",
            "result": render_execution_result(before_list),
        }));

        let set = self
            .execute_debugger_command(args.session_id.as_deref(), breakpoint_command.clone())
            .await?;
        let set_command = set.command.clone();
        let set_output = set.output.clone();
        setup_steps.push(json!({
            "phase": "set_trace_breakpoint",
            "result": render_execution_result(set),
        }));

        let after_list = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;
        let after_output = after_list.output.clone();
        let created_breakpoints = new_breakpoint_ids(&before_output, &after_output);
        validate_created_breakpoints(&set_command, &set_output, &created_breakpoints)
            .map_err(|error| McpError::invalid_params(error, None))?;
        setup_steps.push(json!({
            "phase": "breakpoints_after_trace",
            "result": render_execution_result(after_list),
            "created_breakpoints": created_breakpoints.clone(),
        }));

        let mut capture_commands = if args.include_default_snapshot.unwrap_or(true) {
            default_trace_commands()
        } else {
            Vec::new()
        };
        for command in args.commands.unwrap_or_default() {
            let command = command.trim();
            if !command.is_empty() {
                capture_commands.push(command.to_string());
            }
        }

        let mut hits = Vec::new();
        let mut timed_out = false;
        for index in 0..hit_limit {
            let wait = self
                .continue_until_break(ContinueUntilBreakArgs {
                    session_id: args.session_id.clone(),
                    timeout_secs: Some(timeout_secs),
                    poll_interval_millis: Some(poll_interval.as_millis() as u64),
                    settle_millis: Some(settle_millis),
                    require_stable_break: Some(require_stable_break),
                })
                .await?;
            let wait_timed_out = wait["timed_out"].as_bool().unwrap_or(false);
            timed_out |= wait_timed_out;

            let mut steps = Vec::new();
            if !wait_timed_out {
                for command in &capture_commands {
                    let (step, _) = self
                        .diagnostic_command_step(args.session_id.as_deref(), command)
                        .await;
                    steps.push(step);
                }
            }

            hits.push(json!({
                "index": index + 1,
                "wait": wait,
                "steps": steps,
                "timed_out": wait_timed_out,
            }));

            if wait_timed_out || !auto_resume {
                break;
            }
        }

        let mut cleanup_steps = Vec::new();
        if clear_after && !created_breakpoints.is_empty() {
            let state_payload = self.query_state(args.session_id.as_deref()).await?;
            if state_payload["state"]["ready_for_commands"]
                .as_bool()
                .unwrap_or(false)
            {
                for breakpoint in &created_breakpoints {
                    let disable = self
                        .execute_debugger_command(
                            args.session_id.as_deref(),
                            format!("bd {breakpoint}"),
                        )
                        .await?;
                    cleanup_steps.push(json!({
                        "phase": "disable_trace_breakpoint",
                        "breakpoint": breakpoint,
                        "result": render_execution_result(disable),
                    }));
                    let clear = self
                        .execute_debugger_command(
                            args.session_id.as_deref(),
                            format!("bc {breakpoint}"),
                        )
                        .await?;
                    cleanup_steps.push(json!({
                        "phase": "clear_trace_breakpoint",
                        "breakpoint": breakpoint,
                        "result": render_execution_result(clear),
                    }));
                }
                let list = self
                    .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
                    .await?;
                cleanup_steps.push(json!({
                    "phase": "breakpoints_after_cleanup",
                    "result": render_execution_result(list),
                }));
            } else {
                cleanup_steps.push(json!({
                    "phase": "cleanup_skipped",
                    "reason": "target was not command-ready; trace breakpoint ids are returned so the caller can clear them after interrupting or on a later break",
                    "state": state_payload["state"],
                    "breakpoints": created_breakpoints.clone(),
                }));
            }
        }

        let final_resume = if auto_resume {
            let state_payload = self.query_state(args.session_id.as_deref()).await?;
            if state_payload["state"]["ready_for_commands"]
                .as_bool()
                .unwrap_or(false)
            {
                Some(self.resume_target(args.session_id.as_deref()).await?)
            } else {
                None
            }
        } else {
            None
        };

        let captured_hits = hits.len();
        Ok(json!({
            "breakpoint_command": breakpoint_command,
            "hardware": hardware,
            "process": process,
            "candidates": candidates,
            "set_context": set_context,
            "created_breakpoints": created_breakpoints,
            "capture_commands": capture_commands,
            "requested_hits": hit_limit,
            "captured_hits": captured_hits,
            "timed_out": timed_out,
            "auto_resume": auto_resume,
            "clear_after": clear_after,
            "setup_steps": setup_steps,
            "hits": hits,
            "cleanup_steps": cleanup_steps,
            "final_resume": final_resume,
            "note": "Trace capture is driven synchronously by MCP after a stable breakpoint hit; avoid command-breakpoint strings that self-continue with `g`/`gc` when reliable output capture matters.",
        }))
    }

    async fn poll_until_stable_break(
        &self,
        session_id: Option<&str>,
        timeout_secs: u64,
        poll_interval: Duration,
        settle_millis: u64,
        require_stable_break: bool,
    ) -> Result<Value, McpError> {
        let settle_interval = Duration::from_millis(settle_millis);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let mut transient_breaks = 0u64;
        let mut last_observed_break_state: Option<Value> = None;
        let mut last_unstable_break_state: Option<Value> = None;

        loop {
            let state_payload = self.query_state(session_id).await?;
            let mut state = state_payload["state"].clone();
            if state["ready_for_commands"].as_bool().unwrap_or(false) {
                let first_break_state = state.clone();
                last_observed_break_state = Some(first_break_state.clone());
                if require_stable_break && !settle_interval.is_zero() {
                    tokio::time::sleep(settle_interval).await;
                    let confirmed_payload = self.query_state(session_id).await?;
                    let confirmed_state = confirmed_payload["state"].clone();
                    if confirmed_state["ready_for_commands"]
                        .as_bool()
                        .unwrap_or(false)
                    {
                        return Ok(json!({
                            "final_state": confirmed_state,
                            "timed_out": false,
                            "stability_check": {
                                "enabled": true,
                                "settle_millis": settle_millis,
                                "first_break_state": first_break_state,
                                "transient_breaks": transient_breaks,
                                "unstable_breaks": transient_breaks,
                                "last_observed_break_state": last_observed_break_state,
                                "last_unstable_break_state": last_unstable_break_state,
                            },
                        }));
                    }

                    transient_breaks += 1;
                    last_unstable_break_state = Some(confirmed_state.clone());
                    state = confirmed_state;
                } else {
                    return Ok(json!({
                        "final_state": state,
                        "timed_out": false,
                        "stability_check": {
                            "enabled": false,
                            "settle_millis": settle_millis,
                            "transient_breaks": transient_breaks,
                            "unstable_breaks": transient_breaks,
                            "last_observed_break_state": last_observed_break_state,
                            "last_unstable_break_state": last_unstable_break_state,
                        },
                    }));
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return Ok(json!({
                    "final_state": state,
                    "timed_out": true,
                    "stability_check": {
                        "enabled": require_stable_break,
                        "settle_millis": settle_millis,
                        "transient_breaks": transient_breaks,
                        "unstable_breaks": transient_breaks,
                        "last_observed_break_state": last_observed_break_state,
                        "last_unstable_break_state": last_unstable_break_state,
                    },
                }));
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn continue_until_break(&self, args: ContinueUntilBreakArgs) -> Result<Value, McpError> {
        let timeout_secs = args.timeout_secs.unwrap_or(30).clamp(1, 3600);
        let poll_interval =
            Duration::from_millis(args.poll_interval_millis.unwrap_or(250).clamp(50, 10_000));
        let settle_millis = args.settle_millis.unwrap_or(350).clamp(0, 5_000);
        let require_stable_break = args.require_stable_break.unwrap_or(true);
        let resumed = self.resume_target(args.session_id.as_deref()).await?;

        let mut result = self
            .poll_until_stable_break(
                args.session_id.as_deref(),
                timeout_secs,
                poll_interval,
                settle_millis,
                require_stable_break,
            )
            .await?;
        if let Some(object) = result.as_object_mut() {
            object.insert("resumed".to_string(), resumed);
        }
        Ok(result)
    }

    async fn step_execution(
        &self,
        args: StepExecutionArgs,
        command: &'static str,
        label: &'static str,
    ) -> Result<Value, McpError> {
        let timeout_secs = args.timeout_secs.unwrap_or(30).clamp(1, 3600);
        let poll_interval =
            Duration::from_millis(args.poll_interval_millis.unwrap_or(250).clamp(50, 10_000));
        let settle_millis = args.settle_millis.unwrap_or(350).clamp(0, 5_000);
        let require_stable_break = args.require_stable_break.unwrap_or(true);
        let execution = self
            .execute_debugger_command(args.session_id.as_deref(), command.to_string())
            .await?;
        let wait = self
            .poll_until_stable_break(
                args.session_id.as_deref(),
                timeout_secs,
                poll_interval,
                settle_millis,
                require_stable_break,
            )
            .await?;

        Ok(json!({
            "step": label,
            "command": render_execution_result(execution),
            "wait": wait,
        }))
    }

    async fn evaluate_expression(&self, args: EvaluateExpressionArgs) -> Result<Value, McpError> {
        let expression = args.expression.trim();
        if expression.is_empty() {
            return Err(McpError::invalid_params("expression cannot be empty", None));
        }

        let evaluator = args
            .evaluator
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("masm")
            .to_ascii_lowercase();
        let command = match evaluator.as_str() {
            "masm" | "?" => format!("? {expression}"),
            "cpp" | "c++" | "??" => format!("?? {expression}"),
            _ => {
                return Err(McpError::invalid_params(
                    "evaluator must be `masm` or `cpp`",
                    None,
                ));
            }
        };

        self.execute_command(args.session_id.as_deref(), command)
            .await
    }

    async fn list_modules(&self, args: ListModulesArgs) -> Result<Value, McpError> {
        let mut command = String::from("lm");
        if args.unloaded.unwrap_or(false) {
            command.push('u');
        }
        if args.verbose.unwrap_or(false) {
            command.push('v');
        }
        if let Some(pattern) = trimmed_nonempty(args.pattern.as_deref()) {
            command.push_str(" m ");
            command.push_str(pattern);
        }

        self.execute_command(args.session_id.as_deref(), command)
            .await
    }

    async fn search_symbols(&self, args: SearchSymbolsArgs) -> Result<Value, McpError> {
        let pattern = args.pattern.trim();
        if pattern.is_empty() {
            return Err(McpError::invalid_params("pattern cannot be empty", None));
        }

        self.execute_command(args.session_id.as_deref(), format!("x {pattern}"))
            .await
    }

    async fn inspect_driver(&self, args: InspectDriverArgs) -> Result<Value, McpError> {
        let name = args.name.trim();
        if name.is_empty() {
            return Err(McpError::invalid_params(
                "driver name cannot be empty",
                None,
            ));
        }
        let flags = trimmed_nonempty(args.flags.as_deref()).unwrap_or("7");

        self.execute_command(
            args.session_id.as_deref(),
            format!("!drvobj {name} {flags}"),
        )
        .await
    }

    async fn set_driver_load_breakpoint(
        &self,
        args: SetDriverLoadBreakpointArgs,
    ) -> Result<Value, McpError> {
        let image = debugger_atom(&args.image, "image")
            .map_err(|error| McpError::invalid_params(error, None))?;
        let event_filter = format!("ld:{image}");
        let mut steps = Vec::new();
        if args.prepare_symbols.unwrap_or(true) {
            match self
                .prepare_symbols(PrepareSymbolsArgs {
                    session_id: args.session_id.clone(),
                    module: Some("nt".to_string()),
                    symbol_cache: None,
                    symbol_server: None,
                    force_mismatched: None,
                })
                .await
            {
                Ok(payload) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "phase": "before_load_filter",
                    "result": payload,
                })),
                Err(error) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "phase": "before_load_filter",
                    "error": format!("{error:?}"),
                })),
            }
        }

        let mut commands = Vec::new();
        if args.clear_existing.unwrap_or(false) {
            steps.push(json!({
                "command": format!("sxd {event_filter}"),
                "skipped": true,
                "reason": "disabling `ld` filters with raw `sxd` is blocked in headless mode because this dbgeng path can access-violate after module-load events; opening a fresh short-lived session is safer for clearing load filters",
            }));
        }
        commands.push(format!("sxe {event_filter}"));
        commands.push("sx".to_string());

        for command in commands {
            let (step, _) = self
                .diagnostic_command_step(args.session_id.as_deref(), &command)
                .await;
            steps.push(step);
        }

        Ok(json!({
            "image": image,
            "event_filter": event_filter,
            "steps": steps,
            "symbols_prepared_before_filter": args.prepare_symbols.unwrap_or(true),
            "clear_existing_safely_skipped": args.clear_existing.unwrap_or(false),
            "next_step": "resume the target with windbg_continue_until_break or windbg_resume_target, then start/load the driver from the guest",
        }))
    }

    async fn driver_summary(&self, args: DriverSummaryArgs) -> Result<Value, McpError> {
        let name = debugger_atom(&args.name, "driver")
            .map_err(|error| McpError::invalid_params(error, None))?;
        let short_name = driver_short_name(&name);
        let module_pattern = match trimmed_nonempty(args.module_pattern.as_deref()) {
            Some(pattern) => debugger_atom(pattern, "module_pattern")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None if short_name.is_empty() => "*".to_string(),
            None => format!("{short_name}*"),
        };
        let object_path = if name.starts_with('\\') {
            name.clone()
        } else {
            format!(r"\Driver\{short_name}")
        };
        let device = match trimmed_nonempty(args.device.as_deref()) {
            Some(device) => Some(
                debugger_atom(device, "device")
                    .map_err(|error| McpError::invalid_params(error, None))?,
            ),
            None => None,
        };

        let mut steps = Vec::new();
        if args.prepare_symbols.unwrap_or(false) {
            match self
                .prepare_symbols(PrepareSymbolsArgs {
                    session_id: args.session_id.clone(),
                    module: Some("nt".to_string()),
                    symbol_cache: None,
                    symbol_server: None,
                    force_mismatched: None,
                })
                .await
            {
                Ok(payload) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "result": payload,
                })),
                Err(error) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "error": format!("{error:?}"),
                })),
            }
        }

        let (module_step, _) = self
            .diagnostic_command_step(
                args.session_id.as_deref(),
                &format!("lm m {module_pattern}"),
            )
            .await;
        steps.push(module_step);

        let (drvobj_step, drvobj_output) = self
            .diagnostic_command_step(args.session_id.as_deref(), &format!("!drvobj {name} 7"))
            .await;
        steps.push(drvobj_step);

        let (driver_object_step, _) = self
            .diagnostic_command_step(
                args.session_id.as_deref(),
                &format!("!object {object_path}"),
            )
            .await;
        steps.push(driver_object_step);

        if let Some(device) = device.as_deref() {
            for command in [
                format!("!object {device}"),
                format!("!devobj {device}"),
                format!("!devstack {device}"),
            ] {
                let (step, _) = self
                    .diagnostic_command_step(args.session_id.as_deref(), &command)
                    .await;
                steps.push(step);
            }
        }

        let dispatch_routines = parse_driver_dispatch_routines(&drvobj_output);
        let symbol_problem = output_indicates_symbol_problem(&drvobj_output);
        let recommendations: Vec<&str> = if dispatch_routines.is_empty() && symbol_problem {
            vec![
                "prepare nt symbols before configuring driver-load filters, or call this tool with prepare_symbols=true in a fresh/broken session",
                "if a load filter was just configured, prefer windbg_set_driver_load_breakpoint with its default prepare_symbols=true before retrying driver inspection",
            ]
        } else {
            Vec::new()
        };
        Ok(json!({
            "driver": name,
            "short_name": short_name,
            "module_pattern": module_pattern,
            "driver_object_path": object_path,
            "device": device,
            "symbol_problem": symbol_problem,
            "recommendations": recommendations,
            "dispatch_routines": dispatch_routines,
            "steps": steps,
            "next_tools": [
                "windbg_set_driver_dispatch_breakpoints",
                "windbg_driver_dispatch_snapshot",
                "windbg_read_memory",
                "windbg_backtrace"
            ],
        }))
    }

    async fn set_driver_dispatch_breakpoints(
        &self,
        args: SetDriverDispatchBreakpointsArgs,
    ) -> Result<Value, McpError> {
        let driver = debugger_atom(&args.driver, "driver")
            .map_err(|error| McpError::invalid_params(error, None))?;
        let include_default_handlers = args.include_default_handlers.unwrap_or(false);
        let mut steps = Vec::new();

        if args.prepare_symbols.unwrap_or(false) {
            match self
                .prepare_symbols(PrepareSymbolsArgs {
                    session_id: args.session_id.clone(),
                    module: Some("nt".to_string()),
                    symbol_cache: None,
                    symbol_server: None,
                    force_mismatched: None,
                })
                .await
            {
                Ok(payload) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "result": payload,
                })),
                Err(error) => steps.push(json!({
                    "tool": "windbg_prepare_symbols",
                    "error": format!("{error:?}"),
                })),
            }
        }

        let (drvobj_step, drvobj_output) = self
            .diagnostic_command_step(args.session_id.as_deref(), &format!("!drvobj {driver} 7"))
            .await;
        steps.push(drvobj_step);
        let routines = parse_driver_dispatch_routines(&drvobj_output);
        if routines.is_empty() {
            return Ok(json!({
                "driver": driver,
                "dispatch_routines": routines,
                "selected": [],
                "breakpoints_set": [],
                "warning": "no IRP_MJ dispatch routines were parsed from !drvobj output; verify symbols/extensions and the driver name. If load filters were recently configured, prepare symbols before setting the load filter or retry in a fresh session.",
                "steps": steps,
            }));
        }

        let default_filters = ["IRP_MJ_CREATE", "IRP_MJ_CLOSE", "IRP_MJ_DEVICE_CONTROL"];
        let requested_filters: Vec<String> = match args.functions.as_ref() {
            Some(functions) => functions
                .iter()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect(),
            None => default_filters
                .iter()
                .map(|value| value.to_string())
                .collect(),
        };
        let mut selection_mode = if args.functions.is_some() {
            "explicit".to_string()
        } else {
            "common_default".to_string()
        };
        let mut selected: Vec<DriverDispatchRoutine> = routines
            .iter()
            .filter(|routine| {
                requested_filters
                    .iter()
                    .any(|filter| dispatch_filter_matches(routine, filter))
            })
            .filter(|routine| include_default_handlers || !is_default_dispatch_routine(routine))
            .cloned()
            .collect();

        if args.functions.is_none() && selected.is_empty() {
            selection_mode = "all_non_default_fallback".to_string();
            selected = routines
                .iter()
                .filter(|routine| include_default_handlers || !is_default_dispatch_routine(routine))
                .cloned()
                .collect();
        }

        let mut breakpoints_set = Vec::new();
        for routine in &selected {
            let command = build_breakpoint_command(
                Some("bp"),
                &routine.target,
                args.one_shot,
                None,
                None,
                None,
                args.command.as_deref(),
            )
            .map_err(|error| McpError::invalid_params(error, None))?;
            let result = self
                .execute_debugger_command(args.session_id.as_deref(), command.clone())
                .await?;
            breakpoints_set.push(json!({
                "routine": routine,
                "command": command,
                "result": render_execution_result(result),
            }));
        }

        let breakpoints = self
            .execute_debugger_command(args.session_id.as_deref(), "bl".to_string())
            .await?;

        Ok(json!({
            "driver": driver,
            "selection_mode": selection_mode,
            "requested_functions": requested_filters,
            "include_default_handlers": include_default_handlers,
            "dispatch_routines": routines,
            "selected": selected,
            "breakpoints_set": breakpoints_set,
            "breakpoints": render_execution_result(breakpoints),
            "steps": steps,
        }))
    }

    async fn driver_dispatch_snapshot(
        &self,
        args: DriverDispatchSnapshotArgs,
    ) -> Result<Value, McpError> {
        let irp = match trimmed_nonempty(args.irp.as_deref()) {
            Some(value) => debugger_atom(value, "irp")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "@rdx".to_string(),
        };
        let driver_object = match trimmed_nonempty(args.driver_object.as_deref()) {
            Some(value) => debugger_atom(value, "driver_object")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "@rcx".to_string(),
        };
        let stack_count = clamp_count(args.stack_count, 32, 512);
        let memory_count = clamp_count(args.memory_count, 32, 1024);
        let commands = vec![
            ".lastevent".to_string(),
            "r".to_string(),
            format!("!irp {irp}"),
            format!("dt nt!_IRP {irp}"),
            format!("dq {irp} L{memory_count}"),
            format!("dt nt!_DRIVER_OBJECT {driver_object}"),
            format!("!drvobj {driver_object} 7"),
            format!("dq {driver_object} L16"),
            format!("kv {stack_count}"),
            "u rip L16".to_string(),
            "bl".to_string(),
        ];

        let mut steps = Vec::new();
        for command in commands {
            let (step, _) = self
                .diagnostic_command_step(args.session_id.as_deref(), &command)
                .await;
            steps.push(step);
        }

        Ok(json!({
            "irp": irp,
            "driver_object": driver_object,
            "steps": steps,
        }))
    }

    async fn detect_ioctl_irp(
        &self,
        session_id: Option<&str>,
        candidates: &[String],
    ) -> (Option<String>, Option<String>, Vec<Value>) {
        let mut steps = Vec::new();
        for candidate in candidates {
            let command = format!("!irp {candidate}");
            let (step, output) = self.diagnostic_command_step(session_id, &command).await;
            let valid = irp_output_looks_valid(&output);
            let system_buffer = parse_irp_system_buffer(&output);
            steps.push(json!({
                "candidate": candidate,
                "valid": valid,
                "system_buffer": system_buffer,
                "probe": step,
            }));
            if valid {
                return (Some(candidate.clone()), system_buffer, steps);
            }
        }
        (None, None, steps)
    }

    async fn ioctl_snapshot(&self, args: IoctlSnapshotArgs) -> Result<Value, McpError> {
        let mut detection_steps = Vec::new();
        let auto_detect = args.auto_detect.unwrap_or(true);
        let provided_irp = trimmed_nonempty(args.irp.as_deref()).is_some();
        let mut auto_detected_system_buffer = None;
        let mut irp = match trimmed_nonempty(args.irp.as_deref()) {
            Some(value) => debugger_atom(value, "irp")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "@rdx".to_string(),
        };

        let candidates: Vec<String> = match args.candidate_irps {
            Some(values) => values
                .into_iter()
                .map(|value| debugger_atom(&value, "candidate_irps"))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => ["@rdx", "@r15", "@rsi", "@rbx", "@rdi", "@rcx", "@r8", "@r9"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        };

        let selection_source = if provided_irp {
            "argument"
        } else if auto_detect {
            let (detected_irp, detected_system_buffer, steps) = self
                .detect_ioctl_irp(args.session_id.as_deref(), &candidates)
                .await;
            detection_steps = steps;
            if let Some(detected_irp) = detected_irp {
                irp = detected_irp;
                auto_detected_system_buffer = detected_system_buffer;
                "auto_detect"
            } else {
                "default"
            }
        } else {
            "default"
        };
        let stack_location = match trimmed_nonempty(args.stack_location.as_deref()) {
            Some(value) => debugger_atom(value, "stack_location")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => format!("poi({irp}+b8)"),
        };
        let detected_system_buffer = auto_detected_system_buffer.is_some();
        let system_buffer = match trimmed_nonempty(args.system_buffer.as_deref()) {
            Some(value) => debugger_atom(value, "system_buffer")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => auto_detected_system_buffer.unwrap_or_else(|| format!("poi({irp}+18)")),
        };
        let system_buffer_source = if trimmed_nonempty(args.system_buffer.as_deref()).is_some() {
            "argument"
        } else if detected_system_buffer {
            "auto_detect_irp_output"
        } else {
            "irp_associated_system_buffer"
        };
        let buffer_count = clamp_count(args.buffer_count, 0x84, 0x1000);
        let irp_memory_count = clamp_count(args.irp_memory_count, 0x30, 0x200);
        let stack_count = clamp_count(args.stack_count, 16, 128);
        let buffer_dwords = buffer_count.div_ceil(4);
        let buffer_qwords = buffer_count.div_ceil(8);
        let irp_command = format!("!irp {irp}");
        let stack_args_command = format!("dd {stack_location}+8 L5");
        let system_buffer_bytes_command = format!("db {system_buffer} L{buffer_count}");

        let commands = vec![
            ".lastevent".to_string(),
            "r".to_string(),
            "u @rip L16".to_string(),
            format!("kv {stack_count}"),
            irp_command.clone(),
            format!("dt nt!_IRP {irp}"),
            format!("dq {irp} L{irp_memory_count}"),
            format!("dq {stack_location} L8"),
            stack_args_command.clone(),
            format!("? poi({stack_location}+18)"),
            format!("? poi({stack_location}+10)"),
            format!("? poi({stack_location}+8)"),
            system_buffer_bytes_command.clone(),
            format!("dd {system_buffer} L{buffer_dwords}"),
            format!("dq {system_buffer} L{buffer_qwords}"),
            "bl".to_string(),
        ];

        let mut steps = Vec::new();
        let mut irp_output = String::new();
        let mut stack_args_output = String::new();
        let mut system_buffer_bytes_output = String::new();
        for command in commands {
            let (step, _) = self
                .diagnostic_command_step(args.session_id.as_deref(), &command)
                .await;
            if command == irp_command {
                irp_output = step["output"].as_str().unwrap_or_default().to_string();
            }
            if command == stack_args_command {
                stack_args_output = step["output"].as_str().unwrap_or_default().to_string();
            }
            if command == system_buffer_bytes_command {
                system_buffer_bytes_output =
                    step["output"].as_str().unwrap_or_default().to_string();
            }
            steps.push(step);
        }
        let ioctl_args = parse_ioctl_stack_args(&irp_output);
        let system_buffer_first_bytes = parse_db_bytes(&system_buffer_bytes_output, 32);
        let system_buffer_first_hex = if system_buffer_first_bytes.is_empty() {
            None
        } else {
            Some(system_buffer_first_bytes.join(""))
        };

        Ok(json!({
            "irp": irp,
            "stack_location": stack_location,
            "system_buffer": system_buffer,
            "selection_source": selection_source,
            "system_buffer_source": system_buffer_source,
            "buffer_count": buffer_count,
            "auto_detect": {
                "enabled": auto_detect,
                "candidates": candidates,
                "steps": detection_steps,
            },
            "summary": {
                "irp_valid": irp_output_looks_valid(&irp_output),
                "ioctl": ioctl_args,
                "system_buffer_from_irp": parse_irp_system_buffer(&irp_output),
                "system_buffer_first_bytes": system_buffer_first_bytes,
                "system_buffer_first_hex": system_buffer_first_hex,
                "stack_args_output": stack_args_output,
            },
            "steps": steps,
            "notes": [
                "When `irp` is omitted, the tool probes common IRP-holding registers and falls back to @rdx.",
                "For unusual breakpoints, pass irp/system_buffer/stack_location explicitly.",
            ],
        }))
    }

    async fn minifilter_message_snapshot(
        &self,
        args: MinifilterMessageSnapshotArgs,
    ) -> Result<Value, McpError> {
        let input_buffer = match trimmed_nonempty(args.input_buffer.as_deref()) {
            Some(value) => debugger_atom(value, "input_buffer")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "@rdx".to_string(),
        };
        let input_length = match trimmed_nonempty(args.input_length.as_deref()) {
            Some(value) => debugger_atom(value, "input_length")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "@r8".to_string(),
        };
        let output_buffer = match trimmed_nonempty(args.output_buffer.as_deref()) {
            Some(value) => debugger_atom(value, "output_buffer")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "@r9".to_string(),
        };
        let output_length = match trimmed_nonempty(args.output_length.as_deref()) {
            Some(value) => debugger_atom(value, "output_length")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "poi(@rsp+28)".to_string(),
        };
        let return_length_ptr = match trimmed_nonempty(args.return_length_ptr.as_deref()) {
            Some(value) => debugger_atom(value, "return_length_ptr")
                .map_err(|error| McpError::invalid_params(error, None))?,
            None => "poi(@rsp+30)".to_string(),
        };
        let input_count = clamp_count(args.input_count, 0x80, 0x1000);
        let output_count = clamp_count(args.output_count, 0x80, 0x1000);
        let stack_count = clamp_count(args.stack_count, 32, 512);
        let backtrace_count = clamp_count(args.backtrace_count, 32, 512);

        let input_length_command = format!("? {input_length}");
        let output_length_command = format!("? {output_length}");
        let return_length_ptr_command = format!("? {return_length_ptr}");
        let input_bytes_command = format!("db {input_buffer} L{input_count}");
        let output_bytes_command = format!("db {output_buffer} L{output_count}");

        let commands = vec![
            ("last_event", ".lastevent".to_string()),
            ("registers", "r".to_string()),
            ("disassembly", "u @rip L16".to_string()),
            ("backtrace", format!("kv {backtrace_count}")),
            ("stack", format!("dq @rsp L{stack_count}")),
            ("input_length", input_length_command.clone()),
            ("output_length", output_length_command.clone()),
            ("return_length_ptr", return_length_ptr_command.clone()),
            ("input_bytes", input_bytes_command.clone()),
            (
                "input_dwords",
                format!("dd {input_buffer} L{}", input_count.div_ceil(4)),
            ),
            (
                "input_qwords",
                format!("dq {input_buffer} L{}", input_count.div_ceil(8)),
            ),
            ("output_bytes", output_bytes_command.clone()),
            (
                "output_dwords",
                format!("dd {output_buffer} L{}", output_count.div_ceil(4)),
            ),
            ("breakpoints", "bl".to_string()),
        ];

        let mut steps = Vec::new();
        let mut input_length_output = String::new();
        let mut output_length_output = String::new();
        let mut return_length_ptr_output = String::new();
        let mut input_bytes_output = String::new();
        let mut output_bytes_output = String::new();

        for (label, command) in commands {
            let (mut step, _) = self
                .diagnostic_command_step(args.session_id.as_deref(), &command)
                .await;
            if let Some(object) = step.as_object_mut() {
                object.insert("label".to_string(), json!(label));
            }
            match label {
                "input_length" => {
                    input_length_output = step["output"].as_str().unwrap_or_default().to_string();
                }
                "output_length" => {
                    output_length_output = step["output"].as_str().unwrap_or_default().to_string();
                }
                "return_length_ptr" => {
                    return_length_ptr_output =
                        step["output"].as_str().unwrap_or_default().to_string();
                }
                "input_bytes" => {
                    input_bytes_output = step["output"].as_str().unwrap_or_default().to_string();
                }
                "output_bytes" => {
                    output_bytes_output = step["output"].as_str().unwrap_or_default().to_string();
                }
                _ => {}
            }
            steps.push(step);
        }

        let input_first_bytes = parse_db_bytes(&input_bytes_output, 64);
        let output_first_bytes = parse_db_bytes(&output_bytes_output, 64);
        let message_id = parse_le_u32_from_hex_bytes(&input_first_bytes, 0);
        let payload_length = parse_le_u32_from_hex_bytes(&input_first_bytes, 4);

        Ok(json!({
            "abi": "FLT_PORT_MESSAGE_NOTIFY_CALLBACK_x64",
            "expressions": {
                "input_buffer": input_buffer,
                "input_length": input_length,
                "output_buffer": output_buffer,
                "output_length": output_length,
                "return_length_ptr": return_length_ptr,
            },
            "summary": {
                "input_length_value": parse_evaluator_u64(&input_length_output),
                "output_length_value": parse_evaluator_u64(&output_length_output),
                "return_length_ptr_value": parse_evaluator_u64(&return_length_ptr_output),
                "input_first_bytes": input_first_bytes,
                "input_first_hex": contiguous_hex(&input_first_bytes),
                "output_first_bytes": output_first_bytes,
                "output_first_hex": contiguous_hex(&output_first_bytes),
                "message_header": {
                    "message_id": message_id,
                    "payload_length": payload_length,
                },
            },
            "steps": steps,
            "notes": [
                "Defaults assume the breakpoint is at the minifilter MessageNotifyCallback entry: rcx=PortCookie, rdx=InputBuffer, r8=InputBufferLength, r9=OutputBuffer.",
                "On Windows x64, OutputBufferLength and ReturnOutputBufferLength are stack arguments, defaulting to poi(@rsp+28) and poi(@rsp+30).",
                "Pass explicit expressions when breaking after the prologue or inside a wrapper/virtualized callback."
            ],
        }))
    }

    async fn query_state(&self, session_id: Option<&str>) -> Result<Value, McpError> {
        let state = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .query_state()
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .query_state(session_id)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({ "state": state }))
    }

    async fn get_output(
        &self,
        session_id: Option<&str>,
        cursor: Option<u64>,
    ) -> Result<Value, McpError> {
        let snapshot = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .get_output(cursor)
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .get_output(session_id, cursor)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({
            "entries": snapshot.entries,
            "history_start_cursor": snapshot.history_start_cursor,
            "next_cursor": snapshot.next_cursor,
        }))
    }

    async fn interrupt_target(&self, session_id: Option<&str>) -> Result<Value, McpError> {
        let state = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .interrupt()
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .interrupt(session_id)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({ "state": state }))
    }

    async fn resume_target(&self, session_id: Option<&str>) -> Result<Value, McpError> {
        let state = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .resume()
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .resume(session_id)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({ "state": state }))
    }

    #[cfg(test)]
    async fn run_entry_tool(
        &self,
        entry: &CatalogEntry,
        variant: Option<&str>,
        arguments: Option<&str>,
    ) -> Result<CallToolResult, McpError> {
        if !entry.supports_text_execution {
            let content = format!(
                "{} is documented as a keyboard action or non-text entry and cannot be executed as a raw debugger command string. Read {} for the official documentation.",
                entry.title,
                entry.resource_uri()
            );
            return Ok(CallToolResult::error(vec![Content::text(content)]));
        }

        let command = build_command(entry, variant, arguments)
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
        let execution = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .execute(command.clone())
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { .. } => {
                return Err(McpError::internal_error(
                    "test-only helper is only implemented for attached-session mode",
                    None,
                ));
            }
        };

        Ok(CallToolResult::structured(json!({
            "entry_id": entry.id,
            "title": entry.title,
            "command": command,
            "output": execution.output,
            "state_before": execution.state_before,
            "state_after": execution.state_after,
        })))
    }
}

impl ServerHandler for WindbgMcpServer {
    fn get_info(&self) -> ServerInfo {
        let instructions = if self.is_headless() {
            "Open a session with `windbg_open_session` before using debugger actions. Use `windbg_set_breakpoint`, `windbg_set_hardware_breakpoint`, `windbg_trace_breakpoint`, `windbg_find_process`, `windbg_set_process_breakpoint`, `windbg_set_syscall_breakpoint`, `windbg_set_driver_load_breakpoint`, `windbg_driver_summary`, `windbg_set_driver_dispatch_breakpoints`, `windbg_driver_dispatch_snapshot`, `windbg_ioctl_snapshot`, `windbg_minifilter_message_snapshot`, `windbg_dbgprint`, `windbg_continue_until_break`, `windbg_step`, `windbg_step_over`, `windbg_go_up`, `windbg_breakpoint_snapshot`, `windbg_read_registers`, `windbg_read_memory`, `windbg_disassemble`, `windbg_backtrace`, `windbg_evaluate_expression`, `windbg_list_modules`, `windbg_search_symbols`, and `windbg_inspect_driver` for common reverse-engineering and kernel-driver flows. Use `windbg_execute_command` for raw WinDbg commands, `windbg_get_output` with cursors for buffered output, and `windbg_resume_target` to continue a live target without blocking on raw `g`. Use `windbg_recover_session` if a live KDNET target may have been left broken. When multiple sessions are open, pass `session_id` or set a default with `windbg_switch_session`."
        } else {
            "This server is organized around low-context resources plus a small toolset. Start with `windbg_search_catalog`, read `windbg://command/{id}`, optionally escalate to `windbg://command-full/{id}`, then call `windbg_get_execution_state`. If the debugger is running or busy, call `windbg_interrupt_target` and verify state again before calling `windbg_execute_command`. Use `windbg_get_output` to read buffered command output again later, and `windbg_resume_target` to continue execution without issuing a raw `g` command."
        };

        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_tools()
                .build(),
        )
        .with_instructions(instructions)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = self.management_tools();
        tools.extend(self.base_tools());

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        match name {
            "windbg_execute_command" => Some(self.generic_command_tool()),
            "windbg_get_execution_state" => Some(self.state_tool()),
            "windbg_get_output" => Some(self.output_tool()),
            "windbg_prepare_symbols" => Some(self.prepare_symbols_tool()),
            "windbg_diagnose_extensions" => Some(self.diagnose_extensions_tool()),
            "windbg_dbgprint" => Some(self.dbgprint_tool()),
            "windbg_set_breakpoint" => Some(self.set_breakpoint_tool()),
            "windbg_set_hardware_breakpoint" => Some(self.set_hardware_breakpoint_tool()),
            "windbg_find_process" => Some(self.find_process_tool()),
            "windbg_set_process_breakpoint" => Some(self.set_process_breakpoint_tool()),
            "windbg_set_syscall_breakpoint" => Some(self.set_syscall_breakpoint_tool()),
            "windbg_list_breakpoints" => Some(self.list_breakpoints_tool()),
            "windbg_clear_breakpoint" => Some(self.clear_breakpoint_tool()),
            "windbg_read_registers" => Some(self.read_registers_tool()),
            "windbg_write_register" => Some(self.write_register_tool()),
            "windbg_read_memory" => Some(self.read_memory_tool()),
            "windbg_disassemble" => Some(self.disassemble_tool()),
            "windbg_backtrace" => Some(self.backtrace_tool()),
            "windbg_breakpoint_snapshot" => Some(self.breakpoint_snapshot_tool()),
            "windbg_trace_breakpoint" => Some(self.trace_breakpoint_tool()),
            "windbg_continue_until_break" => Some(self.continue_until_break_tool()),
            "windbg_step" => Some(self.step_tool()),
            "windbg_step_over" => Some(self.step_over_tool()),
            "windbg_go_up" => Some(self.go_up_tool()),
            "windbg_evaluate_expression" => Some(self.evaluate_expression_tool()),
            "windbg_list_modules" => Some(self.list_modules_tool()),
            "windbg_search_symbols" => Some(self.search_symbols_tool()),
            "windbg_inspect_driver" => Some(self.inspect_driver_tool()),
            "windbg_set_driver_load_breakpoint" => Some(self.set_driver_load_breakpoint_tool()),
            "windbg_driver_summary" => Some(self.driver_summary_tool()),
            "windbg_set_driver_dispatch_breakpoints" => {
                Some(self.set_driver_dispatch_breakpoints_tool())
            }
            "windbg_driver_dispatch_snapshot" => Some(self.driver_dispatch_snapshot_tool()),
            "windbg_ioctl_snapshot" => Some(self.ioctl_snapshot_tool()),
            "windbg_minifilter_message_snapshot" => Some(self.minifilter_message_snapshot_tool()),
            "windbg_search_catalog" => Some(self.search_tool()),
            "windbg_interrupt_target" => Some(self.interrupt_tool()),
            "windbg_resume_target" => Some(self.resume_tool()),
            "windbg_open_session" if self.is_headless() => Some(self.open_session_tool()),
            "windbg_close_session" if self.is_headless() => Some(self.close_session_tool()),
            "windbg_switch_session" if self.is_headless() => Some(self.switch_session_tool()),
            "windbg_list_sessions" if self.is_headless() => Some(self.list_sessions_tool()),
            "windbg_current_session" if self.is_headless() => Some(self.current_session_tool()),
            "windbg_recover_session" if self.is_headless() => Some(self.recover_session_tool()),
            _ => None,
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match request.name.as_ref() {
            "windbg_execute_command" => {
                let args: ExecuteRawArgs = self.parse_arguments(request.arguments)?;
                let payload = self
                    .execute_command(args.session_id.as_deref(), args.command)
                    .await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_get_execution_state" => {
                let args: GetExecutionStateArgs = self.parse_arguments(request.arguments)?;
                let payload = self.query_state(args.session_id.as_deref()).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_get_output" => {
                let args: GetOutputArgs = self.parse_arguments(request.arguments)?;
                let payload = self
                    .get_output(args.session_id.as_deref(), args.cursor)
                    .await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_prepare_symbols" => {
                let args: PrepareSymbolsArgs = self.parse_arguments(request.arguments)?;
                let payload = self.prepare_symbols(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_diagnose_extensions" => {
                let args: DiagnoseExtensionsArgs = self.parse_arguments(request.arguments)?;
                let payload = self.diagnose_extensions(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_dbgprint" => {
                let args: DbgPrintArgs = self.parse_arguments(request.arguments)?;
                let payload = self.dbgprint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_set_breakpoint" => {
                let args: SetBreakpointArgs = self.parse_arguments(request.arguments)?;
                let payload = self.set_breakpoint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_set_hardware_breakpoint" => {
                let args: SetHardwareBreakpointArgs = self.parse_arguments(request.arguments)?;
                let payload = self.set_hardware_breakpoint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_find_process" => {
                let args: FindProcessArgs = self.parse_arguments(request.arguments)?;
                let payload = self.find_process(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_set_process_breakpoint" => {
                let args: SetProcessBreakpointArgs = self.parse_arguments(request.arguments)?;
                let payload = self.set_process_breakpoint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_set_syscall_breakpoint" => {
                let args: SetSyscallBreakpointArgs = self.parse_arguments(request.arguments)?;
                let payload = self.set_syscall_breakpoint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_list_breakpoints" => {
                let args: ListBreakpointsArgs = self.parse_arguments(request.arguments)?;
                let payload = self.list_breakpoints(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_clear_breakpoint" => {
                let args: ClearBreakpointArgs = self.parse_arguments(request.arguments)?;
                let payload = self.clear_breakpoint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_read_registers" => {
                let args: ReadRegistersArgs = self.parse_arguments(request.arguments)?;
                let payload = self.read_registers(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_write_register" => {
                let args: WriteRegisterArgs = self.parse_arguments(request.arguments)?;
                let payload = self.write_register(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_read_memory" => {
                let args: ReadMemoryArgs = self.parse_arguments(request.arguments)?;
                let payload = self.read_memory(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_disassemble" => {
                let args: DisassembleArgs = self.parse_arguments(request.arguments)?;
                let payload = self.disassemble(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_backtrace" => {
                let args: BacktraceArgs = self.parse_arguments(request.arguments)?;
                let payload = self.backtrace(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_breakpoint_snapshot" => {
                let args: BreakpointSnapshotArgs = self.parse_arguments(request.arguments)?;
                let payload = self.breakpoint_snapshot(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_trace_breakpoint" => {
                let args: TraceBreakpointArgs = self.parse_arguments(request.arguments)?;
                let payload = self.trace_breakpoint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_continue_until_break" => {
                let args: ContinueUntilBreakArgs = self.parse_arguments(request.arguments)?;
                let payload = self.continue_until_break(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_step" => {
                let args: StepExecutionArgs = self.parse_arguments(request.arguments)?;
                let payload = self.step_execution(args, "t", "step_into").await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_step_over" => {
                let args: StepExecutionArgs = self.parse_arguments(request.arguments)?;
                let payload = self.step_execution(args, "p", "step_over").await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_go_up" => {
                let args: StepExecutionArgs = self.parse_arguments(request.arguments)?;
                let payload = self.step_execution(args, "gu", "go_up").await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_evaluate_expression" => {
                let args: EvaluateExpressionArgs = self.parse_arguments(request.arguments)?;
                let payload = self.evaluate_expression(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_list_modules" => {
                let args: ListModulesArgs = self.parse_arguments(request.arguments)?;
                let payload = self.list_modules(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_search_symbols" => {
                let args: SearchSymbolsArgs = self.parse_arguments(request.arguments)?;
                let payload = self.search_symbols(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_inspect_driver" => {
                let args: InspectDriverArgs = self.parse_arguments(request.arguments)?;
                let payload = self.inspect_driver(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_set_driver_load_breakpoint" => {
                let args: SetDriverLoadBreakpointArgs = self.parse_arguments(request.arguments)?;
                let payload = self.set_driver_load_breakpoint(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_driver_summary" => {
                let args: DriverSummaryArgs = self.parse_arguments(request.arguments)?;
                let payload = self.driver_summary(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_set_driver_dispatch_breakpoints" => {
                let args: SetDriverDispatchBreakpointsArgs =
                    self.parse_arguments(request.arguments)?;
                let payload = self.set_driver_dispatch_breakpoints(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_driver_dispatch_snapshot" => {
                let args: DriverDispatchSnapshotArgs = self.parse_arguments(request.arguments)?;
                let payload = self.driver_dispatch_snapshot(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_ioctl_snapshot" => {
                let args: IoctlSnapshotArgs = self.parse_arguments(request.arguments)?;
                let payload = self.ioctl_snapshot(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_minifilter_message_snapshot" => {
                let args: MinifilterMessageSnapshotArgs =
                    self.parse_arguments(request.arguments)?;
                let payload = self.minifilter_message_snapshot(args).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_search_catalog" => {
                let args: SearchCatalogArgs = self.parse_arguments(request.arguments)?;
                let limit = args.limit.unwrap_or(10).clamp(1, 100) as usize;
                let matches = self.catalog().search(&args.query, args.section, limit);
                let payload: Vec<Value> = matches
                    .into_iter()
                    .map(|entry| {
                        json!({
                            "id": entry.id,
                            "primary_token": entry.primary_token(),
                            "title": entry.title,
                            "tokens": entry.tokens,
                            "summary": entry.summary,
                            "supports_text_execution": entry.supports_text_execution,
                            "syntax_preview": self.syntax_preview(entry),
                            "resource": entry.resource_uri(),
                            "full_resource": entry.full_resource_uri(),
                            "routing": entry.tool_routing_name(),
                            "recommended_tool": entry.recommended_tool(),
                            "execution_state_tool": "windbg_get_execution_state",
                            "resume_tool": "windbg_resume_target"
                        })
                    })
                    .collect();
                Ok(CallToolResult::structured(json!({
                    "query": args.query,
                    "recommended_flow": [
                        "call windbg_search_catalog",
                        "read the compact resource for the best match",
                        "read the full resource only if needed",
                        "call windbg_get_execution_state",
                        "if needed, call windbg_interrupt_target and verify state again",
                        "call windbg_execute_command or another recommended tool"
                    ],
                    "matches": payload,
                })))
            }
            "windbg_interrupt_target" => {
                let args: InterruptTargetArgs = self.parse_arguments(request.arguments)?;
                let payload = self.interrupt_target(args.session_id.as_deref()).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_resume_target" => {
                let args: ResumeTargetArgs = self.parse_arguments(request.arguments)?;
                let payload = self.resume_target(args.session_id.as_deref()).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_open_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let args: OpenSessionArgs = self.parse_arguments(request.arguments)?;
                let session = sessions
                    .open_kernel_session(
                        &args.connection,
                        args.session_id.as_deref(),
                        args.startup_command.as_deref(),
                        args.attach_timeout_secs,
                    )
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!({
                    "session": session
                })))
            }
            "windbg_close_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let args: CloseSessionArgs = self.parse_arguments(request.arguments)?;
                let result = sessions
                    .close_session(
                        &args.session_id,
                        args.shutdown_timeout_secs,
                        args.resume_before_close,
                    )
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!(result)))
            }
            "windbg_recover_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let args: RecoverSessionArgs = self.parse_arguments(request.arguments)?;
                let result = sessions
                    .recover_session(
                        args.session_id.as_deref(),
                        args.resume_if_broken,
                        args.interrupt_if_running,
                    )
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!(result)))
            }
            "windbg_switch_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let args: SwitchSessionArgs = self.parse_arguments(request.arguments)?;
                let session = sessions
                    .switch_session(&args.session_id)
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!({
                    "session": session
                })))
            }
            "windbg_list_sessions" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let _: ListSessionsArgs = self.parse_arguments(request.arguments)?;
                let payload = sessions
                    .list_sessions()
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!(payload)))
            }
            "windbg_current_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let _: CurrentSessionArgs = self.parse_arguments(request.arguments)?;
                let payload = sessions
                    .current_session()
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!({
                    "session": payload
                })))
            }
            _ => Err(McpError::method_not_found::<CallToolRequestMethod>()),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let guide = render_guide(self.catalog());

        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new(GUIDE_URI, "windbg guide")
                    .with_title("WinDbg MCP guide")
                    .with_description(
                        "Low-context workflow for mapping debugger requests to resources and tools",
                    )
                    .with_mime_type("text/plain")
                    .with_size(guide.len() as u32)
                    .no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            resource_templates: vec![
                RawResourceTemplate::new(
                    self.catalog().command_template_uri(),
                    "windbg compact command card",
                )
                .with_description(
                    "Compact syntax-first WinDbg command card by extracted catalog id",
                )
                .with_mime_type("text/plain")
                .no_annotation(),
                RawResourceTemplate::new(
                    self.catalog().full_command_template_uri(),
                    "windbg full command page",
                )
                .with_description("Full extracted debugger command topic by extracted catalog id")
                .with_mime_type("text/plain")
                .no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        if request.uri == GUIDE_URI {
            return Ok(ReadResourceResult::new(vec![ResourceContents::text(
                render_guide(self.catalog()),
                request.uri,
            )]));
        }

        let (kind, entry) = self
            .catalog()
            .resolve_resource_uri(&request.uri)
            .ok_or_else(|| {
                McpError::resource_not_found(
                    "unknown_resource",
                    Some(json!({ "uri": request.uri })),
                )
            })?;
        let content = match kind {
            CatalogResourceKind::Compact => render_compact_command(entry),
            CatalogResourceKind::Full => render_full_command(entry),
        };

        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            content,
            request.uri,
        )]))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::executor::ExecutionMode;

    #[tokio::test]
    async fn command_tool_uses_mock_dispatcher() {
        let mut responses = HashMap::new();
        responses.insert(
            "dt _PEB_LDR_DATA".to_string(),
            "ntdll!_PEB_LDR_DATA".to_string(),
        );
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock { responses })
            .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);
        let entry = server
            .catalog()
            .lookup("dt")
            .expect("dt entry should exist");

        let result = server
            .run_entry_tool(entry, None, Some("_PEB_LDR_DATA"))
            .await
            .expect("tool should succeed");

        let payload = result
            .structured_content
            .expect("structured payload expected");
        assert_eq!(payload["command"], "dt _PEB_LDR_DATA");
        assert_eq!(payload["output"], "ntdll!_PEB_LDR_DATA");
    }

    #[tokio::test]
    async fn dbgprint_returns_bounded_tail_from_mock_dispatcher() {
        let mut responses = HashMap::new();
        responses.insert(".load kdexts".to_string(), "kdexts loaded".to_string());
        responses.insert(
            "!dbgprint".to_string(),
            "first debug line\nsecond debug line\nthird debug line".to_string(),
        );
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock { responses })
            .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let payload = server
            .dbgprint(DbgPrintArgs {
                lines: Some(2),
                ..Default::default()
            })
            .await
            .expect("dbgprint should succeed");

        assert_eq!(payload["command"], "!dbgprint");
        assert_eq!(payload["line_count"], 3);
        assert_eq!(payload["returned_line_count"], 2);
        assert_eq!(payload["truncated"], true);
        assert_eq!(payload["output"], "second debug line\nthird debug line");
        assert!(payload.get("raw_output").is_none());
    }

    #[test]
    fn interrupt_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_interrupt_target")
            .expect("interrupt tool should be listed");
        assert_eq!(tool.name, "windbg_interrupt_target");
    }

    #[test]
    fn resume_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_resume_target")
            .expect("resume tool should be listed");
        assert_eq!(tool.name, "windbg_resume_target");
    }

    #[test]
    fn recover_tool_is_exposed_in_headless_mode() {
        let server = WindbgMcpServer::headless(HeadlessSessionManager::new());

        let tool = server
            .get_tool("windbg_recover_session")
            .expect("recover tool should be listed for headless mode");
        assert_eq!(tool.name, "windbg_recover_session");
    }

    #[test]
    fn prepare_symbols_tool_is_exposed_in_headless_mode() {
        let server = WindbgMcpServer::headless(HeadlessSessionManager::new());

        let tool = server
            .get_tool("windbg_prepare_symbols")
            .expect("prepare symbols tool should be listed for headless mode");
        assert_eq!(tool.name, "windbg_prepare_symbols");
    }

    #[test]
    fn diagnose_extensions_tool_is_exposed_in_headless_mode() {
        let server = WindbgMcpServer::headless(HeadlessSessionManager::new());

        let tool = server
            .get_tool("windbg_diagnose_extensions")
            .expect("diagnose extensions tool should be listed for headless mode");
        assert_eq!(tool.name, "windbg_diagnose_extensions");
    }

    #[test]
    fn dbgprint_tool_is_exposed_in_headless_mode() {
        let server = WindbgMcpServer::headless(HeadlessSessionManager::new());

        let tool = server
            .get_tool("windbg_dbgprint")
            .expect("DbgPrint tool should be listed for headless mode");
        assert_eq!(tool.name, "windbg_dbgprint");
    }

    #[test]
    fn reverse_engineering_tools_are_exposed_in_headless_mode() {
        let server = WindbgMcpServer::headless(HeadlessSessionManager::new());

        for name in [
            "windbg_set_breakpoint",
            "windbg_set_hardware_breakpoint",
            "windbg_find_process",
            "windbg_set_process_breakpoint",
            "windbg_set_syscall_breakpoint",
            "windbg_list_breakpoints",
            "windbg_clear_breakpoint",
            "windbg_read_registers",
            "windbg_write_register",
            "windbg_read_memory",
            "windbg_disassemble",
            "windbg_backtrace",
            "windbg_breakpoint_snapshot",
            "windbg_trace_breakpoint",
            "windbg_continue_until_break",
            "windbg_step",
            "windbg_step_over",
            "windbg_go_up",
            "windbg_evaluate_expression",
            "windbg_list_modules",
            "windbg_search_symbols",
            "windbg_inspect_driver",
            "windbg_set_driver_load_breakpoint",
            "windbg_driver_summary",
            "windbg_set_driver_dispatch_breakpoints",
            "windbg_driver_dispatch_snapshot",
            "windbg_ioctl_snapshot",
            "windbg_minifilter_message_snapshot",
            "windbg_dbgprint",
        ] {
            let tool = server
                .get_tool(name)
                .unwrap_or_else(|| panic!("{name} should be listed for headless mode"));
            assert_eq!(tool.name, name);
        }
    }

    #[test]
    fn tail_output_lines_returns_bounded_tail() {
        let (lines, total, truncated) = tail_output_lines("one\ntwo\nthree\nfour", 2);

        assert_eq!(total, 4);
        assert!(truncated);
        assert_eq!(lines, vec!["three".to_string(), "four".to_string()]);
    }

    #[test]
    fn memory_command_formats_common_reverse_engineering_reads() {
        assert_eq!(
            memory_command("rsp", Some("qwords"), Some(4)).expect("qwords format"),
            "dq rsp L4"
        );
        assert_eq!(
            memory_command("poi(rcx)", Some("bytes"), Some(16)).expect("bytes format"),
            "db poi(rcx) L16"
        );
        assert_eq!(
            memory_command("rcx", Some("poi"), Some(2)).expect("poi format"),
            "dq poi(rcx) L2"
        );
    }

    #[test]
    fn builds_process_scoped_breakpoint_commands() {
        assert_eq!(
            build_breakpoint_command(
                Some("bp"),
                "nt!NtCreateFile",
                Some(true),
                Some("ffff800ff5aa7040"),
                None,
                None,
                Some("r; kv 8")
            )
            .expect("process breakpoint command"),
            r#"bp /1 /p ffff800ff5aa7040 nt!NtCreateFile "r; kv 8""#
        );
    }

    #[test]
    fn builds_hardware_breakpoint_commands() {
        assert_eq!(
            build_hardware_breakpoint_command(
                Some("write"),
                Some(4),
                "fffff806`12345678",
                Some(true),
                Some("ffff800ff5aa7040"),
                None,
                Some(2),
                Some("r; kv 8")
            )
            .expect("hardware breakpoint command"),
            r#"ba w 4 /1 /p ffff800ff5aa7040 fffff806`12345678 2 "r; kv 8""#
        );
    }

    #[test]
    fn parses_created_breakpoint_ids_from_bl_output() {
        let before = r#"
0 e Disable Clear  fffff806`11111111     0001 (0001) nt!DbgBreakPoint
"#;
        let after = r#"
0 e Disable Clear  fffff806`11111111     0001 (0001) nt!DbgBreakPoint
1 e Disable Clear  fffff806`22222222     0001 (0001) mydriver+0x123
2: e Disable Clear  fffff806`33333333     0001 (0001) mydriver+0x456
"#;

        assert_eq!(parse_breakpoint_ids(after), vec!["0", "1", "2"]);
        assert_eq!(new_breakpoint_ids(before, after), vec!["1", "2"]);
    }

    #[test]
    fn detects_breakpoint_creation_failures() {
        assert!(output_indicates_breakpoint_failure(
            "Couldn't resolve error at 'nt!MissingSymbol'"
        ));
        assert!(validate_created_breakpoints("bp missing", "", &[]).is_err());
        assert!(
            validate_created_breakpoints("bp nt!DbgBreakPoint", "", &["0".to_string()]).is_ok()
        );
    }

    #[test]
    fn detects_user_mode_addresses_for_process_context() {
        assert!(looks_like_user_mode_address("0x7ff83ba4dc80"));
        assert!(looks_like_user_mode_address("00007ff8`3ba4dc80"));
        assert!(!looks_like_user_mode_address("fffff806`82e57490"));
        assert!(!looks_like_user_mode_address("nt!KeDelayExecutionThread"));
    }

    #[test]
    fn blocks_fragile_raw_multi_register_reads() {
        assert!(blocked_unsafe_debugger_command("r rip rax rcx").is_some());
        assert!(blocked_unsafe_debugger_command("r rax=1").is_none());
        assert!(blocked_unsafe_debugger_command("r rip").is_none());
    }

    #[test]
    fn parses_process_blocks_from_process_extension_output() {
        let output = r#"
PROCESS ffff800ff5aa7040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ae000  ObjectTable: ffffb28f9fc5bc80  HandleCount: 2263.
    Image: System

PROCESS ffff800ff6bb8040
    SessionId: 1  Cid: 224    Peb: 00000000  ParentCid: 0004
    Image: ShadowGateApp.exe
"#;

        let processes = parse_processes(output);
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].eprocess, "ffff800ff5aa7040");
        assert_eq!(processes[0].pid.as_deref(), Some("0004"));
        assert_eq!(processes[0].image.as_deref(), Some("System"));
        assert!(process_matches(
            &processes[1],
            Some("shadowgate*.exe"),
            None
        ));
        assert!(process_matches(&processes[1], None, Some("0n548")));
    }

    #[test]
    fn normalizes_common_syscall_breakpoint_names() {
        assert_eq!(
            normalize_syscall_location("NtCreateFile").expect("ntcreatefile"),
            "nt!NtCreateFile"
        );
        assert_eq!(
            normalize_syscall_location("DeviceIoControl").expect("device io control"),
            "nt!NtDeviceIoControlFile"
        );
        assert_eq!(
            normalize_syscall_location("nt!ZwCreateFile").expect("explicit symbol"),
            "nt!ZwCreateFile"
        );
    }

    #[test]
    fn parses_driver_dispatch_routines_from_drvobj_output() {
        let output = r#"
Dispatch routines:
[00] IRP_MJ_CREATE                      fffff805`12345678
[02] IRP_MJ_CLOSE                       fffff805`6a8b9050 nt!IopInvalidDeviceRequest
[0e] IRP_MJ_DEVICE_CONTROL              ShadowGateSys+0x1234
"#;

        let routines = parse_driver_dispatch_routines(output);

        assert_eq!(routines.len(), 3);
        assert_eq!(routines[0].index.as_deref(), Some("00"));
        assert_eq!(routines[0].major_function, "IRP_MJ_CREATE");
        assert_eq!(routines[0].target, "fffff805`12345678");
        assert_eq!(
            routines[1].symbol.as_deref(),
            Some("nt!IopInvalidDeviceRequest")
        );
        assert!(is_default_dispatch_routine(&routines[1]));
        assert!(dispatch_filter_matches(&routines[2], "device_control"));
        assert!(dispatch_filter_matches(&routines[2], "0e"));
    }

    #[test]
    fn parses_ioctl_snapshot_summary_from_irp_output() {
        let output = r#"
Irp is active with 1 stacks 1 is current (= 0xffffda8acabffb60)
 No Mdl: System buffer=ffffda8acab17140: Thread ffffda8ac8bf0080:  Irp stack trace.
     cmd  flg cl Device   File     Completion-Context
>[IRP_MJ_DEVICE_CONTROL(e), N/A(0)]
            5  0 ffffda8ac8586e10 ffffda8acb76bd70 00000000-00000000
           \Driver\ShadowGate
            Args: 00000084 0000000c 0x80012004 00000000
"#;

        assert!(irp_output_looks_valid(output));
        assert_eq!(
            parse_irp_system_buffer(output).as_deref(),
            Some("ffffda8acab17140")
        );
        let args = parse_ioctl_stack_args(output).expect("IOCTL args should parse");
        assert_eq!(args.output_buffer_length, 0x84);
        assert_eq!(args.input_buffer_length, 0x0c);
        assert_eq!(args.ioctl_code, 0x80012004);
        assert_eq!(args.type3_input_buffer, 0);
    }

    #[test]
    fn parses_db_byte_prefix_for_system_buffer_summary() {
        let output = r#"
ffffda8a`cab17140  52 00 00 00 00 00 00 00-65 13 ad de 00 00 00 00  R.......e.......
ffffda8a`cab17150  ff ee                                      ..
"#;

        let bytes = parse_db_bytes(output, 18);
        assert_eq!(
            bytes,
            vec![
                "52", "00", "00", "00", "00", "00", "00", "00", "65", "13", "ad", "de", "00", "00",
                "00", "00", "ff", "ee"
            ]
        );
    }

    #[test]
    fn parses_minifilter_message_header_from_bytes() {
        let output = r#"
ffffda8a`ca000000  04 40 15 00 1c 00 00 00-33 1b 4f 4b 32 34 3e 20  .@......3.OK24>
"#;

        let bytes = parse_db_bytes(output, 16);

        assert_eq!(parse_le_u32_from_hex_bytes(&bytes, 0), Some(0x0015_4004));
        assert_eq!(parse_le_u32_from_hex_bytes(&bytes, 4), Some(0x1c));
        assert_eq!(
            contiguous_hex(&bytes).as_deref(),
            Some("044015001c000000331b4f4b32343e20")
        );
    }

    #[test]
    fn blocks_dangerous_load_filter_disable_commands() {
        assert!(blocked_unsafe_debugger_command("sxd ld").is_some());
        assert!(blocked_unsafe_debugger_command("  sxd   ld:ACEDriver.sys  ").is_some());
        assert!(blocked_unsafe_debugger_command("bp nt!DbgBreakPoint; sxd ld*").is_some());
        assert!(blocked_unsafe_debugger_command("sxe ld:ACEDriver.sys").is_none());
        assert!(blocked_unsafe_debugger_command("bc *").is_none());
    }

    #[test]
    fn driver_name_helpers_normalize_common_inputs() {
        assert_eq!(driver_short_name(r"\Driver\ShadowGate"), "ShadowGate");
        assert_eq!(driver_short_name("ShadowGateSys.sys"), "ShadowGateSys");
        assert_eq!(normalize_dispatch_filter("MJ_CREATE"), "IRP_MJ_CREATE");
    }

    #[test]
    fn backtrace_command_preserves_case_sensitive_stack_formats() {
        assert_eq!(
            backtrace_command(Some("kP"), Some(12)).expect("kP format"),
            "kP 12"
        );
        assert_eq!(
            backtrace_command(Some("KP"), Some(12)).expect("case-insensitive kp format"),
            "kp 12"
        );
    }

    #[test]
    fn breakpoint_command_string_preserves_kernel_paths() {
        assert_eq!(
            quote_debugger_command(r#"!drvobj \Driver\ShadowGate 7; g"#),
            r#""!drvobj \Driver\ShadowGate 7; g""#
        );
        assert_eq!(
            quote_debugger_command(r#".printf "hit"; g"#),
            r#"".printf \"hit\"; g""#
        );
    }

    #[test]
    fn lmi_pdb_info_extracts_symbol_server_index() {
        let output = r#"
Loaded Module Info: [nt]
    Image path: nt
    Symbol status:  Symbols deferred
    CodeView: RSDS - GUID: {B9E105C7-03F2-8FE8-B3BF-1877133D5CC2}
        Age: 1, Pdb: ntkrnlmp.pdb
"#;

        let pdb = parse_lmi_pdb_info(output).expect("PDB info should be parsed");

        assert_eq!(pdb.name, "ntkrnlmp.pdb");
        assert_eq!(pdb.guid, "B9E105C7-03F2-8FE8-B3BF-1877133D5CC2");
        assert_eq!(pdb.age, 1);
        assert_eq!(
            pdb.symbol_server_index(),
            "B9E105C703F28FE8B3BF1877133D5CC21"
        );
    }

    #[test]
    fn command_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_execute_command")
            .expect("command tool should be listed");
        assert_eq!(tool.name, "windbg_execute_command");
    }

    #[test]
    fn state_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_get_execution_state")
            .expect("state tool should be listed");
        assert_eq!(tool.name, "windbg_get_execution_state");
    }

    #[test]
    fn compact_resource_stays_small_and_points_to_full_doc() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);
        let entry = server
            .catalog()
            .lookup("bp")
            .expect("bp entry should exist");

        let resource = render_compact_command(entry);
        assert!(resource.contains("Syntax"));
        assert!(resource.contains("windbg://command-full/bp_bu_bm_set_breakpoint"));
        assert!(resource.contains("Next Step"));
    }

    #[test]
    fn syntax_preview_uses_inferred_syntax_when_structured_syntax_is_missing() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);
        let entry = server
            .catalog()
            .lookup("bp")
            .expect("bp entry should exist");

        let preview = server.syntax_preview(entry).expect("preview should exist");
        assert!(preview.contains("User-Mode"));
    }
}
