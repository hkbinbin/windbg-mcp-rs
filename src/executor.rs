use std::{
    collections::HashMap,
    ffi::CString,
    panic::{self, AssertUnwindSafe},
    sync::mpsc,
    thread,
    time::Duration,
};

use serde::Serialize;
use tokio::sync::oneshot;

use crate::catalog::CatalogEntry;

const EXECUTION_STATUS_NO_CHANGE: u32 = 0;
const EXECUTION_STATUS_GO: u32 = 1;
const EXECUTION_STATUS_GO_HANDLED: u32 = 2;
const EXECUTION_STATUS_GO_NOT_HANDLED: u32 = 3;
const EXECUTION_STATUS_STEP_OVER: u32 = 4;
const EXECUTION_STATUS_STEP_INTO: u32 = 5;
const EXECUTION_STATUS_BREAK: u32 = 6;
const EXECUTION_STATUS_NO_DEBUGGEE: u32 = 7;
const EXECUTION_STATUS_STEP_BRANCH: u32 = 8;
const EXECUTION_STATUS_IGNORE_EVENT: u32 = 9;
const EXECUTION_STATUS_RESTART_REQUESTED: u32 = 10;
const EXECUTION_STATUS_REVERSE_GO: u32 = 11;
const EXECUTION_STATUS_REVERSE_STEP_BRANCH: u32 = 12;
const EXECUTION_STATUS_REVERSE_STEP_OVER: u32 = 13;
const EXECUTION_STATUS_REVERSE_STEP_INTO: u32 = 14;
const EXECUTION_STATUS_OUT_OF_SYNC: u32 = 15;
const EXECUTION_STATUS_WAIT_INPUT: u32 = 16;
const EXECUTION_STATUS_TIMEOUT: u32 = 17;

const INTERRUPT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_ATTACH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("command topic `{0}` cannot be executed as plain debugger text")]
    NonTextualCommand(String),
    #[error("variant `{variant}` is not documented for `{command}`")]
    InvalidVariant { command: String, variant: String },
    #[error("dispatcher worker stopped")]
    WorkerStopped,
    #[error("debugger session failed to start: {0}")]
    Startup(String),
    #[error("command execution failed: {0}")]
    Command(String),
    #[error("string contains an embedded NUL byte")]
    InvalidCString,
    #[error("unknown or inactive session: {0}")]
    Session(String),
    #[error("this execution mode is only available on Windows")]
    WindowsOnly,
}

pub enum ExecutionMode {
    KernelConnection {
        connect_options: String,
        startup_command: Option<String>,
        attach_timeout: Duration,
    },
    UserModeProcess {
        attach: UserModeAttach,
        startup_command: Option<String>,
        attach_timeout: Duration,
    },
    Mock {
        responses: HashMap<String, String>,
    },
}

/// How to acquire a user-mode process for debugging.
#[derive(Debug, Clone)]
pub enum UserModeAttach {
    /// Spawn the given command line as a debuggee process and immediately
    /// attach. The first whitespace-separated token must be an executable
    /// path or name resolvable through the launcher's PATH.
    Launch {
        command_line: String,
        /// When true, only the spawned process is debugged (the engine sets
        /// `DEBUG_PROCESS_ONLY_THIS_PROCESS`); when false the engine follows
        /// child processes too.
        only_this_process: bool,
        /// When true, the debuggee is detached automatically when the host
        /// session ends instead of being terminated.
        detach_on_exit: bool,
    },
    /// Attach to a process that is already running on the local machine,
    /// addressed by its decimal PID.
    AttachPid {
        pid: u32,
        /// When true, performs a `DEBUG_ATTACH_NONINVASIVE` attach (no
        /// debug heap injection, freezes threads on the target).
        non_invasive: bool,
        /// When true, the debuggee is detached on session shutdown.
        detach_on_exit: bool,
    },
}

impl UserModeAttach {
    /// Stable string used as the `connection_options` in session info and as
    /// the deduplication key in the session registry.
    pub fn connection_key(&self) -> String {
        match self {
            UserModeAttach::Launch {
                command_line,
                only_this_process,
                detach_on_exit,
            } => {
                format!(
                    "user-launch:only_this_process={only_this_process};detach_on_exit={detach_on_exit};cmd={command_line}"
                )
            }
            UserModeAttach::AttachPid {
                pid,
                non_invasive,
                detach_on_exit,
            } => format!(
                "user-attach:pid={pid};non_invasive={non_invasive};detach_on_exit={detach_on_exit}"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebuggerExecutionState {
    pub raw_status: u32,
    pub status_name: String,
    pub running: bool,
    pub busy: bool,
    pub ready_for_commands: bool,
    pub requires_interrupt_before_command: bool,
    pub summary: String,
}

impl DebuggerExecutionState {
    pub fn from_raw(raw_status: u32) -> Self {
        let (status_name, running, busy, summary) = match raw_status {
            EXECUTION_STATUS_NO_CHANGE => (
                "no_change",
                false,
                false,
                "Debugger state is unchanged and commands can be issued.",
            ),
            EXECUTION_STATUS_GO => ("go", true, false, "The target is running."),
            EXECUTION_STATUS_GO_HANDLED => (
                "go_handled",
                true,
                false,
                "The target is running after a handled event.",
            ),
            EXECUTION_STATUS_GO_NOT_HANDLED => (
                "go_not_handled",
                true,
                false,
                "The target is running after an unhandled event.",
            ),
            EXECUTION_STATUS_STEP_OVER => (
                "step_over",
                true,
                false,
                "The target is running while step-over is in progress.",
            ),
            EXECUTION_STATUS_STEP_INTO => (
                "step_into",
                true,
                false,
                "The target is running while step-into is in progress.",
            ),
            EXECUTION_STATUS_BREAK => (
                "break",
                false,
                false,
                "The target is broken in and ready for debugger commands.",
            ),
            EXECUTION_STATUS_NO_DEBUGGEE => (
                "no_debuggee",
                false,
                true,
                "No debuggee is currently active yet. For a live kernel session this usually means dbgeng is still waiting for the target to reconnect.",
            ),
            EXECUTION_STATUS_STEP_BRANCH => (
                "step_branch",
                true,
                false,
                "The target is running while step-branch is in progress.",
            ),
            EXECUTION_STATUS_IGNORE_EVENT => (
                "ignore_event",
                false,
                true,
                "The debugger is processing an event and is not ready for commands.",
            ),
            EXECUTION_STATUS_RESTART_REQUESTED => (
                "restart_requested",
                false,
                true,
                "The debugger is restarting the target.",
            ),
            EXECUTION_STATUS_REVERSE_GO => (
                "reverse_go",
                true,
                false,
                "The target is running in reverse execution mode.",
            ),
            EXECUTION_STATUS_REVERSE_STEP_BRANCH => (
                "reverse_step_branch",
                true,
                false,
                "The target is reverse-stepping through a branch.",
            ),
            EXECUTION_STATUS_REVERSE_STEP_OVER => (
                "reverse_step_over",
                true,
                false,
                "The target is reverse step-over running.",
            ),
            EXECUTION_STATUS_REVERSE_STEP_INTO => (
                "reverse_step_into",
                true,
                false,
                "The target is reverse step-into running.",
            ),
            EXECUTION_STATUS_OUT_OF_SYNC => (
                "out_of_sync",
                false,
                true,
                "The debugger is out of sync and not ready for commands.",
            ),
            EXECUTION_STATUS_WAIT_INPUT => (
                "wait_input",
                false,
                true,
                "The debugger is waiting for input and is treated as busy.",
            ),
            EXECUTION_STATUS_TIMEOUT => (
                "timeout",
                false,
                true,
                "The debugger reported a timeout and is treated as busy.",
            ),
            _ => (
                "unknown",
                false,
                true,
                "The debugger returned an unknown execution status; interrupt before issuing commands.",
            ),
        };
        let ready_for_commands = !running && !busy;
        Self {
            raw_status,
            status_name: status_name.to_string(),
            running,
            busy,
            ready_for_commands,
            requires_interrupt_before_command: !ready_for_commands,
            summary: summary.to_string(),
        }
    }

    pub fn break_state() -> Self {
        Self::from_raw(EXECUTION_STATUS_BREAK)
    }

    pub fn running_state() -> Self {
        Self::from_raw(EXECUTION_STATUS_GO)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandExecutionResult {
    pub command: String,
    pub output: String,
    pub state_before: DebuggerExecutionState,
    pub state_after: DebuggerExecutionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutputEntry {
    pub seq: u64,
    pub command: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutputSnapshot {
    pub entries: Vec<OutputEntry>,
    pub history_start_cursor: u64,
    pub next_cursor: u64,
}

enum DispatcherRequest {
    Execute {
        command: String,
        response: oneshot::Sender<Result<CommandExecutionResult, ExecutionError>>,
    },
    QueryState {
        response: oneshot::Sender<Result<DebuggerExecutionState, ExecutionError>>,
    },
    Interrupt {
        response: oneshot::Sender<Result<DebuggerExecutionState, ExecutionError>>,
    },
    Resume {
        response: oneshot::Sender<Result<DebuggerExecutionState, ExecutionError>>,
    },
    GetOutput {
        cursor: Option<u64>,
        response: oneshot::Sender<Result<OutputSnapshot, ExecutionError>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), ExecutionError>>,
    },
}

const MAX_OUTPUT_HISTORY_ENTRIES: usize = 256;

#[derive(Default)]
struct OutputHistory {
    next_seq: u64,
    entries: Vec<OutputEntry>,
}

impl OutputHistory {
    fn append_command_output(&mut self, command: &str, text: &str) {
        if text.is_empty() {
            return;
        }

        let entry = OutputEntry {
            seq: self.next_seq,
            command: command.to_string(),
            text: text.to_string(),
        };
        self.next_seq += 1;
        self.entries.push(entry);

        let overflow = self
            .entries
            .len()
            .saturating_sub(MAX_OUTPUT_HISTORY_ENTRIES);
        if overflow > 0 {
            self.entries.drain(0..overflow);
        }
    }

    fn snapshot(&self, cursor: Option<u64>) -> OutputSnapshot {
        let history_start_cursor = self
            .entries
            .first()
            .map(|entry| entry.seq)
            .unwrap_or(self.next_seq);
        let cursor = cursor.unwrap_or(history_start_cursor);
        let entries = self
            .entries
            .iter()
            .filter(|entry| entry.seq >= cursor)
            .cloned()
            .collect();

        OutputSnapshot {
            entries,
            history_start_cursor,
            next_cursor: self.next_seq,
        }
    }
}

#[derive(Clone)]
pub struct CommandDispatcher {
    sender: tokio::sync::mpsc::UnboundedSender<DispatcherRequest>,
}

impl CommandDispatcher {
    pub fn spawn(mode: ExecutionMode) -> Result<Self, ExecutionError> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<DispatcherRequest>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), ExecutionError>>();

        thread::Builder::new()
            .name("windbg-mcp-dispatcher".to_string())
            .spawn(move || {
                let run = || -> Result<(), ExecutionError> {
                    let mut output_history = OutputHistory::default();
                    let mut executor = match build_executor(mode) {
                        Ok(executor) => {
                            let _ = ready_tx.send(Ok(()));
                            executor
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return Ok(());
                        }
                    };

                    loop {
                        match receiver.try_recv() {
                            Ok(request) => {
                                if handle_request(&mut *executor, &mut output_history, request) {
                                    break;
                                }
                                continue;
                            }
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                        }

                        if executor.wants_idle_event_pump() {
                            if let Err(error) = executor.pump_events_when_idle() {
                                tracing::warn!(?error, "dbgeng idle event pump failed");
                                thread::sleep(Duration::from_millis(100));
                            }
                            continue;
                        }

                        let Some(request) = receiver.blocking_recv() else {
                            break;
                        };
                        if handle_request(&mut *executor, &mut output_history, request) {
                            break;
                        }
                    }

                    Ok(())
                };

                match panic::catch_unwind(AssertUnwindSafe(run)) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!(error = %error, "dispatcher thread stopped with an error");
                    }
                    Err(payload) => {
                        let message = if let Some(text) = payload.downcast_ref::<&str>() {
                            format!("dispatcher thread panicked: {text}")
                        } else if let Some(text) = payload.downcast_ref::<String>() {
                            format!("dispatcher thread panicked: {text}")
                        } else {
                            "dispatcher thread panicked with a non-string payload".to_string()
                        };
                        tracing::error!(error = %message, "dispatcher thread panicked");
                    }
                }
            })
            .map_err(|error| ExecutionError::Startup(error.to_string()))?;

        ready_rx
            .recv()
            .map_err(|_| ExecutionError::WorkerStopped)??;

        Ok(Self { sender })
    }

    pub async fn execute(
        &self,
        command: impl Into<String>,
    ) -> Result<CommandExecutionResult, ExecutionError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(DispatcherRequest::Execute {
                command: command.into(),
                response: response_tx,
            })
            .map_err(|_| ExecutionError::WorkerStopped)?;

        response_rx
            .await
            .map_err(|_| ExecutionError::WorkerStopped)?
    }

    pub async fn query_state(&self) -> Result<DebuggerExecutionState, ExecutionError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(DispatcherRequest::QueryState {
                response: response_tx,
            })
            .map_err(|_| ExecutionError::WorkerStopped)?;

        response_rx
            .await
            .map_err(|_| ExecutionError::WorkerStopped)?
    }

    pub async fn interrupt(&self) -> Result<DebuggerExecutionState, ExecutionError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(DispatcherRequest::Interrupt {
                response: response_tx,
            })
            .map_err(|_| ExecutionError::WorkerStopped)?;

        response_rx
            .await
            .map_err(|_| ExecutionError::WorkerStopped)?
    }

    pub async fn resume(&self) -> Result<DebuggerExecutionState, ExecutionError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(DispatcherRequest::Resume {
                response: response_tx,
            })
            .map_err(|_| ExecutionError::WorkerStopped)?;

        response_rx
            .await
            .map_err(|_| ExecutionError::WorkerStopped)?
    }

    pub async fn shutdown(&self) -> Result<(), ExecutionError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(DispatcherRequest::Shutdown {
                response: response_tx,
            })
            .map_err(|_| ExecutionError::WorkerStopped)?;

        response_rx
            .await
            .map_err(|_| ExecutionError::WorkerStopped)?
    }

    pub async fn get_output(&self, cursor: Option<u64>) -> Result<OutputSnapshot, ExecutionError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(DispatcherRequest::GetOutput {
                cursor,
                response: response_tx,
            })
            .map_err(|_| ExecutionError::WorkerStopped)?;

        response_rx
            .await
            .map_err(|_| ExecutionError::WorkerStopped)?
    }
}

fn handle_request(
    executor: &mut dyn BlockingExecutor,
    output_history: &mut OutputHistory,
    request: DispatcherRequest,
) -> bool {
    match request {
        DispatcherRequest::Execute { command, response } => {
            let result = executor.execute(&command);
            if let Ok(execution) = &result {
                output_history.append_command_output(&execution.command, &execution.output);
            }
            let _ = response.send(result);
            false
        }
        DispatcherRequest::QueryState { response } => {
            let result = executor.query_state();
            let _ = response.send(result);
            false
        }
        DispatcherRequest::Interrupt { response } => {
            let result = executor.interrupt();
            let _ = response.send(result);
            false
        }
        DispatcherRequest::Resume { response } => {
            let result = executor.resume();
            let _ = response.send(result);
            false
        }
        DispatcherRequest::GetOutput { cursor, response } => {
            let result = Ok(output_history.snapshot(cursor));
            let _ = response.send(result);
            false
        }
        DispatcherRequest::Shutdown { response } => {
            let result = executor.shutdown();
            let _ = response.send(result);
            true
        }
    }
}

pub fn default_attach_timeout() -> Duration {
    DEFAULT_ATTACH_TIMEOUT
}

pub fn build_command(
    entry: &CatalogEntry,
    variant: Option<&str>,
    arguments: Option<&str>,
) -> Result<String, ExecutionError> {
    if !entry.supports_text_execution {
        return Err(ExecutionError::NonTextualCommand(entry.title.clone()));
    }

    let selected = match variant.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => entry
            .tokens
            .iter()
            .find(|token| token.eq_ignore_ascii_case(value))
            .map(String::as_str)
            .ok_or_else(|| ExecutionError::InvalidVariant {
                command: entry.title.clone(),
                variant: value.to_string(),
            })?,
        None => entry.primary_token(),
    };

    let trimmed_args = arguments.map(str::trim).filter(|value| !value.is_empty());
    Ok(match trimmed_args {
        Some(arguments) => format!("{selected} {arguments}"),
        None => selected.to_string(),
    })
}

trait BlockingExecutor {
    fn query_state(&mut self) -> Result<DebuggerExecutionState, ExecutionError>;

    fn execute_ready(&mut self, command: &str) -> Result<String, ExecutionError>;

    fn wants_idle_event_pump(&self) -> bool {
        false
    }

    fn pump_events_when_idle(&mut self) -> Result<(), ExecutionError> {
        Ok(())
    }

    fn interrupt(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
        Err(ExecutionError::Command(
            "interrupt is not supported for this execution mode".to_string(),
        ))
    }

    fn resume(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
        Err(ExecutionError::Command(
            "resume is not supported for this execution mode".to_string(),
        ))
    }

    fn shutdown(&mut self) -> Result<(), ExecutionError> {
        Ok(())
    }

    fn execute(&mut self, command: &str) -> Result<CommandExecutionResult, ExecutionError> {
        let state_before = self.query_state()?;
        if state_before.requires_interrupt_before_command {
            return Err(ExecutionError::Command(format!(
                "debugger is not ready for commands (status: {}). {} Query execution state first and call `windbg_interrupt_target` if you need to break in.",
                state_before.status_name, state_before.summary
            )));
        }
        let output = self.execute_ready(command)?;
        let state_after = self.query_state()?;

        Ok(CommandExecutionResult {
            command: command.to_string(),
            output,
            state_before,
            state_after,
        })
    }
}

fn build_executor(mode: ExecutionMode) -> Result<Box<dyn BlockingExecutor>, ExecutionError> {
    match mode {
        ExecutionMode::Mock { responses } => Ok(Box::new(MockExecutor {
            responses,
            state: DebuggerExecutionState::break_state(),
        })),
        ExecutionMode::KernelConnection {
            connect_options,
            startup_command,
            attach_timeout,
        } => {
            #[cfg(windows)]
            {
                Ok(Box::new(DbgEngExecutor::attach_kernel(
                    &connect_options,
                    startup_command.as_deref(),
                    attach_timeout,
                )?))
            }
            #[cfg(not(windows))]
            {
                let _ = (connect_options, startup_command, attach_timeout);
                Err(ExecutionError::WindowsOnly)
            }
        }
        ExecutionMode::UserModeProcess {
            attach,
            startup_command,
            attach_timeout,
        } => {
            #[cfg(windows)]
            {
                Ok(Box::new(DbgEngExecutor::attach_user_process(
                    attach,
                    startup_command.as_deref(),
                    attach_timeout,
                )?))
            }
            #[cfg(not(windows))]
            {
                let _ = (attach, startup_command, attach_timeout);
                Err(ExecutionError::WindowsOnly)
            }
        }
    }
}

struct MockExecutor {
    responses: HashMap<String, String>,
    state: DebuggerExecutionState,
}

impl BlockingExecutor for MockExecutor {
    fn query_state(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
        Ok(self.state.clone())
    }

    fn execute_ready(&mut self, command: &str) -> Result<String, ExecutionError> {
        Ok(self
            .responses
            .get(command)
            .cloned()
            .unwrap_or_else(|| format!("mock-executed: {command}")))
    }

    fn interrupt(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
        self.state = DebuggerExecutionState::break_state();
        Ok(self.state.clone())
    }

    fn resume(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
        self.state = DebuggerExecutionState::running_state();
        Ok(self.state.clone())
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::{
        env,
        ffi::c_void,
        fs, mem,
        panic::{self, AssertUnwindSafe},
        path::{Path, PathBuf},
        process::Command,
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use windows::{
        Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_ATTACH_DEFAULT, DEBUG_ATTACH_KERNEL_CONNECTION, DEBUG_ATTACH_NONINVASIVE,
            DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND, DEBUG_CONNECT_SESSION_NO_ANNOUNCE,
            DEBUG_CONNECT_SESSION_NO_VERSION, DEBUG_ENGOPT_INITIAL_BREAK, DEBUG_EXECUTE_DEFAULT,
            DEBUG_INTERRUPT_ACTIVE, DEBUG_INTERRUPT_EXIT, DEBUG_INTERRUPT_PASSIVE,
            DEBUG_OUTCTL_THIS_CLIENT, DEBUG_PROCESS_DETACH_ON_EXIT,
            DEBUG_PROCESS_ONLY_THIS_PROCESS, DEBUG_STATUS_GO_HANDLED, IDebugClient, IDebugClient5,
            IDebugControl, IDebugDataSpaces, IDebugOutputCallbacks, IDebugOutputCallbacks_Impl,
            IDebugRegisters, IDebugSymbols3, IDebugSystemObjects3,
        },
        Win32::System::LibraryLoader::{
            GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW, SetDllDirectoryW,
        },
        core::{
            Error as WinError, HRESULT, HSTRING, Interface, PCSTR, Result as WinResult, implement,
        },
    };

    use super::{
        BlockingExecutor, CString, DebuggerExecutionState, ExecutionError, INTERRUPT_WAIT_TIMEOUT,
        UserModeAttach,
    };
    use crate::headless::{HeadlessEventCallbacks, HeadlessEventControl};

    const POLL_INTERVAL: Duration = Duration::from_millis(250);
    const COMMAND_READY_RETRY_DELAY: Duration = Duration::from_millis(100);
    const COMMAND_READY_RETRY_ATTEMPTS: usize = 8;
    const HOST_COMMAND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);
    const HRESULT_E_PENDING: i32 = 0x8000000A_u32 as i32;
    const HRESULT_E_NOTIMPL: i32 = 0x80004001_u32 as i32;
    const HRESULT_COMMAND_WINDOW_NOT_SETTLED: i32 = 0x80040205_u32 as i32;
    const HRESULT_UNEXPECTED: HRESULT = HRESULT(0x8000FFFF_u32 as i32);

    type DebugCreateFn =
        unsafe extern "system" fn(*const windows::core::GUID, *mut *mut c_void) -> HRESULT;

    static DBGENG_MODULE: OnceLock<Result<usize, String>> = OnceLock::new();

    fn debug_create<T>() -> WinResult<T>
    where
        T: Interface,
    {
        let module = dbgeng_module()?;
        let proc_name = CString::new("DebugCreate").expect("static proc name has no NUL");
        let proc = unsafe { GetProcAddress(module, PCSTR(proc_name.as_ptr() as _)) }
            .ok_or_else(WinError::from_thread)?;
        let debug_create: DebugCreateFn = unsafe { mem::transmute(proc) };
        let mut result = core::ptr::null_mut();

        unsafe {
            debug_create(&T::IID, &mut result).and_then(|| windows_core::Type::from_abi(result))
        }
    }

    fn dbgeng_module() -> WinResult<windows::Win32::Foundation::HMODULE> {
        match DBGENG_MODULE.get_or_init(load_dbgeng_module) {
            Ok(handle) => Ok(windows::Win32::Foundation::HMODULE(*handle as *mut c_void)),
            Err(message) => Err(WinError::new(HRESULT_UNEXPECTED, message.as_str())),
        }
    }

    fn load_dbgeng_module() -> Result<usize, String> {
        let path = preferred_dbgeng_path();
        if let Some(path) = path.as_ref() {
            configure_dbgeng_dll_search_path(path);
            tracing::debug!(
                path = %path.display(),
                "loading dbgeng from the preferred debugger installation"
            );
            let path = HSTRING::from(path.display().to_string());
            let module = unsafe { LoadLibraryExW(&path, None, LOAD_WITH_ALTERED_SEARCH_PATH) }
                .map_err(|error| error.to_string())?;
            return Ok(module.0 as usize);
        }

        tracing::debug!(
            "no preferred WinDbg dbgeng.dll was discovered; falling back to the system loader"
        );
        let path = system_dbgeng_path().unwrap_or_else(|| PathBuf::from("dbgeng.dll"));
        let module = unsafe {
            LoadLibraryExW(
                &HSTRING::from(path.display().to_string()),
                None,
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        }
        .map_err(|error| error.to_string())?;
        configure_default_debugger_runtime_search_path();
        Ok(module.0 as usize)
    }

    fn system_dbgeng_path() -> Option<PathBuf> {
        let system_root = env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let path = system_root.join("System32\\dbgeng.dll");
        path.is_file().then_some(path)
    }

    fn preferred_dbgeng_path() -> Option<PathBuf> {
        if let Some(path) = env::var_os("WINDBG_MCP_DBGENG_PATH").map(PathBuf::from)
            && path.is_file()
        {
            return Some(path);
        }

        if env_flag_enabled("WINDBG_MCP_USE_PREVIEW_DBGENG")
            || env::var_os("WINDBG_MCP_DEBUGGER_ROOT").is_some()
        {
            for root in candidate_debugger_runtime_roots() {
                let path = root.join("amd64\\dbgeng.dll");
                if path.is_file() {
                    return Some(path);
                }
            }
        }

        None
    }

    fn env_flag_enabled(name: &str) -> bool {
        env::var(name)
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    }

    fn configure_dbgeng_dll_search_path(dbgeng_path: &Path) {
        let Some(debugger_dir) = dbgeng_path.parent() else {
            return;
        };
        let debugger_dir = HSTRING::from(debugger_dir.display().to_string());
        if let Err(error) = unsafe { SetDllDirectoryW(&debugger_dir) } {
            tracing::debug!(
                ?error,
                "failed to add the debugger directory to the DLL search path"
            );
        }
    }

    fn configure_default_debugger_runtime_search_path() {
        for root in candidate_debugger_runtime_roots() {
            let debugger_dir = root.join("amd64");
            if !debugger_dir.is_dir() {
                continue;
            }

            let debugger_dir = HSTRING::from(debugger_dir.display().to_string());
            if let Err(error) = unsafe { SetDllDirectoryW(&debugger_dir) } {
                tracing::debug!(
                    ?error,
                    "failed to add the default debugger runtime to the DLL search path"
                );
            }
            return;
        }
    }

    enum HostCommand {
        AwaitCommandReady {
            response: mpsc::Sender<Result<DebuggerExecutionState, ExecutionError>>,
        },
        ExecuteCommand {
            command: String,
            response: mpsc::Sender<Result<String, ExecutionError>>,
        },
        Resume {
            response: mpsc::Sender<Result<DebuggerExecutionState, ExecutionError>>,
        },
        Stop,
    }

    #[derive(Clone)]
    struct CrossThreadInterruptControl(IDebugControl);

    unsafe impl Send for CrossThreadInterruptControl {}

    unsafe impl Sync for CrossThreadInterruptControl {}

    impl CrossThreadInterruptControl {
        fn request_active_interrupt(&self) {
            tracing::debug!("requesting active interrupt on kernel host control");
            let _ = unsafe { self.0.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) };
        }

        fn request_exit_wait(&self) {
            tracing::debug!("requesting host wait-loop exit");
            let _ = unsafe { self.0.SetInterrupt(DEBUG_INTERRUPT_EXIT) };
        }

        fn query_state(&self) -> Result<DebuggerExecutionState, ExecutionError> {
            let raw_status = unsafe { self.0.GetExecutionStatus() }
                .map_err(|error| ExecutionError::Command(error.to_string()))?;
            Ok(DebuggerExecutionState::from_raw(raw_status))
        }
    }

    /// What kind of dbgeng session the host should establish.
    #[derive(Clone)]
    enum HostAttachKind {
        /// Kernel debugging via `AttachKernelWide` (KDNET, COM, etc.).
        Kernel { connect_options: String },
        /// User-mode debugging via `CreateProcessAndAttachWide` /
        /// `AttachProcess`.
        UserMode {
            attach: UserModeAttach,
            // Pre-computed attach flag bits (DEBUG_ATTACH_*) for `AttachPid`
            // or process create flags (DEBUG_PROCESS_*) for `Launch`.
            attach_flags: u32,
            create_flags: u32,
        },
    }

    impl HostAttachKind {
        fn label(&self) -> &'static str {
            match self {
                HostAttachKind::Kernel { .. } => "kernel",
                HostAttachKind::UserMode { .. } => "user",
            }
        }

        fn description(&self) -> String {
            match self {
                HostAttachKind::Kernel { connect_options } => {
                    format!("kernel:{connect_options}")
                }
                HostAttachKind::UserMode { attach, .. } => attach.connection_key(),
            }
        }
    }

    fn build_user_mode_attach_kind(attach: &UserModeAttach) -> HostAttachKind {
        match attach {
            UserModeAttach::Launch {
                only_this_process,
                detach_on_exit,
                ..
            } => {
                let mut create_flags: u32 = 0;
                if *only_this_process {
                    create_flags |= DEBUG_PROCESS_ONLY_THIS_PROCESS;
                }
                if *detach_on_exit {
                    create_flags |= DEBUG_PROCESS_DETACH_ON_EXIT;
                }
                HostAttachKind::UserMode {
                    attach: attach.clone(),
                    attach_flags: DEBUG_ATTACH_DEFAULT,
                    create_flags,
                }
            }
            UserModeAttach::AttachPid {
                non_invasive,
                detach_on_exit,
                ..
            } => {
                let attach_flags = if *non_invasive {
                    DEBUG_ATTACH_NONINVASIVE | DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND
                } else {
                    DEBUG_ATTACH_DEFAULT
                };
                let create_flags = if *detach_on_exit {
                    DEBUG_PROCESS_DETACH_ON_EXIT
                } else {
                    0
                };
                HostAttachKind::UserMode {
                    attach: attach.clone(),
                    attach_flags,
                    create_flags,
                }
            }
        }
    }

    struct KernelSessionHost {
        stop_requested: Arc<AtomicBool>,
        interrupt_control: CrossThreadInterruptControl,
        command_tx: mpsc::Sender<HostCommand>,
        terminal_error: Arc<Mutex<Option<String>>>,
        kind_label: &'static str,
        _join_handle: thread::JoinHandle<()>,
    }

    enum CommandAttemptError {
        Retryable(String),
        Fatal(ExecutionError),
    }

    impl KernelSessionHost {
        fn start(connect_options: &str) -> Result<Self, ExecutionError> {
            Self::start_with_kind(HostAttachKind::Kernel {
                connect_options: connect_options.to_string(),
            })
        }

        fn start_user_mode(attach: &UserModeAttach) -> Result<Self, ExecutionError> {
            Self::start_with_kind(build_user_mode_attach_kind(attach))
        }

        fn start_with_kind(attach_kind: HostAttachKind) -> Result<Self, ExecutionError> {
            let kind_label = attach_kind.label();
            tracing::debug!(
                kind = kind_label,
                target = %attach_kind.description(),
                "spawning headless dbgeng host"
            );
            let stop_requested = Arc::new(AtomicBool::new(false));
            let stop_for_thread = stop_requested.clone();
            let (ready_tx, ready_rx) =
                mpsc::channel::<Result<CrossThreadInterruptControl, ExecutionError>>();
            let (command_tx, command_rx) = mpsc::channel::<HostCommand>();
            let event_control = Arc::new(HeadlessEventControl::default());
            let event_control_for_thread = event_control.clone();
            let terminal_error = Arc::new(Mutex::new(None));
            let terminal_error_for_thread = terminal_error.clone();
            let attach_kind_for_thread = attach_kind;

            let join_handle = thread::Builder::new()
                .name(format!("windbg-mcp-{kind_label}-host"))
                .spawn(move || {
                    let startup = || -> Result<(), ExecutionError> {
                        let client5 = debug_create::<IDebugClient5>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        let initial_control = client5
                            .cast::<IDebugControl>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;

                        unsafe {
                            initial_control
                                .AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK)
                                .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        }
                        tracing::debug!(
                            kind = kind_label,
                            "session host enabled DEBUG_ENGOPT_INITIAL_BREAK"
                        );

                        match &attach_kind_for_thread {
                            HostAttachKind::Kernel { connect_options } => {
                                let options = HSTRING::from(connect_options.as_str());
                                unsafe {
                                    client5
                                        .AttachKernelWide(
                                            DEBUG_ATTACH_KERNEL_CONNECTION,
                                            &options,
                                        )
                                        .map_err(|error| {
                                            ExecutionError::Startup(error.to_string())
                                        })?;
                                }
                                tracing::info!(
                                    options = %options,
                                    "kernel host attached transport"
                                );
                            }
                            HostAttachKind::UserMode {
                                attach,
                                attach_flags,
                                create_flags,
                            } => match attach {
                                UserModeAttach::Launch { command_line, .. } => {
                                    let command_line_w = HSTRING::from(command_line.as_str());
                                    tracing::info!(
                                        command_line = %command_line,
                                        create_flags = format!("0x{create_flags:x}"),
                                        attach_flags = format!("0x{attach_flags:x}"),
                                        "user host spawning debuggee process"
                                    );
                                    unsafe {
                                        client5
                                            .CreateProcessAndAttachWide(
                                                0,
                                                &command_line_w,
                                                *create_flags,
                                                0,
                                                *attach_flags,
                                            )
                                            .map_err(|error| {
                                                ExecutionError::Startup(format!(
                                                    "failed to launch user-mode debuggee `{command_line}`: {error}"
                                                ))
                                            })?;
                                    }
                                }
                                UserModeAttach::AttachPid { pid, .. } => {
                                    if *create_flags != 0 {
                                        unsafe {
                                            client5
                                                .SetProcessOptions(*create_flags)
                                                .map_err(|error| ExecutionError::Startup(format!(
                                                    "failed to set process options 0x{create_flags:x}: {error}"
                                                )))?;
                                        }
                                    }
                                    tracing::info!(
                                        pid = *pid,
                                        attach_flags = format!("0x{attach_flags:x}"),
                                        "user host attaching to existing process"
                                    );
                                    unsafe {
                                        client5
                                            .AttachProcess(0, *pid, *attach_flags)
                                            .map_err(|error| ExecutionError::Startup(format!(
                                                "failed to attach to PID {pid}: {error}"
                                            )))?;
                                    }
                                }
                            },
                        }

                        let client = client5
                            .cast::<IDebugClient>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        let control = client
                            .cast::<IDebugControl>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        let debug_symbols = client
                            .cast::<windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSymbols>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        let debug_data_spaces = client
                            .cast::<IDebugDataSpaces>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        let debug_registers = client
                            .cast::<IDebugRegisters>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        let debug_symbols3 = client
                            .cast::<windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSymbols3>()
                            .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        let event_callbacks = HeadlessEventCallbacks::new(
                            event_control_for_thread.clone(),
                            control.clone(),
                            debug_data_spaces.clone(),
                            debug_registers.clone(),
                            debug_symbols.clone(),
                            debug_symbols3,
                        );
                        let event_callbacks: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugEventCallbacks =
                            event_callbacks.into();

                        unsafe {
                            client
                                .SetEventCallbacks(&event_callbacks)
                                .map_err(|error| ExecutionError::Startup(error.to_string()))?;
                        }
                        tracing::debug!("kernel host registered event callbacks");

                        let _ = ready_tx.send(Ok(CrossThreadInterruptControl(control.clone())));
                        let mut cleared_initial_break = false;
                        let mut configured_extensions = false;
                        let mut wait_for_event_supported = true;

                        while !stop_for_thread.load(Ordering::SeqCst) {
                            let state = current_state(&control)?;
                            if state.ready_for_commands {
                                if event_control_for_thread.take_suppressed_breakpoint_seen() {
                                    tracing::debug!(
                                        "kernel host observed a suppressed synthetic breakpoint in ready state; resuming target"
                                    );
                                    unsafe {
                                        control.SetExecutionStatus(DEBUG_STATUS_GO_HANDLED)
                                    }
                                    .map_err(|error| {
                                        ExecutionError::Command(error.to_string())
                                    })?;
                                    continue;
                                }
                                if !wait_for_event_supported
                                    && event_control_for_thread
                                        .take_pending_breakpoint_suppression()
                                {
                                    tracing::debug!(
                                        "kernel host is polling and found a pending synthetic breakpoint suppression; resuming target"
                                    );
                                    unsafe {
                                        control.SetExecutionStatus(DEBUG_STATUS_GO_HANDLED)
                                    }
                                    .map_err(|error| {
                                        ExecutionError::Command(error.to_string())
                                    })?;
                                    continue;
                                }
                                if !cleared_initial_break {
                                    if let Err(error) = unsafe {
                                        control.RemoveEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK)
                                    } {
                                        tracing::warn!(
                                            ?error,
                                            "kernel host failed to clear DEBUG_ENGOPT_INITIAL_BREAK"
                                        );
                                    } else {
                                        tracing::debug!(
                                            "kernel host cleared DEBUG_ENGOPT_INITIAL_BREAK after first break"
                                        );
                                    }
                                    cleared_initial_break = true;
                                }
                                if !configured_extensions {
                                    if let Err(error) =
                                        configure_standard_debugger_extensions(&client, &control)
                                    {
                                        tracing::warn!(
                                            error = %error,
                                            "kernel host failed to configure debugger extension paths"
                                        );
                                    }
                                    configured_extensions = true;
                                }
                                match command_rx.recv_timeout(POLL_INTERVAL) {
                                    Ok(HostCommand::AwaitCommandReady { response }) => {
                                        let _ = response.send(current_state(&control));
                                    }
                                    Ok(HostCommand::Resume { response }) => {
                                        event_control_for_thread.suppress_one_breakpoint();
                                        let result = unsafe {
                                            control.SetExecutionStatus(DEBUG_STATUS_GO_HANDLED)
                                        }
                                        .map_err(|error| ExecutionError::Command(error.to_string()))
                                        .and_then(|_| current_state(&control));
                                        let _ = response.send(result);
                                    }
                                    Ok(HostCommand::ExecuteCommand { command, response }) => {
                                        let result = execute_host_command_with_retry(
                                            &client,
                                            &control,
                                            &command,
                                        );
                                        if result.is_ok() {
                                            event_control_for_thread.refresh_module_load_watch(
                                                &command,
                                                &control,
                                                &debug_symbols,
                                            );
                                        }
                                        let _ = response.send(result);
                                    }
                                    Ok(HostCommand::Stop) => break,
                                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                                }
                                continue;
                            }

                            if !wait_for_event_supported {
                                tracing::trace!(
                                    status = state.raw_status,
                                    name = %state.status_name,
                                    "kernel host is polling because WaitForEvent is unavailable"
                                );
                                if event_control_for_thread
                                    .has_pending_module_load_watch()
                                    && event_control_for_thread.poll_module_load_watch(&debug_symbols)
                                {
                                    tracing::debug!(
                                        "module load watch matched while polling; requesting passive interrupt"
                                    );
                                    let _ =
                                        unsafe { control.SetInterrupt(DEBUG_INTERRUPT_PASSIVE) };
                                }
                                thread::sleep(POLL_INTERVAL);
                                continue;
                            }

                            let wait_timeout = u32::MAX;
                            tracing::trace!(wait_timeout, "kernel host entering WaitForEvent");
                            let result = unsafe { control.WaitForEvent(0, wait_timeout) };
                            match result {
                                Ok(()) => {
                                    let status = unsafe { control.GetExecutionStatus() };
                                    tracing::debug!(?status, "kernel host WaitForEvent returned");
                                    if event_control_for_thread.take_suppressed_breakpoint_seen() {
                                        tracing::debug!(
                                            "kernel host consumed a synthetic breakpoint and will explicitly resume target"
                                        );
                                        unsafe { control.SetExecutionStatus(DEBUG_STATUS_GO_HANDLED) }
                                            .map_err(|error| {
                                                ExecutionError::Command(error.to_string())
                                            })?;
                                        continue;
                                    }
                                }
                                Err(error) if error.code().0 == HRESULT_E_PENDING => {
                                    tracing::trace!("kernel host WaitForEvent returned E_PENDING");
                                }
                                Err(error) if error.code().0 == HRESULT_E_NOTIMPL => {
                                    wait_for_event_supported = false;
                                    tracing::warn!(
                                        "kernel host WaitForEvent is not implemented for this session state; falling back to polling"
                                    );
                                }
                                Err(error) => {
                                    tracing::warn!(?error, "kernel host WaitForEvent returned an error");
                                    break;
                                }
                            }
                        }

                        Ok(())
                    };

                    let startup_result = panic::catch_unwind(AssertUnwindSafe(startup));
                    match startup_result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            let message = error.to_string();
                            tracing::error!(error = %message, "kernel host thread stopped");
                            if let Ok(mut slot) = terminal_error_for_thread.lock() {
                                *slot = Some(message.clone());
                            }
                            let _ = ready_tx.send(Err(error));
                        }
                        Err(payload) => {
                            let message = if let Some(text) = payload.downcast_ref::<&str>() {
                                format!("kernel host thread panicked: {text}")
                            } else if let Some(text) = payload.downcast_ref::<String>() {
                                format!("kernel host thread panicked: {text}")
                            } else {
                                "kernel host thread panicked with a non-string payload"
                                    .to_string()
                            };
                            tracing::error!(error = %message, "kernel host thread panicked");
                            if let Ok(mut slot) = terminal_error_for_thread.lock() {
                                *slot = Some(message.clone());
                            }
                            let _ = ready_tx.send(Err(ExecutionError::Command(message)));
                        }
                    }
                })
                .map_err(|error| ExecutionError::Startup(error.to_string()))?;

            let interrupt_control = ready_rx
                .recv()
                .map_err(|_| ExecutionError::WorkerStopped)??;

            Ok(Self {
                stop_requested,
                interrupt_control,
                command_tx,
                terminal_error,
                kind_label,
                _join_handle: join_handle,
            })
        }

        fn kind_label(&self) -> &'static str {
            self.kind_label
        }

        fn worker_stopped_error(&self) -> ExecutionError {
            if let Ok(slot) = self.terminal_error.lock()
                && let Some(message) = slot.clone()
            {
                return ExecutionError::Command(message);
            }
            ExecutionError::WorkerStopped
        }

        fn request_stop(&self) {
            self.stop_requested.store(true, Ordering::SeqCst);
            let _ = self.command_tx.send(HostCommand::Stop);
            self.interrupt_control.request_exit_wait();
        }

        fn request_active_interrupt(&self) {
            self.interrupt_control.request_active_interrupt();
        }

        fn query_state(&self) -> Result<DebuggerExecutionState, ExecutionError> {
            self.interrupt_control.query_state()
        }

        fn resume_target(&self) -> Result<DebuggerExecutionState, ExecutionError> {
            let (response_tx, response_rx) =
                mpsc::channel::<Result<DebuggerExecutionState, ExecutionError>>();
            self.command_tx
                .send(HostCommand::Resume {
                    response: response_tx,
                })
                .map_err(|_| self.worker_stopped_error())?;
            response_rx
                .recv_timeout(INTERRUPT_WAIT_TIMEOUT)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => ExecutionError::Command(
                        "timed out waiting for the kernel host to resume the target".to_string(),
                    ),
                    mpsc::RecvTimeoutError::Disconnected => self.worker_stopped_error(),
                })?
        }

        fn await_command_ready(&self) -> Result<DebuggerExecutionState, ExecutionError> {
            let (response_tx, response_rx) =
                mpsc::channel::<Result<DebuggerExecutionState, ExecutionError>>();
            self.command_tx
                .send(HostCommand::AwaitCommandReady {
                    response: response_tx,
                })
                .map_err(|_| self.worker_stopped_error())?;
            response_rx
                .recv_timeout(INTERRUPT_WAIT_TIMEOUT)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => ExecutionError::Command(
                        "timed out waiting for the kernel host to enter a stable command-ready state"
                            .to_string(),
                    ),
                    mpsc::RecvTimeoutError::Disconnected => self.worker_stopped_error(),
                })?
        }

        fn execute_command(&self, command: &str) -> Result<String, ExecutionError> {
            let (response_tx, response_rx) = mpsc::channel::<Result<String, ExecutionError>>();
            self.command_tx
                .send(HostCommand::ExecuteCommand {
                    command: command.to_string(),
                    response: response_tx,
                })
                .map_err(|_| self.worker_stopped_error())?;
            response_rx
                .recv_timeout(HOST_COMMAND_RESPONSE_TIMEOUT)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => ExecutionError::Command(format!(
                        "timed out after {} seconds waiting for the kernel host to execute `{}`",
                        HOST_COMMAND_RESPONSE_TIMEOUT.as_secs(),
                        command
                    )),
                    mpsc::RecvTimeoutError::Disconnected => self.worker_stopped_error(),
                })?
        }
    }

    impl Drop for KernelSessionHost {
        fn drop(&mut self) {
            self.request_stop();
        }
    }

    #[implement(IDebugOutputCallbacks)]
    struct OutputCollector {
        buffer: Arc<Mutex<String>>,
    }

    impl OutputCollector {
        fn new(buffer: Arc<Mutex<String>>) -> Self {
            Self { buffer }
        }
    }

    impl IDebugOutputCallbacks_Impl for OutputCollector_Impl {
        fn Output(&self, _mask: u32, text: &PCSTR) -> WinResult<()> {
            if !text.is_null() {
                let fragment = unsafe { text.to_string() }.unwrap_or_default();
                self.buffer
                    .lock()
                    .expect("buffer lock poisoned")
                    .push_str(&fragment);
            }
            Ok(())
        }
    }

    fn try_execute_host_command_once(
        client: &IDebugClient,
        control: &IDebugControl,
        command: &str,
    ) -> Result<String, CommandAttemptError> {
        let captured = Arc::new(Mutex::new(String::new()));
        let callback: IDebugOutputCallbacks = OutputCollector::new(captured.clone()).into();
        let command = CString::new(command)
            .map_err(|_| CommandAttemptError::Fatal(ExecutionError::InvalidCString))?;
        unsafe {
            client.SetOutputCallbacks(&callback).map_err(|error| {
                CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
            })?;
            control
                .Execute(
                    DEBUG_OUTCTL_THIS_CLIENT,
                    PCSTR(command.as_ptr() as _),
                    DEBUG_EXECUTE_DEFAULT,
                )
                .map_err(|error| {
                    if is_transient_command_error(&error) {
                        CommandAttemptError::Retryable(error.to_string())
                    } else {
                        CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
                    }
                })?;
            client.FlushCallbacks().map_err(|error| {
                CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
            })?;
        }
        Ok(captured.lock().expect("buffer lock poisoned").clone())
    }

    fn execute_host_command_with_retry(
        client: &IDebugClient,
        control: &IDebugControl,
        command: &str,
    ) -> Result<String, ExecutionError> {
        let mut last_retryable_reason = None;
        let resolved_command = resolve_headless_extension_command(command);
        let actual_command = resolved_command
            .as_ref()
            .map(|resolved| resolved.actual.as_str())
            .unwrap_or(command);

        for attempt in 0..COMMAND_READY_RETRY_ATTEMPTS {
            sync_host_command_scope(client);

            match try_execute_host_command_once(client, control, actual_command) {
                Ok(output) => {
                    return Ok(render_resolved_command_output(
                        resolved_command.as_ref(),
                        output,
                    ));
                }
                Err(CommandAttemptError::Retryable(reason))
                    if attempt + 1 < COMMAND_READY_RETRY_ATTEMPTS =>
                {
                    tracing::debug!(
                        attempt = attempt + 1,
                        total_attempts = COMMAND_READY_RETRY_ATTEMPTS,
                        reason = %reason,
                        command = %actual_command,
                        "host command did not settle yet; retrying"
                    );
                    last_retryable_reason = Some(reason);
                    thread::sleep(COMMAND_READY_RETRY_DELAY);
                }
                Err(CommandAttemptError::Retryable(reason)) => {
                    if let Some(fallback) =
                        try_render_thread_command_fallback(client, command, &reason)
                    {
                        return fallback;
                    }
                    return Err(ExecutionError::Command(format!(
                        "kernel host command did not settle after {} attempts while running `{}`: {}",
                        COMMAND_READY_RETRY_ATTEMPTS, actual_command, reason
                    )));
                }
                Err(CommandAttemptError::Fatal(error)) => return Err(error),
            }
        }

        Err(ExecutionError::Command(format!(
            "kernel host command window never stabilized for `{}`. Last retryable reason: {}",
            actual_command,
            last_retryable_reason.unwrap_or_else(|| "unknown".to_string())
        )))
    }

    #[derive(Debug)]
    struct ResolvedDebuggerCommand {
        actual: String,
        note: String,
    }

    fn resolve_headless_extension_command(command: &str) -> Option<ResolvedDebuggerCommand> {
        let trimmed = command.trim();
        let mut parts = trimmed.split_whitespace();
        let verb = parts.next()?;
        if !verb.eq_ignore_ascii_case(".load") {
            return None;
        }

        let requested = parts.next()?;
        if parts.next().is_some() {
            return None;
        }

        let requested = requested.trim_matches('"').trim_matches('\'');
        let normalized = requested
            .strip_suffix(".dll")
            .unwrap_or(requested)
            .to_ascii_lowercase();
        if !matches!(
            normalized.as_str(),
            "kdexts" | "ext" | "kext" | "ntsdexts" | "wdfkd"
        ) {
            return None;
        }

        let dll_name = format!("{normalized}.dll");
        let path = find_debugger_extension_dll(&dll_name)?;
        Some(ResolvedDebuggerCommand {
            actual: format!(".load {}", quote_debugger_load_path(&path)),
            note: format!(
                "Resolved `{}` to `{}` for this headless session.",
                trimmed,
                path.display()
            ),
        })
    }

    fn render_resolved_command_output(
        resolved: Option<&ResolvedDebuggerCommand>,
        output: String,
    ) -> String {
        let Some(resolved) = resolved else {
            return output;
        };

        let mut rendered = String::new();
        rendered.push_str(&resolved.note);
        rendered.push('\n');
        rendered.push_str(&output);
        rendered
    }

    fn configure_standard_debugger_extensions(
        client: &IDebugClient,
        control: &IDebugControl,
    ) -> Result<(), ExecutionError> {
        let dirs = discover_debugger_extension_dirs();
        if dirs.is_empty() {
            tracing::warn!(
                "no WinDbg extension directories were discovered; extension commands may require manual .extpath setup"
            );
            return Ok(());
        }

        let extpath = dirs
            .iter()
            .map(|dir| dir.display().to_string())
            .collect::<Vec<_>>()
            .join(";");
        let command = format!(".extpath+ {}", quote_debugger_path_text(&extpath));
        let output = execute_host_command_with_retry(client, control, &command)?;
        tracing::debug!(
            directories = ?dirs,
            output = %output,
            "configured debugger extension search path"
        );

        for dll_name in ["kdexts.dll", "ext.dll", "kext.dll"] {
            if let Some(path) = find_debugger_extension_dll_in_dirs(&dirs, dll_name) {
                if let Err(error) = add_debugger_extension(control, &path) {
                    tracing::debug!(
                        dll = dll_name,
                        path = %path.display(),
                        ?error,
                        "standard debugger extension could not be preloaded"
                    );
                }
            }
        }

        Ok(())
    }

    fn add_debugger_extension(control: &IDebugControl, path: &Path) -> Result<u64, WinError> {
        let path = CString::new(path.display().to_string()).map_err(|_| {
            WinError::new(
                windows::core::HRESULT(0x80070057_u32 as i32),
                "debugger extension path contains an interior NUL",
            )
        })?;
        let path = PCSTR(path.as_ptr() as _);

        if let Ok(handle) = unsafe { control.GetExtensionByPath(path) } {
            return Ok(handle);
        }

        unsafe { control.AddExtension(path, 0) }
    }

    fn find_debugger_extension_dll(dll_name: &str) -> Option<PathBuf> {
        find_debugger_extension_dll_in_dirs(&discover_debugger_extension_dirs(), dll_name)
    }

    fn find_debugger_extension_dll_in_dirs(dirs: &[PathBuf], dll_name: &str) -> Option<PathBuf> {
        dirs.iter()
            .map(|dir| dir.join(dll_name))
            .find(|path| path.is_file())
    }

    fn discover_debugger_extension_dirs() -> Vec<PathBuf> {
        let mut dirs = Vec::new();

        if let Ok(value) = env::var("_NT_DEBUGGER_EXTENSION_PATH") {
            for path in env::split_paths(&value) {
                push_existing_dir(&mut dirs, path);
            }
        }

        for root in candidate_debugger_runtime_roots() {
            for relative in ["amd64\\winxp", "amd64\\winext", "amd64"] {
                push_existing_dir(&mut dirs, root.join(relative));
            }
        }

        for root in candidate_windows_kits_debugger_roots() {
            for relative in ["winxp", "winext", ""] {
                push_existing_dir(&mut dirs, root.join(relative));
            }
        }

        dirs
    }

    fn candidate_debugger_runtime_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();

        if let Some(root) = env::var_os("WINDBG_MCP_DEBUGGER_ROOT").map(PathBuf::from) {
            push_existing_dir(&mut roots, root);
        }

        for package_root in candidate_windbg_package_roots() {
            if let Some(cache_root) = materialize_windbg_runtime_cache(&package_root) {
                push_existing_dir(&mut roots, cache_root);
            } else {
                push_existing_dir(&mut roots, package_root);
            }
        }

        roots
    }

    fn candidate_windbg_package_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        let Some(program_files) = env::var_os("ProgramFiles").map(PathBuf::from) else {
            return roots;
        };
        let windows_apps = program_files.join("WindowsApps");
        let mut packages = fs::read_dir(windows_apps)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.filter_map(Result::ok))
            .filter_map(|entry| {
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                if file_name.starts_with("Microsoft.WinDbg_")
                    && file_name.contains("_x64__")
                    && entry.path().is_dir()
                {
                    Some(entry.path())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if let Some(path) = query_windbg_appx_install_location() {
            packages.push(path);
        }
        packages.sort_by(|left, right| right.cmp(left));
        for package in packages {
            push_existing_dir(&mut roots, package);
        }
        roots
    }

    fn materialize_windbg_runtime_cache(package_root: &Path) -> Option<PathBuf> {
        let package_name = package_root.file_name()?.to_string_lossy();
        let local_app_data = env::var_os("LOCALAPPDATA").map(PathBuf::from)?;
        let cache_root = local_app_data
            .join("windbg-mcp-rs")
            .join("dbgeng-cache")
            .join(package_name.as_ref());

        for relative in ["amd64", "amd64\\winext", "amd64\\winxp"] {
            let source = package_root.join(relative);
            if let Err(error) = copy_runtime_dir_files(&source, &cache_root.join(relative)) {
                tracing::debug!(
                    source = %source.display(),
                    cache = %cache_root.display(),
                    ?error,
                    "failed to copy WinDbg runtime files into the local cache"
                );
                return None;
            }
        }

        if cache_root.join("amd64\\dbgeng.dll").is_file() {
            Some(cache_root)
        } else {
            None
        }
    }

    fn copy_runtime_dir_files(source: &Path, destination: &Path) -> std::io::Result<()> {
        if !source.is_dir() {
            return Ok(());
        }

        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            let source_file = entry.path();
            let destination_file = destination.join(entry.file_name());
            if should_copy_runtime_file(&source_file, &destination_file)? {
                fs::copy(&source_file, &destination_file)?;
            }
        }

        Ok(())
    }

    fn should_copy_runtime_file(source: &Path, destination: &Path) -> std::io::Result<bool> {
        let source_metadata = source.metadata()?;
        let Ok(destination_metadata) = destination.metadata() else {
            return Ok(true);
        };

        Ok(source_metadata.len() != destination_metadata.len())
    }

    fn query_windbg_appx_install_location() -> Option<PathBuf> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-AppxPackage Microsoft.WinDbg | Select-Object -First 1 -ExpandProperty InstallLocation)",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            tracing::debug!(
                status = ?output.status.code(),
                stderr = %String::from_utf8_lossy(&output.stderr),
                "Get-AppxPackage Microsoft.WinDbg did not return an install location"
            );
            return None;
        }

        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .find(|path| path.is_dir())
    }

    fn candidate_windows_kits_debugger_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for env_name in ["ProgramFiles(x86)", "ProgramFiles"] {
            let Some(program_files) = env::var_os(env_name).map(PathBuf::from) else {
                continue;
            };
            push_existing_dir(
                &mut roots,
                program_files.join("Windows Kits\\10\\Debuggers\\x64"),
            );
        }
        roots
    }

    fn push_existing_dir(dirs: &mut Vec<PathBuf>, path: PathBuf) {
        if !path.is_dir() {
            return;
        }

        let normalized = path.display().to_string().to_ascii_lowercase();
        if dirs
            .iter()
            .any(|existing| existing.display().to_string().to_ascii_lowercase() == normalized)
        {
            return;
        }

        dirs.push(path);
    }

    fn quote_debugger_load_path(path: &Path) -> String {
        quote_debugger_path_text(&path.display().to_string().replace('\\', "\\\\"))
    }

    fn quote_debugger_path_text(path: &str) -> String {
        format!("\"{}\"", path.replace('"', "\\\""))
    }

    fn sync_host_command_scope(client: &IDebugClient) {
        if let Ok(debug_symbols3) = client.cast::<IDebugSymbols3>() {
            if let Err(error) = unsafe { debug_symbols3.SetScopeFromStoredEvent() } {
                tracing::trace!(
                    ?error,
                    "kernel host could not restore scope from the stored event"
                );
            }
        } else {
            tracing::trace!("kernel host could not acquire IDebugSymbols3 for scope sync");
        }

        let Ok(system_objects) = client.cast::<IDebugSystemObjects3>() else {
            tracing::trace!("kernel host could not acquire IDebugSystemObjects3 for scope sync");
            return;
        };

        sync_scope_from_event(
            "system",
            || unsafe { system_objects.GetEventSystem() },
            || unsafe { system_objects.GetCurrentSystemId() },
            |id| unsafe { system_objects.SetCurrentSystemId(id) },
        );
        sync_scope_from_event(
            "process",
            || unsafe { system_objects.GetEventProcess() },
            || unsafe { system_objects.GetCurrentProcessId() },
            |id| unsafe { system_objects.SetCurrentProcessId(id) },
        );
        sync_scope_from_event(
            "thread",
            || unsafe { system_objects.GetEventThread() },
            || unsafe { system_objects.GetCurrentThreadId() },
            |id| unsafe { system_objects.SetCurrentThreadId(id) },
        );
    }

    fn sync_scope_from_event<GetEvent, GetCurrent, SetCurrent>(
        scope_name: &str,
        get_event: GetEvent,
        get_current: GetCurrent,
        set_current: SetCurrent,
    ) where
        GetEvent: FnOnce() -> WinResult<u32>,
        GetCurrent: FnOnce() -> WinResult<u32>,
        SetCurrent: FnOnce(u32) -> WinResult<()>,
    {
        let event_id = match get_event() {
            Ok(id) => id,
            Err(error) => {
                tracing::trace!(
                    scope = scope_name,
                    ?error,
                    "kernel host could not query event scope"
                );
                return;
            }
        };

        match get_current() {
            Ok(current_id) if current_id == event_id => {
                tracing::trace!(
                    scope = scope_name,
                    id = event_id,
                    "kernel host scope already matches event context"
                );
                return;
            }
            Ok(current_id) => {
                tracing::debug!(
                    scope = scope_name,
                    current_id,
                    event_id,
                    "kernel host is synchronizing current scope to event context"
                );
            }
            Err(error) => {
                tracing::debug!(
                    scope = scope_name,
                    event_id,
                    ?error,
                    "kernel host could not read current scope; forcing event context"
                );
            }
        }

        if let Err(error) = set_current(event_id) {
            tracing::warn!(
                scope = scope_name,
                event_id,
                ?error,
                "kernel host failed to synchronize scope to the current event"
            );
        }
    }

    fn try_render_thread_command_fallback(
        client: &IDebugClient,
        command: &str,
        retryable_reason: &str,
    ) -> Option<Result<String, ExecutionError>> {
        if !is_thread_list_command(command) || !retryable_reason.contains("0x80040205") {
            return None;
        }

        tracing::debug!(
            command = %command,
            reason = %retryable_reason,
            "text thread-list command failed in the command window; using dbgeng system-object fallback"
        );
        Some(render_thread_list_from_system_objects(client))
    }

    pub(super) fn is_thread_list_command(command: &str) -> bool {
        matches!(command.trim(), "~" | "~*")
    }

    fn render_thread_list_from_system_objects(
        client: &IDebugClient,
    ) -> Result<String, ExecutionError> {
        sync_host_command_scope(client);

        let system_objects = client
            .cast::<IDebugSystemObjects3>()
            .map_err(|error| ExecutionError::Command(error.to_string()))?;
        let thread_count = unsafe { system_objects.GetNumberThreads() }
            .map_err(|error| ExecutionError::Command(error.to_string()))?;
        let current_thread_id = unsafe { system_objects.GetCurrentThreadId() }.ok();
        let event_thread_id = unsafe { system_objects.GetEventThread() }.ok();
        let current_system_id = unsafe { system_objects.GetCurrentThreadSystemId() }.ok();

        let mut ids = vec![0u32; thread_count as usize];
        let mut system_ids = vec![0u32; thread_count as usize];
        if thread_count > 0 {
            unsafe {
                system_objects
                    .GetThreadIdsByIndex(
                        0,
                        thread_count,
                        Some(ids.as_mut_ptr()),
                        Some(system_ids.as_mut_ptr()),
                    )
                    .map_err(|error| ExecutionError::Command(error.to_string()))?;
            }
        }

        let mut output = String::new();
        output.push_str(
            "Thread list supplied by dbgeng API fallback because the text `~` command window was not settled.\n",
        );
        output.push_str("Legend: `.` = current thread, `#` = event thread.\n");
        if let Some(system_id) = current_system_id {
            output.push_str(&format!(
                "Current thread system id: {system_id} (0x{system_id:x})\n"
            ));
        }
        output.push_str("   Id        SystemId\n");

        for (id, system_id) in ids.into_iter().zip(system_ids) {
            let current_marker = if Some(id) == current_thread_id {
                '.'
            } else {
                ' '
            };
            let event_marker = if Some(id) == event_thread_id {
                '#'
            } else {
                ' '
            };
            output.push_str(&format!(
                "{current_marker}{event_marker} {id:>4} {system_id:>12} (0x{system_id:x})\n"
            ));
        }

        if thread_count == 0 {
            output.push_str("No threads are currently reported by dbgeng.\n");
        }

        Ok(output)
    }

    pub(super) fn is_transient_command_hresult(code: i32) -> bool {
        matches!(code, HRESULT_E_PENDING | HRESULT_COMMAND_WINDOW_NOT_SETTLED)
    }

    fn is_transient_command_error(error: &WinError) -> bool {
        is_transient_command_hresult(error.code().0)
    }

    pub(crate) struct DbgEngExecutor {
        client: IDebugClient,
        control: IDebugControl,
        last_known_state: DebuggerExecutionState,
        pending_startup_command: Option<String>,
        kernel_host: Option<KernelSessionHost>,
    }

    impl DbgEngExecutor {
        pub(crate) fn connect_session() -> Result<Self, ExecutionError> {
            let client = debug_create::<IDebugClient>()
                .map_err(|error| ExecutionError::Startup(error.to_string()))?;

            unsafe {
                client
                    .ConnectSession(
                        DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE,
                        0,
                    )
                    .map_err(|error| ExecutionError::Startup(error.to_string()))?;
            }

            let control = client
                .cast::<IDebugControl>()
                .map_err(|error| ExecutionError::Startup(error.to_string()))?;
            let last_known_state = current_state(&control)?;

            Ok(Self {
                client,
                control,
                last_known_state,
                pending_startup_command: None,
                kernel_host: None,
            })
        }

        pub(crate) fn attach_kernel(
            connect_options: &str,
            startup_command: Option<&str>,
            attach_timeout: Duration,
        ) -> Result<Self, ExecutionError> {
            tracing::debug!(%connect_options, ?attach_timeout, "starting kernel host thread");
            let host = KernelSessionHost::start(connect_options)?;
            Self::connect_command_client(host, startup_command, attach_timeout)
        }

        pub(crate) fn attach_user_process(
            attach: UserModeAttach,
            startup_command: Option<&str>,
            attach_timeout: Duration,
        ) -> Result<Self, ExecutionError> {
            tracing::debug!(?attach, ?attach_timeout, "starting user-mode host thread");
            let host = KernelSessionHost::start_user_mode(&attach)?;
            Self::connect_command_client(host, startup_command, attach_timeout)
        }

        fn connect_command_client(
            host: KernelSessionHost,
            startup_command: Option<&str>,
            attach_timeout: Duration,
        ) -> Result<Self, ExecutionError> {
            let kind_label = host.kind_label();
            let connect_deadline = Instant::now() + attach_timeout.max(Duration::from_secs(5));

            loop {
                match Self::connect_session() {
                    Ok(mut executor) => {
                        // The host client owns the underlying transport (KDNET, COM, or
                        // local user-mode debug port). Calling EndSession from this
                        // connected command client can trip dbgeng's nested LoadModule guard
                        // during driver-load or module-load events, so cleanup is handled by
                        // stopping the host client.
                        executor.pending_startup_command = startup_command
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(str::to_string);
                        executor.kernel_host = Some(host);
                        executor.last_known_state = executor.refresh_state()?;
                        executor.maybe_run_startup_command()?;
                        tracing::debug!(
                            kind = kind_label,
                            state = %executor.last_known_state.status_name,
                            "connected command client to dbgeng host session"
                        );
                        return Ok(executor);
                    }
                    Err(error) => {
                        if Instant::now() >= connect_deadline {
                            // The host owns the transport as soon as Attach* succeeds.
                            // If the command client never connects, do not leave an
                            // unregistered host running.
                            host.request_stop();
                            return Err(error);
                        }
                        thread::sleep(POLL_INTERVAL);
                    }
                }
            }
        }

        fn control(&self) -> IDebugControl {
            self.control.clone()
        }

        fn refresh_state(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
            let state = if let Some(host) = &self.kernel_host {
                host.query_state()?
            } else {
                current_state(&self.control)?
            };
            self.last_known_state = state.clone();
            Ok(state)
        }

        fn maybe_run_startup_command(&mut self) -> Result<(), ExecutionError> {
            if !self.last_known_state.ready_for_commands {
                return Ok(());
            }

            let Some(command) = self.pending_startup_command.take() else {
                return Ok(());
            };

            let _ = self.execute_ready(&command)?;
            let _ = self.refresh_state()?;
            Ok(())
        }

        fn wait_for_stable_command_window(
            &mut self,
        ) -> Result<DebuggerExecutionState, ExecutionError> {
            let state = if let Some(host) = &self.kernel_host {
                host.await_command_ready()?
            } else {
                current_state(&self.control)?
            };
            self.last_known_state = state.clone();
            Ok(state)
        }

        fn try_execute_command_once(
            &self,
            c_command: &CString,
        ) -> Result<String, CommandAttemptError> {
            let captured = Arc::new(Mutex::new(String::new()));
            let callback: IDebugOutputCallbacks = OutputCollector::new(captured.clone()).into();
            let child = unsafe { self.client.CreateClient() }.map_err(|error| {
                CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
            })?;
            let child_control = child.cast::<IDebugControl>().map_err(|error| {
                CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
            })?;
            let child_state = current_state(&child_control).map_err(CommandAttemptError::Fatal)?;
            if !child_state.ready_for_commands {
                return Err(CommandAttemptError::Retryable(format!(
                    "child command client still reports {} ({})",
                    child_state.status_name, child_state.raw_status
                )));
            }

            unsafe {
                child.SetOutputCallbacks(&callback).map_err(|error| {
                    CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
                })?;
                child_control
                    .Execute(
                        DEBUG_OUTCTL_THIS_CLIENT,
                        PCSTR(c_command.as_ptr() as _),
                        DEBUG_EXECUTE_DEFAULT,
                    )
                    .map_err(|error| {
                        if is_transient_command_error(&error) {
                            CommandAttemptError::Retryable(error.to_string())
                        } else {
                            CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
                        }
                    })?;
                child.FlushCallbacks().map_err(|error| {
                    CommandAttemptError::Fatal(ExecutionError::Command(error.to_string()))
                })?;
            }

            Ok(captured.lock().expect("buffer lock poisoned").clone())
        }

        fn request_interrupt_signal(&self) -> Result<(), ExecutionError> {
            if let Some(host) = &self.kernel_host {
                host.request_active_interrupt();
                Ok(())
            } else {
                let control = self.control();
                unsafe {
                    control
                        .SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
                        .map_err(|error| ExecutionError::Command(error.to_string()))
                }
            }
        }

        fn wait_until_ready_after_interrupt(
            &mut self,
        ) -> Result<DebuggerExecutionState, ExecutionError> {
            let deadline = Instant::now() + INTERRUPT_WAIT_TIMEOUT;
            let mut next_interrupt = Instant::now() + Duration::from_secs(1);
            loop {
                let state = self.refresh_state()?;
                tracing::trace!(
                    status = state.raw_status,
                    name = %state.status_name,
                    ready = state.ready_for_commands,
                    "waiting for debugger to become ready after interrupt"
                );
                if state.ready_for_commands {
                    self.maybe_run_startup_command()?;
                    return Ok(self.last_known_state.clone());
                }

                if Instant::now() >= deadline {
                    return Err(ExecutionError::Command(format!(
                        "timed out waiting for debugger to become ready; last status was {} ({})",
                        state.status_name, state.raw_status
                    )));
                }

                if Instant::now() >= next_interrupt {
                    tracing::debug!(
                        status = state.raw_status,
                        name = %state.status_name,
                        "debugger is still running after interrupt; reissuing break-in request"
                    );
                    self.request_interrupt_signal()?;
                    next_interrupt = Instant::now() + Duration::from_secs(1);
                }

                thread::sleep(POLL_INTERVAL);
            }
        }

        fn shutdown_host_if_needed(&mut self) {
            if let Some(host) = &self.kernel_host {
                host.request_stop();
            }
            self.kernel_host = None;
        }

        fn resume_if_ready_for_shutdown(&self, reason: &str) {
            match current_state(&self.control) {
                Ok(state) if state.ready_for_commands => {
                    tracing::debug!(
                        status = state.raw_status,
                        name = %state.status_name,
                        reason,
                        "resuming target during shutdown so the guest is not left broken"
                    );
                    if let Err(error) =
                        unsafe { self.control.SetExecutionStatus(DEBUG_STATUS_GO_HANDLED) }
                    {
                        tracing::warn!(?error, reason, "failed to resume target during shutdown");
                    }
                }
                Ok(state) => {
                    tracing::trace!(
                        status = state.raw_status,
                        name = %state.status_name,
                        reason,
                        "target was not command-ready during shutdown resume check"
                    );
                }
                Err(error) => {
                    tracing::trace!(
                        ?error,
                        reason,
                        "could not query state during shutdown resume check"
                    );
                }
            }
        }
    }

    impl BlockingExecutor for DbgEngExecutor {
        fn query_state(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
            self.refresh_state()
        }

        fn execute_ready(&mut self, command: &str) -> Result<String, ExecutionError> {
            if let Some(host) = &self.kernel_host {
                match host.execute_command(command) {
                    Ok(output) => return Ok(output),
                    Err(error) if should_fallback_from_host_command(command, &error) => {
                        tracing::debug!(
                            command = %command,
                            error = %error,
                            "kernel host command path stayed unstable; falling back to the command client"
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
            let c_command = CString::new(command).map_err(|_| ExecutionError::InvalidCString)?;
            let max_attempts = if self.kernel_host.is_some() {
                COMMAND_READY_RETRY_ATTEMPTS
            } else {
                1
            };
            let mut last_retryable_reason = None;

            for attempt in 0..max_attempts {
                let command_window_state = self.wait_for_stable_command_window()?;
                if !command_window_state.ready_for_commands {
                    let reason = format!(
                        "host command window still reports {} ({})",
                        command_window_state.status_name, command_window_state.raw_status
                    );
                    if attempt + 1 < max_attempts {
                        tracing::debug!(
                            attempt = attempt + 1,
                            total_attempts = max_attempts,
                            reason = %reason,
                            "debugger reported break earlier, but the command window is not settled yet; retrying"
                        );
                        last_retryable_reason = Some(reason);
                        thread::sleep(COMMAND_READY_RETRY_DELAY);
                        continue;
                    }
                    return Err(ExecutionError::Command(reason));
                }

                match self.try_execute_command_once(&c_command) {
                    Ok(output) => return Ok(output),
                    Err(CommandAttemptError::Retryable(reason)) if attempt + 1 < max_attempts => {
                        tracing::debug!(
                            attempt = attempt + 1,
                            total_attempts = max_attempts,
                            reason = %reason,
                            "command client was not ready even though the host reported break; retrying"
                        );
                        last_retryable_reason = Some(reason);
                        thread::sleep(COMMAND_READY_RETRY_DELAY);
                    }
                    Err(CommandAttemptError::Retryable(reason)) => {
                        let current_state = self
                            .refresh_state()
                            .unwrap_or_else(|_| self.last_known_state.clone());
                        return Err(ExecutionError::Command(format!(
                            "debugger reported break but the command client never settled after {} attempts: {}. Last observed state: {} ({}).",
                            max_attempts,
                            reason,
                            current_state.status_name,
                            current_state.raw_status
                        )));
                    }
                    Err(CommandAttemptError::Fatal(error)) => return Err(error),
                }
            }

            Err(ExecutionError::Command(format!(
                "debugger command window never stabilized. Last retryable reason: {}",
                last_retryable_reason.unwrap_or_else(|| "unknown".to_string())
            )))
        }

        fn interrupt(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
            let state = self.refresh_state()?;
            tracing::debug!(
                status = state.raw_status,
                name = %state.status_name,
                ready = state.ready_for_commands,
                "interrupt requested"
            );
            if state.ready_for_commands {
                return Ok(state);
            }

            self.request_interrupt_signal()?;

            self.wait_until_ready_after_interrupt()
        }

        fn resume(&mut self) -> Result<DebuggerExecutionState, ExecutionError> {
            let state = self.refresh_state()?;
            if state.running {
                return Ok(state);
            }
            if !state.ready_for_commands {
                return Err(ExecutionError::Command(format!(
                    "target cannot be resumed while debugger status is {} ({}). {}",
                    state.status_name, state.raw_status, state.summary
                )));
            }

            if let Some(host) = &self.kernel_host {
                let state = host.resume_target()?;
                self.last_known_state = state.clone();
                return Ok(state);
            } else {
                let control = self.control();
                unsafe {
                    control
                        .SetExecutionStatus(DEBUG_STATUS_GO_HANDLED)
                        .map_err(|error| ExecutionError::Command(error.to_string()))?;
                }
            }

            self.last_known_state = DebuggerExecutionState::running_state();
            Ok(self.last_known_state.clone())
        }

        fn shutdown(&mut self) -> Result<(), ExecutionError> {
            if self.kernel_host.is_some() {
                self.resume_if_ready_for_shutdown("before detach");
                self.shutdown_host_if_needed();
                self.resume_if_ready_for_shutdown("after host stop");
            }
            Ok(())
        }
    }

    impl Drop for DbgEngExecutor {
        fn drop(&mut self) {
            if self.kernel_host.is_some() {
                self.resume_if_ready_for_shutdown("drop before host stop");
                thread::sleep(Duration::from_secs(2));
                self.shutdown_host_if_needed();
                self.resume_if_ready_for_shutdown("drop after host stop");
            } else {
                self.shutdown_host_if_needed();
            }
        }
    }

    fn current_state(control: &IDebugControl) -> Result<DebuggerExecutionState, ExecutionError> {
        let raw_status = unsafe { control.GetExecutionStatus() }
            .map_err(|error| ExecutionError::Command(error.to_string()))?;
        Ok(DebuggerExecutionState::from_raw(raw_status))
    }

    fn should_fallback_from_host_command(command: &str, error: &ExecutionError) -> bool {
        let trimmed = command.trim_start();
        (trimmed.starts_with('~') || trimmed.starts_with('|'))
            && matches!(error, ExecutionError::Command(message) if message.contains("0x80040205"))
    }
}

#[cfg(windows)]
pub(crate) use windows_impl::DbgEngExecutor;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;

    #[test]
    fn build_command_uses_first_variant_by_default() {
        let catalog = Catalog::global();
        let entry = catalog.lookup("bp").expect("bp entry should exist");
        let rendered =
            build_command(entry, None, Some("ntdll!NtClose")).expect("command should render");
        assert_eq!(rendered, "bp ntdll!NtClose");
    }

    #[test]
    fn build_command_rejects_unknown_variant() {
        let catalog = Catalog::global();
        let entry = catalog.lookup("bp").expect("bp entry should exist");
        let error = build_command(entry, Some("bogus"), None).expect_err("variant must fail");
        assert!(matches!(error, ExecutionError::InvalidVariant { .. }));
    }

    #[test]
    fn mock_executor_rejects_execution_when_running() {
        let mut executor = MockExecutor {
            responses: HashMap::from([("g".to_string(), "continued execution".to_string())]),
            state: DebuggerExecutionState::from_raw(EXECUTION_STATUS_GO),
        };

        let error = executor.execute("g").expect_err("execute should fail");
        assert!(
            error
                .to_string()
                .contains("debugger is not ready for commands")
        );
    }

    #[tokio::test]
    async fn dispatcher_can_resume_and_interrupt_mock_state() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");

        let state = dispatcher.query_state().await.expect("query should work");
        assert!(state.ready_for_commands);

        let running = dispatcher.resume().await.expect("resume should work");
        assert!(running.running);

        let interrupted = dispatcher.interrupt().await.expect("interrupt should work");
        assert!(interrupted.ready_for_commands);
    }

    #[cfg(windows)]
    #[test]
    fn classifies_transient_command_hrresults() {
        assert!(crate::executor::windows_impl::is_transient_command_hresult(
            0x8000000A_u32 as i32
        ));
        assert!(crate::executor::windows_impl::is_transient_command_hresult(
            0x80040205_u32 as i32
        ));
        assert!(
            !crate::executor::windows_impl::is_transient_command_hresult(0x80004001_u32 as i32)
        );
    }

    #[cfg(windows)]
    #[test]
    fn identifies_thread_list_fallback_commands() {
        assert!(crate::executor::windows_impl::is_thread_list_command("~"));
        assert!(crate::executor::windows_impl::is_thread_list_command(
            "  ~*  "
        ));
        assert!(!crate::executor::windows_impl::is_thread_list_command(
            "~0 k"
        ));
        assert!(!crate::executor::windows_impl::is_thread_list_command("k"));
    }
}
