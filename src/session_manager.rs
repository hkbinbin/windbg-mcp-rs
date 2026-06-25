use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio::time::{sleep, timeout};

use crate::executor::{
    CommandDispatcher, CommandExecutionResult, DebuggerExecutionState, ExecutionError,
    ExecutionMode, OutputSnapshot, UserModeAttach, default_attach_timeout,
};

#[derive(Debug, Clone, Serialize)]
pub struct HeadlessSessionInfo {
    pub session_id: String,
    pub transport: String,
    pub connection_options: String,
    pub startup_command: Option<String>,
    pub created_at_unix_ms: u64,
    pub last_accessed_unix_ms: u64,
    pub is_default: bool,
    pub state: Option<DebuggerExecutionState>,
    pub state_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeadlessSessionList {
    pub default_session_id: Option<String>,
    pub sessions: Vec<HeadlessSessionInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloseSessionResult {
    pub closed_session_id: String,
    pub default_session_id: Option<String>,
    pub remaining_sessions: usize,
    pub resume_before_close: bool,
    pub resume_attempted: bool,
    pub resume_error: Option<String>,
    pub shutdown_completed: bool,
    pub shutdown_error: Option<String>,
    pub shutdown_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoverSessionResult {
    pub session_id: String,
    pub action: String,
    pub recovered: bool,
    pub state_before: DebuggerExecutionState,
    pub state_after: DebuggerExecutionState,
    pub error: Option<String>,
}

#[derive(Clone, Default)]
pub struct HeadlessSessionManager {
    inner: Arc<Mutex<SessionRegistry>>,
}

const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CLOSE_RESUME_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_KERNEL_CLOSE_POST_RESUME_DELAY: Duration = Duration::from_secs(2);
const DEFAULT_CLOSE_RESUME_VERIFY_ATTEMPTS: usize = 3;
const DEFAULT_RESUME_BEFORE_CLOSE: bool = true;

struct SessionRegistry {
    sessions: HashMap<String, ManagedSession>,
    by_connection: HashMap<String, String>,
    default_session_id: Option<String>,
    next_session_number: u64,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            by_connection: HashMap::new(),
            default_session_id: None,
            next_session_number: 1,
        }
    }
}

#[derive(Clone)]
struct ManagedSession {
    session_id: String,
    transport: String,
    connection_options: String,
    startup_command: Option<String>,
    created_at_unix_ms: u64,
    last_accessed_unix_ms: u64,
    dispatcher: CommandDispatcher,
}

#[derive(Clone)]
struct ManagedSessionSnapshot {
    session_id: String,
    transport: String,
    connection_options: String,
    startup_command: Option<String>,
    created_at_unix_ms: u64,
    last_accessed_unix_ms: u64,
    is_default: bool,
    dispatcher: CommandDispatcher,
}

impl HeadlessSessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn open_kernel_session(
        &self,
        connect_options: impl AsRef<str>,
        session_id: Option<&str>,
        startup_command: Option<&str>,
        attach_timeout_secs: Option<u64>,
    ) -> Result<HeadlessSessionInfo, ExecutionError> {
        let normalized = normalize_kernel_connect_options(connect_options.as_ref())?;
        let startup_command = startup_command
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        let session_id = {
            let mut registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");

            if let Some(existing_id) = registry.by_connection.get(&normalized).cloned() {
                if let Some(requested) = session_id
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .filter(|requested| *requested != existing_id)
                {
                    return Err(ExecutionError::Session(format!(
                        "connection `{normalized}` is already open as session `{existing_id}` and cannot be re-opened as `{requested}`"
                    )));
                }

                registry.default_session_id = Some(existing_id.clone());
                if let Some(existing) = registry.sessions.get_mut(&existing_id) {
                    existing.last_accessed_unix_ms = timestamp_now_ms();
                }
                existing_id
            } else {
                let session_id = match session_id.map(str::trim).filter(|value| !value.is_empty()) {
                    Some(requested) => {
                        if registry.sessions.contains_key(requested) {
                            return Err(ExecutionError::Session(format!(
                                "session `{requested}` already exists"
                            )));
                        }
                        requested.to_string()
                    }
                    None => {
                        let generated = format!("session-{:02}", registry.next_session_number);
                        registry.next_session_number += 1;
                        generated
                    }
                };

                let attach_timeout = Duration::from_secs(
                    attach_timeout_secs.unwrap_or(default_attach_timeout().as_secs()),
                );
                let dispatcher = CommandDispatcher::spawn(ExecutionMode::KernelConnection {
                    connect_options: normalized.clone(),
                    startup_command: startup_command.clone(),
                    attach_timeout,
                })?;
                let now = timestamp_now_ms();
                registry
                    .by_connection
                    .insert(normalized.clone(), session_id.clone());
                registry.sessions.insert(
                    session_id.clone(),
                    ManagedSession {
                        session_id: session_id.clone(),
                        transport: "kernel".to_string(),
                        connection_options: normalized,
                        startup_command,
                        created_at_unix_ms: now,
                        last_accessed_unix_ms: now,
                        dispatcher,
                    },
                );
                registry.default_session_id = Some(session_id.clone());
                session_id
            }
        };

        self.describe_session(&session_id).await
    }

    /// Open a session that debugs a user-mode process either by spawning the
    /// debuggee (`UserModeAttach::Launch`) or by attaching to an already
    /// running PID (`UserModeAttach::AttachPid`).
    pub async fn open_user_process_session(
        &self,
        attach: UserModeAttach,
        session_id: Option<&str>,
        startup_command: Option<&str>,
        attach_timeout_secs: Option<u64>,
    ) -> Result<HeadlessSessionInfo, ExecutionError> {
        let attach = normalize_user_mode_attach(attach)?;
        let normalized = attach.connection_key();
        let startup_command = startup_command
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let transport = match &attach {
            UserModeAttach::Launch { .. } => "user-launch",
            UserModeAttach::AttachPid { .. } => "user-attach",
        };

        let session_id = {
            let mut registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");

            if let Some(existing_id) = registry.by_connection.get(&normalized).cloned() {
                if let Some(requested) = session_id
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .filter(|requested| *requested != existing_id)
                {
                    return Err(ExecutionError::Session(format!(
                        "user-mode target `{normalized}` is already open as session `{existing_id}` and cannot be re-opened as `{requested}`"
                    )));
                }
                registry.default_session_id = Some(existing_id.clone());
                if let Some(existing) = registry.sessions.get_mut(&existing_id) {
                    existing.last_accessed_unix_ms = timestamp_now_ms();
                }
                existing_id
            } else {
                let session_id = match session_id.map(str::trim).filter(|value| !value.is_empty()) {
                    Some(requested) => {
                        if registry.sessions.contains_key(requested) {
                            return Err(ExecutionError::Session(format!(
                                "session `{requested}` already exists"
                            )));
                        }
                        requested.to_string()
                    }
                    None => {
                        let generated = format!("user-{:02}", registry.next_session_number);
                        registry.next_session_number += 1;
                        generated
                    }
                };

                let attach_timeout = Duration::from_secs(
                    attach_timeout_secs.unwrap_or(default_attach_timeout().as_secs()),
                );
                let dispatcher = CommandDispatcher::spawn(ExecutionMode::UserModeProcess {
                    attach: attach.clone(),
                    startup_command: startup_command.clone(),
                    attach_timeout,
                })?;
                let now = timestamp_now_ms();
                registry
                    .by_connection
                    .insert(normalized.clone(), session_id.clone());
                registry.sessions.insert(
                    session_id.clone(),
                    ManagedSession {
                        session_id: session_id.clone(),
                        transport: transport.to_string(),
                        connection_options: normalized,
                        startup_command,
                        created_at_unix_ms: now,
                        last_accessed_unix_ms: now,
                        dispatcher,
                    },
                );
                registry.default_session_id = Some(session_id.clone());
                session_id
            }
        };

        self.describe_session(&session_id).await
    }

    pub async fn close_session(
        &self,
        session_id: &str,
        shutdown_timeout_secs: Option<u64>,
        resume_before_close: Option<bool>,
    ) -> Result<CloseSessionResult, ExecutionError> {
        let (dispatcher, session_id, transport, default_session_id, remaining_sessions) = {
            let mut registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");
            let Some(removed) = registry.sessions.remove(session_id) else {
                return Err(ExecutionError::Session(session_id.to_string()));
            };
            registry.by_connection.remove(&removed.connection_options);
            if registry.default_session_id.as_deref() == Some(session_id) {
                registry.default_session_id = registry.sessions.keys().next().cloned();
            }
            let default_session_id = registry.default_session_id.clone();
            let remaining_sessions = registry.sessions.len();
            (
                removed.dispatcher,
                removed.session_id,
                removed.transport,
                default_session_id,
                remaining_sessions,
            )
        };

        let resume_before_close = resume_before_close.unwrap_or(DEFAULT_RESUME_BEFORE_CLOSE);
        let (resume_attempted, resume_error) = if resume_before_close {
            resume_session_before_close(&dispatcher, &transport).await
        } else {
            (false, None)
        };

        let shutdown_timeout =
            Duration::from_secs(shutdown_timeout_secs.unwrap_or(DEFAULT_CLOSE_TIMEOUT.as_secs()));
        let (shutdown_completed, shutdown_error) = match timeout(
            shutdown_timeout,
            dispatcher.shutdown(),
        )
        .await
        {
            Ok(Ok(())) => (true, None),
            Ok(Err(error)) => (false, Some(error.to_string())),
            Err(_) => (
                false,
                Some(format!(
                    "timed out after {} seconds while waiting for session shutdown; the session was removed from the MCP registry, but dbgeng may still be detaching in the background",
                    shutdown_timeout.as_secs()
                )),
            ),
        };

        Ok(CloseSessionResult {
            closed_session_id: session_id,
            default_session_id,
            remaining_sessions,
            resume_before_close,
            resume_attempted,
            resume_error,
            shutdown_completed,
            shutdown_error,
            shutdown_timeout_secs: shutdown_timeout.as_secs(),
        })
    }

    pub async fn close_all_sessions(
        &self,
        shutdown_timeout_secs: Option<u64>,
        resume_before_close: Option<bool>,
    ) -> Vec<Result<CloseSessionResult, ExecutionError>> {
        let session_ids: Vec<String> = {
            let registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");
            registry.sessions.keys().cloned().collect()
        };

        let mut results = Vec::with_capacity(session_ids.len());
        for session_id in session_ids {
            results.push(
                self.close_session(&session_id, shutdown_timeout_secs, resume_before_close)
                    .await,
            );
        }
        results
    }

    pub async fn switch_session(
        &self,
        session_id: &str,
    ) -> Result<HeadlessSessionInfo, ExecutionError> {
        {
            let mut registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");
            if !registry.sessions.contains_key(session_id) {
                return Err(ExecutionError::Session(session_id.to_string()));
            }
            registry.default_session_id = Some(session_id.to_string());
            if let Some(session) = registry.sessions.get_mut(session_id) {
                session.last_accessed_unix_ms = timestamp_now_ms();
            }
        }

        self.describe_session(session_id).await
    }

    pub async fn list_sessions(&self) -> Result<HeadlessSessionList, ExecutionError> {
        let (default_session_id, session_ids) = {
            let registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");
            let mut session_ids: Vec<String> = registry.sessions.keys().cloned().collect();
            session_ids.sort();
            (registry.default_session_id.clone(), session_ids)
        };

        let mut sessions = Vec::with_capacity(session_ids.len());
        for session_id in session_ids {
            sessions.push(self.describe_session(&session_id).await?);
        }

        Ok(HeadlessSessionList {
            default_session_id,
            sessions,
        })
    }

    pub async fn current_session(&self) -> Result<Option<HeadlessSessionInfo>, ExecutionError> {
        let session_id = {
            let registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");
            registry.default_session_id.clone()
        };

        match session_id {
            Some(session_id) => Ok(Some(self.describe_session(&session_id).await?)),
            None => Ok(None),
        }
    }

    /// Resolve the transport tag (`kernel`, `user-launch`, `user-attach`, or
    /// `mock`) for `session_id`, or for the default session if `None`.
    /// Returns `None` if no session is registered.
    pub fn session_transport(&self, session_id: Option<&str>) -> Option<String> {
        let registry = self
            .inner
            .lock()
            .expect("headless session registry lock poisoned");
        let resolved_id = match session_id.map(str::trim).filter(|value| !value.is_empty()) {
            Some(requested) => requested.to_string(),
            None => registry.default_session_id.clone()?,
        };
        registry
            .sessions
            .get(&resolved_id)
            .map(|session| session.transport.clone())
    }

    /// Returns true when the addressed session is a user-mode session
    /// (either spawned via `Launch` or attached via `AttachPid`).
    pub fn is_user_mode_session(&self, session_id: Option<&str>) -> bool {
        match self.session_transport(session_id) {
            Some(transport) => transport == "user-launch" || transport == "user-attach",
            None => false,
        }
    }

    pub async fn execute_command(
        &self,
        session_id: Option<&str>,
        command: String,
    ) -> Result<CommandExecutionResult, ExecutionError> {
        if let Some(message) = blocked_unsafe_debugger_command(&command) {
            return Err(ExecutionError::Blocked(message));
        }
        let (session_id, dispatcher) = self.resolve_dispatcher(session_id)?;
        let result = dispatcher.execute(command).await?;
        self.touch_session(&session_id);
        Ok(result)
    }

    pub async fn query_state(
        &self,
        session_id: Option<&str>,
    ) -> Result<DebuggerExecutionState, ExecutionError> {
        let (session_id, dispatcher) = self.resolve_dispatcher(session_id)?;
        let result = dispatcher.query_state().await?;
        self.touch_session(&session_id);
        Ok(result)
    }

    pub async fn interrupt(
        &self,
        session_id: Option<&str>,
    ) -> Result<DebuggerExecutionState, ExecutionError> {
        let (session_id, dispatcher) = self.resolve_dispatcher(session_id)?;
        let result = dispatcher.interrupt().await?;
        self.touch_session(&session_id);
        Ok(result)
    }

    pub async fn resume(
        &self,
        session_id: Option<&str>,
    ) -> Result<DebuggerExecutionState, ExecutionError> {
        let (session_id, dispatcher) = self.resolve_dispatcher(session_id)?;
        let result = dispatcher.resume().await?;
        self.touch_session(&session_id);
        Ok(result)
    }

    pub async fn recover_session(
        &self,
        session_id: Option<&str>,
        resume_if_broken: Option<bool>,
        interrupt_if_running: Option<bool>,
    ) -> Result<RecoverSessionResult, ExecutionError> {
        let resume_if_broken = resume_if_broken.unwrap_or(true);
        let interrupt_if_running = interrupt_if_running.unwrap_or(false);
        let (session_id, dispatcher) = self.resolve_dispatcher(session_id)?;
        let state_before = dispatcher.query_state().await?;

        let (action, recovered, state_after, error) =
            if state_before.ready_for_commands && resume_if_broken {
                match dispatcher.resume().await {
                    Ok(state_after) => ("resume_target".to_string(), true, state_after, None),
                    Err(error) => (
                        "resume_target".to_string(),
                        false,
                        dispatcher
                            .query_state()
                            .await
                            .unwrap_or_else(|_| state_before.clone()),
                        Some(error.to_string()),
                    ),
                }
            } else if state_before.running && interrupt_if_running {
                match dispatcher.interrupt().await {
                    Ok(state_after) => ("interrupt_target".to_string(), true, state_after, None),
                    Err(error) => (
                        "interrupt_target".to_string(),
                        false,
                        dispatcher
                            .query_state()
                            .await
                            .unwrap_or_else(|_| state_before.clone()),
                        Some(error.to_string()),
                    ),
                }
            } else {
                ("none".to_string(), false, state_before.clone(), None)
            };

        self.touch_session(&session_id);
        Ok(RecoverSessionResult {
            session_id,
            action,
            recovered,
            state_before,
            state_after,
            error,
        })
    }

    pub async fn get_output(
        &self,
        session_id: Option<&str>,
        cursor: Option<u64>,
    ) -> Result<OutputSnapshot, ExecutionError> {
        let (session_id, dispatcher) = self.resolve_dispatcher(session_id)?;
        let result = dispatcher.get_output(cursor).await?;
        self.touch_session(&session_id);
        Ok(result)
    }

    fn resolve_dispatcher(
        &self,
        session_id: Option<&str>,
    ) -> Result<(String, CommandDispatcher), ExecutionError> {
        let registry = self
            .inner
            .lock()
            .expect("headless session registry lock poisoned");

        let resolved_id = match session_id.map(str::trim).filter(|value| !value.is_empty()) {
            Some(requested) => requested.to_string(),
            None => registry.default_session_id.clone().ok_or_else(|| {
                ExecutionError::Session(
                    "no active session; call `windbg_open_session` first".to_string(),
                )
            })?,
        };

        let session = registry
            .sessions
            .get(&resolved_id)
            .ok_or_else(|| ExecutionError::Session(resolved_id.clone()))?;

        Ok((resolved_id, session.dispatcher.clone()))
    }

    fn describe_session_snapshot(
        &self,
        session_id: &str,
    ) -> Result<ManagedSessionSnapshot, ExecutionError> {
        let registry = self
            .inner
            .lock()
            .expect("headless session registry lock poisoned");
        let session = registry
            .sessions
            .get(session_id)
            .ok_or_else(|| ExecutionError::Session(session_id.to_string()))?;

        Ok(ManagedSessionSnapshot {
            session_id: session.session_id.clone(),
            transport: session.transport.clone(),
            connection_options: session.connection_options.clone(),
            startup_command: session.startup_command.clone(),
            created_at_unix_ms: session.created_at_unix_ms,
            last_accessed_unix_ms: session.last_accessed_unix_ms,
            is_default: registry.default_session_id.as_deref() == Some(session_id),
            dispatcher: session.dispatcher.clone(),
        })
    }

    async fn describe_session(
        &self,
        session_id: &str,
    ) -> Result<HeadlessSessionInfo, ExecutionError> {
        let snapshot = self.describe_session_snapshot(session_id)?;
        let (state, state_error) = match snapshot.dispatcher.query_state().await {
            Ok(state) => (Some(state), None),
            Err(error) => (None, Some(error.to_string())),
        };

        Ok(HeadlessSessionInfo {
            session_id: snapshot.session_id,
            transport: snapshot.transport,
            connection_options: snapshot.connection_options,
            startup_command: snapshot.startup_command,
            created_at_unix_ms: snapshot.created_at_unix_ms,
            last_accessed_unix_ms: snapshot.last_accessed_unix_ms,
            is_default: snapshot.is_default,
            state,
            state_error,
        })
    }

    fn touch_session(&self, session_id: &str) {
        let mut registry = self
            .inner
            .lock()
            .expect("headless session registry lock poisoned");
        if let Some(session) = registry.sessions.get_mut(session_id) {
            session.last_accessed_unix_ms = timestamp_now_ms();
        }
    }

    #[cfg(test)]
    async fn open_mock_session(
        &self,
        session_id: &str,
        responses: HashMap<String, String>,
    ) -> Result<HeadlessSessionInfo, ExecutionError> {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock { responses })?;
        {
            let mut registry = self
                .inner
                .lock()
                .expect("headless session registry lock poisoned");
            let now = timestamp_now_ms();
            registry.sessions.insert(
                session_id.to_string(),
                ManagedSession {
                    session_id: session_id.to_string(),
                    transport: "mock".to_string(),
                    connection_options: "mock".to_string(),
                    startup_command: None,
                    created_at_unix_ms: now,
                    last_accessed_unix_ms: now,
                    dispatcher,
                },
            );
            registry.default_session_id = Some(session_id.to_string());
        }

        self.describe_session(session_id).await
    }
}

fn timestamp_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn resume_session_before_close(
    dispatcher: &CommandDispatcher,
    transport: &str,
) -> (bool, Option<String>) {
    let mut attempted = false;
    let mut last_error = None;

    for attempt in 0..DEFAULT_CLOSE_RESUME_VERIFY_ATTEMPTS {
        let state = match timeout(DEFAULT_CLOSE_RESUME_TIMEOUT, dispatcher.query_state()).await {
            Ok(Ok(state)) => state,
            Ok(Err(error)) => return (attempted, Some(error.to_string())),
            Err(_) => {
                return (
                    attempted,
                    Some(format!(
                        "timed out after {} seconds while checking whether the target should be resumed before close",
                        DEFAULT_CLOSE_RESUME_TIMEOUT.as_secs()
                    )),
                );
            }
        };

        if state.running {
            if transport == "kernel" {
                sleep(DEFAULT_KERNEL_CLOSE_POST_RESUME_DELAY).await;
            }
            continue;
        }

        if !state.ready_for_commands {
            return (
                attempted,
                Some(format!(
                    "target was not resumed before close because debugger status is {} ({}): {}",
                    state.status_name, state.raw_status, state.summary
                )),
            );
        }

        attempted = true;
        match timeout(DEFAULT_CLOSE_RESUME_TIMEOUT, dispatcher.resume()).await {
            Ok(Ok(state_after)) => {
                last_error = None;
                if transport == "kernel" && state_after.running {
                    sleep(DEFAULT_KERNEL_CLOSE_POST_RESUME_DELAY).await;
                }
            }
            Ok(Err(error)) => {
                last_error = Some(error.to_string());
                if attempt + 1 >= DEFAULT_CLOSE_RESUME_VERIFY_ATTEMPTS {
                    return (attempted, last_error);
                }
            }
            Err(_) => {
                last_error = Some(format!(
                    "timed out after {} seconds while resuming the target before close",
                    DEFAULT_CLOSE_RESUME_TIMEOUT.as_secs()
                ));
                if attempt + 1 >= DEFAULT_CLOSE_RESUME_VERIFY_ATTEMPTS {
                    return (attempted, last_error);
                }
            }
        }
    }

    (attempted, last_error)
}

fn normalize_kernel_connect_options(raw: &str) -> Result<String, ExecutionError> {
    let normalized_dashes = raw.replace(['–', '—'], "-");
    let trimmed = normalized_dashes.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Err(ExecutionError::Session(
            "kernel connection options cannot be empty".to_string(),
        ));
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(ExecutionError::Session(
            "kernel connection options cannot be empty".to_string(),
        ));
    }

    if tokens.len() >= 3 && tokens[1].eq_ignore_ascii_case("-k") {
        return Ok(tokens[2..].join(" "));
    }

    if tokens.len() >= 2 && tokens[0].eq_ignore_ascii_case("-k") {
        return Ok(tokens[1..].join(" "));
    }

    Ok(trimmed.to_string())
}

fn normalize_user_mode_attach(attach: UserModeAttach) -> Result<UserModeAttach, ExecutionError> {
    match attach {
        UserModeAttach::Launch {
            command_line,
            only_this_process,
            detach_on_exit,
        } => {
            let trimmed = command_line.trim().trim_matches('"').to_string();
            if trimmed.is_empty() {
                return Err(ExecutionError::Session(
                    "user-mode launch command line cannot be empty".to_string(),
                ));
            }
            Ok(UserModeAttach::Launch {
                command_line: trimmed,
                only_this_process,
                detach_on_exit,
            })
        }
        UserModeAttach::AttachPid {
            pid,
            non_invasive,
            detach_on_exit,
        } => {
            if pid == 0 {
                return Err(ExecutionError::Session(
                    "user-mode attach PID must be greater than zero".to_string(),
                ));
            }
            Ok(UserModeAttach::AttachPid {
                pid,
                non_invasive,
                detach_on_exit,
            })
        }
    }
}

/// Reject WinDbg commands that have crashed or destabilized dbgeng in this
/// headless path. Shared by every `execute_command` caller (MCP and CLI).
///
/// Returns `Some(message)` when the command must be blocked.
fn blocked_unsafe_debugger_command(command: &str) -> Option<String> {
    for segment in command.split([';', '\n', '\r']) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if disables_load_event_filter(segment) {
            return Some(format!(
                "blocked unsafe WinDbg command `{segment}`: this dbgeng headless path has been observed to access-violate when disabling `ld` filters after a module-load event. Leave the load filter in the short-lived session, clear normal breakpoints with `bc`, then resume or close the session."
            ));
        }
        if looks_like_fragile_multi_register_read(segment) {
            return Some(format!(
                "blocked fragile WinDbg command `{segment}`: raw `r <reg> <reg> ...` subset reads have produced transient dbgeng `0x80040205` states in headless mode. Use `do reg <reg> <reg>` instead; it reads each register as an isolated command."
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn manager_routes_commands_to_the_default_mock_session() {
        let manager = HeadlessSessionManager::new();
        manager
            .open_mock_session(
                "session-01",
                HashMap::from([("r".to_string(), "register dump".to_string())]),
            )
            .await
            .expect("mock session should open");

        let result = manager
            .execute_command(None, "r".to_string())
            .await
            .expect("command should execute");
        assert_eq!(result.output, "register dump");
    }

    #[test]
    fn blocklist_rejects_sxd_load_filter_and_multi_register_reads() {
        assert!(blocked_unsafe_debugger_command("sxd ld").is_some());
        assert!(blocked_unsafe_debugger_command("sxd ld:foo.sys").is_some());
        assert!(blocked_unsafe_debugger_command("sxd ld*").is_some());
        assert!(blocked_unsafe_debugger_command("r rip rax rcx").is_some());
        // Safe commands must pass through.
        assert!(blocked_unsafe_debugger_command("r").is_none());
        assert!(blocked_unsafe_debugger_command("r @rip").is_none());
        assert!(blocked_unsafe_debugger_command("r rax=5").is_none());
        assert!(blocked_unsafe_debugger_command("sxe ld:foo.sys").is_none());
        assert!(blocked_unsafe_debugger_command("bp nt!NtClose").is_none());
    }

    #[tokio::test]
    async fn execute_command_blocks_unsafe_input_before_dispatch() {
        let manager = HeadlessSessionManager::new();
        manager
            .open_mock_session("session-01", HashMap::new())
            .await
            .expect("mock session should open");

        let err = manager
            .execute_command(None, "sxd ld".to_string())
            .await
            .expect_err("unsafe command should be blocked");
        assert!(matches!(err, ExecutionError::Blocked(_)));
    }

    #[tokio::test]
    async fn close_session_removes_session_and_reports_shutdown_status() {
        let manager = HeadlessSessionManager::new();
        manager
            .open_mock_session("session-01", HashMap::new())
            .await
            .expect("mock session should open");

        let result = manager
            .close_session("session-01", Some(1), None)
            .await
            .expect("close should remove the session");

        assert_eq!(result.closed_session_id, "session-01");
        assert_eq!(result.remaining_sessions, 0);
        assert_eq!(result.default_session_id, None);
        assert!(result.resume_before_close);
        assert!(result.resume_attempted);
        assert_eq!(result.resume_error, None);
        assert!(result.shutdown_completed);
        assert_eq!(result.shutdown_error, None);
        assert_eq!(result.shutdown_timeout_secs, 1);

        let error = manager
            .execute_command(Some("session-01"), "r".to_string())
            .await
            .expect_err("closed session should no longer be routable");
        assert!(matches!(error, ExecutionError::Session(_)));
    }

    #[tokio::test]
    async fn recover_session_resumes_broken_mock_session() {
        let manager = HeadlessSessionManager::new();
        manager
            .open_mock_session("session-01", HashMap::new())
            .await
            .expect("mock session should open");

        let result = manager
            .recover_session(None, None, None)
            .await
            .expect("recover should resume the broken mock session");

        assert_eq!(result.session_id, "session-01");
        assert_eq!(result.action, "resume_target");
        assert!(result.recovered);
        assert_eq!(result.error, None);
        assert!(result.state_before.ready_for_commands);
        assert!(result.state_after.running);
    }

    #[tokio::test]
    async fn normalize_strips_windbg_launcher_prefix() {
        let normalized =
            normalize_kernel_connect_options("windbgx –k net:port=50000,key=abc,target=10.0.0.5")
                .expect("normalization should work");
        assert_eq!(normalized, "net:port=50000,key=abc,target=10.0.0.5");
    }

    #[test]
    fn user_mode_attach_normalization_trims_quotes_and_whitespace() {
        let normalized = normalize_user_mode_attach(UserModeAttach::Launch {
            command_line: "  \"C:\\path\\to\\app.exe arg\"  ".to_string(),
            only_this_process: true,
            detach_on_exit: true,
        })
        .expect("launch normalization should work");
        match normalized {
            UserModeAttach::Launch { command_line, .. } => {
                assert_eq!(command_line, "C:\\path\\to\\app.exe arg");
            }
            other => panic!("expected Launch, got {other:?}"),
        }
    }

    #[test]
    fn user_mode_attach_normalization_rejects_empty_command_line() {
        let error = normalize_user_mode_attach(UserModeAttach::Launch {
            command_line: "  ".to_string(),
            only_this_process: true,
            detach_on_exit: true,
        })
        .expect_err("empty command line should fail");
        assert!(matches!(error, ExecutionError::Session(_)));
    }

    #[test]
    fn user_mode_attach_normalization_rejects_zero_pid() {
        let error = normalize_user_mode_attach(UserModeAttach::AttachPid {
            pid: 0,
            non_invasive: false,
            detach_on_exit: true,
        })
        .expect_err("pid 0 should fail");
        assert!(matches!(error, ExecutionError::Session(_)));
    }

    #[test]
    fn user_mode_attach_connection_keys_are_unique_per_target() {
        let launch_key = UserModeAttach::Launch {
            command_line: "C:\\app.exe".to_string(),
            only_this_process: true,
            detach_on_exit: true,
        }
        .connection_key();
        let attach_key = UserModeAttach::AttachPid {
            pid: 1234,
            non_invasive: false,
            detach_on_exit: true,
        }
        .connection_key();
        assert!(launch_key.starts_with("user-launch:"));
        assert!(attach_key.starts_with("user-attach:"));
        assert_ne!(launch_key, attach_key);
    }
}
