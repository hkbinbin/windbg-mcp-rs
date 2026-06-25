pub mod catalog;
pub mod daemon;
pub mod daemon_launcher;
pub mod executor;
mod headless;
pub mod resources;
pub mod server;
pub mod session_manager;

pub use catalog::{Catalog, CatalogEntry, CatalogSection};
pub use daemon::{
    DEFAULT_DAEMON_NAME, DaemonRegistry, Request as DaemonRequest, Response as DaemonResponse,
    list_registries, log_path, read_registry, registry_dir, registry_path, remove_registry,
    send_request, write_registry,
};
pub use executor::{
    CommandDispatcher, CommandExecutionResult, DebuggerExecutionState, ExecutionError,
    ExecutionMode, OutputEntry, OutputSnapshot, UserModeAttach, build_command,
    default_attach_timeout,
};
pub use server::WindbgMcpServer;
pub use session_manager::{
    CloseSessionResult, HeadlessSessionInfo, HeadlessSessionList, HeadlessSessionManager,
    RecoverSessionResult,
};
