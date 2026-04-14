pub mod catalog;
pub mod executor;
mod headless;
pub mod resources;
pub mod server;
pub mod session_manager;

pub use catalog::{Catalog, CatalogEntry, CatalogSection};
pub use executor::{
    CommandDispatcher, CommandExecutionResult, DebuggerExecutionState, ExecutionError,
    ExecutionMode, OutputEntry, OutputSnapshot, build_command, default_attach_timeout,
};
pub use server::WindbgMcpServer;
pub use session_manager::{
    CloseSessionResult, HeadlessSessionInfo, HeadlessSessionList, HeadlessSessionManager,
    RecoverSessionResult,
};
