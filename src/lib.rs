pub mod catalog;
pub mod executor;
mod headless;
#[cfg(windows)]
pub mod plugin_server;
pub mod resources;
pub mod server;
pub mod session_manager;

#[cfg(windows)]
pub mod extension;

pub use catalog::{Catalog, CatalogEntry, CatalogSection};
pub use executor::{
    CommandDispatcher, CommandExecutionResult, DebuggerExecutionState, ExecutionError,
    ExecutionMode, OutputEntry, OutputSnapshot, build_command, default_attach_timeout,
};
#[cfg(windows)]
pub use plugin_server::{PluginServerControl, PluginServerStatus};
pub use server::WindbgMcpServer;
pub use session_manager::{
    CloseSessionResult, HeadlessSessionInfo, HeadlessSessionList, HeadlessSessionManager,
};
