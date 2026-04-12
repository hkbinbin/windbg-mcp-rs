pub(crate) mod command_sync;

#[cfg(windows)]
pub(crate) mod events;

#[cfg(windows)]
pub(crate) mod module_match;

#[cfg(windows)]
pub(crate) mod synthetic_load;

#[cfg(windows)]
pub(crate) use events::{HeadlessEventCallbacks, HeadlessEventControl};
