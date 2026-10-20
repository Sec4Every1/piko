//! The only native FFI boundary. This development transport is scoped to one
//! Windows user and logon session. It is not the future privileged service API.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::*;

#[cfg(windows)]
pub mod event_log;
#[cfg(windows)]
pub mod file_response;
#[cfg(windows)]
pub mod network_control;
#[cfg(windows)]
pub mod network_elevation;
#[cfg(windows)]
pub mod observations;
#[cfg(windows)]
pub mod references;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod software_inventory;

#[cfg(windows)]
pub mod diagnostics;

#[cfg(windows)]
pub mod startup;

#[cfg(windows)]
pub mod signature;

#[cfg(windows)]
pub mod etw;

#[cfg(windows)]
pub mod restricted;

#[cfg(windows)]
pub mod process_control;

#[cfg(windows)]
pub mod registry_history;

#[cfg(windows)]
mod udp;
