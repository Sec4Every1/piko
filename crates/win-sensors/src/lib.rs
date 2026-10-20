#![forbid(unsafe_code)]
mod normalize;
pub use normalize::{normalize, EventMetadata};

#[cfg(windows)]
mod collector;
#[cfg(windows)]
pub use collector::*;

#[cfg(windows)]
mod observations;
#[cfg(windows)]
pub use observations::*;

#[cfg(windows)]
mod etw;
#[cfg(windows)]
pub use etw::*;
