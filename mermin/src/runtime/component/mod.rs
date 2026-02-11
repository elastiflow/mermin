//! Unified component lifecycle management.
//!
//! This module provides [`ComponentManager`] for registering and coordinating
//! both async tokio tasks and dedicated OS threads, with ordered shutdown and
//! hot-reloadable configuration support.

pub mod error;
pub mod handle;
pub mod manager;

pub use error::ShutdownResult;
pub use handle::{Handle, ShutdownEventFd};
pub use manager::ComponentManager;
