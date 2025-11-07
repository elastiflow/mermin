// Interface monitoring module using pure Rust netlink implementation
//
// This module provides a pure Rust implementation for monitoring network interface
// changes using the netlink protocol. It replaces raw libc syscalls with the
// netlink-sys crate while maintaining compatibility with namespace switching.

pub mod controller;
pub mod netlink_monitor;
pub mod netns;

// Re-export key types for convenience
pub use controller::IfaceController;
pub use netlink_monitor::{LinkEvent, NetlinkMonitor};
