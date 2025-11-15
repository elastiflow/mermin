//! Network interface management and eBPF program lifecycle.
//!
//! This module provides the controller for managing eBPF program attachments
//! to network interfaces, handling interface lifecycle events via netlink.

pub mod controller;
pub mod threads;
pub mod types;
