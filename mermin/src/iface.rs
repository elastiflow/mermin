//! Network interface management module.
//!
//! This module provides interface lifecycle management including:
//! - Controller for dynamic eBPF attachment/detachment
//! - Network namespace switching for host interface access

pub mod controller;
pub mod netns;
