//! Packet source handling.
//!
//! This module contains the components responsible for reading packet metadata from
//! the eBPF ring buffer and applying filtering rules before forwarding to the
//! processing pipeline.
//!
//! # Architecture
//!
//! - `filter`: Pre-compiled packet filtering rules
//! - `ringbuf`: Async ring buffer reader that applies filters

pub mod filter;
pub mod ringbuf;
