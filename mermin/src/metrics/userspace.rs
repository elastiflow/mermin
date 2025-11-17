//! Userspace metrics helper functions.
//!
//! This module provides convenient functions for updating userspace-related metrics
//! such as ring buffer statistics and channel capacity/size tracking.

use super::registry;

/// Set the capacity of an internal channel.
///
/// # Arguments
/// * `channel` - The name of the channel (e.g., "packet_worker", "exporter")
/// * `capacity` - The capacity of the channel
pub fn set_channel_capacity(channel: &str, capacity: usize) {
    registry::USERSPACE_CHANNEL_CAPACITY
        .with_label_values(&[channel])
        .set(capacity as i64);
}

/// Set the current size (number of items) in an internal channel.
///
/// # Arguments
/// * `channel` - The name of the channel (e.g., "decorator_input", "exporter_input")
/// * `size` - The current number of items in the channel
pub fn set_channel_size(channel: &str, size: usize) {
    registry::USERSPACE_CHANNEL_SIZE
        .with_label_values(&[channel])
        .set(size as i64);
}

/// Increment the ring buffer packet counter.
///
/// # Arguments
/// * `typ` - The type of packet event (e.g., "received", "filtered", "dropped")
/// * `count` - The number of packets to increment by
pub fn inc_ringbuf_packets(typ: &str, count: u64) {
    registry::USERSPACE_RINGBUF_PACKETS
        .with_label_values(&[typ])
        .inc_by(count);
}

/// Increment the ring buffer byte counter.
///
/// # Arguments
/// * `bytes` - The number of bytes to increment by
pub fn inc_ringbuf_bytes(bytes: u64) {
    registry::USERSPACE_RINGBUF_BYTES.inc_by(bytes);
}
