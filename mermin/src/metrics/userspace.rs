//! Userspace metrics helper functions.
//!
//! This module provides convenient functions for updating userspace-related metrics
//! such as ring buffer statistics and channel capacity/size tracking.

use crate::metrics::registry;

/// Set the capacity of an internal channel.
///
/// ### Arguments:
///
/// - `packet_type` - Type of packet: "received" or "filtered"
/// - `count` - Number of packets
pub fn inc_ringbuf_packets(packet_type: &str, count: u64) {
    registry::USERSPACE_RINGBUF_PACKETS
        .with_label_values(&[packet_type])
        .inc_by(count);
}

/// Increment the ring buffer bytes counter.
///
/// ### Arguments:
///
/// - `bytes` - Number of bytes received
pub fn inc_ringbuf_bytes(bytes: u64) {
    registry::USERSPACE_RINGBUF_BYTES.inc_by(bytes);
}

/// Set the capacity of a channel.
///
/// ### Arguments:
///
/// - `channel` - Channel name: "packet_worker" or "exporter"
/// - `capacity` - Channel capacity
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

/// Increment the channel send counter.
///
/// # Arguments
/// * `channel` - The name of the channel (e.g., "packet_worker", "exporter")
/// * `status` - The status of the send operation (e.g., "success", "error")
pub fn inc_channel_sends(channel: &str, status: &str) {
    registry::USERSPACE_CHANNEL_SENDS
        .with_label_values(&[channel, status])
        .inc();
}
