//! Helper functions for userspace ring buffer and channel metrics.

use crate::metrics::registry;

/// Increment the ring buffer packets counter.
///
/// ### Arguments:
///
/// - `packet_type` - Type of packet: "received", "dropped", or "filtered"
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

/// Set the current size of a channel.
///
/// ### Arguments:
///
/// - `channel` - Channel name: "packet_worker", "decorator_input", or "exporter_input"
/// - `size` - Current number of items in channel
pub fn set_channel_size(channel: &str, size: usize) {
    registry::USERSPACE_CHANNEL_SIZE
        .with_label_values(&[channel])
        .set(size as i64);
}

/// Increment the channel send operations counter.
///
/// ### Arguments:
///
/// - `channel` - Channel name: "packet_worker" or "exporter"
/// - `status` - Send status: "success" or "error"
pub fn inc_channel_sends(channel: &str, status: &str) {
    registry::USERSPACE_CHANNEL_SENDS
        .with_label_values(&[channel, status])
        .inc();
}
