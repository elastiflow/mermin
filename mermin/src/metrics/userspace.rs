//! Helper functions for userspace ring buffer and channel metrics.

use crate::metrics::registry;

/// Type of packet in the ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Received,
    Filtered,
}

impl AsRef<str> for PacketType {
    fn as_ref(&self) -> &str {
        match self {
            PacketType::Received => "received",
            PacketType::Filtered => "filtered",
        }
    }
}

/// Channel name for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelName {
    PacketWorker,
    Exporter,
    DecoratorInput,
    ExporterInput,
}

impl AsRef<str> for ChannelName {
    fn as_ref(&self) -> &str {
        match self {
            ChannelName::PacketWorker => "packet_worker",
            ChannelName::Exporter => "exporter",
            ChannelName::DecoratorInput => "decorator_input",
            ChannelName::ExporterInput => "exporter_input",
        }
    }
}

/// Channel send operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSendStatus {
    Success,
    Error,
}

impl AsRef<str> for ChannelSendStatus {
    fn as_ref(&self) -> &str {
        match self {
            ChannelSendStatus::Success => "success",
            ChannelSendStatus::Error => "error",
        }
    }
}

/// Increment the ring buffer packets counter.
pub fn inc_ringbuf_packets(packet_type: PacketType, count: u64) {
    registry::USERSPACE_RINGBUF_PACKETS
        .with_label_values(&[packet_type.as_ref()])
        .inc_by(count);
}

/// Increment the ring buffer bytes counter.
pub fn inc_ringbuf_bytes(bytes: u64) {
    registry::USERSPACE_RINGBUF_BYTES.inc_by(bytes);
}

/// Set the capacity of a channel.
pub fn set_channel_capacity(channel: ChannelName, capacity: usize) {
    registry::USERSPACE_CHANNEL_CAPACITY
        .with_label_values(&[channel.as_ref()])
        .set(capacity as i64);
}

/// Set the current size of a channel.
pub fn set_channel_size(channel: ChannelName, size: usize) {
    registry::USERSPACE_CHANNEL_SIZE
        .with_label_values(&[channel.as_ref()])
        .set(size as i64);
}

/// Increment the channel send operations counter.
pub fn inc_channel_sends(channel: ChannelName, status: ChannelSendStatus) {
    registry::USERSPACE_CHANNEL_SENDS
        .with_label_values(&[channel.as_ref(), status.as_ref()])
        .inc();
}
