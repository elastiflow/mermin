//! Helper functions for userspace ring buffer and channel metrics.

use crate::metrics::registry;

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

/// Set the capacity of a channel.
pub fn set_channel_capacity(channel: ChannelName, capacity: usize) {
    registry::CHANNEL_CAPACITY
        .with_label_values(&[channel.as_ref()])
        .set(capacity as i64);
}

/// Set the current size of a channel.
pub fn set_channel_size(channel: ChannelName, size: usize) {
    registry::CHANNEL_SIZE
        .with_label_values(&[channel.as_ref()])
        .set(size as i64);
}

/// Increment the channel send operations counter.
pub fn inc_channel_sends(channel: ChannelName, status: ChannelSendStatus) {
    registry::CHANNEL_SENDS_TOTAL
        .with_label_values(&[channel.as_ref(), status.as_ref()])
        .inc();
}
