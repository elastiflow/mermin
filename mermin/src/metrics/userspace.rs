//! Enums for userspace ring buffer and channel metrics labels.

/// Channel name for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelName {
    PacketWorker,
    ProducerOutput,
    DecoratorOutput,
}

impl ChannelName {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelName::PacketWorker => "packet_worker",
            ChannelName::ProducerOutput => "producer_output",
            ChannelName::DecoratorOutput => "decorator_output",
        }
    }
}

/// Channel send operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSendStatus {
    Success,
    Error,
    Backpressure,
}

impl ChannelSendStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelSendStatus::Success => "success",
            ChannelSendStatus::Error => "error",
            ChannelSendStatus::Backpressure => "backpressure",
        }
    }
}
