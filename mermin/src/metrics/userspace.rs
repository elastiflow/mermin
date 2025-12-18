//! Enums for userspace ring buffer and channel metrics labels.

/// Channel name for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelName {
    PacketWorker,
    ProducerOutput,
    DecoratorOutput,
}

impl AsRef<str> for ChannelName {
    fn as_ref(&self) -> &str {
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

impl AsRef<str> for ChannelSendStatus {
    fn as_ref(&self) -> &str {
        match self {
            ChannelSendStatus::Success => "success",
            ChannelSendStatus::Error => "error",
            ChannelSendStatus::Backpressure => "backpressure",
        }
    }
}
