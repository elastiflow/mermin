//! Enums for flow lifecycle metrics labels.

/// Type of flow event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEventResult {
    Received,
    Filtered,
    DroppedBackpressure,
    DroppedError,
}

impl AsRef<str> for FlowEventResult {
    fn as_ref(&self) -> &str {
        match self {
            FlowEventResult::Received => "received",
            FlowEventResult::Filtered => "filtered",
            FlowEventResult::DroppedBackpressure => "dropped_backpressure",
            FlowEventResult::DroppedError => "dropped_error",
        }
    }
}

/// Flow span status for producer metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSpanProducerStatus {
    Created,
    Recorded,
    Idled,
    Dropped,
}

impl AsRef<str> for FlowSpanProducerStatus {
    fn as_ref(&self) -> &str {
        match self {
            FlowSpanProducerStatus::Created => "created",
            FlowSpanProducerStatus::Recorded => "recorded",
            FlowSpanProducerStatus::Idled => "idled",
            FlowSpanProducerStatus::Dropped => "dropped",
        }
    }
}
