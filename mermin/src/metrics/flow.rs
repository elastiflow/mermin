//! Enums for flow lifecycle metrics labels.

/// Type of flow event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEventResult {
    Received,
    Filtered,
    DroppedBackpressure,
    DroppedError,
}

impl FlowEventResult {
    pub const fn as_str(self) -> &'static str {
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

impl FlowSpanProducerStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            FlowSpanProducerStatus::Created => "created",
            FlowSpanProducerStatus::Recorded => "recorded",
            FlowSpanProducerStatus::Idled => "idled",
            FlowSpanProducerStatus::Dropped => "dropped",
        }
    }
}
