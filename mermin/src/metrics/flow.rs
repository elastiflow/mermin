//! Helper functions for flow lifecycle metrics.

use crate::metrics::registry;

/// Type of flow event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEventResult {
    Received,
    DroppedBackpressure,
    DroppedError,
}

impl AsRef<str> for FlowEventResult {
    fn as_ref(&self) -> &str {
        match self {
            FlowEventResult::Received => "received",
            FlowEventResult::DroppedBackpressure => "dropped_backpressure",
            FlowEventResult::DroppedError => "dropped_error",
        }
    }
}

/// Flow span status for producer metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSpanProducerStatus {
    Created,
    Active,
    Recorded,
    Idled,
    Dropped,
}

impl AsRef<str> for FlowSpanProducerStatus {
    fn as_ref(&self) -> &str {
        match self {
            FlowSpanProducerStatus::Created => "created",
            FlowSpanProducerStatus::Active => "active",
            FlowSpanProducerStatus::Recorded => "recorded",
            FlowSpanProducerStatus::Idled => "idled",
            FlowSpanProducerStatus::Dropped => "dropped",
        }
    }
}

/// Flow stats map access status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowStatsStatus {
    Ok,
    Error,
    NotFound,
}

impl AsRef<str> for FlowStatsStatus {
    fn as_ref(&self) -> &str {
        match self {
            FlowStatsStatus::Ok => "ok",
            FlowStatsStatus::Error => "error",
            FlowStatsStatus::NotFound => "not_found",
        }
    }
}

/// Increment the flow events counter.
pub fn inc_flow_events(event_type: FlowEventResult) {
    registry::FLOW_EVENTS_TOTAL
        .with_label_values(&[event_type.as_ref()])
        .inc();
}

/// Increment the flow creation counter.
pub fn inc_flows_created(interface: &str) {
    registry::FLOWS_CREATED
        .with_label_values(&[interface])
        .inc();

    registry::FLOWS_ACTIVE.with_label_values(&[interface]).inc();
}

/// Decrement the active flows gauge.
pub fn dec_flows_active(interface: &str) {
    registry::FLOWS_ACTIVE.with_label_values(&[interface]).dec();
}

/// Increment the producer flow spans counter.
pub fn inc_producer_flow_spans(interface: &str, status: FlowSpanProducerStatus) {
    registry::PRODUCER_FLOW_SPANS_TOTAL
        .with_label_values(&[interface, status.as_ref()])
        .inc();
}

/// Increment the flow stats map access counter.
pub fn inc_flow_stats_map_access(status: FlowStatsStatus) {
    registry::FLOW_STATS_MAP_ACCESS_TOTAL
        .with_label_values(&[status.as_ref()])
        .inc();
}
