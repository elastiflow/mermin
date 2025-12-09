//! Helper functions for flow lifecycle metrics.

use mermin_common::Direction;

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
///
/// Always increments the aggregated counter. If debug metrics are enabled,
/// also increments the per-interface debug counter.
pub fn inc_flows_created(interface: &str) {
    // Always increment aggregated metric
    registry::FLOWS_CREATED_TOTAL.inc();

    // Conditionally increment debug metric with labels
    if registry::debug_enabled() {
        registry::FLOWS_CREATED_BY_INTERFACE_TOTAL
            .with_label_values(&[interface])
            .inc();
    }
}

/// Increment the active flows gauge.
pub fn inc_flows_active(interface: &str) {
    // Always increment aggregated metric
    registry::FLOWS_ACTIVE_TOTAL.inc();

    // Conditionally increment debug metric with labels
    if registry::debug_enabled() {
        registry::FLOWS_ACTIVE_BY_INTERFACE_TOTAL
            .with_label_values(&[interface])
            .inc();
    }
}

/// Decrement the active flows gauge.
pub fn dec_flows_active(interface: &str) {
    // Always decrement aggregated metric
    registry::FLOWS_ACTIVE_TOTAL.dec();

    // Conditionally decrement debug metric with labels
    if registry::debug_enabled() {
        registry::FLOWS_ACTIVE_BY_INTERFACE_TOTAL
            .with_label_values(&[interface])
            .dec();
    }
}

/// Increment the producer flow spans counter.
pub fn inc_producer_flow_spans(interface: &str, status: FlowSpanProducerStatus) {
    // Always increment aggregated metric (by status only, no interface label)
    registry::PRODUCER_FLOW_SPANS_TOTAL
        .with_label_values(&[status.as_ref()])
        .inc();

    // Conditionally increment debug metric with labels
    if registry::debug_enabled() {
        registry::PRODUCER_FLOW_SPANS_BY_INTERFACE_TOTAL
            .with_label_values(&[interface, status.as_ref()])
            .inc();
    }
}

/// Increment the flow stats map access counter.
pub fn inc_flow_stats_map_access(status: FlowStatsStatus) {
    registry::FLOW_STATS_ACCESS_TOTAL
        .with_label_values(&[status.as_ref()])
        .inc();
}

/// Increment the packets total counter.
///
/// Tracks packet deltas by interface and direction.
/// For bidirectional flows:
/// - If direction = Ingress: forward packets came via ingress, reverse via egress
/// - If direction = Egress: forward packets came via egress, reverse via ingress
pub fn inc_packets_total(interface: &str, direction: Direction, count: u64) {
    // Always increment aggregated metric (no interface or direction labels)
    registry::PACKETS_TOTAL.inc_by(count);

    // Conditionally increment debug metric with labels
    if registry::debug_enabled() {
        let direction_str = match direction {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        };
        registry::PACKETS_BY_INTERFACE_TOTAL
            .with_label_values(&[interface, direction_str])
            .inc_by(count);
    }
}
