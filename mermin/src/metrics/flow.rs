//! Helper functions for flow lifecycle metrics.

use crate::metrics::registry;

/// Increment the flow events counter.
///
/// ### Arguments
///
/// - `event_type` - Type of flow event: "received", "dropped_backpressure", or "dropped_error"
pub fn inc_flow_events(event_type: &str) {
    registry::FLOW_EVENTS_TOTAL
        .with_label_values(&[event_type])
        .inc();
}

/// Increment the flow creation counter.
///
/// ### Arguments
///
/// - `interface` - Network interface name
pub fn inc_flows_created(interface: &str) {
    registry::FLOWS_CREATED
        .with_label_values(&[interface])
        .inc();

    registry::FLOWS_ACTIVE.with_label_values(&[interface]).inc();
}

/// Decrement the active flows gauge.
///
/// ### Arguments
///
/// - `interface` - Network interface name
pub fn dec_flows_active(interface: &str) {
    registry::FLOWS_ACTIVE.with_label_values(&[interface]).dec();
}

/// Increment the producer flow spans counter.
///
/// ### Arguments
///
/// - `interface` - Network interface name
/// - `status` - Flow span status: "created", "active", "recorded", "idled", or "dropped"
pub fn inc_producer_flow_spans(interface: &str, status: &str) {
    registry::PRODUCER_FLOW_SPANS_TOTAL
        .with_label_values(&[interface, status])
        .inc();
}

/// Increment the flow stats map access counter.
///
/// ### Arguments
///
/// - `status` - Map access status: "ok", "error", or "not_found"
pub fn inc_flow_stats_map_access(status: &str) {
    registry::FLOW_STATS_MAP_ACCESS_TOTAL
        .with_label_values(&[status])
        .inc();
}
