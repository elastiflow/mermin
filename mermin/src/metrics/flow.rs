//! Helper functions for flow lifecycle metrics.

use std::time::Duration;

use crate::metrics::registry;

/// Increment the flow creation counter by protocol.
///
/// ### Arguments
///
/// - `protocol` - Protocol name (e.g., "tcp", "udp", "icmp", "icmpv6")
/// - `interface` - Network interface name
pub fn inc_flows_created_by_protocol(protocol: &str, interface: &str) {
    registry::FLOWS_BY_PROTOCOL
        .with_label_values(&[protocol, interface])
        .inc();

    registry::FLOWS_ACTIVE_BY_PROTOCOL
        .with_label_values(&[protocol, interface])
        .inc();
}

/// Decrement the active flow counter by protocol and increment expiry counter.
///
/// ### Arguments
///
/// - `protocol` - Protocol name (e.g., "tcp", "udp", "icmp", "icmpv6")
/// - `interface` - Network interface name
/// - `reason` - Reason for expiry: "timeout", "recorded", "error", "guard_cleanup"
pub fn inc_flows_expired_by_protocol(protocol: &str, interface: &str, reason: &str) {
    registry::FLOWS_EXPIRED.with_label_values(&[reason]).inc();

    registry::FLOWS_ACTIVE_BY_PROTOCOL
        .with_label_values(&[protocol, interface])
        .dec();
}

/// Record flow duration.
///
/// ### Arguments
///
/// - `duration` - Duration from first to last packet
pub fn observe_flow_duration(duration: Duration) {
    registry::FLOW_DURATION.observe(duration.as_secs_f64());
}

/// Increment the packets filtered counter.
///
/// ### Arguments
///
/// - `interface` - Network interface name
/// - `reason` - Reason for filtering (e.g., "source_filter", "destination_filter")
pub fn inc_packets_filtered(interface: &str, reason: &str) {
    registry::PACKETS_FILTERED
        .with_label_values(&[interface, reason])
        .inc();
}
