//! Helper functions for flow lifecycle metrics.

use std::time::Duration;

use crate::metrics::registry;

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

/// Increment the flow expiry counter and decrement active count.
///
/// ### Arguments
///
/// - `interface` - Network interface name
/// - `reason` - Reason for expiry: "timeout", "recorded", "error", "guard_cleanup"
pub fn inc_flows_expired(interface: &str, reason: &str) {
    registry::FLOWS_EXPIRED.with_label_values(&[reason]).inc();

    registry::FLOWS_ACTIVE.with_label_values(&[interface]).dec();
}

/// Record flow duration.
///
/// ### Arguments
///
/// - `duration` - Duration from first to last packet
pub fn observe_flow_duration(duration: Duration) {
    registry::FLOW_DURATION.observe(duration.as_secs_f64());
}
