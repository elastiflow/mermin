//! Helper functions for eBPF-related metrics.

use crate::metrics::{opts, registry};

/// Increment the orphan cleanup counter.
///
/// Call this when the orphan scanner successfully removes a stale entry.
///
/// ### Arguments:
///
/// - `count` - Number of orphaned entries cleaned up
pub fn inc_orphans_cleaned(count: u64) {
    registry::EBPF_ORPHANS_CLEANED.inc_by(count);
}

/// Set the current number of entries in the eBPF map.
///
/// ### Arguments:
///
/// - `entries` - Current number of entries in the flow stats map
pub fn set_map_entries(entries: u64) {
    registry::EBPF_MAP_ENTRIES
        .with_label_values(&["flow_stats"])
        .set(entries as i64);
}

/// Increment the TC program attached counter.
///
/// ### Arguments:
///
/// - `interface` - Network interface name
/// - `direction` - Traffic direction ("ingress" or "egress")
pub fn inc_tc_programs_attached(interface: &str, direction: &str) {
    opts::with_debug_metrics(|| {
        registry::TC_PROGRAMS_ATTACHED
            .with_label_values(&[interface, direction])
            .inc();
    });
}

/// Increment the TC program detached counter.
///
/// ### Arguments:
///
/// - `interface` - Network interface name
/// - `direction` - Traffic direction ("ingress" or "egress")
pub fn inc_tc_programs_detached(interface: &str, direction: &str) {
    opts::with_debug_metrics(|| {
        registry::TC_PROGRAMS_DETACHED
            .with_label_values(&[interface, direction])
            .inc();
    });
}
