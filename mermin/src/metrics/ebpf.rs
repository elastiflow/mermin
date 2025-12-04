//! Helper functions for eBPF-related metrics.

use crate::metrics::registry;

/// Increment the orphan cleanup counter.
///
/// Call this when the orphan scanner successfully removes a stale entry.
pub fn inc_orphans_cleaned(count: u64) {
    registry::EBPF_ORPHANS_CLEANED_TOTAL.inc_by(count);
}

/// Set the current number of entries in the eBPF map.
pub fn set_map_entries(entries: u64) {
    registry::EBPF_MAP_ENTRIES
        .with_label_values(&["flow_stats"])
        .set(entries as i64);
}

/// Increment the TC program attached counter.
///
/// Always increments the aggregated counter. If debug metrics are enabled,
/// also increments the per-interface debug counter.
pub fn inc_tc_programs_attached(interface: &str, direction: &str) {
    // Always increment aggregated metric
    registry::TC_PROGRAMS_ATTACHED_TOTAL.inc();

    // Conditionally increment debug metric with labels
    if registry::debug_enabled() {
        registry::TC_PROGRAMS_ATTACHED_BY_INTERFACE_TOTAL
            .with_label_values(&[interface, direction])
            .inc();
    }
}

/// Increment the TC program detached counter.
///
/// Always increments the aggregated counter. If debug metrics are enabled,
/// also increments the per-interface debug counter.
pub fn inc_tc_programs_detached(interface: &str, direction: &str) {
    // Always increment aggregated metric
    registry::TC_PROGRAMS_DETACHED_TOTAL.inc();

    // Conditionally increment debug metric with labels
    if registry::debug_enabled() {
        registry::TC_PROGRAMS_DETACHED_BY_INTERFACE_TOTAL
            .with_label_values(&[interface, direction])
            .inc();
    }
}
