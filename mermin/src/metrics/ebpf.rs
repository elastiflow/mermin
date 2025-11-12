//! Helper functions for eBPF-related metrics.

use crate::metrics::registry;

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

/// Set the current number of flows tracked in userspace.
///
/// ### Arguments:
///
/// - `flows` - Current number of flows in the userspace flow store
pub fn set_userspace_flows(flows: u64) {
    registry::EBPF_USERSPACE_FLOWS.set(flows as i64);
}

/// Increment the TC program attached counter.
///
/// ### Arguments:
///
/// - `interface` - Network interface name
/// - `direction` - Traffic direction ("ingress" or "egress")
pub fn inc_tc_programs_attached(interface: &str, direction: &str) {
    registry::TC_PROGRAMS_ATTACHED
        .with_label_values(&[interface, direction])
        .inc();
}

/// Increment the TC program detached counter.
///
/// ### Arguments:
///
/// - `interface` - Network interface name
/// - `direction` - Traffic direction ("ingress" or "egress")
pub fn inc_tc_programs_detached(interface: &str, direction: &str) {
    registry::TC_PROGRAMS_DETACHED
        .with_label_values(&[interface, direction])
        .inc();
}

/// Increment the eBPF parsing errors counter.
///
/// ### Arguments:
///
/// - `error_type` - Type of parsing error (e.g., "out_of_bounds", "malformed_header")
/// - `interface` - Network interface name
pub fn inc_parsing_errors(error_type: &str, interface: &str) {
    registry::EBPF_PARSING_ERRORS
        .with_label_values(&[error_type, interface])
        .inc();
}

/// Increment the ring buffer events counter.
///
/// ### Arguments:
///
/// - `interface` - Network interface name (or "unknown" if not available)
pub fn inc_ring_buffer_events(interface: &str) {
    registry::EBPF_RING_BUFFER_EVENTS
        .with_label_values(&[interface])
        .inc();
}

/// Increment the flow worker events processed counter.
///
/// ### Arguments:
///
/// - `worker_id` - Worker identifier
pub fn inc_flow_worker_events(worker_id: usize) {
    registry::FLOW_WORKER_EVENTS_PROCESSED
        .with_label_values(&[&worker_id.to_string()])
        .inc();
}

/// Set the current flow worker queue depth.
///
/// ### Arguments:
///
/// - `worker_id` - Worker identifier
/// - `depth` - Current queue depth
pub fn set_flow_worker_queue_depth(worker_id: usize, depth: usize) {
    registry::FLOW_WORKER_QUEUE_DEPTH
        .with_label_values(&[&worker_id.to_string()])
        .set(depth as i64);
}

/// Increment the eBPF map lookup errors counter.
///
/// ### Arguments:
///
/// - `map_name` - Name of the map (e.g., "flow_stats", "flow_events")
pub fn inc_map_lookup_errors(map_name: &str) {
    registry::EBPF_MAP_LOOKUP_ERRORS
        .with_label_values(&[map_name])
        .inc();
}

/// Increment the eBPF map update/insert errors counter.
///
/// ### Arguments:
///
/// - `map_name` - Name of the map (e.g., "flow_stats", "flow_events")
pub fn inc_map_update_errors(map_name: &str) {
    registry::EBPF_MAP_UPDATE_ERRORS
        .with_label_values(&[map_name])
        .inc();
}
