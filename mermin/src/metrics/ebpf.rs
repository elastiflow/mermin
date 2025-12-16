//! Helper functions for eBPF-related metrics.

use crate::metrics::registry;

/// eBPF map names for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapName {
    FlowStats,
    FlowEvents,
    ListeningPorts,
}

impl AsRef<str> for EbpfMapName {
    fn as_ref(&self) -> &str {
        match self {
            EbpfMapName::FlowStats => "FLOW_STATS",
            EbpfMapName::FlowEvents => "FLOW_EVENTS",
            EbpfMapName::ListeningPorts => "LISTENING_PORTS",
        }
    }
}

/// eBPF map operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapOperation {
    Read,
    Write,
    Delete,
}

impl AsRef<str> for EbpfMapOperation {
    fn as_ref(&self) -> &str {
        match self {
            EbpfMapOperation::Read => "read",
            EbpfMapOperation::Write => "write",
            EbpfMapOperation::Delete => "delete",
        }
    }
}

/// eBPF map operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapStatus {
    Ok,
    Error,
    NotFound,
}

impl AsRef<str> for EbpfMapStatus {
    fn as_ref(&self) -> &str {
        match self {
            EbpfMapStatus::Ok => "ok",
            EbpfMapStatus::Error => "error",
            EbpfMapStatus::NotFound => "not_found",
        }
    }
}

/// Increment the eBPF map operations counter.
pub fn inc_ebpf_map_ops(map: EbpfMapName, operation: EbpfMapOperation, status: EbpfMapStatus) {
    registry::EBPF_MAP_OPS_TOTAL
        .with_label_values(&[map.as_ref(), operation.as_ref(), status.as_ref()])
        .inc();
}

/// Increment the eBPF map bytes counter.
///
/// Used to track bytes read from ring buffers (e.g., FLOW_EVENTS).
pub fn inc_map_bytes(map: EbpfMapName, bytes: u64) {
    registry::EBPF_MAP_BYTES_TOTAL
        .with_label_values(&[map.as_ref()])
        .inc_by(bytes);
}

/// Increment the orphan cleanup counter.
///
/// Call this when the orphan scanner successfully removes a stale entry.
pub fn inc_orphans_cleaned(count: u64) {
    registry::EBPF_ORPHANS_CLEANED_TOTAL.inc_by(count);
}

/// Set the current number of entries in the eBPF map.
///
/// The `map` parameter should be one of: "FLOW_STATS", "FLOW_EVENTS", or "LISTENING_PORTS".
pub fn set_map_entries(map: &str, entries: u64) {
    registry::EBPF_MAP_ENTRIES
        .with_label_values(&[map])
        .set(entries as i64);
}

/// Set the maximum capacity of an eBPF map.
///
/// The `map` parameter should be one of: "FLOW_STATS", "FLOW_EVENTS", or "LISTENING_PORTS".
pub fn set_map_capacity(map: &str, capacity: u64) {
    registry::EBPF_MAP_CAPACITY
        .with_label_values(&[map])
        .set(capacity as i64);
}

/// Increment the TC program attached counter.
///
/// Always increments the aggregated counter. If debug metrics are enabled,
/// also increments the per-interface debug counter.
pub fn inc_tc_programs_attached(interface: &str, direction: &str) {
    // Always increment aggregated metric
    registry::TC_PROGRAMS_TOTAL
        .with_label_values(&["attached"])
        .inc();

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
    registry::TC_PROGRAMS_TOTAL
        .with_label_values(&["detached"])
        .inc();

    // Conditionally increment debug metric with labels
    if registry::debug_enabled() {
        registry::TC_PROGRAMS_DETACHED_BY_INTERFACE_TOTAL
            .with_label_values(&[interface, direction])
            .inc();
    }
}
