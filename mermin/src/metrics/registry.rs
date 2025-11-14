//! Global metrics registry and collector definitions.
//!
//! This module defines all Prometheus metrics used by Mermin and provides
//! a centralized registry for metric collection.

use lazy_static::lazy_static;
use prometheus::{
    GaugeVec, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry,
};

lazy_static! {
    /// Global Prometheus registry for all Mermin metrics.
    pub static ref REGISTRY: Registry = Registry::new();

    // ============================================================================
    // eBPF Resource Metrics
    // ============================================================================

    /// Current number of entries in the eBPF FLOW_STATS_MAP.
    pub static ref EBPF_MAP_ENTRIES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("mermin_ebpf_map_entries", "Current number of entries in eBPF maps")
            .namespace("mermin"),
        &["map"]
    ).expect("failed to create ebpf_map_entries metric");

    /// Maximum capacity of eBPF maps.
    pub static ref EBPF_MAP_CAPACITY: IntGaugeVec = IntGaugeVec::new(
        Opts::new("mermin_ebpf_map_capacity", "Maximum capacity of eBPF maps")
            .namespace("mermin"),
        &["map"]
    ).expect("failed to create ebpf_map_capacity metric");

    /// Utilization ratio of eBPF maps (entries/capacity).
    pub static ref EBPF_MAP_UTILIZATION: GaugeVec = GaugeVec::new(
        Opts::new("mermin_ebpf_map_utilization_ratio", "Utilization ratio of eBPF maps (0.0-1.0)")
            .namespace("mermin"),
        &["map"]
    ).expect("failed to create ebpf_map_utilization metric");

    /// Total number of dropped ring buffer events due to buffer full.
    pub static ref EBPF_RING_BUFFER_DROPS: IntCounter = IntCounter::new(
        "mermin_ebpf_ring_buffer_drops_total",
        "Total number of ring buffer events dropped due to buffer full"
    ).expect("failed to create ebpf_ring_buffer_drops metric");

    /// Total number of orphaned entries cleaned up by the orphan scanner.
    pub static ref EBPF_ORPHANS_CLEANED: IntCounter = IntCounter::new(
        "mermin_ebpf_orphans_cleaned_total",
        "Total number of orphaned eBPF map entries cleaned up"
    ).expect("failed to create ebpf_orphans_cleaned metric");

    /// Current number of flows tracked in userspace flow store.
    pub static ref EBPF_USERSPACE_FLOWS: IntGauge = IntGauge::new(
        "mermin_ebpf_userspace_flows",
        "Current number of flows tracked in userspace"
    ).expect("failed to create ebpf_userspace_flows metric");

    /// Total number of TC programs attached to interfaces.
    pub static ref TC_PROGRAMS_ATTACHED: IntCounterVec = IntCounterVec::new(
        Opts::new("mermin_tc_programs_attached_total", "Total number of TC programs attached")
            .namespace("mermin"),
        &["interface", "direction"]
    ).expect("failed to create tc_programs_attached metric");

    /// Total number of TC programs detached from interfaces.
    pub static ref TC_PROGRAMS_DETACHED: IntCounterVec = IntCounterVec::new(
        Opts::new("mermin_tc_programs_detached_total", "Total number of TC programs detached")
            .namespace("mermin"),
        &["interface", "direction"]
    ).expect("failed to create tc_programs_detached metric");

    // ============================================================================
    // Flow Lifecycle Metrics
    // ============================================================================

    pub static ref FLOW_EVENTS_DROPPED_BACKPRESSURE: IntCounter = IntCounter::with_opts(
        Opts::new("flow_events_dropped_backpressure_total", "Flow events dropped due to worker channel backpressure")
            .namespace("mermin")
    ).expect("failed to create flow_events_dropped_backpressure metric");

    /// Total number of flows created.
    pub static ref FLOWS_CREATED: IntCounterVec = IntCounterVec::new(
        Opts::new("mermin_flows_created_total", "Total number of flows created")
            .namespace("mermin"),
        &["interface"]
    ).expect("failed to create flows_created metric");

    /// Total number of flows expired/removed.
    pub static ref FLOWS_EXPIRED: IntCounterVec = IntCounterVec::new(
        Opts::new("mermin_flows_expired_total", "Total number of flows expired")
            .namespace("mermin"),
        &["reason"]  // timeout, recorded, error, guard_cleanup
    ).expect("failed to create flows_expired metric");

    /// Current number of active flows being tracked.
    pub static ref FLOWS_ACTIVE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("mermin_flows_active", "Current number of active flows")
            .namespace("mermin"),
        &["interface"]
    ).expect("failed to create flows_active metric");

    /// Histogram of flow durations.
    pub static ref FLOW_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("mermin_flow_duration_seconds", "Duration of flows from first to last packet")
            .namespace("mermin")
            .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0])
    ).expect("failed to create flow_duration metric");

    // ============================================================================
    // Export Metrics
    // ============================================================================

    /// Total number of spans successfully exported.
    pub static ref SPANS_EXPORTED: IntCounter = IntCounter::new(
        "mermin_spans_exported_total",
        "Total number of flow spans successfully exported"
    ).expect("failed to create spans_exported metric");

    /// Total number of span export errors.
    pub static ref SPANS_EXPORT_ERRORS: IntCounterVec = IntCounterVec::new(
        Opts::new("mermin_spans_export_errors_total", "Total number of span export errors")
            .namespace("mermin"),
        &["reason"]
    ).expect("failed to create spans_export_errors metric");

    /// Histogram of export batch sizes.
    pub static ref EXPORT_BATCH_SIZE: Histogram = Histogram::with_opts(
        HistogramOpts::new("mermin_export_batch_size", "Number of spans per export batch")
            .namespace("mermin")
            .buckets(vec![1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0])
    ).expect("failed to create export_batch_size metric");

    /// Histogram of export operation latency.
    pub static ref EXPORT_LATENCY: Histogram = Histogram::with_opts(
        HistogramOpts::new("mermin_export_latency_seconds", "Latency of span export operations")
            .namespace("mermin")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
    ).expect("failed to create export_latency metric");

    // ============================================================================
    // Per-Interface Statistics
    // ============================================================================

    /// Total number of packets processed.
    pub static ref PACKETS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("mermin_packets_total", "Total number of packets processed")
            .namespace("mermin"),
        &["interface", "direction"]  // direction: ingress/egress
    ).expect("failed to create packets_total metric");

    /// Total number of bytes processed.
    pub static ref BYTES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("mermin_bytes_total", "Total number of bytes processed")
            .namespace("mermin"),
        &["interface", "direction"]
    ).expect("failed to create bytes_total metric");
}

/// Initialize the metrics registry by registering all collectors.
///
/// This should be called once at application startup before any metrics are used.
pub fn init_registry() -> Result<(), prometheus::Error> {
    // eBPF metrics
    REGISTRY.register(Box::new(EBPF_MAP_ENTRIES.clone()))?;
    REGISTRY.register(Box::new(EBPF_MAP_CAPACITY.clone()))?;
    REGISTRY.register(Box::new(EBPF_MAP_UTILIZATION.clone()))?;
    REGISTRY.register(Box::new(EBPF_RING_BUFFER_DROPS.clone()))?;
    REGISTRY.register(Box::new(EBPF_ORPHANS_CLEANED.clone()))?;
    REGISTRY.register(Box::new(EBPF_USERSPACE_FLOWS.clone()))?;
    REGISTRY.register(Box::new(TC_PROGRAMS_ATTACHED.clone()))?;
    REGISTRY.register(Box::new(TC_PROGRAMS_DETACHED.clone()))?;

    // Flow metrics
    REGISTRY.register(Box::new(FLOW_EVENTS_DROPPED_BACKPRESSURE.clone()))?;
    REGISTRY.register(Box::new(FLOWS_CREATED.clone()))?;
    REGISTRY.register(Box::new(FLOWS_EXPIRED.clone()))?;
    REGISTRY.register(Box::new(FLOWS_ACTIVE.clone()))?;
    REGISTRY.register(Box::new(FLOW_DURATION.clone()))?;

    // Export metrics
    REGISTRY.register(Box::new(SPANS_EXPORTED.clone()))?;
    REGISTRY.register(Box::new(SPANS_EXPORT_ERRORS.clone()))?;
    REGISTRY.register(Box::new(EXPORT_BATCH_SIZE.clone()))?;
    REGISTRY.register(Box::new(EXPORT_LATENCY.clone()))?;

    // Interface metrics
    REGISTRY.register(Box::new(PACKETS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(BYTES_TOTAL.clone()))?;

    Ok(())
}
