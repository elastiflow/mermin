//! Global metrics registry and collector definitions.
//!
//! This module defines all Prometheus metrics used by Mermin and provides
//! a centralized registry for metric collection.

use lazy_static::lazy_static;
use prometheus::{
    GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry,
};

lazy_static! {
    /// Global Prometheus registry for all Mermin metrics.
    pub static ref REGISTRY: Registry = Registry::new();

    // ============================================================================
    // eBPF Resource Metrics
    // ============================================================================

    /// Current number of entries in the eBPF FLOW_STATS_MAP.
    pub static ref EBPF_MAP_ENTRIES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ebpf_map_entries", "Current number of entries in eBPF maps")
            .namespace("mermin"),
        &["map"]
    ).expect("failed to create ebpf_map_entries metric");

    /// Maximum capacity of eBPF maps.
    pub static ref EBPF_MAP_CAPACITY: IntGaugeVec = IntGaugeVec::new(
        Opts::new("ebpf_map_capacity", "Maximum capacity of eBPF maps")
            .namespace("mermin"),
        &["map"]
    ).expect("failed to create ebpf_map_capacity metric");

    /// Utilization ratio of eBPF maps (entries/capacity).
    pub static ref EBPF_MAP_UTILIZATION: GaugeVec = GaugeVec::new(
        Opts::new("ebpf_map_utilization_ratio", "Utilization ratio of eBPF maps (0.0-1.0)")
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
        Opts::new("ebpf_tc_programs_attached_total", "Total number of TC programs attached")
            .namespace("mermin"),
        &["interface", "direction"]
    ).expect("failed to create tc_programs_attached metric");

    /// Total number of TC programs detached from interfaces.
    pub static ref TC_PROGRAMS_DETACHED: IntCounterVec = IntCounterVec::new(
        Opts::new("ebpf_tc_programs_detached_total", "Total number of TC programs detached")
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

    // TODO: Implement adaptive sampling in ring buffer consumer (mermin-ebpf/src/main.rs)
    // This metric tracks intentional drops when worker channels are full to prevent complete stalls.
    // Should be incremented when sampling logic drops events based on channel capacity.
    // See: performance.sampling_enabled config option
    /// Total number of flow events sampled (dropped intentionally during backpressure).
    pub static ref FLOW_EVENTS_SAMPLED: IntCounter = IntCounter::with_opts(
        Opts::new("flow_events_sampled_total", "Flow events sampled (dropped) during adaptive backpressure")
            .namespace("mermin")
    ).expect("failed to create flow_events_sampled metric");

    // TODO: Implement dynamic sampling rate gauge in ring buffer consumer
    // Should be updated when sampling logic adjusts drop rate based on channel utilization.
    // One gauge per worker thread for granular visibility.
    /// Current adaptive sampling rate (0.0 = no sampling, 1.0 = dropping everything).
    pub static ref FLOW_EVENTS_SAMPLING_RATE: GaugeVec = GaugeVec::new(
        Opts::new("flow_events_sampling_rate", "Current adaptive sampling rate")
            .namespace("mermin"),
        &["worker"]
    ).expect("failed to create flow_events_sampling_rate metric");

    // TODO: Add channel monitoring in pipeline (main.rs)
    // Calculate ratio = current_len / capacity for each channel periodically.
    // Channels: worker channels, flow_span_rx, k8s_decorated_flow_span_tx
    // Helps identify bottlenecks and backpressure points.
    /// Channel capacity utilization ratio (0.0-1.0).
    pub static ref CHANNEL_CAPACITY_USED_RATIO: GaugeVec = GaugeVec::new(
        Opts::new("channel_capacity_used_ratio", "Channel capacity utilization ratio (0.0 to 1.0)")
            .namespace("mermin"),
        &["channel"]
    ).expect("failed to create channel_capacity_used_ratio metric");

    // TODO: Increment when try_send() fails on any channel
    // Add to worker dispatch, decorator send, and export send paths.
    // Indicates when backpressure is actively blocking the pipeline.
    /// Total number of times a channel was full (try_send failed).
    pub static ref CHANNEL_FULL_EVENTS: IntCounterVec = IntCounterVec::new(
        Opts::new("channel_full_events_total", "Total number of channel full events")
            .namespace("mermin"),
        &["channel"]
    ).expect("failed to create channel_full_events metric");

    // TODO: Add timing instrumentation to pipeline stages (main.rs)
    // Stages: "flow_production", "k8s_decoration", "otlp_export"
    // Wrap each stage with: let timer = PROCESSING_LATENCY.with_label_values(&["stage"]).start_timer();
    // Critical for identifying slow stages under load.
    /// Processing latency by pipeline stage.
    pub static ref PROCESSING_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("processing_latency_seconds", "Processing latency by pipeline stage")
            .namespace("mermin")
            .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]),
        &["stage"]
    ).expect("failed to create processing_latency metric");

    /// Total number of flow spans dropped due to export channel full.
    pub static ref FLOW_SPANS_DROPPED_EXPORT_FAILURE: IntCounter = IntCounter::with_opts(
        Opts::new("flow_spans_dropped_export_failure_total", "Flow spans dropped due to export channel full")
            .namespace("mermin")
    ).expect("failed to create flow_spans_dropped_export_failure metric");

    /// Total number of export operations that timed out.
    pub static ref EXPORT_TIMEOUTS: IntCounter = IntCounter::with_opts(
        Opts::new("export_timeouts_total", "Total number of export operations that timed out")
            .namespace("mermin")
    ).expect("failed to create export_timeouts metric");

    /// Time spent blocked waiting for export operations to complete.
    pub static ref EXPORT_BLOCKING_TIME: Histogram = Histogram::with_opts(
        HistogramOpts::new("export_blocking_time_seconds", "Time spent blocked waiting for export operations")
            .namespace("mermin")
            .buckets(vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0])
    ).expect("failed to create export_blocking_time metric");

    /// Total number of flows created.
    pub static ref FLOWS_CREATED: IntCounterVec = IntCounterVec::new(
        Opts::new("span_flows_created_total", "Total number of flows created")
            .namespace("mermin"),
        &["interface"]
    ).expect("failed to create flows_created metric");

    /// Total number of flows expired/removed.
    pub static ref FLOWS_EXPIRED: IntCounterVec = IntCounterVec::new(
        Opts::new("span_flows_expired_total", "Total number of flows expired")
            .namespace("mermin"),
        &["reason"]  // timeout, recorded, error, guard_cleanup
    ).expect("failed to create flows_expired metric");

    /// Current number of active flows being tracked.
    pub static ref FLOWS_ACTIVE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("span_flows_active", "Current number of active flows")
            .namespace("mermin"),
        &["interface"]
    ).expect("failed to create flows_active metric");

    /// Histogram of flow durations.
    pub static ref FLOW_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("span_flow_duration_seconds", "Duration of flows from first to last packet")
            .namespace("mermin")
            .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0])
    ).expect("failed to create flow_duration metric");

    // ============================================================================
    // Export Metrics
    // ============================================================================

    /// Total number of spans successfully exported.
    pub static ref SPANS_EXPORTED: IntCounter = IntCounter::new(
        "mermin_export_spans_total",
        "Total number of flow spans successfully exported"
    ).expect("failed to create spans_exported metric");

    /// Total number of span export errors.
    pub static ref SPANS_EXPORT_ERRORS: IntCounterVec = IntCounterVec::new(
        Opts::new("export_errors_total", "Total number of span export errors")
            .namespace("mermin"),
        &["reason"]
    ).expect("failed to create spans_export_errors metric");

    /// Histogram of export batch sizes.
    pub static ref EXPORT_BATCH_SIZE: Histogram = Histogram::with_opts(
        HistogramOpts::new("export_batch_size", "Number of spans per export batch")
            .namespace("mermin")
            .buckets(vec![1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0])
    ).expect("failed to create export_batch_size metric");

    /// Histogram of export operation latency.
    pub static ref EXPORT_LATENCY: Histogram = Histogram::with_opts(
        HistogramOpts::new("export_latency_seconds", "Latency of span export operations")
            .namespace("mermin")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
    ).expect("failed to create export_latency metric");

    // ============================================================================
    // Kubernetes Watcher Metrics
    // ============================================================================

    /// Total number of K8s resource watcher events received.
    pub static ref K8S_WATCHER_EVENTS: IntCounterVec = IntCounterVec::new(
        Opts::new("k8s_watcher_events_total", "Total number of K8s resource watcher events")
            .namespace("mermin"),
        &["resource", "event_type"]  // event_type: applied, deleted, restarted
    ).expect("failed to create k8s_watcher_events metric");

    /// Total number of K8s watcher errors.
    pub static ref K8S_WATCHER_ERRORS: IntCounterVec = IntCounterVec::new(
        Opts::new("k8s_watcher_errors_total", "Total number of K8s watcher errors")
            .namespace("mermin"),
        &["resource"]
    ).expect("failed to create k8s_watcher_errors metric");

    /// Total number of K8s IP index updates triggered.
    pub static ref K8S_IP_INDEX_UPDATES: IntCounter = IntCounter::with_opts(
        Opts::new("k8s_ip_index_updates_total", "Total number of K8s IP index updates")
            .namespace("mermin")
    ).expect("failed to create k8s_ip_index_updates metric");

    /// Histogram of K8s IP index update duration.
    pub static ref K8S_IP_INDEX_UPDATE_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("k8s_ip_index_update_duration_seconds", "Duration of K8s IP index updates")
            .namespace("mermin")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
    ).expect("failed to create k8s_ip_index_update_duration metric");

    // ============================================================================
    // Per-Interface Statistics
    // ============================================================================

    /// Total number of packets processed.
    pub static ref PACKETS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("packets_total", "Total number of packets processed")
            .namespace("mermin"),
        &["interface", "direction"]  // direction: ingress/egress
    ).expect("failed to create packets_total metric");

    /// Total number of bytes processed.
    pub static ref BYTES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("bytes_total", "Total number of bytes processed")
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
    REGISTRY.register(Box::new(FLOW_EVENTS_SAMPLED.clone()))?;
    REGISTRY.register(Box::new(FLOW_EVENTS_SAMPLING_RATE.clone()))?;
    REGISTRY.register(Box::new(CHANNEL_CAPACITY_USED_RATIO.clone()))?;
    REGISTRY.register(Box::new(CHANNEL_FULL_EVENTS.clone()))?;
    REGISTRY.register(Box::new(PROCESSING_LATENCY.clone()))?;
    REGISTRY.register(Box::new(FLOW_SPANS_DROPPED_EXPORT_FAILURE.clone()))?;
    REGISTRY.register(Box::new(EXPORT_TIMEOUTS.clone()))?;
    REGISTRY.register(Box::new(EXPORT_BLOCKING_TIME.clone()))?;
    REGISTRY.register(Box::new(FLOWS_CREATED.clone()))?;
    REGISTRY.register(Box::new(FLOWS_EXPIRED.clone()))?;
    REGISTRY.register(Box::new(FLOWS_ACTIVE.clone()))?;
    REGISTRY.register(Box::new(FLOW_DURATION.clone()))?;

    // Export metrics
    REGISTRY.register(Box::new(SPANS_EXPORTED.clone()))?;
    REGISTRY.register(Box::new(SPANS_EXPORT_ERRORS.clone()))?;
    REGISTRY.register(Box::new(EXPORT_BATCH_SIZE.clone()))?;
    REGISTRY.register(Box::new(EXPORT_LATENCY.clone()))?;

    // K8s watcher metrics
    REGISTRY.register(Box::new(K8S_WATCHER_EVENTS.clone()))?;
    REGISTRY.register(Box::new(K8S_WATCHER_ERRORS.clone()))?;
    REGISTRY.register(Box::new(K8S_IP_INDEX_UPDATES.clone()))?;
    REGISTRY.register(Box::new(K8S_IP_INDEX_UPDATE_DURATION.clone()))?;

    // Interface metrics
    REGISTRY.register(Box::new(PACKETS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(BYTES_TOTAL.clone()))?;

    Ok(())
}
