//! Global metrics registry and collector definitions.
//!
//! This module defines all Prometheus metrics used by Mermin and provides
//! a centralized registry for metric collection.

use std::sync::OnceLock;

use lazy_static::lazy_static;
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, Opts, Registry,
};

/// Global flag indicating whether debug metrics with high-cardinality labels are enabled.
///
/// This is initialized once at application startup via `init_registry()` and provides
/// thread-safe access without needing to pass the flag through every function call.
static DEBUG_METRICS_ENABLED: OnceLock<bool> = OnceLock::new();

lazy_static! {
    /// Global Prometheus registry for all Mermin metrics (standard + debug).
    pub static ref REGISTRY: Registry = Registry::new();

    /// Registry for standard metrics only (no high-cardinality labels).
    /// These are always enabled and safe for production use.
    pub static ref STANDARD_REGISTRY: Registry = Registry::new();

    /// Registry for debug metrics only (high-cardinality labels).
    /// Only populated when debug_metrics_enabled = true.
    pub static ref DEBUG_REGISTRY: Registry = Registry::new();

    // ============================================================================
    // eBPF Resource Metrics
    // ============================================================================

    // Standard metrics (always registered)
    pub static ref EBPF_MAP_ENTRIES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("map_entries", "Current number of entries in eBPF maps. For hash maps (FLOW_STATS, LISTENING_PORTS) this is the entry count. Not available for ring buffers (FLOW_EVENTS).")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["map"]
    ).expect("failed to create ebpf_map_entries metric");

    pub static ref EBPF_MAP_CAPACITY: IntGaugeVec = IntGaugeVec::new(
        Opts::new("map_capacity", "Maximum capacity of eBPF maps. For hash maps (FLOW_STATS, LISTENING_PORTS) this is max entries. For ring buffers (FLOW_EVENTS) this is size in bytes.")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["map"]
    ).expect("failed to create ebpf_map_capacity metric");

    pub static ref EBPF_ATTACHMENT_MODE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("method", "Current eBPF attachment method used (tc or tcx)")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["attachment"]
    ).expect("failed to create ebpf_method metric");

    pub static ref BPF_FS_WRITABLE: prometheus::IntGauge = prometheus::IntGauge::with_opts(
        Opts::new("bpf_fs_writable", "Whether /sys/fs/bpf is writable for TCX link pinning (1 = writable, 0 = not writable)")
            .namespace("mermin")
            .subsystem("ebpf")
    ).expect("failed to create ebpf_bpf_fs_writable metric");

    /// Total bytes processed through eBPF maps/ring buffers.
    /// Labels: map = "FLOW_EVENTS" (ring buffer bytes read by userspace)
    pub static ref EBPF_MAP_BYTES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("map_bytes_total", "Total bytes processed through eBPF maps and ring buffers")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["map"]
    ).expect("failed to create ebpf_map_bytes_total metric");

    /// Total number of eBPF map operations.
    /// Labels: map = "FLOW_STATS" | "LISTENING_PORTS", operation = "read" | "write" | "delete", status = "ok" | "error" | "not_found"
    pub static ref EBPF_MAP_OPS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("map_ops_total", "Total number of eBPF map operations")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["map", "operation", "status"]
    ).expect("failed to create ebpf_map_ops_total metric");

    // Debug metrics (only registered if debug_metrics_enabled)
    pub static ref EBPF_ORPHANS_CLEANED_TOTAL: IntCounter = IntCounter::with_opts(
        Opts::new("orphans_cleaned_total", "Total number of orphaned eBPF map entries cleaned up")
            .namespace("mermin")
            .subsystem("ebpf")
    ).expect("failed to create ebpf_orphans_cleaned_total metric");

    pub static ref TC_PROGRAMS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("tc_programs_total", "Total number of TC programs attached or detached across all interfaces")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["operation"]  // operation: "attached" | "detached"
    ).expect("failed to create ebpf_tc_programs_total metric");

    pub static ref TC_PROGRAMS_ATTACHED_BY_INTERFACE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("tc_programs_attached_by_interface_total", "Total number of TC programs attached by interface and direction")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["interface", "direction"]
    ).expect("failed to create ebpf_tc_programs_attached_by_interface_total metric");

    pub static ref TC_PROGRAMS_DETACHED_BY_INTERFACE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("tc_programs_detached_by_interface_total", "Total number of TC programs detached by interface and direction")
            .namespace("mermin")
            .subsystem("ebpf"),
        &["interface", "direction"]
    ).expect("failed to create ebpf_tc_programs_detached_by_interface_total metric");

    // ============================================================================
    // Channel Subsystem
    // ============================================================================

    // Standard metrics (always registered)
    pub static ref CHANNEL_CAPACITY: IntGaugeVec = IntGaugeVec::new(
        Opts::new("channel_capacity", "Capacity of internal channels")
            .namespace("mermin")
            .subsystem("channel"),
        &["channel"]  // packet_worker, exporter
    ).expect("failed to create channel_capacity metric");

    pub static ref CHANNEL_ENTRIES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("channel_entries", "Current number of items in channels")
            .namespace("mermin")
            .subsystem("channel"),
        &["channel"]  // packet_worker, exporter
    ).expect("failed to create channel_entries metric");

    /// Channel send operations counter.
    /// Labels: channel, status = "success" | "error" | "backpressure"
    pub static ref CHANNEL_SENDS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("channel_sends_total", "Total number of send operations to internal channels")
            .namespace("mermin")
            .subsystem("channel"),
        &["channel", "status"]  // channel: packet_worker, producer_output, decorator_output; status: success, error, backpressure
    ).expect("failed to create channel_sends_total metric");

    // ============================================================================
    // Flow Subsystem
    // ============================================================================

    // Standard metrics (always registered)
    /// Processing latency by pipeline stage.
    ///
    /// Buckets are designed to cover both fast operations (eBPF ring buffer processing,
    /// typically microseconds to milliseconds) and slow operations (export, which can take
    /// seconds). The bucket range spans from 10μs to 60s to capture the full latency
    /// distribution across all pipeline stages.
    pub static ref PROCESSING_LATENCY_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new("processing_latency_seconds", "Processing latency by pipeline stage")
            .namespace("mermin")
            .subsystem("flow")
            .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]),
        &["stage"]
    ).expect("failed to create processing_latency_seconds metric");

    pub static ref FLOW_SPANS_CREATED_TOTAL: IntCounter = IntCounter::with_opts(
        Opts::new("spans_created_total", "Total number of flow spans created across all interfaces")
            .namespace("mermin")
            .subsystem("flow")
    ).expect("failed to create flow_spans_created_total metric");

    pub static ref FLOW_SPANS_ACTIVE_TOTAL: prometheus::IntGauge = prometheus::IntGauge::with_opts(
        Opts::new("spans_active_total", "Current number of active flow traces across all interfaces")
            .namespace("mermin")
            .subsystem("flow")
    ).expect("failed to create flow_spans_active_total metric");

    pub static ref PROCESSING_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("processing_total", "Total number of flow spans processed by Flow Producer stage (aggregated across interfaces)")
            .namespace("mermin")
            .subsystem("flow"),
        &["status"]
    ).expect("failed to create processing_total metric");

    // Debug metrics (only registered if debug_metrics_enabled)
    pub static ref FLOW_SPAN_STORE_SIZE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("span_store_size", "Current number of flows in flow_store per poller")
            .namespace("mermin")
            .subsystem("flow"),
        &["poller_id"]  // Track per poller for sharded architecture (max 32 pollers)
    ).expect("failed to create flow_span_store_size metric");

    pub static ref FLOW_SPANS_PROCESSED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("spans_processed_total", "Total number of flow spans processed by FlowWorker per poller")
            .namespace("mermin")
            .subsystem("flow"),
        &["poller_id"]  // Track per poller for sharded architecture (max 32 pollers)
    ).expect("failed to create flow_spans_processed_total metric");

    /// Total number of flow events processed by ring buffer stage.
    /// Labels: status = "received" | "filtered" | "dropped_backpressure" | "dropped_error"
    pub static ref FLOW_EVENTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("events_total", "Total number of flow events processed by ring buffer stage")
            .namespace("mermin")
            .subsystem("flow"),
        &["status"]
    ).expect("failed to create flow_events_total metric");

    pub static ref FLOWS_CREATED_BY_INTERFACE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("spans_created_by_interface_total", "Total number of flow spans created by interface")
            .namespace("mermin")
            .subsystem("flow"),
        &["interface"]
    ).expect("failed to create flow_spans_created_by_interface_total metric");

    pub static ref FLOWS_ACTIVE_BY_INTERFACE_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("spans_active_by_interface_total", "Current number of active flow traces by interface")
            .namespace("mermin")
            .subsystem("flow"),
        &["interface"]
    ).expect("failed to create flow_spans_active_by_interface_total metric");

    // ============================================================================
    // Producer Subsystem
    // ============================================================================

    // Debug metrics (only registered if debug_metrics_enabled)
    pub static ref FLOW_PRODUCER_QUEUE_SIZE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("queue_size", "Current number of flows queued for processing per poller")
            .namespace("mermin")
            .subsystem("producer"),
        &["poller_id"]  // Track per poller (max 32 pollers)
    ).expect("failed to create flow_producer_queue_size metric");

    pub static ref FLOW_PRODUCER_FLOW_SPANS_BY_INTERFACE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("spans_by_interface_total", "Total number of flow spans processed by producer workers by interface")
            .namespace("mermin")
            .subsystem("producer"),
        &["interface", "status"]
    ).expect("failed to create flow_producer_flow_spans_by_interface_total metric");

    // ============================================================================
    // Export Subsystem
    // ============================================================================

    // Standard metrics (always registered)
    /// Total number of flow spans exported to external systems.
    /// Labels: exporter = "otlp" | "stdout", status = "ok" | "attempted" | "error" | "noop"
    pub static ref EXPORT_FLOW_SPANS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("flow_spans_total", "Total number of flow spans exported to external systems")
            .namespace("mermin")
            .subsystem("export"),
        &["exporter", "status"]
    ).expect("failed to create export_flow_spans_total metric");

    pub static ref EXPORT_BATCH_SIZE: Histogram = Histogram::with_opts(
        HistogramOpts::new("batch_size", "Number of spans per export batch")
            .namespace("mermin")
            .subsystem("export")
            .buckets(vec![1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0])
    ).expect("failed to create export_batch_size metric");

    // Debug metrics (only registered if debug_metrics_enabled)
    pub static ref EXPORT_TIMEOUTS_TOTAL: IntCounter = IntCounter::with_opts(
        Opts::new("timeouts_total", "Total number of export operations that timed out")
            .namespace("mermin")
            .subsystem("export")
    ).expect("failed to create export_timeouts_total metric");

    // ============================================================================
    // Kubernetes Decorator Subsystem
    // ============================================================================

    // Standard metrics (always registered)
    /// Total number of flow spans processed by K8s decorator.
    /// Labels: status = "dropped" | "ok" | "error" | "undecorated"
    pub static ref K8S_DECORATOR_FLOW_SPANS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("flow_spans_total", "Total number of flow spans processed by K8s decorator")
            .namespace("mermin")
            .subsystem("k8s_decorator"),
        &["status"]
    ).expect("failed to create k8s_decorator_flow_spans_total metric");

    // ============================================================================
    // Kubernetes Watcher Subsystem
    // ============================================================================

    // Standard metrics (always registered)
    /// K8s watcher events counter.
    /// Labels: event = "apply" | "delete" | "init" | "init_done" | "error"
    pub static ref K8S_WATCHER_EVENTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("events_total", "Total number of K8s resource watcher events (aggregated across resources)")
            .namespace("mermin")
            .subsystem("k8s_watcher"),
        &["event"]  // apply, delete, init, init_done, error
    ).expect("failed to create k8s_watcher_events_total metric");

    /// Total number of K8s IP index updates triggered.
    pub static ref K8S_IP_INDEX_UPDATES_TOTAL: IntCounter = IntCounter::with_opts(
        Opts::new("ip_index_updates_total", "Total number of K8s IP index updates")
            .namespace("mermin")
            .subsystem("k8s_watcher")
    ).expect("failed to create k8s_ip_index_updates metric");

    /// Histogram of K8s IP index update duration.
    pub static ref K8S_IP_INDEX_UPDATE_DURATION_SECONDS: Histogram = Histogram::with_opts(
        HistogramOpts::new("ip_index_update_duration_seconds", "Duration of K8s IP index updates")
            .namespace("mermin")
            .subsystem("k8s_watcher")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
    ).expect("failed to create k8s_ip_index_update_duration metric");

    // Debug metrics (only registered if debug_metrics_enabled)
    /// K8s watcher events counter by resource type.
    /// Labels: resource, event = "apply" | "delete" | "init" | "init_done" | "error"
    pub static ref K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("events_by_resource_total", "Total number of K8s resource watcher events by resource type")
            .namespace("mermin")
            .subsystem("k8s_watcher"),
        &["resource", "event"]  // apply, delete, init, init_done, error
    ).expect("failed to create k8s_watcher_events_by_resource_total metric");

    // ============================================================================
    // Taskmanager Subsystem
    // ============================================================================

    // Standard metrics (always registered)
    pub static ref TASKMANAGER_TASKS_ACTIVE_TOTAL: prometheus::IntGauge = prometheus::IntGauge::with_opts(
        Opts::new("tasks_active_total", "Current number of active tasks across all task types")
            .namespace("mermin")
            .subsystem("taskmanager")
    ).expect("failed to create taskmanager_tasks_active_total metric");

    /// Duration of shutdown operations.
    pub static ref SHUTDOWN_DURATION_SECONDS: Histogram = Histogram::with_opts(
        HistogramOpts::new("shutdown_duration_seconds", "Duration of shutdown operations")
            .namespace("mermin")
            .subsystem("taskmanager")
            .buckets(vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0])
    ).expect("failed to create shutdown_duration metric");

    /// Total number of shutdown operations that timed out.
    pub static ref SHUTDOWN_TIMEOUTS_TOTAL: IntCounter = IntCounter::with_opts(
        Opts::new("shutdown_timeouts_total", "Total number of shutdown operations that timed out")
            .namespace("mermin")
            .subsystem("taskmanager")
    ).expect("failed to create shutdown_timeouts metric");

    /// Flow spans processed during shutdown.
    /// Labels: status = "preserved" | "lost"
    pub static ref SHUTDOWN_FLOWS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("shutdown_flows_total", "Total flow spans processed during shutdown")
            .namespace("mermin")
            .subsystem("taskmanager"),
        &["status"]  // preserved, lost
    ).expect("failed to create shutdown_flows_total metric");

    // Debug metrics (only registered if debug_metrics_enabled)
    /// Task lifecycle events counter.
    /// Labels: status = "spawned" | "completed" | "cancelled" | "panicked"
    /// Note: spawned count should equal sum of completed + cancelled + panicked over time
    pub static ref TASKMANAGER_TASKS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("tasks_total", "Total tasks handled by the Mermin TaskManager")
            .namespace("mermin")
            .subsystem("taskmanager"),
        &["status"]  // spawned, completed, cancelled, panicked
    ).expect("failed to create taskmanager_tasks_total metric");

    /// Task lifecycle events counter by task name.
    /// Labels: task_name, status = "spawned" | "completed" | "cancelled" | "panicked"
    pub static ref TASKS_BY_NAME_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("tasks_by_name_total", "Total task lifecycle events by task name")
            .namespace("mermin")
            .subsystem("taskmanager"),
        &["task_name", "status"]  // spawned, completed, cancelled, panicked
    ).expect("failed to create tasks_by_name_total metric");

    pub static ref TASKS_ACTIVE_BY_NAME_TOTAL: IntGaugeVec = IntGaugeVec::new(
        Opts::new("tasks_active_by_name_total", "Current number of active tasks across all task types handled by the Mermin TaskManager")
            .namespace("mermin")
            .subsystem("taskmanager"),
        &["task_name"]
    ).expect("failed to create tasks_active_by_name_total metric");

    // ============================================================================
    // Interface Subsystem
    // ============================================================================

    // Standard metrics (always registered)
    pub static ref PACKETS_TOTAL: IntCounter = IntCounter::with_opts(
        Opts::new("packets_total", "Total number of packets processed across all interfaces")
            .namespace("mermin")
            .subsystem("interface")
    ).expect("failed to create packets_total metric");

    pub static ref BYTES_TOTAL: IntCounter = IntCounter::with_opts(
        Opts::new("bytes_total", "Total number of bytes processed across all interfaces")
            .namespace("mermin")
            .subsystem("interface")
    ).expect("failed to create bytes_total metric");

    // Debug metrics (only registered if debug_metrics_enabled)
    pub static ref PACKETS_BY_INTERFACE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("packets_by_interface_total", "Total number of packets processed by interface and direction")
            .namespace("mermin")
            .subsystem("interface"),
        &["interface", "direction"]  // direction: ingress/egress
    ).expect("failed to create packets_by_interface_total metric");

    pub static ref BYTES_BY_INTERFACE_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("bytes_by_interface_total", "Total number of bytes processed by interface and direction")
            .namespace("mermin")
            .subsystem("interface"),
        &["interface", "direction"]
    ).expect("failed to create bytes_by_interface_total metric");
}

// Helper macro to register a metric to both combined and standard registries
macro_rules! register_standard {
    ($metric:expr) => {{
        REGISTRY.register(Box::new($metric.clone()))?;
        STANDARD_REGISTRY.register(Box::new($metric.clone()))?;
    }};
}

// Helper macro to register a debug metric (only when enabled)
macro_rules! register_debug {
    ($metric:expr, $debug_enabled:expr) => {{
        if $debug_enabled {
            REGISTRY.register(Box::new($metric.clone()))?;
            DEBUG_REGISTRY.register(Box::new($metric.clone()))?;
        }
    }};
}

/// Initialize the metrics registry by registering all collectors.
///
/// Registers metrics to three registries:
/// - REGISTRY: All metrics (standard + debug if enabled)
/// - STANDARD_REGISTRY: Only standard metrics (no high-cardinality labels)
/// - DEBUG_REGISTRY: Only debug metrics (high-cardinality labels, only if debug_enabled)
///
/// If `debug_enabled` is true, registers high-cardinality debug metrics with per-resource labels.
/// Standard aggregated metrics are always registered.
///
/// # Errors
///
/// Returns [`prometheus::Error`] if:
/// - A metric with the same name is already registered
/// - The registry is already initialized with a different `debug_enabled` value
/// - Metric creation fails due to invalid configuration
///
/// # Examples
///
/// ```
/// use mermin::metrics::registry;
///
/// registry::init_registry(false)?;
///
/// registry::init_registry(false)?;
/// # Ok::<(), prometheus::Error>(())
/// ```
pub fn init_registry(debug_enabled: bool) -> Result<(), prometheus::Error> {
    // Check if already initialized with different value
    if let Some(&existing) = DEBUG_METRICS_ENABLED.get() {
        if existing != debug_enabled {
            return Err(prometheus::Error::Msg(format!(
                "Registry already initialized with debug_enabled={existing}, cannot reinitialize with {debug_enabled}",
            )));
        }
        return Ok(());
    }

    // Initialize the global debug flag (first time only)
    DEBUG_METRICS_ENABLED
        .set(debug_enabled)
        .expect("DEBUG_METRICS_ENABLED should not be set yet");

    // ============================================================================
    // eBPF metrics (always registered)
    // ============================================================================
    register_standard!(EBPF_MAP_ENTRIES);
    register_standard!(EBPF_MAP_CAPACITY);
    register_standard!(EBPF_ATTACHMENT_MODE);
    register_standard!(BPF_FS_WRITABLE);
    register_standard!(EBPF_MAP_BYTES_TOTAL);
    register_standard!(EBPF_MAP_OPS_TOTAL);

    // Debug eBPF metrics (conditional)
    register_debug!(EBPF_ORPHANS_CLEANED_TOTAL, debug_enabled);
    register_debug!(TC_PROGRAMS_TOTAL, debug_enabled);
    register_debug!(TC_PROGRAMS_ATTACHED_BY_INTERFACE_TOTAL, debug_enabled);
    register_debug!(TC_PROGRAMS_DETACHED_BY_INTERFACE_TOTAL, debug_enabled);

    // ============================================================================
    // Channel metrics (always registered)
    // ============================================================================
    register_standard!(CHANNEL_CAPACITY);
    register_standard!(CHANNEL_ENTRIES);
    register_standard!(CHANNEL_SENDS_TOTAL);

    // ============================================================================
    // Flow metrics
    // ============================================================================
    register_standard!(PROCESSING_LATENCY_SECONDS);
    register_standard!(FLOW_SPANS_CREATED_TOTAL);
    register_standard!(FLOW_SPANS_ACTIVE_TOTAL);
    register_standard!(PROCESSING_TOTAL);

    // Debug flow metrics (high-cardinality labels)
    register_debug!(FLOW_SPAN_STORE_SIZE, debug_enabled);
    register_debug!(FLOW_SPANS_PROCESSED_TOTAL, debug_enabled);
    register_debug!(FLOW_EVENTS_TOTAL, debug_enabled);
    register_debug!(FLOWS_CREATED_BY_INTERFACE_TOTAL, debug_enabled);
    register_debug!(FLOWS_ACTIVE_BY_INTERFACE_TOTAL, debug_enabled);

    // ============================================================================
    // Producer metrics
    // ============================================================================
    // Debug producer metrics (high-cardinality labels)
    register_debug!(FLOW_PRODUCER_QUEUE_SIZE, debug_enabled);
    register_debug!(FLOW_PRODUCER_FLOW_SPANS_BY_INTERFACE_TOTAL, debug_enabled);

    // ============================================================================
    // Export metrics (always registered)
    // ============================================================================
    register_standard!(EXPORT_FLOW_SPANS_TOTAL);
    register_standard!(EXPORT_BATCH_SIZE);

    // Debug export metrics (conditional)
    register_debug!(EXPORT_TIMEOUTS_TOTAL, debug_enabled);

    // ============================================================================
    // K8s decorator metrics (always registered)
    // ============================================================================
    register_standard!(K8S_DECORATOR_FLOW_SPANS_TOTAL);

    // ============================================================================
    // K8s watcher metrics
    // ============================================================================
    register_standard!(K8S_IP_INDEX_UPDATES_TOTAL);
    register_standard!(K8S_IP_INDEX_UPDATE_DURATION_SECONDS);
    register_standard!(K8S_WATCHER_EVENTS_TOTAL);

    // Debug K8s watcher metrics
    register_debug!(K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL, debug_enabled);

    // ============================================================================
    // Taskmanager metrics
    // ============================================================================
    register_standard!(SHUTDOWN_DURATION_SECONDS);
    register_standard!(SHUTDOWN_TIMEOUTS_TOTAL);
    register_standard!(SHUTDOWN_FLOWS_TOTAL);
    register_standard!(TASKMANAGER_TASKS_ACTIVE_TOTAL);

    // Debug taskmanager metrics
    register_debug!(TASKMANAGER_TASKS_TOTAL, debug_enabled);
    register_debug!(TASKS_BY_NAME_TOTAL, debug_enabled);
    register_debug!(TASKS_ACTIVE_BY_NAME_TOTAL, debug_enabled);

    // ============================================================================
    // Per-interface statistics
    // ============================================================================
    register_standard!(PACKETS_TOTAL);
    register_standard!(BYTES_TOTAL);

    // Debug interface metrics
    register_debug!(PACKETS_BY_INTERFACE_TOTAL, debug_enabled);
    register_debug!(BYTES_BY_INTERFACE_TOTAL, debug_enabled);

    Ok(())
}

/// Get whether debug metrics with high-cardinality labels are enabled.
///
/// Returns false if the registry has not been initialized.
#[inline]
pub fn debug_enabled() -> bool {
    DEBUG_METRICS_ENABLED.get().copied().unwrap_or(false)
}

/// Remove all metrics for an interface (only works if debug metrics are enabled).
///
/// Cleans up all metric label combinations for the specified interface.
/// This includes TC programs, packets, bytes, flows, and producer metrics.
pub fn remove_interface_metrics(iface: &str) {
    // TC programs (ingress/egress)
    let _ = TC_PROGRAMS_ATTACHED_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "ingress"]);
    let _ = TC_PROGRAMS_ATTACHED_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "egress"]);
    let _ = TC_PROGRAMS_DETACHED_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "ingress"]);
    let _ = TC_PROGRAMS_DETACHED_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "egress"]);

    // Packets/bytes (ingress/egress)
    let _ = PACKETS_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "ingress"]);
    let _ = PACKETS_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "egress"]);
    let _ = BYTES_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "ingress"]);
    let _ = BYTES_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "egress"]);

    // Flows
    let _ = FLOWS_CREATED_BY_INTERFACE_TOTAL.remove_label_values(&[iface]);
    let _ = FLOWS_ACTIVE_BY_INTERFACE_TOTAL.remove_label_values(&[iface]);

    // Producer flow spans (all status values)
    let _ = FLOW_PRODUCER_FLOW_SPANS_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "created"]);
    let _ = FLOW_PRODUCER_FLOW_SPANS_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "recorded"]);
    let _ = FLOW_PRODUCER_FLOW_SPANS_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "idled"]);
    let _ = FLOW_PRODUCER_FLOW_SPANS_BY_INTERFACE_TOTAL.remove_label_values(&[iface, "dropped"]);
}

/// Remove all metrics for a K8s resource (only works if debug metrics are enabled).
///
/// Cleans up watcher events metrics for the specified resource.
pub fn remove_k8s_resource_metrics(resource: &str) {
    // Watcher events (all event types including error)
    let _ = K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL.remove_label_values(&[resource, "apply"]);
    let _ = K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL.remove_label_values(&[resource, "init"]);
    let _ = K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL.remove_label_values(&[resource, "init_done"]);
    let _ = K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL.remove_label_values(&[resource, "delete"]);
    let _ = K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL.remove_label_values(&[resource, "error"]);
}

/// Remove all metrics for a task (only works if debug metrics are enabled).
///
/// Cleans up task lifecycle metrics for the specified task name.
pub fn remove_task_metrics(task_name: &str) {
    // Remove all status variants for this task
    let _ = TASKS_BY_NAME_TOTAL.remove_label_values(&[task_name, "spawned"]);
    let _ = TASKS_BY_NAME_TOTAL.remove_label_values(&[task_name, "completed"]);
    let _ = TASKS_BY_NAME_TOTAL.remove_label_values(&[task_name, "cancelled"]);
    let _ = TASKS_BY_NAME_TOTAL.remove_label_values(&[task_name, "panicked"]);
    let _ = TASKS_ACTIVE_BY_NAME_TOTAL.remove_label_values(&[task_name]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_interface_metrics_does_not_panic() {
        remove_interface_metrics("test-iface");
        assert!(true);
    }

    #[test]
    fn test_remove_k8s_resource_metrics_does_not_panic() {
        remove_k8s_resource_metrics("Pod");
        assert!(true);
    }

    #[test]
    fn test_remove_task_metrics_does_not_panic() {
        remove_task_metrics("test-task");
        assert!(true);
    }

    #[test]
    fn test_metrics_system_initialization() {
        // Initialize registry without debug metrics
        // Note: May already be initialized by another test, which is fine
        let _ = init_registry(false);

        // The important thing is that debug can be queried
        // (It might be enabled from a different test, but that's OK for this basic test)
        let _ = debug_enabled();
    }

    #[test]
    fn test_standard_registry_always_has_metrics() {
        // Initialize with debug disabled
        let _ = init_registry(false);

        // Standard registry should have metrics
        let families = STANDARD_REGISTRY.gather();

        // Should have at least some standard metrics
        // (exact count depends on what's been registered)
        assert!(
            !families.is_empty(),
            "Standard registry should not be empty"
        );
    }

    #[test]
    fn test_separate_registries_exist() {
        // All three registries should exist
        let _ = &REGISTRY;
        let _ = &STANDARD_REGISTRY;
        let _ = &DEBUG_REGISTRY;

        assert!(true, "All registries are accessible");
    }
}
