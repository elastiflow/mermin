# Application Metrics

This guide describes the Prometheus metrics endpoint exposed by Mermin and provides a comprehensive breakdown of all available metrics, their types, and descriptions.

## Metrics Endpoint

Mermin exposes Prometheus metrics in the standard Prometheus text format at multiple HTTP endpoints:

- `/metrics` - All metrics (standard + debug if enabled)
- `/metrics/standard` - Standard metrics only (no high-cardinality labels)
- `/metrics/debug` - Debug metrics only (returns 404 if disabled)

**Default URL:** `http://localhost:10250/metrics`

The endpoints return metrics in Prometheus text format, which can be scraped by Prometheus or queried directly using tools like `curl`.

## Metrics Reference

All metrics follow the naming convention: `mermin_<subsystem>_<name>_<unit>` where applicable.

### Metric Types

The suffix of a metric name indicates its type:

- `_total`: A counter that only increases
- `_bytes_total`: A counter for bytes
- `_seconds`: A histogram for duration measurements in seconds
- `_ratio`: A gauge representing a ratio (0.0-1.0)
- (no suffix): A gauge representing the current value

### Standard vs Debug Metrics

- **Standard metrics**: Always enabled, aggregated across resources, safe for production
- **Debug metrics**: High-cardinality labels (per-interface, per-resource), must be explicitly enabled via `metrics.debug_metrics_enabled = true`

---

## eBPF Resource Metrics (`mermin_ebpf_*`)

Metrics for eBPF programs, maps, and kernel-level packet capture.

### Map Statistics

**`mermin_ebpf_map_entries{map}`**
- **Type:** Gauge
- **Labels:** `map` = "FLOW_STATS" | "LISTENING_PORTS"
- **Description:** Current number of entries in eBPF hash maps. Not available for ring buffers.

**`mermin_ebpf_map_capacity{map}`**
- **Type:** Gauge
- **Labels:** `map` = "FLOW_STATS" | "FLOW_EVENTS" | "LISTENING_PORTS"
- **Description:** Maximum capacity of eBPF maps. For hash maps this is max entries; for ring buffers (FLOW_EVENTS) this is size in bytes.

**`mermin_ebpf_map_utilization_ratio{map}`**
- **Type:** Gauge (0.0-1.0)
- **Labels:** `map` = "FLOW_STATS" | "LISTENING_PORTS"
- **Description:** Utilization ratio (entries/capacity). Available for hash maps only.

**`mermin_health_ready_to_process`**
- **Type:** Gauge
- **Description:** Indicates if Mermin is ready to process data.

**`mermin_health_overall`**
- **Type:** Gauge
- **Description:** A combined health status gauge for the entire application (e.g., `up`).

### Component States

**`mermin_component_state{component, error_code}`**
- **Type:** Gauge
- **Description:** A status gauge for different components with an optional `error_code` label for debugging.
  - `component="ringbuf_reader"`
  - `component="flow_span_producer"`
  - `component="k8s"` (potentially break k8s into further components)
  - `component="otlp_exporter"`

## eBPF Metrics (`mermin_ebpf_*`)

This section focuses on metrics originating from the eBPF layer, which is responsible for capturing low-level packets.

### Attachment Mode

**`mermin_ebpf_method{attachment}`**
- **Type:** Gauge
- **Description:** Indicates the active eBPF attachment method. The `attachment` label will be either `tcx` (Kernel >= 6.6) or `tc` (Legacy Netlink). The value is `1` for the active mode.

### Program Status

**`mermin_ebpf_programs_loaded{program}`**
- **Type:** Gauge
- **Description:** Indicates if the specified eBPF program (`ingress` or `egress`) is loaded.

### Map and Ring Buffer Statistics

**`mermin_ebpf_map_size_bytes{map_name}`**
- **Type:** Gauge
- **Description:** The size in bytes of an eBPF map.

**`mermin_ebpf_map_entries{map_name}`**
- **Type:** Gauge
- **Description:** The number of entries in an eBPF map.

**`mermin_ebpf_stack_bytes`**
- **Type:** Gauge
- **Description:** The stack memory usage in bytes.

**`mermin_ebpf_map_operations_total{map, operation, status}`**
- **Type:** Counter
- **Labels:**
  - `map` = "FLOW_STATS" | "LISTENING_PORTS"
  - `operation` = "read" | "write" | "delete"
  - `status` = "ok" | "error" | "not_found"
- **Description:** Total number of eBPF map operations by type and outcome.

**`mermin_ebpf_map_bytes_total{map}`**
- **Type:** Counter
- **Labels:** `map` = "FLOW_EVENTS"
- **Description:** Total bytes read from eBPF ring buffers.

**`mermin_ebpf_orphans_cleaned_total`**
- **Type:** Counter
- **Description:** Total number of orphaned eBPF map entries cleaned up during periodic maintenance.

### TC Program Attachment

**`mermin_ebpf_tc_programs_attached_total`**
- **Type:** Counter
- **Description:** Total number of TC programs attached across all interfaces.

**`mermin_ebpf_tc_programs_detached_total`**
- **Type:** Counter
- **Description:** Total number of TC programs detached across all interfaces.

**`mermin_ebpf_tc_programs_attached_by_interface_total{interface, direction}`** *(debug)*
- **Type:** Counter
- **Labels:** `interface`, `direction` = "ingress" | "egress"
- **Description:** TC programs attached by interface and direction.

**`mermin_ebpf_tc_programs_detached_by_interface_total{interface, direction}`** *(debug)*
- **Type:** Counter
- **Labels:** `interface`, `direction` = "ingress" | "egress"
- **Description:** TC programs detached by interface and direction.

**`mermin_ebpf_bpf_fs_writable`**
- **Type:** Gauge (0 or 1)
- **Description:** Whether /sys/fs/bpf is writable for TCX link pinning.

---

## Channel Metrics (`mermin_channel_*`)

Metrics for internal async channels between pipeline stages.

**`mermin_channel_capacity{channel}`**
- **Type:** Gauge
- **Labels:** `channel` = "packet_worker" | "exporter" | "decorator_input" | "exporter_input"
- **Description:** Maximum capacity of internal channels.

**`mermin_channel_size{channel}`**
- **Type:** Gauge
- **Labels:** `channel` = "packet_worker" | "exporter" | "decorator_input" | "exporter_input"
- **Description:** Current number of items in channels.

**`mermin_channel_sends_total{channel, status}`**
- **Type:** Counter
- **Labels:**
  - `channel` = "packet_worker" | "exporter" | "exporter_input" | "decorator_input"
  - `status` = "success" | "error"
- **Description:** Total send operations to internal channels by outcome.

---

## Flow Event Metrics (`mermin_flow_*`)

Metrics for flow events from the eBPF ring buffer stage.

**`mermin_flow_events_total{status}`**
- **Type:** Counter
- **Labels:** `status` = "received" | "filtered" | "dropped_backpressure" | "dropped_error"
- **Description:** Total flow events processed by the ring buffer stage.

---

## Flow Span Lifecycle Metrics (`mermin_flow_spans_*`)

Metrics for flow span creation, processing, and export.

### Aggregated Metrics (Standard)

**`mermin_flow_spans_created_total`**
- **Type:** Counter
- **Description:** Total flow spans created across all interfaces.

**`mermin_flow_spans_active_total`**
- **Type:** Gauge
- **Description:** Current number of active flow spans across all interfaces.

**`mermin_flow_spans_processed_total`**
- **Type:** Counter
- **Description:** Total flow spans processed by FlowWorker.

**`mermin_producer_flow_spans_total{status}`**
- **Type:** Counter
- **Labels:** `status` = "created" | "active" | "recorded" | "idled" | "dropped"
- **Description:** Flow spans processed by producer workers by lifecycle stage.

### Per-Interface Metrics (Debug)

**`mermin_flow_spans_created_by_interface_total{interface}`** *(debug)*
- **Type:** Counter
- **Description:** Flow spans created by interface.

**`mermin_flow_spans_active_by_interface_total{interface}`** *(debug)*
- **Type:** Gauge
- **Description:** Active flow spans by interface.

**`mermin_producer_flow_spans_by_interface_total{interface, status}`** *(debug)*
- **Type:** Counter
- **Description:** Producer flow spans by interface and status.

### Producer Internal Metrics

**`mermin_flow_span_store_size{poller_id}`**
- **Type:** Gauge
- **Description:** Current number of flows in flow_store per poller.

**`mermin_producer_queue_size{poller_id}`**
- **Type:** Gauge
- **Description:** Current number of flows queued for processing per poller.

---

## Processing Latency Metrics

**`mermin_processing_latency_seconds{stage}`**
- **Type:** Histogram
- **Labels:** `stage` = "ringbuf_read" | "flow_worker"
- **Buckets:** 10μs to 100ms
- **Description:** Processing latency by pipeline stage.

---

## Packet/Byte Statistics (`mermin_packets_*`, `mermin_bytes_*`)

### Aggregated Metrics (Standard)

**`mermin_packets_total`**
- **Type:** Counter
- **Description:** Total packets processed across all interfaces.

**`mermin_bytes_total`**
- **Type:** Counter
- **Description:** Total bytes processed across all interfaces.

### Per-Interface Metrics (Debug)

**`mermin_packets_by_interface_total{interface, direction}`** *(debug)*
- **Type:** Counter
- **Labels:** `direction` = "ingress" | "egress"
- **Description:** Packets processed by interface and direction.

**`mermin_bytes_by_interface_total{interface, direction}`** *(debug)*
- **Type:** Counter
- **Labels:** `direction` = "ingress" | "egress"
- **Description:** Bytes processed by interface and direction.

---

## Export Metrics (`mermin_export_*`)

Metrics for the OTLP export stage.

**`mermin_export_flow_spans_total{status}`**
- **Type:** Counter
- **Labels:** `status` = "queued" | "dropped" | "ok" | "error" | "noop"
- **Description:** Flow spans processed by export stage.

**`mermin_export_batch_spans`**
- **Type:** Histogram
- **Buckets:** 1 to 1000 spans
- **Description:** Number of spans per export batch.

**`mermin_export_latency_seconds`**
- **Type:** Histogram
- **Buckets:** 1ms to 5s
- **Description:** Latency of span export operations.

**`mermin_export_timeouts_total`**
- **Type:** Counter
- **Description:** Total export operations that timed out.

**`mermin_export_blocking_time_seconds`**
- **Type:** Histogram
- **Buckets:** 1ms to 60s
- **Description:** Time spent blocked waiting for export operations.

---

## Kubernetes Decorator Metrics (`mermin_k8s_*`)

Metrics for Kubernetes metadata enrichment.

### Decorator Performance

**`mermin_k8s_decorator_flow_spans_total{status}`**
- **Type:** Counter
- **Labels:** `status` = "dropped" | "ok" | "error" | "undecorated"
- **Description:** Flow spans processed by K8s decorator.

### Watcher Events

**`mermin_k8s_watcher_events_total{event_type}`**
- **Type:** Counter
- **Labels:** `event_type` = "apply" | "delete" | "init" | "init_done" | "error"
- **Description:** K8s resource watcher events (aggregated).

**`mermin_k8s_watcher_events_by_resource_total{resource, event_type}`** *(debug)*
- **Type:** Counter
- **Labels:** `resource` = "Pod" | "Service" | "Node" | etc., `event_type` as above
- **Description:** K8s watcher events by resource type.

### IP Index Performance

**`mermin_k8s_ip_index_updates_total`**
- **Type:** Counter
- **Description:** Total K8s IP index updates triggered.

**`mermin_k8s_ip_index_update_duration_seconds`**
- **Type:** Histogram
- **Buckets:** 1ms to 1s
- **Description:** Duration of K8s IP index updates.

---

## Task Lifecycle Metrics (`mermin_tasks_*`)

Metrics for async task management.

### Aggregated Metrics (Standard)

**`mermin_tasks_total{status}`**
- **Type:** Counter
- **Labels:** `status` = "spawned" | "completed" | "cancelled" | "panicked"
- **Description:** Task lifecycle events. Note: `spawned` count should equal sum of other statuses over time.

**`mermin_tasks_active_total`**
- **Type:** Gauge
- **Description:** Current number of active tasks.

### Per-Task Metrics (Debug)

**`mermin_tasks_by_name_total{task_name, status}`** *(debug)*
- **Type:** Counter
- **Description:** Task lifecycle events by task name.

**`mermin_tasks_active_by_name_total{task_name}`** *(debug)*
- **Type:** Gauge
- **Description:** Active tasks by task name.

---

## Shutdown Metrics (`mermin_shutdown_*`)

Metrics for graceful shutdown behavior.

**`mermin_shutdown_duration_seconds`**
- **Type:** Histogram
- **Buckets:** 100ms to 120s
- **Description:** Duration of shutdown operations.

**`mermin_shutdown_timeouts_total`**
- **Type:** Counter
- **Description:** Shutdown operations that exceeded timeout.

**`mermin_shutdown_flows_total{status}`**
- **Type:** Counter
- **Labels:** `status` = "preserved" | "lost"
- **Description:** Flow spans processed during shutdown.

---

## Example Prometheus Queries

### Pipeline Health

```prometheus
# Backpressure detection
rate(mermin_flow_events_total{status="dropped_backpressure"}[5m]) > 0

# Channel utilization
mermin_channel_size / mermin_channel_capacity

# eBPF map utilization
mermin_ebpf_map_utilization_ratio{map="FLOW_STATS"}
```

### Performance Monitoring

```prometheus
# Processing latency p95
histogram_quantile(0.95, rate(mermin_processing_latency_seconds_bucket[5m]))

# Export success rate
rate(mermin_export_flow_spans_total{status="ok"}[5m]) /
rate(mermin_export_flow_spans_total[5m])

# Flow throughput
rate(mermin_flow_spans_created_total[5m])
```

### Task Health

```prometheus
# Active tasks
mermin_tasks_active_total

# Task failure rate
rate(mermin_tasks_total{status="panicked"}[5m])
```

### Kubernetes Integration

```prometheus
# K8s decoration success rate
rate(mermin_k8s_decorator_flow_spans_total{status="ok"}[5m]) /
rate(mermin_k8s_decorator_flow_spans_total[5m])

# Watcher errors
rate(mermin_k8s_watcher_events_total{event_type="error"}[5m])
```
