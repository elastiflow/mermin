# Internal Metrics

- [Metrics Endpoint](#metrics-endpoint)
- [Metrics Reference](#metrics-reference)
  - [eBPF Metrics (`mermin_ebpf_*`)](#ebpf-metrics-mermin_ebpf_)
  - [Network Interface Metrics (`mermin_interface_*`)](#network-interface-metrics-mermin_interface_)
  - [Flow Metrics (`mermin_flow_*`)](#flow-metrics-mermin_flow_)
  - [Kubernetes Watcher Metrics (`mermin_k8s_watcher_*`)](#kubernetes-watcher-metrics-mermin_k8s_watcher_)
  - [Kubernetes Decorator Metrics (`mermin_k8s_decorator_*`)](#kubernetes-decorator-metrics-mermin_k8s_decorator_)
  - [Flow Span Export Metrics (`mermin_export_*`)](#flow-span-export-metrics-mermin_export_)
  - [Channel Metrics (`mermin_channel_*`)](#channel-metrics-mermin_channel_)
  - [Pipeline Metrics (`mermin_pipeline_*`)](#pipeline-metrics-mermin_pipeline_)
  - [TaskManager Metrics (`mermin_taskmanager_*`)](#taskmanager-metrics-mermin_taskmanager_)
- [Grafana Dashboard](#grafana-dashboard)

This guide describes the Prometheus metrics endpoint exposed by Mermin and provides a comprehensive breakdown of all available metrics, their types, and descriptions.
See the [metrics configuration document](../configuration/metrics.md) for more details on metrics configuration.

## Metrics Endpoint

Mermin exposes Prometheus metrics in the standard Prometheus text format at multiple HTTP endpoints:

- `/metrics` - All metrics (standard + debug if enabled)
- `/metrics/standard` - Standard metrics only (no high-cardinality labels)
- `/metrics/debug` - Debug metrics only (returns 404 if disabled)
- `/metrics:summary` - JSON summary of all available metrics with metadata (name, type, description, labels, category)

**Standard vs Debug Metrics:**

- **Standard metrics**: Always enabled, aggregated across resources, safe for production.
- **Debug metrics**: High-cardinality labels (per-interface, per-resource), must be explicitly enabled via `metrics.debug_metrics_enabled = true`.

## Metrics Reference

All metrics follow the naming convention: `mermin_<subsystem>_<name>`.
Metrics are categorized into logical subsystems that correspond to different components of Mermin:

- `ebpf`: For eBPF-specific metrics
- `channel`: Internal Mermin channels metrics
- `export`: Export-related metrics
- `flow`: Metrics on the Flow Spans
- `interface`: Network interface-related metrics
- `k8s`: For Kubernetes watcher metrics
- `taskmanager`: Internal Mermin tasks metrics

### eBPF Metrics (`mermin_ebpf_*`)

This section describes metrics from the eBPF layer, responsible for capturing low-level packets. These metrics provide visibility into the status of loaded eBPF programs and the usage of eBPF maps.
Monitoring these is crucial for ensuring that Mermin's foundational data collection mechanism functions as expected.

- `mermin_ebpf_bpf_fs_writable`
  *Type*: `gauge`
  *Description*: Whether /sys/fs/bpf is writable for TCX link pinning (1 = writable, 0 = not writable)
- `mermin_ebpf_map_capacity`
  *Type*: `gauge`
  *Description*: Maximum capacity of eBPF maps. For hash maps (FLOW_STATS, TCP_STATS, ICMP_STATS, LISTENING_PORTS) this is max entries. For ring buffers (FLOW_EVENTS) this is size in bytes.
  *Labels*:
  - `map`
  - `unit`
- `mermin_ebpf_map_ops_total`
  *Type*: `counter`
  *Description*: Total number of eBPF map operations
  *Labels*:
  - `map`
  - `operation`
  - `status`
- `mermin_ebpf_map_size`
  *Type*: `gauge`
  *Description*: Current size of eBPF maps. For hash maps (FLOW_STATS, TCP_STATS, ICMP_STATS, LISTENING_PORTS) this is the entry count. For ring buffers (FLOW_EVENTS) this is pending bytes (producer_pos - consumer_pos).
  *Labels*:
  - `map`
  - `unit`
- `mermin_ebpf_method`
  *Type*: `gauge`
  *Description*: Current eBPF attachment method used (tc or tcx)
  *Labels*:
  - `attachment`

### Network Interface Metrics (`mermin_interface_*`)

These metrics provide visibility into network traffic processed by Mermin across all monitored interfaces. They are essential for understanding the overall throughput and packet rates processed by Mermin.

- `mermin_interface_bytes_total`
  *Type*: `counter`
  *Description*: Total number of bytes processed across all interfaces
- `mermin_interface_packets_total`
  *Type*: `counter`
  *Description*: Total number of packets processed across all interfaces

### Flow Metrics (`mermin_flow_*`)

- `mermin_flow_spans_active_total`
  *Type*: `gauge`
  *Description*: Current number of active flow traces across all interfaces
- `mermin_flow_spans_created_total`
  *Type*: `counter`
  *Description*: Total number of flow spans created across all interfaces

### Kubernetes Watcher Metrics (`mermin_k8s_watcher_*`)

These metrics track events and performance of the Kubernetes resource watchers used by Mermin for metadata enrichment and resource monitoring.

- `mermin_k8s_watcher_events_total`
  *Type*: `counter`
  *Description*: Total number of K8s kind watcher events (aggregated across resources)
  *Labels*:
  - `event`
  - `kind`
- `mermin_k8s_watcher_ip_index_update_duration_seconds`
  *Type*: `histogram`
  *Description*: Duration of K8s IP index updates

### Kubernetes Decorator Metrics (`mermin_k8s_decorator_*`)

These metrics exposes the details to the Kubernetes decorator stage.

- `mermin_k8s_decorator_flow_spans_total`
  *Type*: `counter`
  *Description*: Total number of flow spans processed by the K8s decorator
  *Labels*:
  - `status`

### Flow Span Export Metrics (`mermin_export_*`)

These metrics track the export of flow spans from Mermin to external systems (such as OTLP collectors), providing insight into export performance and reliability.

- `mermin_export_batch_size`
  *Type*: `histogram`
  *Description*: Number of spans per export batch
- `mermin_export_flow_spans_total`
  *Type*: `counter`
  *Description*: Total number of flow spans exported to external systems
  *Labels*:
  - `exporter`
  - `status`

### Channel Metrics (`mermin_channel_*`)

These metrics offer insight into the internal channels used for data transmission.

- `mermin_channel_capacity`
  *Type*: `gauge`
  *Description*: Capacity of internal channels
  *Labels*:
  - `channel`
- `mermin_channel_entries`
  *Type*: `gauge`
  *Description*: Current number of items in channels
  *Labels*:
  - `channel`
- `mermin_channel_sends_total`
  *Type*: `counter`
  *Description*: Total number of send operations to internal channels
  *Labels*:
  - `channel`
  - `status`

### Pipeline Metrics (`mermin_pipeline_*`)

These metrics offer insight into the internal pipelines used for data mutation (flow generation, decoration).

- `mermin_pipeline_duration_seconds`
  *Type*: `histogram`
  *Description*: Processing duration by pipeline stage
  *Labels*:
  - `stage`

### TaskManager Metrics (`mermin_taskmanager_*`)

These metrics track the number and type of active background tasks managed by Mermin.

- `mermin_taskmanager_tasks_active`
  *Type*: `gauge`
  *Description*: Current number of active tasks across all task types
  *Labels*:
  - `task`

## Grafana Dashboard

Grafana dashboard can be imported from the [Dashboard JSON](./grafana-mermin-app.json)
