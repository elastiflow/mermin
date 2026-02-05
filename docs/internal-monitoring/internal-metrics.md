# Internal Metrics

* [Metrics Endpoint](internal-metrics.md#metrics-endpoint)
* [Metrics Reference](internal-metrics.md#metrics-reference)
  * [eBPF Metrics (`mermin_ebpf_*`)](internal-metrics.md#ebpf-metrics-mermin_ebpf_)
  * [Network Interface Metrics (`mermin_interface_*`)](internal-metrics.md#network-interface-metrics-mermin_interface_)
  * [Flow Metrics (`mermin_flow_*`)](internal-metrics.md#flow-metrics-mermin_flow_)
  * [Kubernetes Watcher Metrics (`mermin_k8s_watcher_*`)](internal-metrics.md#kubernetes-watcher-metrics-mermin_k8s_watcher_)
  * [Kubernetes Decorator Metrics (`mermin_k8s_decorator_*`)](internal-metrics.md#kubernetes-decorator-metrics-mermin_k8s_decorator_)
  * [Flow Span Export Metrics (`mermin_export_*`)](internal-metrics.md#flow-span-export-metrics-mermin_export_)
  * [Channel Metrics (`mermin_channel_*`)](internal-metrics.md#channel-metrics-mermin_channel_)
  * [Pipeline Metrics (`mermin_pipeline_*`)](internal-metrics.md#pipeline-metrics-mermin_pipeline_)
  * [TaskManager Metrics (`mermin_taskmanager_*`)](internal-metrics.md#taskmanager-metrics-mermin_taskmanager_)
* [Grafana Dashboard](internal-metrics.md#grafana-dashboard)

This guide describes the Prometheus metrics endpoint exposed by Mermin and provides a comprehensive breakdown of all available metrics, their types, and descriptions. See the [metrics configuration document](../configuration/reference/metrics.md) for more details on metrics configuration.

## Metrics Endpoint

Mermin exposes Prometheus metrics in the standard Prometheus text format at multiple HTTP endpoints:

* `/metrics` - All metrics (standard + debug if enabled)
* `/metrics/standard` - Standard metrics only (no high-cardinality labels)
* `/metrics/debug` - Debug metrics only (returns 404 if disabled)
* `/metrics:summary` - JSON summary of all available metrics with metadata (name, type, description, labels, category)

**Standard vs Debug Metrics:**

* **Standard metrics**: Always enabled, aggregated across resources, safe for production.
* **Debug metrics**: High-cardinality labels (per-interface, per-resource), must be explicitly enabled via `metrics.debug_metrics_enabled = true`.

## Metrics Reference

All metrics follow the naming convention: `mermin_<subsystem>_<name>`. Metrics are categorized into logical subsystems that correspond to different components of Mermin:

* `ebpf`: For eBPF-specific metrics
* `channel`: Internal Mermin channels metrics
* `export`: Export-related metrics
* `flow`: Metrics on the Flow Spans
* `interface`: Network interface-related metrics
* `k8s`: For Kubernetes watcher metrics
* `taskmanager`: Internal Mermin tasks metrics

### eBPF Metrics (`mermin_ebpf_*`)

This section describes metrics from the eBPF layer, responsible for capturing low-level packets. These metrics provide visibility into the status of loaded eBPF programs and the usage of eBPF maps. Monitoring these is crucial for ensuring that Mermin's foundational data collection mechanism functions as expected.

* `mermin_ebpf_bpf_fs_writable` _Type_: `gauge` _Description_: Whether /sys/fs/bpf is writable for TCX link pinning (1 = writable, 0 = not writable)
* `mermin_ebpf_map_capacity` _Type_: `gauge` _Description_: Maximum capacity of eBPF maps. For hash maps (FLOW\_STATS, TCP\_STATS, ICMP\_STATS, LISTENING\_PORTS) this is max entries. For ring buffers (FLOW\_EVENTS) this is size in bytes. _Labels_:
  * `map`
  * `unit`
* `mermin_ebpf_map_ops_total` _Type_: `counter` _Description_: Total number of eBPF map operations _Labels_:
  * `map`
  * `operation`
  * `status`
* `mermin_ebpf_map_size` _Type_: `gauge` _Description_: Current size of eBPF maps. For hash maps (FLOW\_STATS, TCP\_STATS, ICMP\_STATS, LISTENING\_PORTS) this is the entry count. For ring buffers (FLOW\_EVENTS) this is pending bytes (producer\_pos - consumer\_pos). _Labels_:
  * `map`
  * `unit`
* `mermin_ebpf_method` _Type_: `gauge` _Description_: Current eBPF attachment method used (tc or tcx) _Labels_:
  * `attachment`

### Network Interface Metrics (`mermin_interface_*`)

These metrics provide visibility into network traffic processed by Mermin across all monitored interfaces. They are essential for understanding the overall throughput and packet rates processed by Mermin.

* `mermin_interface_bytes_total` _Type_: `counter` _Description_: Total number of bytes processed across all interfaces
* `mermin_interface_packets_total` _Type_: `counter` _Description_: Total number of packets processed across all interfaces

### Flow Metrics (`mermin_flow_*`)

* `mermin_flow_spans_active_total` _Type_: `gauge` _Description_: Current number of active flow traces across all interfaces
* `mermin_flow_spans_created_total` _Type_: `counter` _Description_: Total number of flow spans created across all interfaces

### Kubernetes Watcher Metrics (`mermin_k8s_watcher_*`)

These metrics track events and performance of the Kubernetes resource watchers used by Mermin for metadata enrichment and resource monitoring.

* `mermin_k8s_watcher_events_total` _Type_: `counter` _Description_: Total number of K8s kind watcher events (aggregated across resources) _Labels_:
  * `event`
  * `kind`
* `mermin_k8s_watcher_ip_index_update_duration_seconds` _Type_: `histogram` _Description_: Duration of K8s IP index updates

### Kubernetes Decorator Metrics (`mermin_k8s_decorator_*`)

These metrics exposes the details to the Kubernetes decorator stage.

* `mermin_k8s_decorator_flow_spans_total` _Type_: `counter` _Description_: Total number of flow spans processed by the K8s decorator _Labels_:
  * `status`

### Flow Span Export Metrics (`mermin_export_*`)

These metrics track the export of flow spans from Mermin to external systems (such as OTLP collectors), providing insight into export performance and reliability.

* `mermin_export_batch_size` _Type_: `histogram` _Description_: Number of spans per export batch
* `mermin_export_flow_spans_total` _Type_: `counter` _Description_: Total number of flow spans exported to external systems _Labels_:
  * `exporter`
  * `status`

### Channel Metrics (`mermin_channel_*`)

These metrics offer insight into the internal channels used for data transmission.

* `mermin_channel_capacity` _Type_: `gauge` _Description_: Capacity of internal channels _Labels_:
  * `channel`
* `mermin_channel_entries` _Type_: `gauge` _Description_: Current number of items in channels _Labels_:
  * `channel`
* `mermin_channel_sends_total` _Type_: `counter` _Description_: Total number of send operations to internal channels _Labels_:
  * `channel`
  * `status`

### Pipeline Metrics (`mermin_pipeline_*`)

These metrics offer insight into the internal pipelines used for data mutation (flow generation, decoration).

* `mermin_pipeline_duration_seconds` _Type_: `histogram` _Description_: Processing duration by pipeline stage _Labels_:
  * `stage`

### TaskManager Metrics (`mermin_taskmanager_*`)

These metrics track the number and type of active background tasks managed by Mermin.

* `mermin_taskmanager_tasks_active` _Type_: `gauge` _Description_: Current number of active tasks across all task types _Labels_:
  * `task`

## Grafana Dashboard

Grafana dashboard can be imported from the [Dashboard JSON](https://github.com/elastiflow/mermin/blob/beta/docs/internal-monitoring/grafana-mermin-app.json)
