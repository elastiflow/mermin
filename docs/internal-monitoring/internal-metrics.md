# Internal Metrics

This guide describes the Prometheus metrics endpoint exposed by Mermin and provides a comprehensive breakdown of all available metrics, their types, and descriptions.
See the [metrics configuration document](../configuration/reference/internal-prometheus-metrics.md) for more details on metrics configuration.

## Metrics Endpoint

Mermin exposes Prometheus metrics in the standard Prometheus text format at multiple HTTP endpoints on port `10250` (configurable via `internal.metrics.port`):

- `/metrics` - All metrics (standard + debug if enabled)
- `/metrics/standard` - Standard metrics only (no high-cardinality labels)
- `/metrics/debug` - Debug metrics only (returns 404 if disabled)
- `/metrics:summary` - JSON summary of all available metrics with metadata (name, type, description, labels, category)

**Standard vs Debug Metrics:**

- **Standard metrics**: Always enabled, aggregated across resources, safe for production.
- **Debug metrics**: High-cardinality labels (per-interface, per-resource), must be explicitly enabled via `metrics.debug_metrics_enabled = true`.

## Prometheus Scraping

Prometheus can be configured in multiple ways: [annotation-based discovery or Kubernetes service discovery](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config),
[Prometheus Operator CRDs](https://github.com/prometheus-operator/prometheus-operator?tab=readme-ov-file#customresourcedefinitions) (e.g. ServiceMonitor, PodMonitor), or engine-specific CRDs.
Prometheus-compatible engines such as [VictoriaMetrics](https://docs.victoriametrics.com/operator/integrations/prometheus/) use similar CRDs (`VMServiceScrape`, `VMPodScrape`).
The following options work with Mermin's metrics endpoint.

**Pod annotations** — for annotation-based discovery, see [Expose Mermin metrics to Prometheus](../deployment/advanced-scenarios.md#metrics-to-monitor) in Advanced Scenarios.

A **PodMonitor** example for Mermin is in [values_prom_stack.yaml](../deployment/examples/local/values_prom_stack.yaml)
(see `prometheus.additionalPodMonitors`), used when [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator) or other compatible controller is deployed

**Further reading:**

- [Prometheus configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/) — scrape config and discovery
- [GKE Managed Service for Prometheus — PodMonitoring](https://docs.cloud.google.com/stackdriver/docs/managed-prometheus/setup-managed#gmp-pod-monitoring) —
  Google Cloud's `PodMonitoring` CR for managed collection

See also the [Kubernetes Helm deployment guide](../deployment/kubernetes-helm.md), [Helm deployment examples](../deployment/examples/README.md) and
[Advanced Scenarios](../deployment/advanced-scenarios.md#performance-monitoring-and-tuning)
for more deployment examples.

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

  Whether /sys/fs/bpf is writable for TCX link pinning (1 = writable, 0 = not writable).

  **Type:** `gauge`

- `mermin_ebpf_map_capacity`

  Maximum capacity of eBPF maps. For hash maps (FLOW_STATS, TCP_STATS, ICMP_STATS, LISTENING_PORTS) this is max entries. For ring buffers (FLOW_EVENTS) this is size in bytes.

  **Type:** `gauge`

  **Labels:**
  - `map`: `FLOW_STATS`, `FLOW_EVENTS`, `TCP_STATS`, `ICMP_STATS`, `LISTENING_PORTS`
  - `unit`: `entries` (for hash maps), `bytes` (for ring buffers)

- `mermin_ebpf_map_ops_total`

  Total number of eBPF map operations. Not all maps track all operation types:
  - `FLOW_EVENTS`: `read` only (ring buffer consumed by userspace)
  - `FLOW_STATS`, `TCP_STATS`, `ICMP_STATS`: `read` and `delete` (hash maps read during flow processing, deleted on eviction)
  - `LISTENING_PORTS`: `write` only (populated at startup from `/proc`)

  **Type:** `counter`

  **Labels:**
  - `map`: `FLOW_STATS`, `FLOW_EVENTS`, `TCP_STATS`, `ICMP_STATS`, `LISTENING_PORTS`
  - `operation`: `read`, `write`, `delete`
  - `status`: `ok`, `error`, `not_found`

- `mermin_ebpf_map_size`

  Current size of eBPF maps. For hash maps (FLOW_STATS, TCP_STATS, ICMP_STATS, LISTENING_PORTS) this is the entry count. For ring buffers (FLOW_EVENTS) this is pending bytes (producer_pos - consumer_pos).

  **Type:** `gauge`

  **Labels:**
  - `map`: `FLOW_STATS`, `FLOW_EVENTS`, `TCP_STATS`, `ICMP_STATS`, `LISTENING_PORTS`
  - `unit`: `entries` (for hash maps), `bytes` (for ring buffers)

- `mermin_ebpf_method`

  Current eBPF attachment method used (tc or tcx).

  **Type:** `gauge`

  **Labels:**
  - `attachment`: `tc`, `tcx`

### Network Interface Metrics (`mermin_interface_*`)

These metrics provide visibility into network traffic processed by Mermin across all monitored interfaces. They are essential for understanding the overall throughput and packet rates processed by Mermin.

- `mermin_interface_bytes_total`

  Total number of bytes processed across all interfaces.

  **Type:** `counter`

  **Unit:** bytes

  **Labels:**
  - `interface`: Network interface name (e.g., `eth0`)
  - `direction`: `ingress`, `egress`

- `mermin_interface_packets_total`

  Total number of packets processed across all interfaces.

  **Type:** `counter`

  **Unit:** packets (count)

  **Labels:**
  - `interface`: Network interface name (e.g., `eth0`)
  - `direction`: `ingress`, `egress`

### Flow Metrics (`mermin_flow_*`)

- `mermin_flow_spans_active_total`

  Current number of active flow traces across all interfaces.

  **Type:** `gauge`

  **Unit:** spans (count)

- `mermin_flow_spans_created_total`

  Total number of flow spans created across all interfaces.

  **Type:** `counter`

  **Unit:** spans (count)

### Kubernetes Watcher Metrics (`mermin_k8s_watcher_*`)

These metrics track events and performance of the Kubernetes resource watchers used by Mermin for metadata enrichment and resource monitoring.

- `mermin_k8s_watcher_events_total`

  Total number of K8s kind watcher events (aggregated across resources).

  **Type:** `counter`

  **Labels:**
  - `event`: `apply`, `delete`, `init`, `init_done`, `error`
  - `kind`: Kubernetes resource types (e.g., `Pod`, `Service`, `Node`, `Deployment`, `ReplicaSet`, `DaemonSet`, `StatefulSet`, `EndpointSlice`)

- `mermin_k8s_watcher_ip_index_update_duration_seconds`

  Duration of K8s IP index updates.

  **Type:** `histogram`

  **Unit:** seconds

  **Default buckets:** `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]` (1ms to 1s)

### Kubernetes Decorator Metrics (`mermin_k8s_decorator_*`)

These metrics expose the details to the Kubernetes decorator stage.

- `mermin_k8s_decorator_flow_spans_total`

  Total number of flow spans processed by the K8s decorator.

  **Type:** `counter`

  **Unit:** spans (count)

  **Labels:**
  - `status`: `ok`, `dropped`, `error`, `undecorated`

### Flow Span Export Metrics (`mermin_export_*`)

These metrics track the export of flow spans from Mermin to external systems (such as OTLP collectors), providing insight into export performance and reliability.

- `mermin_export_batch_size`

  Number of spans per export batch.

  **Type:** `histogram`

  **Unit:** spans (count)

  **Default buckets:** `[1, 10, 50, 100, 250, 500, 1000]`

- `mermin_export_flow_spans_total`

  Total number of flow spans exported to external systems.

  **Type:** `counter`

  **Unit:** spans (count)

  **Labels:**
  - `exporter`: `otlp`, `stdout`, `noop`
  - `status`: `ok`, `error`, `noop`

### Channel Metrics (`mermin_channel_*`)

These metrics offer insight into the internal channels used for data transmission.

- `mermin_channel_capacity`

  Capacity of internal channels.

  **Type:** `gauge`

  **Unit:** items (count)

  **Labels:**
  - `channel`: `packet_worker`, `producer_output`, `decorator_output`

- `mermin_channel_entries`

  Current number of items in channels.

  **Type:** `gauge`

  **Unit:** items (count)

  **Labels:**
  - `channel`: `packet_worker`, `producer_output`, `decorator_output`

- `mermin_channel_sends_total`

  Total number of send operations to internal channels.

  **Type:** `counter`

  **Labels:**
  - `channel`: `packet_worker`, `producer_output`, `decorator_output`
  - `status`: `success`, `error`, `backpressure`

### Pipeline Metrics (`mermin_pipeline_*`)

These metrics offer insight into the internal pipelines used for data mutation (flow generation, decoration).

- `mermin_pipeline_duration_seconds`

  Processing duration by pipeline stage.

  **Type:** `histogram`

  **Unit:** seconds

  **Labels:**
  - `stage`:
    - `flow_producer_out`: Time spent reading and processing flow events from the eBPF ring buffer (typically microseconds to milliseconds)
    - `k8s_decorator_out`: Time spent enriching flow spans with Kubernetes metadata (pod, service, namespace lookups)
    - `export_out`: Time spent exporting spans to configured exporters (OTLP or stdout), including serialization and network I/O

  **Default buckets:** `[0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]` (10μs to 60s)

### TaskManager Metrics (`mermin_taskmanager_*`)

These metrics track the number and type of active background tasks managed by Mermin.

- `mermin_taskmanager_tasks_active`

  Current number of active tasks across all task types.

  **Type:** `gauge`

  **Unit:** tasks (count)

  **Labels:**
  - `task`: Task names are dynamic and correspond to spawned background tasks (e.g., watcher tasks, producer tasks)

## Label Values Reference

This section provides a quick reference for all label values used across metrics.

| Label                  | Valid Values                                                                                            |
|------------------------|---------------------------------------------------------------------------------------------------------|
| `map`                  | `FLOW_STATS`, `FLOW_EVENTS`, `TCP_STATS`, `ICMP_STATS`, `LISTENING_PORTS`                               |
| `unit`                 | `entries`, `bytes`                                                                                      |
| `operation`            | `read`, `write`, `delete`                                                                               |
| `status` (eBPF)        | `ok`, `error`, `not_found`                                                                              |
| `attachment`           | `tc`, `tcx`                                                                                             |
| `channel`              | `packet_worker`, `producer_output`, `decorator_output`                                                  |
| `status` (channel)     | `success`, `error`, `backpressure`                                                                      |
| `exporter`             | `otlp`, `stdout`, `noop`                                                                                |
| `status` (export)      | `ok`, `error`, `noop`                                                                                   |
| `status` (decorator)   | `ok`, `dropped`, `error`, `undecorated`                                                                 |
| `event`                | `apply`, `delete`, `init`, `init_done`, `error`                                                         |
| `kind`                 | `Pod`, `Service`, `Node`, `Deployment`, `ReplicaSet`, `DaemonSet`, `StatefulSet`, `EndpointSlice`, etc. |
| `stage`                | `flow_producer_out`, `k8s_decorator_out`, `export_out`                                                  |

## Histogram Buckets

Histogram metrics use configurable bucket boundaries. The default buckets are optimized for typical workloads but can be customized via configuration. See [metrics configuration](../configuration/metrics.md#histogram_buckets-block) for details.

| Metric                                                   | Default Buckets                                                                                       | Range           |
|----------------------------------------------------------|-------------------------------------------------------------------------------------------------------|-----------------|
| `mermin_pipeline_duration_seconds`                       | `[0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]`  | 10μs to 60s     |
| `mermin_export_batch_size`                               | `[1, 10, 50, 100, 250, 500, 1000]`                                                                    | 1 to 1000 spans |
| `mermin_k8s_watcher_ip_index_update_duration_seconds`    | `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]`                                                           | 1ms to 1s       |
| `mermin_taskmanager_shutdown_duration_seconds` (debug)   | `[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0]`                                                       | 100ms to 120s   |

## Grafana Dashboard

Grafana dashboard can be imported from the [Dashboard JSON](./grafana-mermin-app.json)

---

## Next Steps

{% tabs %}
{% tab title="Configure Metrics" %}
1. [**Configure Prometheus Endpoint**](../configuration/reference/internal-prometheus-metrics.md): Customize metrics exposure
2. [**Set Up Alerting**](../configuration/reference/internal-server.md): Configure health checks
{% endtab %}

{% tab title="Troubleshoot" %}
1. [**Diagnose Performance Issues**](../troubleshooting/troubleshooting.md): Use metrics to identify bottlenecks
2. [**Tune the Pipeline**](../configuration/reference/flow-processing-pipeline.md): Optimize based on metrics
{% endtab %}
{% endtabs %}

### Need Help?

- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Share dashboards and alerting configurations
