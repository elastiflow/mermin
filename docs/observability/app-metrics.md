---
hidden: true
---

# Mermin Application Metrics

This guide describes the Prometheus metrics endpoint exposed by Mermin and provides a comprehensive breakdown of all available metrics, their types, and descriptions.
Please find more details on the metrics configuration in [this document](../configuration/metrics.md)

## Metrics Endpoint

Mermin exposes Prometheus metrics in the standard Prometheus text format at the `/metrics` HTTP endpoint. The metrics server is enabled by default and listens on port `10250`.

**Endpoint URL:** `http://<listen_address>:<port>/metrics`

The endpoint returns all registered metrics in Prometheus text format, which can be scraped by Prometheus or queried directly using tools like `curl` or `wget`.

## Metrics Reference

All metrics follow the naming convention

```text
<namespace>_<subsytem>_<name>_(optional<type>)
# For example
mermin_<ringbuf>_<packets>_<total>
```

### Metric Types

The suffix of a metric name indicates its type:

- `_total`: A counter that only increases
- `_bytes`: A counter for bytes
- `_seconds`: A histogram for duration measurements in seconds
- (no suffix): A gauge representing the current value of a metric

### Subsystems

Metrics are categorized into logical subsystems that correspond to different components of Mermin:

- `ebpf`: For eBPF-specific metrics
- `span`: For flow span producer metrics
- `k8s`: For Kubernetes integration metrics
- `export`: For metrics related to the export subsystem
- `(none)`: For application-wide metrics

## eBPF Metrics (`mermin_ebpf_*`)

This section focuses on metrics originating from the eBPF layer, which is responsible for capturing low-level packets. These metrics provide visibility into the status of loaded eBPF programs and the usage of eBPF maps.  
Monitoring these is crucial for ensuring that Mermin's foundational data collection mechanism functions as expected.

- `mermin_ebpf_map_entries{map}`: A gauge for the number of entries in an eBPF maps, `map`'s:
  <!-- TODO(#lgo-421) What are possible `map` for `mermin_ebpf_map_entries` metric, details on each of those  -->
  - `flow_stats`:  
<!-- TODO(#lgo-421) Rename `ring_buffer` to `ringbuf` or vise versa for consistency -->
- `mermin_ebpf_ring_buffer_drops_total`: A counter of the total number of ring buffer events (packets) dropped due to buffer full
<!-- TODO(#lgo-421)  "orphaned eBPF map entries" or "orphaned TC programs detached"? -->
- `mermin_ebpf_orphans_cleaned_total`: A counter of the total number of orphaned eBPF map entries cleaned up
- `mermin_ebpf_tc_programs_attached_total`: A counter of the total number of TC programs attached across all interfaces
- `mermin_ebpf_tc_programs_detached_total` A counter of the total number of TC programs detached across all interfaces
- `mermin_ebpf_bpf_fs_writable`: Gauge indicating if `/sys/fs/bpf` is writable by Mermin (`0` not writable, `1` writable)

## Userspace Ring Buffer metrics (`mermin_ringbuf_*`)

Ring Buffer is used to "transport" packets from the eBPF (kernel space) to userspace (references: [packet capture](../getting-started/architecture.md), [flow aggregation](../getting-started/architecture.md))

- `mermin_ringbuf_bytes_total` Total number of bytes received from the userspace ring buffer
- `mermin_ringbuf_packets_total` Total number of packets in the userspace ring buffer
<!-- TODO(lgo-421):  Add link to the `docs/configuration/span.md` configuration -->

## Application/System Metrics (`mermin_*`)

These metrics cover the overall application health, build information, and the state of high-level components.

### Build and Runtime

**`mermin_build_info{version, git_sha}`**
- **Type:** Gauge
- **Description:** Exposes build information, including the version and Git SHA of the build.

### Health Status

These gauges indicate the health of various Mermin components. A value of `1` indicates healthy, and `0` indicates unhealthy.

**`mermin_health_ebpf_loaded`**
- **Type:** Gauge
- **Description:** Indicates if the eBPF programs are successfully loaded.

**`mermin_health_k8s`**
- **Type:** Gauge
- **Description:** Indicates if the Kubernetes caches are synced.

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

**`mermin_ebpf_ringbuf_packets_total{type, interface}`**
- **Type:** Counter
- **Description:** A counter for packets from the eBPF ring buffer. `type` can be `received` or `malformed`.

**`mermin_ebpf_ringbuf_bytes`**
- **Type:** Counter
- **Description:** The total bytes received from the eBPF ring buffer.

## Userspace Ring Buffer Metrics (`mermin_*`)

These metrics describe the flow of data from the eBPF programs to the userspace application via the ring buffer.

### Packet Processing

**`mermin_ringbuf_packets_total{type}`**
- **Type:** Counter
- **Description:** A counter for packets in the userspace ring buffer. `type` can be `received`, `dropped`, or `filtered`.

**`mermin_ringbuf_bytes`**
- **Type:** Counter
- **Description:** The total bytes received in the userspace ring buffer.

### Channel Metrics

These metrics offer insight into the internal channels used for data transmission.

**`mermin_channel_capacity{channel}`**
- **Type:** Gauge
- **Description:** The capacity of internal channels (`packet_meta`, `exporter`).

**`mermin_channel_size{channel}`**
- **Type:** Gauge
- **Description:** The current number of items in the channels.

**`mermin_channel_sends_total{status, error_code}`**
- **Type:** Counter
- **Description:** A counter for send operations on channels. `status` can be `error` or `success`.

## Flow Span Metrics (`mermin_span_*`)

This group of metrics covers the core logic of Mermin, where raw packet data is processed into flow spans.

### Flow Lifecycle

**`mermin_span_active`**
- **Type:** Gauge
- **Description:** The number of currently active flows.

**`mermin_span_processed_total{reason}`**
- **Type:** Counter
- **Description:** A counter for flows that have been processed and expired. The `reason` label indicates why the flow expired (e.g., `idle`, `fin`, `rst`, `error`, `sampling`, `full`).

**`mermin_span_sent_total{status, exporter, error_code}`**
- **Type:** Counter
- **Description:** A counter for spans sent to an exporter. `status` can be `sent` or `failed`.

### Flow Metrics

These metrics provide insights into the nature of the observed flows beyond just the exported span data.

**`mermin_span_packets_processed_total{protocol}`**
- **Type:** Counter
- **Description:** A counter for processed packets by protocol (`tcp`, `udp`, `icmp`).

### Worker Performance

These metrics are for debugging and performance tuning of the span processing workers.

**`mermin_span_worker_packets_processed_total{worker_id}`**
- **Type:** Counter
- **Description:** A counter for packets processed by each worker.

**`mermin_span_worker_processing_duration_seconds`**
- **Type:** Histogram
- **Description:** A histogram of the processing latency for workers.

**`mermin_span_record_tasks_active`**
- **Type:** Gauge
- **Description:** The number of active record tasks.

**`mermin_span_timeout_tasks_active`**
- **Type:** Gauge
- **Description:** The number of active timeout tasks.

## Kubernetes Integration Metrics (`mermin_k8s_*`)

These metrics are related to Mermin's interaction with the Kubernetes API for metadata enrichment of flow spans.

### Client & Cache

**`mermin_k8s_client_up`**
- **Type:** Gauge
- **Description:** Indicates the status of the connection to the Kubernetes API. An error code label could be added in the future.

**`mermin_k8s_client_api_status{status, error_code}`**
- **Type:** Gauge
- **Description:** Indicates if the API is responding.

**`mermin_k8s_informer_last_sync_timestamp_seconds`**
- **Type:** Gauge
- **Description:** The timestamp of the last successful sync for an informer.

**`mermin_k8s_informer_sync_duration_seconds`**
- **Type:** Histogram
- **Description:** A histogram of the sync duration for informers.

**`mermin_k8s_informer_object_total{kind}`**
- **Type:** Gauge
- **Description:** The number of objects in the informer cache by kind (`Pod`, `Service`, `Endpoint`, etc.).

### Decorator Performance

**`mermin_k8s_decorator_spans_processed_total{status, reason}`**
- **Type:** Counter
- **Description:** A counter for spans processed by the decorator. `status` can be `success` or `fail`. `reason` could be `no_pod_match`, `lookup_error`, `not_found`, etc. This metric merges successful and undecorated spans.

**`mermin_k8s_decorator_lookup_duration_seconds`**
- **Type:** Histogram
- **Description:** A histogram of the lookup latency for the decorator.

## Export Metrics (`mermin_export_*`)

This section covers the final stage of the Mermin pipeline, where processed spans are exported to an external collector via OTLP.

### Export Statistics

**`mermin_export_otlp_batches_sent_total{status, error_code}`**
- **Type:** Counter
- **Description:** A counter for OTLP batches sent. `status` can be `success` or `error`. This merges successful and failed batches.

**`mermin_export_otlp_spans_sent_total{status, error_code}`**
- **Type:** Counter
- **Description:** A counter for OTLP spans sent. `status` can be `success` or `error`. This merges successful and failed spans.

**`mermin_export_otlp_duration_seconds`**
- **Type:** Histogram
- **Description:** A histogram of the export latency.

**`mermin_export_otlp_batch_size`**
- **Type:** Histogram
- **Description:** A histogram of batch sizes.

**`mermin_export_otlp_span_size`**
- **Type:** Histogram
- **Description:** A histogram of span sizes.

### Queue Metrics

**`mermin_export_queue_capacity{exporter}`**
- **Type:** Gauge
- **Description:** The capacity of the export queue.

**`mermin_export_queue_size{exporter}`**
- **Type:** Gauge
- **Description:** The current size of the export queue.


* Flow event is a singular flow read from eBPF
* Span (flow span) is a flow record
* Trace (flow trace) is a connection

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          eBPF FLOW SPAN PRODUCTION PIPELINE                             │
└─────────────────────────────────────────────────────────────────────────────────────────┘

**Metric Consolidation Note:** Some metrics are consolidated for consistency:
- Channel sizes: All channels use `mermin_channel_size{channel="<name>"}` 
(decorator_input, exporter_input, packet_worker)
- Processing latencies: All stages use `mermin_processing_latency_seconds{stage="<stage>"}` 
(flow_ingestion, k8s_decoration, otlp_export)

**Flow Span Lifecycle Tracking:**
The pipeline tracks flow spans through their complete lifecycle using the following metrics:
- **Ring Buffer → Worker**: `mermin_flow_events_total{type="received"}` → 
`mermin_flow_spans_processed_total` (successful creation)
- **Worker → Store**: `mermin_producer_flow_spans_total{status="created"}` → 
`mermin_producer_flow_spans_total{status="recorded"}` → 
`mermin_producer_flow_spans_total{status="idled"}`
- **Store → Decoration**: Flow spans sent via channel 
    (tracked via `mermin_export_flow_spans_total{status="queued"}` when received by export thread)
- **Decoration → Export**: `mermin_export_flow_spans_total{status="queued"}` → 
