This guide describes the Prometheus metrics endpoint exposed by Mermin and provides a comprehensive breakdown of all available metrics, their types, and descriptions.

## Metrics Endpoint

Mermin exposes Prometheus metrics in the standard Prometheus text format at the `/metrics` HTTP endpoint. The metrics server is enabled by default and listens on port `10250` (configurable via the `metrics.port` configuration option).

**Endpoint URL:** `http://<listen_address>:<port>/metrics`

By default, this resolves to: `http://localhost:10250/metrics`

The endpoint returns all registered metrics in Prometheus text format, which can be scraped by Prometheus or queried directly using tools like `curl` or `wget`.

## Metrics Reference

All metrics follow the naming convention: `mermin_<subsystem>_<name>_(optional<type>)`

### Metric Types

The suffix of a metric name indicates its type:

- `_total`: A counter that only increases
- `_bytes`: A counter for bytes
- `_seconds`: A histogram for duration measurements in seconds
- (no suffix): A gauge representing the current value of a metric

### Subsystems

Metrics are categorized into logical subsystems that correspond to different components of Mermin:

- `(none)`: For application-wide metrics
- `ebpf`: For eBPF-specific metrics
- `mermin`: For userspace ring buffer and packet source metrics
- `span`: For flow span producer metrics
- `k8s`: For Kubernetes integration metrics
- `export`: For metrics related to the export subsystem

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

┌──────────────────┐
│   eBPF Kernel    │
│   (Packet Hook)  │
└────────┬─────────┘
         │ First packet 
         │ Packet aggregation 
         │ Flow events emitted
         ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│  RING BUFFER STAGE                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────┐      │
│  │ File: producer.rs (FlowSpanProducer::run)                                   │      │
│  │ Location: Lines 285-295                                                     │      │
│  └─────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                       │
│  📊 METRICS:                                                                          │
│  • mermin_flow_events_total{type="received|dropped_backpressure|dropped_error"}      │
│    - "received": successfully read and validated from ring buffer                     │
│    - "dropped_backpressure": all worker channels full, event dropped                  │
│    - "dropped_error": invalid/corrupted event detected, validation failed            │
│                                                                                       │
│  ⚠️  FAILURE POINTS:                                                                  │
│  • Ring buffer full → drops occur (handled by eBPF)                                   │
│  • Worker channels full → backpressure drops (`dropped_backpressure`)                │
│  • Corrupted/invalid event data → validation fails (`dropped_error`)                 │
└──────────────────┬────────────────────────────────────────────────────────────────────┘
                   │ FlowEvent dispatched to workers
                   ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│  WORKER PROCESSING STAGE                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────┐      │
│  │ File: producer.rs (FlowWorker::create_direct_flow)                          │      │
│  │ Location: Lines 490-551                                                     │      │
│  └─────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                       │
│  📊 METRICS:                                                                          │
│  • mermin_producer_flow_spans_total{interface="<name>",                               |
│      status="<status>"}                                                               │
│    - status values: "created", "dropped", "recorded", "idled", "active"               │
│    - interface: actual interface name or "unknown"                                    │
│    - "created": flow span created successfully (producer.rs)                          │
│    - "active": flow span marked as active (producer.rs)                               │
│    - "dropped": flow filtered/removed during processing (producer.rs)                 │
│    - "recorded": flow sent to K8s decorator (producer.rs:record_flow)                 │
│    - "idled": flow timed out and removed (producer.rs:timeout_and_remove_flow)        │
│  • mermin_flow_spans_processed_total ← Successful flow span creation                  │
│  • mermin_flow_stats_map_access_total{status="ok|error|not_found"} ← BPF map read ops |
│                                                                                       │
│  ⚠️  FAILURE POINTS:                                                                  │
│  • Flow filtering → filtered flows removed (not counted in processed)                │
│  • eBPF map read failures → flow creation fails                                      │
│  • Invalid flow keys → processing errors                                             │
└──────────────────┬───────────────────────────────────────────────────────────────────┘
                   │ FlowSpan → flow_store
                   ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│  FLOW STORE & POLLER STAGE (Sharded by poller_id)                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐      │
│  │ File: producer.rs (flow_poller_task)                                        │      │
│  │ Location: Lines 1242-1418                                                   │      │
│  └─────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                       │
│  📊 METRICS:                                                                          │
│  • mermin_flow_span_store_size{poller_id="<id>"}     ← Current flows per poller       │
│  • mermin_producer_queue_size{poller_id="<id>"}      ← Queued flows per poller        │
│  • mermin_producer_flow_spans_total{status="recorded"} ← Flows recorded (sent to K8s)│
│  • mermin_producer_flow_spans_total{status="idled"} ← Flows expired/timed out         │
│    - Note: "recorded" and "idled" are status values of producer_flow_spans_total      │
│                                                                                       │
│  🔍 DIAGNOSTIC INSIGHTS:                                                              │
│  • Monitor poller imbalance: compare flow_store_size across pollers                  │
│  • High queue_size → poller overload / slow processing                               │
│  • Cyclic patterns → check poller processing times                                   │
└──────────────────┬───────────────────────────────────────────────────────────────────┘
                   │ FlowSpan → record_flow() → flow_span_tx
                   ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│  K8S DECORATION STAGE                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────┐      │
│  │ File: main.rs (K8s decorator thread)                                        │      │
│  │ Location: Lines 516-585                                                     │      │
│  └─────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                       │
│  📊 METRICS:                                                                          │
│  • mermin_k8s_decorator_flow_spans_total{status="dropped|ok|error|undecorated"}       │
│    - "dropped": export channel full, span dropped (main.rs)                           │
│    - "ok": successful decoration (main.rs)                                            │
│    - "error": decoration failed, span sent undecorated (main.rs)                      │
│    - "undecorated": K8s client unavailable, span sent without decoration (main.rs)    │
│  • mermin_channel_size{channel="decorator_input"}     ← Decorator Q size (consolidated)│
│  • mermin_channel_size{channel="exporter"}           ← Exporter channel size          │
│  • mermin_processing_latency_seconds{stage="k8s_decoration"} ← Decoration time (consolidated)│
│ Export channel is tracked via `mermin_export_flow_spans_total{status="queued"}` when received by export thread│
│                                                                                       │
│  ⚠️  FAILURE POINTS:                                                                  │
│  • Decoration failures → spans sent undecorated (still counted)                       │
│  • Export channel full → spans dropped                                                │
└──────────────────┬────────────────────────────────────────────────────────────────────┘
                   │ Decorated FlowSpan → export channel
                   ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│  EXPORT STAGE                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────┐      │
│  │ File: main.rs (Export thread)                                               │      │
│  │ Location: Lines 608-627                                                     │      │
│  └─────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                       │
│  📊 METRICS:                                                                          │
│  • mermin_export_flow_spans_total{status="queued|dropped|ok|error|noop"}              │
│    - "queued": span received by export thread                                         │
│    - "dropped": export channel full (from producer/decoration stages)                 │
│    - "ok": span successfully sent to OTEL BatchSpanProcessor                          │
│    - "error": OTEL export failure (captured via tracing layer)                        │
│    - "noop": span processed but not exported (NoOpExporterAdapter)                    │
│  • mermin_export_latency_seconds                      ← Export operation time         │
│  • mermin_channel_size{channel="exporter_input"}   ← Export Queue size (consolidated) │
│  • mermin_export_batch_size                           ← Spans per batch               │
│  • mermin_processing_latency_seconds{stage="otlp_export"} ← Export processing time    │
│                                                                                       │
│  📝 NOTE: Export errors are captured via tracing layer intercepting OTEL ERROR logs   │
│                                                                                       │
│  ⚠️  FAILURE POINTS:                                                                  │
│  • Export channel full → spans dropped (`export_flow_spans_total{status="dropped"}`)  │
│  • Export backend failures → OTEL errors logged, captured by tracing layer            │
│    (`export_flow_spans_total{status="error"}`)                                        │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Diagnostic Queries for Cyclic Spikes/Fall-offs

### 1. Flow Attrition

Once spans are created, need to track flow spans through each pipeline stage to identify
where drops or slowdowns may be occuring.

```
mermin_flow_events_total{type="received"}
  ↓ (should match or be ~same rate)
mermin_flow_spans_processed_total
  ↓ (should be ~equal)
mermin_producer_flow_spans_total{status="recorded"}
  ↓ (should be ~equal)
mermin_export_flow_spans_total{status="queued"}
  ↓ (should be ~equal)
mermin_export_flow_spans_total{status="ok"}
```

**Additional Lifecycle Queries:**

- **Flow Creation**: `mermin_producer_flow_spans_total{status="created"}` per interface
- **Flow Expiration**: `mermin_producer_flow_spans_total{status="idled"}` - flows that timed out
- **Decoration Success Rate**: `mermin_k8s_decorator_flow_spans_total{status="ok"}` / `mermin_k8s_decorator_flow_spans_total{status="ok|error|undecorated"}`
- **Export Success Rate**: `mermin_export_flow_spans_total{status="ok"}` / `mermin_export_flow_spans_total`
- **Export Errors**: `mermin_export_flow_spans_total{status="error"}` - captured from OTEL tracing layer
