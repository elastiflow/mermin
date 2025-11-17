## Flow Span Production Pipeline

### Complete Pipeline Visualization

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          eBPF FLOW SPAN PRODUCTION PIPELINE                             │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐
│   eBPF Kernel    │
│   (Packet Hook)  │
└────────┬─────────┘
         │ Packets processed
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
│  • mermin_ringbuf_packets_total{type="received"}     ← Flow events received           │
│  • mermin_ringbuf_bytes_total                         ← Total bytes received          │
│  • mermin_flow_events_dropped_backpressure_total      ← Events dropped (full buffer)  │
│                                                                                       │
│  ⚠️  FAILURE POINTS:                                                                  │
│  • Ring buffer full → drops occur                                                     │
│  • Worker channels full → backpressure drops                                          │
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
│  • mermin_flow_spans_processed_total                  ← Successful flow creation      │
│  • mermin_flow_spans_created_total{interface="<name>"} ← Flows created per iface      │
│  • mermin_flow_spans_active{interface="<name>"}       ← Current active flows          │
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
│  • mermin_flow_store_size{poller_id="<id>"}          ← Current flows per poller       │
│  • mermin_flow_poller_queue_size{poller_id="<id>"}   ← Queued flows per poller        │
│  • mermin_flow_spans_expired_total{reason="timeout"} ← Expired flows                  │
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
│  • mermin_flow_spans_decorated_total                  ← Successfully decorated        │
│  • mermin_channel_size{channel="decorator_input"}     ← Queue size before decorator   │
│  • mermin_processing_latency_seconds{stage="k8s_decoration"} ← Decoration time        │
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
│  │ File: main.rs (K8s decorator)                                               │      │
│  │ Location: Lines 542-557                                                     │      │
│  └─────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                       │
│  📊 METRICS:                                                                          │
│  • mermin_flow_spans_sent_to_exporter_total          ← Queued for export             │
│  • mermin_export_spans_total                          ← Actually exported            │
│  • mermin_flow_spans_dropped_export_failure_total     ← Drops (channel full)         │
│  • mermin_export_latency_seconds                      ← Export operation time        │
│  • mermin_export_batch_size                           ← Spans per batch              │
│                                                                                      │
│  ⚠️  FAILURE POINTS:                                                                 │
│  • Export channel full → spans dropped (export_failure_total)                        │
│  • Export backend failures → spans may be retried or lost                            │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Diagnostic Queries for Cyclic Spikes/Fall-offs

### 1. Flow Attrition

Track flows through each pipeline stage to identify where drops occur:

```
ringbuf_packets_total{type="received"}
  ↓ (should match or be ~same rate)
flow_spans_processed_total
  ↓ (should be ~equal)
flow_spans_decorated_total
  ↓ (should be ~equal)
flow_spans_sent_to_exporter_total
  ↓ (should be ~equal)
export_spans_total
```

**PromQL Query Example:**
```promql
# Compare rates across stages
rate(mermin_ringbuf_packets_total{type="received"}[5m])
rate(mermin_flow_spans_processed_total[5m])
rate(mermin_flow_spans_decorated_total[5m])
rate(mermin_flow_spans_sent_to_exporter_total[5m])
rate(mermin_export_spans_total[5m])
```

**If gaps appear, that's where flows are being lost!**

### 2. Poller Imbalance Detection

Check for uneven distribution across pollers:

```promql
# Compare flow store sizes across pollers
mermin_flow_store_size{poller_id="0"}
mermin_flow_store_size{poller_id="1"}
mermin_flow_store_size{poller_id="2"}

# Calculate variance (high variance = imbalance)
stddev_over_time(mermin_flow_store_size[5m])
```

**Symptoms:**
- High variance → uneven distribution → potential bottlenecks
- One poller consistently higher → hash distribution issue

### 3. Backpressure Detection

Identify bottlenecks causing drops:

```promql
# Ring buffer / worker channel backpressure
rate(mermin_flow_events_dropped_backpressure_total[5m])

# Export channel backpressure
rate(mermin_flow_spans_dropped_export_failure_total[5m])

# Decoration queue buildup
mermin_channel_size{channel="decorator_input"}
```

**Alert Conditions:**
- `flow_events_dropped_backpressure_total` increasing → worker channels saturated
- `flow_spans_dropped_export_failure_total` increasing → export channel full
- `channel_size{channel="decorator_input"}` > 80% capacity → decoration bottleneck


## Metric Reference

### Pipeline Stage Metrics

| Metric | Type | Stage | Description |
|--------|------|-------|-------------|
| `mermin_ringbuf_packets_total{type="received"}` | Counter | Ring Buffer | Flow events received from eBPF |
| `mermin_flow_spans_processed_total` | Counter | Worker | Flows successfully processed |
| `mermin_flow_spans_decorated_total` | Counter | Decoration | Flows enriched with K8s metadata |
| `mermin_flow_spans_sent_to_exporter_total` | Counter | Export Queue | Flows queued for export |
| `mermin_export_spans_total` | Counter | Export | Flows actually exported to backend |

### Store & Queue Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mermin_flow_store_size{poller_id="<id>"}` | Gauge | Current flows in store per poller |
| `mermin_flow_poller_queue_size{poller_id="<id>"}` | Gauge | Queued flows per poller |
| `mermin_flow_spans_active{interface="<name>"}` | Gauge | Active flows per interface |

### Error Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mermin_flow_events_dropped_backpressure_total` | Counter | Events dropped due to worker backpressure |
| `mermin_flow_spans_dropped_export_failure_total` | Counter | Spans dropped due to export channel full |

### Latency Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `mermin_processing_latency_seconds{stage="flow_ingestion"}` | Histogram | Ring buffer processing time |
| `mermin_processing_latency_seconds{stage="k8s_decoration"}` | Histogram | K8s decoration time |
| `mermin_export_latency_seconds` | Histogram | Export operation time |
