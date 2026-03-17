# Configure Flow Processing Pipeline

**Block:** `pipeline`

The `pipeline` block configures the flow processing pipeline: eBPF map sizing, worker threading, Kubernetes decoration, and inter-stage buffer capacities.

**Default baseline:** All defaults are tuned for deployments with ≤16,384 concurrent flows (~3,200 flow records/s at the default 5s poll interval). Memory is pre-allocated at the configured sizes.
Scale values proportionally for higher-traffic nodes.

## Configuration

A full example is in the [default config](../default/config.hcl).

### `pipeline.flow_capture` block

Configures eBPF-level flow tracking.

- `flow_stats_capacity` attribute

  Max entries in the `FLOW_STATS` eBPF map. The map is created at this fixed size at program load time and does not resize at runtime. Uses `BPF_F_NO_PREALLOC`:
  memory grows on demand as flows are tracked, up to this limit — so actual kernel memory equals the number of active concurrent flows × ~270 bytes (FlowStats: 192B + FlowKey: 40B aligned + htab_elem overhead: ~38B).
  Once full, new flows are dropped.

  **Type:** Integer

  **Default:** `16384`

  **Example:**

  ```hcl
  pipeline {
    flow_capture {
      flow_stats_capacity = 65536
    }
  }
  ```

- `flow_events_capacity` attribute

  Max entries in the `FLOW_EVENTS` ring buffer. This buffer carries new-flow notifications from eBPF to userspace — one event per unique flow, not per flow record. The ring buffer is created at this fixed size during eBPF program load.
  Each entry is 234 bytes; default 1,024 entries = ~240 KB.

  **Type:** Integer (entries)

  **Default:** `1024`

  If you see `"ring buffer full - dropping flow event"` log entries, increase this value. The aya loader automatically aligns to page size.

  **Example:**

  ```hcl
  pipeline {
    flow_capture {
      flow_events_capacity = 2048
    }
  }
  ```

### `pipeline.flow_producer` block

Configures userspace flow processing.

- `workers` attribute

  Number of parallel worker threads that process eBPF flow events. Each worker has its own queue with depth `worker_queue_capacity`.
  Workers handle event ingestion only —
  flow table polling and timeout handling are done by a separate set of poller tasks whose count is set automatically based on the CPU resources available to the process (respecting CPU limits in containerised environments).

  **Type:** Integer

  **Default:** `4`

  | Traffic level       | Recommended workers |
  |---------------------|---------------------|
  | Low / default       | 2–4 (default: 4)    |
  | High (>50K flows/s) | 6–8                 |
  | Extreme (>100K/s)   | 8–16                |

  **Example:**

  ```hcl
  pipeline {
    flow_producer {
      workers = 8
    }
  }
  ```

- `worker_queue_capacity` attribute

  Per-worker event queue depth. Total worker buffer memory ≈ `workers × worker_queue_capacity × 234 bytes`. Scale up if metrics show `mermin_flow_events_total{status="dropped_backpressure"}` increasing.

  **Type:** Integer

  **Default:** `1024`

  **Example:**

  ```hcl
  pipeline {
    flow_producer {
      worker_queue_capacity = 2048
    }
  }
  ```

- `flow_store_poll_interval` attribute

  How often pollers scan the flow table to emit periodic flow records and expire idle flows. Lower values give more responsive timeout detection at slightly higher CPU cost.
  The number of pollers is set automatically based on available CPU resources and is independent of `workers`.

  **Type:** String (duration)

  **Default:** `"5s"`

  **Example:**

  ```hcl
  pipeline {
    flow_producer {
      flow_store_poll_interval = "3s"
    }
  }
  ```

- `flow_span_queue_capacity` attribute

  Buffer between flow workers and the K8s decorator. Default provides ~1.3s of buffering at the 3,200 spans/s baseline. Scale proportionally with `flow_stats_capacity`.

  **Type:** Integer

  **Default:** `4096`

  **Example:**

  ```hcl
  pipeline {
    flow_producer {
      flow_span_queue_capacity = 8192
    }
  }
  ```

### `pipeline.k8s_decorator` block

Configures Kubernetes metadata decoration.

- `decorated_span_queue_capacity` attribute

  Buffer between the K8s decorator and the OTLP exporter — the final stage before network export. Default provides ~2.5s of buffering at the 3,200 spans/s baseline. Scale proportionally with `flow_stats_capacity`.

  **Type:** Integer

  **Default:** `8192`

  **Example:**

  ```hcl
  pipeline {
    k8s_decorator {
      decorated_span_queue_capacity = 16384
    }
  }
  ```

## Monitoring Performance Configuration

For Kubernetes deployments, ensure the Tokio worker thread count matches your pod's CPU
limit to avoid CFS throttling. See [Worker threads](../overview.md#worker-threads) in the
Configuration Overview.

After tuning, monitor these metrics:

- `mermin_flow_events_total{status="dropped_backpressure"}` — backpressure drops
- `mermin_flow_events_total{status="dropped_error"}` — error drops
- `mermin_channel_size` / `mermin_channel_capacity` — channel utilization
- `mermin_pipeline_duration_seconds` — pipeline stage latency

**Healthy indicators:** no backpressure drops, channel utilization < 80%, p95 latency < 10ms.

See [Internal Metrics](../../internal-monitoring/internal-metrics.md) for Prometheus query examples.

## Next Steps

{% tabs %}
{% tab title="Tune Performance" %}
1. [**Configure Flow Timeouts**](flow-span-producer.md): Balance latency vs. accuracy
2. [**Tune Export Batching**](opentelemetry-otlp-exporter.md): Optimize for your backend
{% endtab %}

{% tab title="Learn More" %}
1. [**Understand the Architecture**](../../concepts/agent-architecture.md): How data flows through the pipeline
2. [**Review Production Examples**](../examples.md): High-throughput configurations
{% endtab %}
{% endtabs %}

### Need Help?

- [**Troubleshoot Performance Issues**](../../troubleshooting/troubleshooting.md): Diagnose bottlenecks
- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Share pipeline configurations
