# Configure Flow Processing Pipeline

**Block:** `pipeline`

The `pipeline` block provides advanced configuration for flow processing pipeline optimization, including channel capacity tuning, worker threading, Kubernetes decoration, backpressure management, and buffer multipliers.

The configuration options become useful to take advantage of additional resources allocated for Mermin or to generally optimize the performance for your specific use-case.

## Configuration

A full pipeline example is in the [default config](./default/config.hcl) in the repository.

### Configuration Structure

The pipeline configuration is organized into nested blocks that reflect the architecture:

```hcl
pipeline {
  flow_capture {
    # eBPF-level flow tracking configuration
  }
  flow_producer {
    # Userspace flow processing configuration
  }
  k8s_decorator {
    # Kubernetes metadata decoration configuration
  }
}
```

## Configuration Options

### `pipeline.flow_capture` block

- `flow_stats_capacity` attribute

  The capacity of the `FLOW_STATS` eBPF map. See [eBPF Programs](../getting-started/agent-architecture.md#ebpf-programs) in the architecture documentation for more information.

  **Type:** Integer

  **Default:** `100000`

  **Tuning Guidelines:**

  | Traffic Volume             | Recommended Value |
  |----------------------------|-------------------|
  | Low (< 10K flows/s)        | 50000             |
  | Medium (10K-50K flows/s)   | 100000 (default)  |
  | High (50K-100K flows/s)    | 250000            |
  | Very High (> 100K flows/s) | 500000+           |

  **Example:** Increase capacity for high-traffic ingress

  ```hcl
  pipeline {
    flow_capture {
      flow_stats_capacity = 500000
    }
  }
  ```

- `flow_events_capacity` attribute

  The capacity of the `FLOW_EVENTS` ring buffer as number of entries. Each entry is 234 bytes (FlowEvent size), so the default 1024 entries equals ~240 KB. This buffer is used to pass new flow events from eBPF to userspace.
  Keep the buffer high enough to provide flow record burst tolerance.

  **Type:** Integer (entries)

  **Default:** `1024`

  **Sizing Guide** (based on flows per second):

  | Traffic Pattern              | Recommended Value | Memory Usage |
  |------------------------------|-------------------|--------------|
  | General/Mixed (50-500 FPS)   | `1024` (default)  | ~240 KB      |
  | High Traffic (500-2K FPS)    | `2048`            | ~480 KB      |
  | Very High Traffic (2K-5K FPS)| `4096`            | ~960 KB      |
  | Extreme Traffic (>5K FPS)    | `8192+`           | ~1.9 MB+     |

  **Example:** Increase buffer for very high traffic

  ```hcl
  pipeline {
    flow_capture {
      flow_events_capacity = 4096
    }
  }
  ```

### `pipeline.flow_producer` block

- `workers` attribute

  Number of parallel worker threads processing packets and generating flow spans. Each worker processes eBPF events independently from a dedicated worker queue.

  **Type:** Integer

  **Default:** `4`

  **Behavior:**

  - Each worker processes packets independently
  - More workers = more parallelism = higher throughput
  - More workers = more CPU usage
  - Workers share the flow table (synchronized)

  **Tuning Guidelines:**

  | Traffic Volume             | Recommended Workers | CPU Allocation |
  |----------------------------|---------------------|----------------|
  | Low (< 10K flows/s)        | 1-2                 | 0.5-1 cores    |
  | Medium (10K-50K flows/s)   | 2-4                 | 1-2 cores      |
  | High (50K-100K flows/s)    | 4 (default)         | 2-4 cores      |
  | Very High (> 100K flows/s) | 8-16                | 4-8 cores      |

  **Optimal Worker Count:**

  - Start with CPU count / 2
  - Monitor CPU usage with metrics
  - Increase if CPU is underutilized and packet drops occur
  - Decrease if CPU is overutilized

  **Relationship with CPU Resources:**

  ```yaml
  # Kubernetes resources should match worker count
  resources:
    requests:
      cpu: 2     # For flow_producer.workers = 4
    limits:
      cpu: 4     # For flow_producer.workers = 4
  ```

  **Example:** Use more workers for increased parallelism

  ```hcl
  pipeline {
    flow_producer {
      workers = 8
    }
  }
  ```

- `worker_queue_capacity` attribute

  Capacity for each worker thread's event queue. Determines how many raw eBPF events can be buffered per worker before drops occur.

  **Type:** Integer

  **Default:** `2048`

  **Formula:** Total worker buffer memory ≈ `flow_producer.workers` × `flow_producer.worker_queue_capacity` × 256 bytes

  **Tuning Guidelines:**

  | Traffic Volume             | Recommended Value |
  |----------------------------|-------------------|
  | Low (< 10K flows/s)        | 512-1024          |
  | Medium (10K-50K flows/s)   | 1024-2048         |
  | High (50K-100K flows/s)    | 2048 (default)    |
  | Very High (> 100K flows/s) | 4096+             |

  **Signs You Need to Increase:**

  - Metrics show `mermin_flow_events_total{status="dropped_backpressure"}` increasing

  **Example:** Increase queue capacity for high traffic

  ```hcl
  pipeline {
    flow_producer {
      worker_queue_capacity = 4096
    }
  }
  ```

- `flow_store_poll_interval` attribute

  Interval at which flow pollers check for flow records and timeouts. Pollers iterate through active flows to generate periodic flow records (based on `max_record_interval` in `span` config) and detect and remove idle flows (based on protocol-specific timeouts in `span` config).

  See [eBPF Programs](../getting-started/agent-architecture.md#ebpf-programs) in the architecture documentation for more information.

  **Type:** String (duration)

  **Default:** `"5s"`

  **Behavior:**

  - Lower values = more responsive timeout detection and flow recording
  - Higher values = less CPU overhead
  - At typical enterprise scale (10K flows/sec with 100K active flows and 32 pollers): ~600 flow checks/sec per poller
  - Modern CPUs handle flow checking very efficiently (microseconds per check)

  **Tuning Guidelines:**

  | Traffic Pattern          | Recommended Interval | Rationale                           |
  |--------------------------|----------------------|-------------------------------------|
  | Short-lived flows (ICMP) | 3-5s                 | Fast timeout detection              |
  | Mixed traffic            | 5s (default)         | Balance responsiveness and overhead |
  | Long-lived flows (TCP)   | 10s                  | Lower overhead, slower timeouts     |
  | Memory constrained       | 3-5s                 | More frequent cleanup               |

  **Trade-offs:**

  - **3s interval**: Most responsive, slightly higher CPU (~10K checks/sec per poller)
  - **5s interval** (default): Best balance for most workloads
  - **10s interval**: Lowest CPU, flows may linger longer before timeout

  **Signs You Should Decrease:**

  - Flows lingering past their intended timeout
  - Memory usage growing steadily
  - Short-lived flow protocols (ICMP with 10s timeout)

  **Signs You Can Increase:**

  - CPU constrained
  - Primarily long-lived TCP flows
  - Flow timeout accuracy not critical

  **Example:** Poll more frequently for short-lived flows

  ```hcl
  pipeline {
    flow_producer {
      flow_store_poll_interval = "2s"
    }
  }
  ```

- `flow_span_queue_capacity` attribute

  Explicit capacity for the flow span channel, acting as a buffer between workers and the K8s decorator. With default settings, this provides approximately 160ms of buffer at 100K flows/sec.

  **Type:** Integer

  **Default:** `16384`

  **Recommendations:**

  | Use Case              | Recommended Value |
  |-----------------------|-------------------|
  | Steady traffic        | 16384 (default)   |
  | Bursty traffic        | 24576-32768       |
  | Low latency priority  | 12288             |

  **Example:** Increase buffer for high-latency decoration

  ```hcl
  pipeline {
    flow_producer {
      flow_span_queue_capacity = 24576
    }
  }
  ```

### `pipeline.k8s_decorator` block

- `threads` attribute

  Number of dedicated threads for Kubernetes metadata decoration. Running decoration on separate threads prevents K8s API lookups from blocking flow processing. Each thread handles ~8K flows/sec (~100-150μs per flow), so 4 threads provide 32K flows/sec capacity.

  **Type:** Integer

  **Default:** `4`

  **Recommendations based on typical FPS (flows per second):**

  | Cluster Type               | Typical FPS | Recommended Threads |
  |----------------------------|-------------|---------------------|
  | General/Mixed              | 50-200      | 2-4 (default: 4)    |
  | Service Mesh               | 100-300     | 4 (default)         |
  | Public Ingress             | 1K-5K       | 4-8                 |
  | High-Traffic Ingress       | 5K-25K      | 8-12                |
  | Extreme Scale (Edge/CDN)   | >25K        | 12-24               |

  **Example:** Increase threads for faster decoration

  ```hcl
  pipeline {
    k8s_decorator {
      threads = 8
    }
  }
  ```

- `decorated_span_queue_capacity` attribute

  Explicit capacity for the decorated span (export) channel, acting as a buffer between the K8s decorator and the OTLP exporter. This should be the largest buffer since network export is the slowest stage. With default settings, this provides approximately 320ms of buffer at 100K flows/sec.

  **Type:** Integer

  **Default:** `32768`

  **Recommendations:**

  | Network Condition      | Recommended Value |
  |------------------------|-------------------|
  | Reliable network       | 32768 (default)   |
  | Unreliable network     | 49152-65536       |
  | Very high throughput   | 65536-98304       |

  **Example:** Increase buffer for slow exporters

  ```hcl
  pipeline {
    k8s_decorator {
      decorated_span_queue_capacity = 65536
    }
  }
  ```

## Monitoring Performance Configuration

After tuning performance settings, monitor these key metrics:

- `mermin_flow_events_total{status="dropped_backpressure"}` - Backpressure events
- `mermin_flow_events_total{status="dropped_error"}` - Error drops
- `mermin_channel_size` / `mermin_channel_capacity` - Channel utilization
- `mermin_pipeline_duration_seconds` - Pipeline duration histogram

See the [Internal Metrics](../internal-monitoring/internal-metrics.md) guide for complete Prometheus query examples.

**Healthy indicators:**

- Sampling rate = 0 (no backpressure)
- Channel utilization < 80%
- p95 processing latency < 10ms
- IP index updates < 100ms

## Next Steps

- [**Configuration Overview**](overview.md): Config file format and structure
- [**Architecture**](../getting-started/agent-architecture.md): Data flow and eBPF programs
- [**Span Options**](span.md): Flow timeouts and span generation
- [**OTLP Exporter**](export-otlp.md): Export tuning and backpressure
- [**Configuration Examples**](examples.md): Full pipeline examples (production, high-throughput)
