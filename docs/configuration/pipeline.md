# Pipeline Configuration

The `pipeline` block provides advanced configuration for flow processing pipeline optimization, including channel capacity tuning, worker threading, Kubernetes decoration, backpressure management, and buffer multipliers.

The configuration options become useful to take advantage of additional resources allocated for Mermin or to generally optimize the performance for your specific use-case.

## Configuration

Full configuration example may be found in the [Default Config](https://github.com/elastiflow/mermin/tree/beta/charts/mermin/config/default/config.hcl).

## Configuration Structure

The pipeline configuration is organized into nested blocks for which reflect the architecture:

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
  # Top-level backpressure and sampling settings
  sampling_enabled = true
  sampling_min_rate = 0.1
  backpressure_warning_threshold = 0.01
}
```

## Configuration Options

### Flow Capture (`flow_capture`)

#### `flow_stats_capacity`

**Type:** Integer **Default:** `100000`

The capacity of the `FLOW_STATS` eBPF map. (Refer to the [architecture](../getting-started/architecture.md#ebpf-programs) documentation for more information.)

**Example:**
```hcl
pipeline {
  flow_capture {
    flow_stats_capacity = 500000  # For high-traffic ingress
  }
}
```

#### `flow_events_capacity`

**Type:** Integer (entries) **Default:** `1024`

The capacity of the `FLOW_EVENTS` ring buffer as number of entries. Each entry is 234 bytes (FlowEvent size), so the default 1024 entries equals ~240 KB. This buffer is used to pass new flow events from eBPF to userspace. Keep the buffer high enough to provide flow record burst tolerance.

**Sizing Guide** (based on flows per second):
- **General/Mixed** (50-500 FPS): `1024` entries (~240 KB)
- **High Traffic** (500-2K FPS): `2048` entries (~480 KB)
- **Very High Traffic** (2K-5K FPS): `4096` entries (~960 KB)
- **Extreme Traffic** (>5K FPS): `8192+` entries (~1.9 MB+)

**Example:**
```hcl
pipeline {
  flow_capture {
    flow_events_capacity = 4096  # 4x default for very high traffic
  }
}
```

### Flow Producer (`flow_producer`)

#### `workers`

**Type:** Integer **Default:** `4`

The number of parallel flow worker threads. Adjust this value based on the available CPU resources.

**Example:**
```hcl
pipeline {
  flow_producer {
    workers = 8  # Use more workers for increased parallelism
  }
}
```

#### `worker_queue_capacity`

**Type:** Integer **Default:** `2048`

Capacity for each worker thread's event queue. Determines how many raw eBPF events can be buffered per worker before drops occur.

**Example:**
```hcl
pipeline {
  flow_producer {
    worker_queue_capacity = 4096
  }
}
```

#### `flow_store_poll_interval`

**Type:** String (duration) **Default:** `"5s"`

The polling interval for flow workers. This controls how frequently workers poll the flow data from the `FLOW_STATS` map. (Refer to the [architecture](../getting-started/architecture.md#ebpf-programs) documentation for more information.)
Reducing the interval may increase the CPU usage.

**Example:**
```hcl
pipeline {
  flow_producer {
    flow_store_poll_interval = "2s"  # Poll more frequently
  }
}
```

#### `flow_span_queue_capacity`

**Type:** Integer **Default:** `16384`

Explicit capacity for the flow span channel, acting as a buffer between workers and the K8s decorator.
With default settings, this provides approximately 1.6s of buffer at 10,000 flows/sec.

**Example:**
```hcl
pipeline {
  flow_producer {
    flow_span_queue_capacity = 24576  # Larger buffer for high-latency decoration
  }
}
```

### Kubernetes Decorator (`k8s_decorator`)

#### `threads`

**Type:** Integer **Default:** `4`

The number of threads dedicated to Kubernetes decoration. Increase this value for larger clusters.

**Example:**
```hcl
pipeline {
  k8s_decorator {
    threads = 8  # More threads for faster decoration
  }
}
```

#### `decorated_span_queue_capacity`

**Type:** Integer **Default:** `32768`

Explicit capacity for the decorated span channel, acting as a buffer between the K8s decorator and the exporter.
With default settings, this provides approximately 3.2s of buffer at 10,000 flows/sec.

**Example:**
```hcl
pipeline {
  k8s_decorator {
    decorated_span_queue_capacity = 65536  # Increase for slow exporters
  }
}
```
