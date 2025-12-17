# Pipeline Configuration

The `pipeline` block provides advanced configuration for flow processing pipeline optimization, including base channel sizing, worker threading, Kubernetes decoration, backpressure management, and buffer multipliers.

The configuration options become useful to take advantage of additional resources allocated for Mermin or to generally optimize the performance for your specific use-case.

## Configuration

Full configuration example may be found in the [Default Config](https://github.com/elastiflow/mermin/tree/beta/charts/mermin/config/default/config.hcl).

## Configuration Options

### `ebpf_max_flows`

**Type:** Integer **Default:** `100000`

The capacity of the `FLOW_STATS` map. (Refer to the [architecture](../getting-started/architecture.md#ebpf-programs) documentation for more information.)

**Example:**

```hcl
metrics {
  ebpf_max_flows = 5000  # Reduce `FLOW_STATS` capacity
}
```

### `base_capacity`

**Type:** Integer **Default:** `8192`

The base capacity for **userspace channels** between pipeline stages (workers → K8s decorator → exporter). This value is used to calculate:

- **Worker queue capacity**: `base_capacity / worker_count` (default: 8192 / 4 = 2048 per worker)
- **Flow span channel**: `base_capacity × flow_span_channel_multiplier` (default: 8192 × 2.0 = 16,384)
- **Decorated span channel**: `base_capacity × decorated_span_channel_multiplier` (default: 8192 × 4.0 = 32,768)
- **Flow store initial capacity**: `base_capacity × 4` (default: 8192 × 4 = 32,768)

Increasing this value provides larger buffers throughout the pipeline, reducing backpressure during traffic spikes.

**Note:** This does NOT control the eBPF `FLOW_EVENTS` ring buffer size, which is hardcoded at compile time (256 KB, ~1,120 events).

**Example:**

```hcl
pipeline {
  base_capacity = 16384  # Increase userspace buffers for high-throughput environments
}
```

### `worker_count`

**Type:** Integer **Default:** `4`

The number of parallel flow worker threads. Adjust this value based on the available CPU resources.

**Example:**

```hcl
pipeline {
  worker_count = 8  # Use more workers for increased parallelism
}
```

### `worker_poll_interval`

**Type:** String (duration) **Default:** `"5s"`

The polling interval for flow workers. This controls how frequently workers poll the flow data from the `FLOW_STATS` map. (Refer to the [architecture](../getting-started/architecture.md#ebpf-programs) documentation for more information.)
Reducing the interval may increase the CPU usage.

**Example:**

```hcl
pipeline {
  worker_poll_interval = "2s"  # Poll more frequently
}
```

### `k8s_decorator_threads`

**Type:** Integer **Default:** `4`

The number of threads dedicated to Kubernetes decoration. Increase this value for larger clusters.

**Example:**

```hcl
pipeline {
  k8s_decorator_threads = 8  # More threads for faster decoration
}
```

### `flow_span_channel_multiplier`

**Type:** Float **Default:** `2.0`

The multiplier for the flow span channel size, relative to the ring buffer capacity.
The channel is used in the "Flow Producer" stage, please refer to the [architecture](../getting-started/architecture.md#components) documentation for more information.

**Example:**

```hcl
pipeline {
  flow_span_channel_multiplier = 3.0  # Larger channel for bursty flows
}
```

### `decorated_span_channel_multiplier`

**Type:** Float **Default:** `4.0`

The multiplier for the decorated span channel size, relative to the ring buffer capacity.
The channel is used in the "K8s Decorator" stage, please refer to the [architecture](../getting-started/architecture.md#components) documentation for more information.

**Example:**

```hcl
pipeline {
  decorated_span_channel_multiplier = 6.0  # Increase for heavy decoration workloads
}
```
