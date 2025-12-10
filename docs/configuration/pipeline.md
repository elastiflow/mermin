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

### `ring_buffer_capacity`

**Type:** Integer **Default:** `8192`

The default capacity of the `FLOW_EVENTS` ring buffer. (Refer to the [architecture](../getting-started/architecture.md#ebpf-programs) documentation for more information.) Increasing this value can help process higher flow rates.

**Example:**

```hcl
pipeline {
  ring_buffer_capacity = 16384  # Increase buffer for high-throughput environments
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

Number of threads dedicated to Kubernetes decoration. Increase for larger clusters.

**Example:**

```hcl
pipeline {
  k8s_decorator_threads = 8  # More threads for faster decoration
}
```

### `flow_span_channel_multiplier`

**Type:** Float **Default:** `2.0`

Multiplier for the flow span channel size, relative to the ring buffer capacity.
<!-- TODO(lgo-421): Is it true? -->
The channel is used in the "Flow Producer" stage, please refer the [architecture](../getting-started/architecture.md#components) for more details.

**Example:**

```hcl
pipeline {
  flow_span_channel_multiplier = 3.0  # Larger channel for bursty flows
}
```

### `decorated_span_channel_multiplier`

**Type:** Float **Default:** `4.0`

Multiplier for the decorated span channel size, relative to the ring buffer capacity.
<!-- TODO(lgo-421): Is it true? -->
The channel is used in the "K8s Decorator" stage, please refer the [architecture](../getting-started/architecture.md#components) for more details.

**Example:**

```hcl
pipeline {
  decorated_span_channel_multiplier = 6.0  # Increase for heavy decoration workloads
}
```
