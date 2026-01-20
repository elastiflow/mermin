# Pipeline Configuration

The `pipeline` block provides advanced configuration for flow processing pipeline optimization, including channel capacity tuning, worker threading, Kubernetes decoration, backpressure management, and buffer multipliers.

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
### `ebpf_ringbuf_size`

**Type:** String (byte size) **Default:** `"256KB"`

The size of the `FLOW_EVENTS` ring buffer used to pass new flow events from eBPF to userspace. Keep the buffer high enough to provide flow record burst tolerance.

**Sizing Guide** (based on flows per second):
- **General/Mixed** (50-500 FPS): `256KB` (~1,120 events)
- **High Traffic** (500-2K FPS): `512KB` (~2,240 events)
- **Very High Traffic** (2K-5K FPS): `1MB` (~4,480 events)
- **Extreme Traffic** (>5K FPS): `2MB`+

**Example:**

```hcl
pipeline {
  ebpf_ringbuf_size = "1MB"
}
```

### `ebpf_ringbuf_worker_capacity`

**Type:** Integer **Default:** `2048`

Capacity for each worker thread's event queue. Determines how many raw eBPF events can be buffered per worker before drops occur.

**Example:**

```hcl
pipeline {
  ebpf_ringbuf_worker_capacity = 4096
}
```

### `flow_producer_store_capacity`

**Type:** Integer **Default:** `32768`

Initial capacity for the userspace flow tracking map. Should be set large enough to hold active flows to avoid expensive resizing operations.

**Example:**

```hcl
pipeline {
  flow_producer_store_capacity = 65536
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

### `flow_producer_channel_capacity`

**Type:** Integer **Default:** `16384`

Explicit capacity for the flow span channel, acting as a buffer between workers and the K8s decorator.
With default settings, this provides approximately 1.6s of buffer at 10,000 flows/sec.

**Example:**

```hcl
pipeline {
  flow_producer_channel_capacity = 24576  # Larger buffer for high-latency decoration
}
```

### `k8s_decorator_channel_capacity`

**Type:** Integer **Default:** `32768`

Explicit capacity for the decorated span channel, acting as a buffer between the K8s decorator and the exporter.
With default settings, this provides approximately 3.2s of buffer at 10,000 flows/sec.

**Example:**

```hcl
pipeline {
  k8s_decorator_channel_capacity = 65536  # Increase for slow exporters
}
```
