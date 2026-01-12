---
hidden: true
---

# Global Options

Global options are top-level configuration settings that control Mermin's overall behavior. These are the only options that can be configured via CLI flags or environment variables in addition to the configuration file.

## Configuration Methods

### Configuration File (HCL)

```hcl
# config.hcl
log_level = "info"
auto_reload = true
shutdown_timeout = "10s"
```

### Command-Line Flags

```bash
mermin \
  --config=/etc/mermin/config.hcl \
  --log-level=debug \
  --auto-reload
```

### Environment Variables

```bash
export MERMIN_CONFIG_PATH=/etc/mermin/config.hcl
export MERMIN_LOG_LEVEL=debug
export MERMIN_CONFIG_AUTO_RELOAD=true
mermin
```

## Configuration Options

### `config` / `MERMIN_CONFIG_PATH`

**Type:** String (file path) **Default:** None (required) **CLI Flag:** `--config` **Environment:** `MERMIN_CONFIG_PATH`

Path to the HCL or YAML configuration file.

**Example:**

```bash
mermin --config=/etc/mermin/config.hcl
# or
export MERMIN_CONFIG_PATH=/etc/mermin/config.hcl
```

### `auto_reload` / `MERMIN_CONFIG_AUTO_RELOAD`

**Type:** Boolean **Default:** `false` **CLI Flag:** `--auto-reload` **Environment:** `MERMIN_CONFIG_AUTO_RELOAD`

Automatically reload configuration when the file changes. When enabled, Mermin watches the config file and reloads it without requiring a restart.

**HCL:**

```hcl
auto_reload = true
```

**CLI:**

```bash
mermin --auto-reload --config=config.hcl
```

**Environment:**

```bash
export MERMIN_CONFIG_AUTO_RELOAD=true
```

**Behavior:**

* File is monitored for changes using filesystem watches
* Configuration is reloaded atomically
* Brief pause in flow capture during reload (\~100ms)
* Invalid configuration prevents reload (old config remains active)
* Logs indicate successful/failed reload attempts

**Use Cases:**

* Development and testing: Iterate quickly without restarts
* Production: Update configuration without downtime
* Debugging: Temporarily change log levels or filters

{% hint style="warning" %}
Some configuration changes may require a full restart, such as changing monitored network interfaces or modifying RBAC permissions.
{% endhint %}

### `log_level` / `MERMIN_LOG_LEVEL`

**Type:** String (enum) **Default:** `info` **CLI Flag:** `--log-level` **Environment:** `MERMIN_LOG_LEVEL`

Sets the logging verbosity level.

**Valid Values:**

* `trace`: Most verbose, includes all debug information
* `debug`: Detailed debugging information
* `info`: General informational messages (default)
* `warn`: Warning messages only
* `error`: Error messages only

**HCL:**

```hcl
log_level = "debug"
```

**CLI:**

```bash
mermin --log-level=trace --config=config.hcl
```

**Environment:**

```bash
export MERMIN_LOG_LEVEL=warn
```

**Recommendations:**

* **Production:** `info` or `warn` to reduce log volume
* **Debugging:** `debug` for detailed troubleshooting
* **Development:** `trace` for comprehensive visibility

### `shutdown_timeout`

**Type:** Duration **Default:** `5s` **CLI Flag:** Not available **Environment:** Not available

Maximum time to wait for graceful shutdown before forcing termination.

**HCL:**

```hcl
shutdown_timeout = "10s"
```

**Behavior:** During shutdown, Mermin:

1. Stops accepting new packets
2. Waits for in-flight flows to export (up to `shutdown_timeout`)
3. Closes OTLP connections gracefully
4. Forces shutdown if timeout is exceeded

**Recommendations:**

* **Production:** `10s` to ensure flows are exported
* **Development:** `5s` (default) is usually sufficient
* **High-throughput:** Increase to `30s` or more

**Related Settings:**

* `export.otlp.max_export_timeout`: Should be less than `shutdown_timeout`

## Monitoring Shutdown Behavior

Mermin provides metrics to monitor shutdown behavior:

### Shutdown Metrics

- `shutdown_duration_seconds`: Histogram of actual shutdown durations
- `shutdown_timeouts_total`: Count of shutdowns that exceeded timeout
- `shutdown_flows_total{status="preserved"}`: Flows successfully exported during shutdown
- `shutdown_flows_total{status="lost"}`: Flows lost due to shutdown timeout

### `worker_queue_capacity`

**Type:** Integer
**Default:** `2048`

Capacity for each worker thread's event queue. Determines how many raw eBPF events can be buffered per worker before drops occur.

**Formula:** Total worker buffer memory ≈ `worker_count` × `worker_queue_capacity` × 256 bytes

**Tuning Guidelines:**

| Traffic Volume             | Recommended Value |
|----------------------------|-------------------|
| Low (< 10K flows/s)        | 1024              |
| Medium (10K-50K flows/s)   | 2048 (default)    |
| High (50K-100K flows/s)    | 4096              |
| Very High (> 100K flows/s) | 8192+             |

**Signs You Need to Increase:**
* Metrics show `mermin_flow_events_total{status="dropped_backpressure"}` increasing

### `flow_store_capacity`

**Type:** Integer
**Default:** `32768`

Initial capacity for the userspace flow tracking map (`DashMap`). Should be set large enough to hold active flows to avoid expensive resizing operations.

**Formula:** Active flows ≈ flows_per_sec × avg_flow_lifetime

**Tuning Guidelines:**

| Active Flows               | Recommended Value |
|----------------------------|-------------------|
| < 10,000                   | 16384             |
| 10,000 - 25,000            | 32768 (default)   |
| 25,000 - 100,000           | 131072            |
| > 100,000                  | 262144+           |

**Signs You Need to Increase:**
* High CPU usage during startup or traffic spikes (due to map resizing)

### `worker_count`

**Type:** Integer
**Default:** `4`

Number of parallel worker threads processing packets and generating flow spans. Each worker processes eBPF events independently from a dedicated worker queue.

**Behavior:**

* Each worker processes packets independently
* More workers = more parallelism = higher throughput
* More workers = more CPU usage
* Workers share the flow table (synchronized)

**Tuning Guidelines:**

| Traffic Volume             | Recommended Workers | CPU Allocation |
|----------------------------|---------------------|----------------|
| Low (< 10K flows/s)        | 1-2                 | 0.5-1 cores    |
| Medium (10K-50K flows/s)   | 2-4                 | 1-2 cores      |
| High (50K-100K flows/s)    | 4 (default)         | 2-4 cores      |
| Very High (> 100K flows/s) | 8-16                | 4-8 cores      |

**Optimal Worker Count:**

* Start with CPU count / 2
* Monitor CPU usage with metrics
* Increase if CPU is underutilized and packet drops occur
* Decrease if CPU is overutilized

**Relationship with CPU Resources:**

```yaml
# Kubernetes resources should match worker count
resources:
  requests:
    cpu: 2     # For worker_count = 4
  limits:
    cpu: 4     # For worker_count = 4
```

### `worker_poll_interval`

**Type:** Duration
**Default:** `5s`

Interval at which flow pollers check for flow records and timeouts. Pollers iterate through active flows to:

* Generate periodic flow records (based on `max_record_interval` in `span` config)
* Detect and remove idle flows (based on protocol-specific timeouts in `span` config)

**Behavior:**

* Lower values = more responsive timeout detection and flow recording
* Higher values = less CPU overhead
* At typical enterprise scale (10K flows/sec with 100K active flows and 32 pollers): ~600 flow checks/sec per poller
* Modern CPUs handle flow checking very efficiently (microseconds per check)

**Tuning Guidelines:**

| Traffic Pattern | Recommended Interval | Rationale |
|-----------------|---------------------|-----------|
| Short-lived flows (ICMP) | 3-5s | Fast timeout detection |
| Mixed traffic | 5s (default) | Balance responsiveness and overhead |
| Long-lived flows (TCP) | 10s | Lower overhead, slower timeouts |
| Memory constrained | 3-5s | More frequent cleanup |

**Trade-offs:**

* **3s interval**: Most responsive, slightly higher CPU (~10K checks/sec per poller)
* **5s interval** (default): Best balance for most workloads
* **10s interval**: Lowest CPU, flows may linger longer before timeout

**Signs You Should Decrease:**

* Flows lingering past their intended timeout
* Memory usage growing steadily
* Short-lived flow protocols (ICMP with 10s timeout)

**Signs You Can Increase:**

* CPU constrained
* Primarily long-lived TCP flows
* Flow timeout accuracy not critical

### `k8s_decorator_threads`

**Type:** Integer
**Default:** `4`

Number of dedicated threads for Kubernetes metadata decoration. Running decoration on separate threads prevents K8s API lookups from blocking flow processing. Each thread handles ~8K flows/sec (~100-150μs per flow), so 4 threads provide 32K flows/sec capacity.

**Recommendations based on typical FPS (flows per second):**

| Cluster Type               | Typical FPS | Recommended Threads |
|----------------------------|-------------|---------------------|
| General/Mixed              | 50-200      | 2-4 (default: 4)    |
| Service Mesh               | 100-300     | 4 (default)         |
| Public Ingress             | 1K-5K       | 4-8                 |
| High-Traffic Ingress       | 5K-25K      | 8-12                |
| Extreme Scale (Edge/CDN)   | >25K        | 12-24               |

### `sampling_enabled`

**Type:** Boolean
**Default:** `true`

Enable adaptive sampling when worker channels are full. When enabled, Mermin intelligently drops events to prevent complete pipeline stalls while preserving critical flow information (TCP FIN/RST, new flows).

**Behavior:**

* Sampling activates only under backpressure
* Preserves flow control packets (FIN, RST)
* Maintains minimum sampling rate (see `sampling_min_rate`)

### `sampling_min_rate`

**Type:** Float (0.0-1.0)
**Default:** `0.1` (10%)

Minimum fraction of events to keep during maximum backpressure. A value of `0.1` ensures at least 10% of events are processed even under extreme load.

### `backpressure_warning_threshold`

**Type:** Float (0.0-1.0)
**Default:** `0.01` (1%)

Drop rate threshold for logging backpressure warnings. Warnings are logged when the fraction of dropped events exceeds this value.

### Channel Capacity Tuning

These options control the buffer sizes between pipeline stages to optimize for your workload.

#### `flow_span_channel_capacity`

**Type:** Integer
**Default:** `16384`

Explicit capacity for the flow span channel. Provides buffering between workers and K8s decorator. With defaults (16,384 slots, ~160ms buffer at 100K/s).

**Recommendations:**

* **Steady traffic**: `16384` (default)
* **Bursty traffic**: `32768`
* **Low latency priority**: `8192`

#### `decorated_span_channel_capacity`

**Type:** Integer
**Default:** `32768`

Explicit capacity for the decorated span (export) channel. Provides buffering between K8s decorator and OTLP exporter. This should be the largest buffer since network export is the slowest stage. With defaults (32,768 slots, ~320ms buffer at 100K/s).

**Recommendations:**

* **Reliable network**: `32768` (default)
* **Unreliable network**: `65536`
* **Very high throughput**: `131072`

### Monitoring Performance Configuration

After tuning performance settings, monitor these key metrics:

- `mermin_flow_events_total{status="dropped_backpressure"}` - Backpressure events
- `mermin_flow_events_total{status="dropped_error"}` - Error drops
- `mermin_channel_size` / `mermin_channel_capacity` - Channel utilization
- `mermin_pipeline_duration_seconds` - Pipeline duration histogram

See the [Application Metrics](../observability/app-metrics.md) guide for complete Prometheus query examples.

**Healthy indicators:**

* Sampling rate = 0 (no backpressure)
* Channel utilization < 80%
* p95 processing latency < 10ms
* IP index updates < 100ms

## Next Steps

* [**API and Metrics**](api-metrics.md): Configure health checks and monitoring
* [**Network Interface Discovery**](discovery-interfaces.md): Select which interfaces to monitor
* [**Flow Span Options**](span-options.md): Configure flow generation and timeouts
* [**Configuration Examples**](examples.md): See complete configurations
