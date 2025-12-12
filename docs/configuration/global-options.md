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

### `ring_buffer_capacity`

**Type:** Integer
**Default:** `8192`

Base capacity for the eBPF ring buffer between kernel and userspace. This is the foundation for all pipeline channel sizes.

**Behavior:**

* Acts as a buffer for packets captured by eBPF before userspace processing
* Used directly for worker channels and as the base for multipliers (`flow_span_channel_multiplier`, `decorated_span_channel_multiplier`)
* Higher values provide more buffering for burst traffic
* Lower values reduce memory usage
* If channel fills, packets are dropped (visible in metrics)

**Tuning Guidelines:**

| Traffic Volume             | Recommended Value |
|----------------------------|-------------------|
| Low (< 10K flows/s)        | 2048-4096         |
| Medium (10K-50K flows/s)   | 4096-8192         |
| High (50K-100K flows/s)    | 8192 (default)    |
| Very High (> 100K flows/s) | 16384+            |

**Signs You Need to Increase:**

* Metrics show dropped events (`mermin_flow_events_total{status="dropped_backpressure"}`)
* Gaps in Flow Trace exports
* Warning logs about channel capacity or backpressure

**Signs You Can Decrease:**

* Low CPU usage
* Minimal traffic volume
* Memory constraints

### `worker_count`

**Type:** Integer
**Default:** `4`

Number of parallel worker threads processing packets and generating flow spans. Each worker processes eBPF events independently from a dedicated worker queue.

**Behavior:**

* Each worker processes packets independently
* More workers = more parallelism = higher throughput
* More workers = more CPU usage
* Workers share the flow table (synchronized)
* Worker queue capacity = `ring_buffer_capacity / worker_count`

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

#### `flow_span_channel_multiplier`

**Type:** Float
**Default:** `2.0`

Multiplier for flow span channel capacity. Provides buffering between workers and K8s decorator. Channel size = `ring_buffer_capacity * flow_span_channel_multiplier`. With defaults (8192 × 2.0 = 16,384 slots, ~160ms buffer at 100K/s).

**Recommendations:**

* **Steady traffic**: `2.0` (default)
* **Bursty traffic**: `3.0`-`4.0`
* **Low latency priority**: `1.5`

#### `decorated_span_channel_multiplier`

**Type:** Float
**Default:** `4.0`

Multiplier for decorated span (export) channel capacity. Provides buffering between K8s decorator and OTLP exporter. This should be the largest buffer since network export is the slowest stage. Channel size = `ring_buffer_capacity * decorated_span_channel_multiplier`. With defaults (8192 × 4.0 = 32,768 slots, ~320ms buffer at 100K/s).

**Recommendations:**

* **Reliable network**: `4.0` (default)
* **Unreliable network**: `6.0`-`8.0`
* **Very high throughput**: `8.0`-`12.0`

### Monitoring Performance Configuration

After tuning performance settings, monitor these metrics:

```prometheus
# Backpressure detection
rate(mermin_flow_events_total{status="dropped_backpressure"}[5m])
rate(mermin_flow_events_total{status="dropped_error"}[5m])

# Channel utilization
mermin_channel_size / mermin_channel_capacity

# Pipeline latency
histogram_quantile(0.95, rate(mermin_processing_latency_seconds_bucket[5m]))
```

**Healthy indicators:**

* Sampling rate = 0 (no backpressure)
* Channel utilization < 80%
* p95 processing latency < 10ms
* IP index updates < 100ms

### Pipeline Tuning Example

For a large cluster with high throughput:

```hcl
pipeline {
  # High-throughput base capacity
  ring_buffer_capacity = 16384
  worker_count = 8

  # Increase decorator parallelism
  k8s_decorator_threads = 16

  # Channel multipliers
  flow_span_channel_multiplier = 3.0
  decorated_span_channel_multiplier = 8.0

  # Adaptive sampling enabled
  sampling_enabled = true
  sampling_min_rate = 0.15
}
```

## Complete Example

```hcl
# Global configuration options

# Required: Path to this config file (set via CLI or ENV)
# mermin --config=/etc/mermin/config.hcl

# Logging verbosity
log_level = "info"

# Auto-reload config on file changes
auto_reload = true

# Graceful shutdown timeout
shutdown_timeout = "10s"

# Pipeline tuning for flow processing
pipeline {
  ring_buffer_capacity = 8192
  worker_count = 4
  k8s_decorator_threads = 4
}

```

## Precedence Example

When the same option is set in multiple places:

```hcl
# config.hcl
log_level = "info"
```

```bash
# Environment variable
export MERMIN_LOG_LEVEL=warn

# CLI flag (highest precedence)
mermin --log-level=debug --config=config.hcl
```

**Result:** `log_level` will be `debug` (CLI flag wins).

**Precedence Order (highest to lowest):**

1. Command-line flags
2. Environment variables
3. Configuration file
4. Built-in defaults

## Validation

Invalid values are rejected on startup:

```hcl
log_level = "invalid"
```

```
Error: invalid log level "invalid", must be one of: trace, debug, info, warn, error
```

```hcl
pipeline {
  ring_buffer_capacity = -1
}
```

```
Error: pipeline.ring_buffer_capacity must be a positive integer
```

## Monitoring Configuration Effectiveness

After changing global options, monitor these metrics:

```prometheus
# Packet processing
rate(mermin_packets_total[5m])
rate(mermin_flow_events_total{status="dropped_backpressure"}[5m])

# CPU usage
rate(container_cpu_usage_seconds_total[5m])

# Memory usage
container_memory_working_set_bytes
```

**Healthy indicators:**

* Zero or minimal packet drops
* CPU usage 50-80% of allocated
* Stable memory usage

## Best Practices

1. **Start conservative**: Use default values initially
2. **Monitor before tuning**: Collect metrics for at least 24 hours
3. **Change one at a time**: Isolate the impact of each change
4. **Document changes**: Note why specific values were chosen
5. **Test in non-production**: Validate tuning before production rollout

## Troubleshooting

### High Packet Drop Rate

**Symptoms:** `mermin_flow_events_total{status="dropped_backpressure"}` increasing

**Solutions:**

1. Increase `pipeline.ring_buffer_capacity`
2. Increase `pipeline.worker_count`
3. Allocate more CPU resources
4. Reduce monitored interfaces

### High CPU Usage

**Symptoms:** CPU utilization near limits

**Solutions:**

1. Decrease `pipeline.worker_count`
2. Increase flow timeouts (see [Span Options](span-options.md))
3. Add flow filters (see [Filtering](filtering.md))
4. Allocate more CPU resources

### High Memory Usage

**Symptoms:** Memory usage growing unbounded

**Solutions:**

1. Decrease `pipeline.ring_buffer_capacity`
2. Decrease flow timeouts (see [Span Options](span-options.md))
3. Add flow filters to reduce active flows
4. Allocate more memory resources

### Configuration Not Reloading

**Symptoms:** Changes to config file not applied

**Solutions:**

1. Verify `auto_reload = true` is set
2. Check logs for reload errors
3. Validate configuration syntax
4. Ensure file permissions allow reading
5. Some changes require full restart

## Next Steps

* [**API and Metrics**](api-metrics.md): Configure health checks and monitoring
* [**Network Interface Discovery**](discovery-interfaces.md): Select which interfaces to monitor
* [**Flow Span Options**](span-options.md): Configure flow generation and timeouts
* [**Configuration Examples**](examples.md): See complete configurations
