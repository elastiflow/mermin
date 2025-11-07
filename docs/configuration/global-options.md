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
packet_channel_capacity = 2048
packet_worker_count = 4
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

### `packet_channel_capacity`

**Type:** Integer **Default:** `1024` **CLI Flag:** Not available **Environment:** Not available

Size of the internal channel buffer between eBPF packet capture and userspace flow processing.

**HCL:**

```hcl
packet_channel_capacity = 2048
```

**Behavior:**

* Acts as a buffer for packets captured by eBPF before userspace processing
* Higher values provide more buffering for burst traffic
* Lower values reduce memory usage
* If channel fills, packets are dropped (visible in metrics)

**Tuning Guidelines:**

| Traffic Volume           | Recommended Value |
| ------------------------ | ----------------- |
| Low (< 1K pkt/s)         | 512               |
| Medium (1K-10K pkt/s)    | 1024 (default)    |
| High (10K-100K pkt/s)    | 2048              |
| Very High (> 100K pkt/s) | 4096              |

**Signs You Need to Increase:**

* Metrics show packet drops (`mermin_packets_dropped_total`)
* Gaps in Flow Trace exports
* Warning logs about channel capacity

**Signs You Can Decrease:**

* Low CPU usage
* Minimal traffic volume
* Memory constraints

### `packet_worker_count`

**Type:** Integer **Default:** `2` **CLI Flag:** Not available **Environment:** Not available

Number of parallel goroutines processing packets and generating flows.

**HCL:**

```hcl
packet_worker_count = 4
```

**Behavior:**

* Each worker processes packets independently
* More workers = more parallelism = higher throughput
* More workers = more CPU usage
* Workers share the flow table (synchronized)

**Tuning Guidelines:**

| Traffic Volume | Recommended Workers | CPU Allocation |
| -------------- | ------------------- | -------------- |
| Low            | 1-2                 | 0.1-0.5 cores  |
| Medium         | 2-4 (default)       | 0.5-1 cores    |
| High           | 4-8                 | 1-2 cores      |
| Very High      | 8-16                | 2-4 cores      |

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
    cpu: 500m  # For packet_worker_count = 2
  limits:
    cpu: 1     # For packet_worker_count = 2
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

# Internal packet processing buffer
packet_channel_capacity = 2048

# Number of parallel flow processors
packet_worker_count = 4
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
packet_channel_capacity = -1
```

```
Error: packet_channel_capacity must be a positive integer
```

## Monitoring Configuration Effectiveness

After changing global options, monitor these metrics:

```prometheus
# Packet processing
rate(mermin_packets_total[5m])
rate(mermin_packets_dropped_total[5m])

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

**Symptoms:** `mermin_packets_dropped_total` increasing

**Solutions:**

1. Increase `packet_channel_capacity`
2. Increase `packet_worker_count`
3. Allocate more CPU resources
4. Reduce monitored interfaces

### High CPU Usage

**Symptoms:** CPU utilization near limits

**Solutions:**

1. Decrease `packet_worker_count`
2. Increase flow timeouts (see [Span Options](span-options.md))
3. Add flow filters (see [Filtering](filtering.md))
4. Allocate more CPU resources

### High Memory Usage

**Symptoms:** Memory usage growing unbounded

**Solutions:**

1. Decrease `packet_channel_capacity`
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
