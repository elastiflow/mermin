# Metrics

Mermin provides Prometheus metrics HTTP endpoints (default port `10250`). This page documents metrics configuration.
Endpoints available:

- `/metrics` - All metrics (standard + debug if `internal.metrics.debug_metrics_enabled` is `true`)
- `/metrics/standard` - Standard metrics only (aggregated, no high-cardinality labels)
- `/metrics/debug` - Debug metrics only (returns 404 if `internal.metrics.debug_metrics_enabled` is `false`)
- `/metrics:summary` - JSON summary of all available metrics with metadata (name, type, description, labels, category)

## Configuration

Full configuration example may be found in the [Default Config](https://github.com/elastiflow/mermin/tree/beta/charts/mermin/config/default/config.hcl)

## Configuration Options

### `enabled`

**Type:** Boolean **Default:** `true`

Enable or disable the metrics server.

**Example:**

```hcl
internal "metrics" {
  enabled = false  # Disable metrics
}
```

### `listen_address`

**Type:** String (IP address) **Default:** `"0.0.0.0"`

IP address the metrics server binds to.

**Example:**

```hcl
internal "metrics" {
  listen_address = "127.0.0.1"  # Localhost only
}
```

### `port`

**Type:** Integer **Default:** `10250`

TCP port the metrics server listens on.

**Example:**

```hcl
internal "metrics" {
  port = 9090  # Custom port
}
```

{% hint style="info" %}
Port 10250 is chosen to align with kubelet metrics port, making it familiar to Kubernetes administrators.
{% endhint %}

### `debug_metrics_enabled`

**Type:** Boolean **Default:** `false`

Enable debug metrics

{% hint style="warning" %}
Enabling debug metrics can cause significant memory growth in production
{% endhint %}

**Example:**

```hcl
internal "metrics" {
  debug_metrics_enabled = true  # Enable debug metrics
}
```

### `stale_metric_ttl`

**Type:** String (duration) **Default:** `5m`

Time-to-live for stale metrics after resource deletion. `0s` applies immediate cleanup

{% hint style="info" %}
Only applies when debug_metrics_enabled
{% endhint %}

**Example:**

```hcl
internal "metrics" {
  stale_metric_ttl = "1m" # Cleanup after 1 minute
}
```

## Histogram Bucket Configuration

Mermin provides several histogram metrics that track distributions of values (durations, batch sizes, etc.). By default, these metrics use pre-configured bucket sizes optimized for typical workloads. You can customize these bucket sizes to better match your specific use case.

### `pipeline_duration_buckets`

**Type:** Array of numbers **Default:** `[0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]`

Custom buckets for the `mermin_pipeline_duration_seconds` histogram metric. This metric tracks processing duration by pipeline stage (eBPF ring buffer processing, Kubernetes decoration, export operations).

The default buckets cover a range from 10μs to 60s to capture both fast operations (eBPF ring buffer processing, typically microseconds to milliseconds) and slow operations (export, which can take seconds).

**Example:**

```hcl
internal "metrics" {
  # Customize buckets for pipeline duration to focus on sub-second operations
  pipeline_duration_buckets = [0.0001, 0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0]
}
```

### `export_batch_size_buckets`

**Type:** Array of numbers **Default:** `[1, 10, 50, 100, 250, 500, 1000]`

Custom buckets for the `mermin_export_batch_size` histogram metric. This metric tracks the number of spans per export batch.

The default buckets cover batch sizes from 1 to 1000 spans, which is suitable for most deployments.

**Example:**

```hcl
internal "metrics" {
  # Customize buckets for larger batch sizes
  export_batch_size_buckets = [10, 50, 100, 500, 1000, 2000, 5000]
}
```

### `export_duration_buckets`

**Type:** Array of numbers **Default:** `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]`

Custom buckets for the `mermin_export_duration_seconds` histogram metric (debug metric). This metric tracks the duration of span export operations.

The default buckets cover durations from 1ms to 5s, which is appropriate for most export operations.

{% hint style="info" %}
This metric is only available when `debug_metrics_enabled = true`
{% endhint %}

**Example:**

```hcl
internal "metrics" {
  debug_metrics_enabled = true
  # Customize buckets for faster export operations
  export_duration_buckets = [0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
}
```

### `k8s_ip_index_update_duration_buckets`

**Type:** Array of numbers **Default:** `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]`

Custom buckets for the `mermin_k8s_watcher_ip_index_update_duration_seconds` histogram metric. This metric tracks the duration of Kubernetes IP index updates.

The default buckets cover durations from 1ms to 1s, which is typical for IP index updates.

**Example:**

```hcl
internal "metrics" {
  # Customize buckets for faster IP index updates
  k8s_ip_index_update_duration_buckets = [0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
}
```

### `shutdown_duration_buckets`

**Type:** Array of numbers **Default:** `[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0]`

Custom buckets for the `mermin_taskmanager_shutdown_duration_seconds` histogram metric (debug metric). This metric tracks the duration of shutdown operations.

The default buckets cover durations from 100ms to 120s, which accommodates both quick shutdowns and longer graceful shutdowns.

{% hint style="info" %}
This metric is only available when `debug_metrics_enabled = true`
{% endhint %}

**Example:**

```hcl
internal "metrics" {
  debug_metrics_enabled = true
  # Customize buckets for faster shutdowns
  shutdown_duration_buckets = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
}
```

### Bucket Configuration Best Practices

1. **Bucket boundaries should be sorted**: Buckets must be provided in ascending order. Prometheus will reject invalid configurations.

2. **Cover your expected range**: Ensure your buckets cover the full range of values you expect to observe. Values outside the bucket range will be counted in the `+Inf` bucket.

3. **Balance granularity and cardinality**: More buckets provide finer granularity but increase metric cardinality. Typically, 5-15 buckets is sufficient.

4. **Consider your SLOs**: Align bucket boundaries with your service level objectives (SLOs) to make it easier to calculate percentiles and set alerts.

**Example with all bucket configurations:**

```hcl
internal "metrics" {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250
  debug_metrics_enabled = false
  stale_metric_ttl = "5m"

  # Customize histogram buckets
  pipeline_duration_buckets = [0.0001, 0.001, 0.01, 0.1, 1.0, 5.0, 10.0]
  export_batch_size_buckets = [10, 50, 100, 500, 1000]
  k8s_ip_index_update_duration_buckets = [0.001, 0.01, 0.1, 0.5, 1.0]
}
```

## Authentication and Security

Currently, the metrics endpoints do not support neither authentication nor TLS encryption. Use network policies or service mesh policies to restrict access.

For production environments:

1. Use network policies to limit access
2. Do not expose metrics endpoints externally
3. Use port-forwarding for manual access: `kubectl port-forward pod/mermin-xxx 10250:10250`

# Troubleshooting

## Metrics Not Scraped by Prometheus

**Symptoms:** No Mermin metrics in Prometheus

**Solutions:**

1. Verify `internal.metrics.enabled = true`
2. Check Prometheus configuration
3. Verify pod annotations or `ServiceMonitor` (or another K8s CRD responsible for scraping configuration)
4. Test manual scrape: `curl http://pod-ip:10250/metrics`
5. Check network policies

### High Metrics Cardinality

**Symptoms:** Too many unique metric series

**Solutions:**

1. Limit labels in metrics
2. Use aggregation in queries
3. Adjust Prometheus retention

## Next Steps

- [**Mermin Application Metrics**](docs/observability/app-metrics.md): Mermin metrics documentation
