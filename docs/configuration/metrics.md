# Configure Internal Prometheus Metrics Server

**Block:** `internal.metrics`

Mermin provides Prometheus metrics HTTP endpoints (default port `10250`). This page documents metrics configuration.

**Endpoints available:**

- `/metrics` - All metrics (standard + debug if `internal.metrics.debug_metrics_enabled` is `true`)
- `/metrics/standard` - Standard metrics only (aggregated, no high-cardinality labels)
- `/metrics/debug` - Debug metrics only (returns 404 if `internal.metrics.debug_metrics_enabled` is `false`)
- `/metrics:summary` - JSON summary of all available metrics with metadata (name, type, description, labels, category)

## Configuration

A full configuration example may be found in the [Default Configuration](./default/config.hcl).

### Configuration Structure

The metrics configuration is organized into nested blocks:

```hcl
internal "metrics" {
  # Server configuration
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 10250

  # Debug settings
  debug_metrics_enabled = false
  stale_metric_ttl      = "5m"

  histogram_buckets {
    # Custom histogram bucket overrides
  }
}
```

## Configuration Options

### `internal.metrics` block

- `enabled` attribute

  Enable or disable the metrics server.

  **Type:** Boolean

  **Default:** `true`

  **Example:** Disable metrics

  ```hcl
  internal "metrics" {
    enabled = false
  }
  ```

- `listen_address` attribute

  IP address the metrics server binds to.

  **Type:** String (IP address)

  **Default:** `"0.0.0.0"`

  **Example:** Listen on localhost only

  ```hcl
  internal "metrics" {
    listen_address = "127.0.0.1"
  }
  ```

- `port` attribute

  TCP port the metrics server listens on.

  **Type:** Integer

  **Default:** `10250`

  {% hint style="info" %}
  Port 10250 is chosen to align with kubelet metrics port, making it familiar to Kubernetes administrators.
  {% endhint %}

  **Example:** Custom port

  ```hcl
  internal "metrics" {
    port = 9090
  }
  ```

- `debug_metrics_enabled` attribute

  Enable debug metrics.

  **Type:** Boolean

  **Default:** `false`

  {% hint style="warning" %}
  Enabling debug metrics can cause significant memory growth in production.
  {% endhint %}

  **Example:** Enable debug metrics

  ```hcl
  internal "metrics" {
    debug_metrics_enabled = true
  }
  ```

- `stale_metric_ttl` attribute

  Time-to-live for stale metrics after resource deletion. `0s` applies immediate cleanup.

  **Type:** String (duration)

  **Default:** `"5m"`

  {% hint style="info" %}
  Only applies when `debug_metrics_enabled` is `true`.
  {% endhint %}

  **Example:** Cleanup after 1 minute

  ```hcl
  internal "metrics" {
    stale_metric_ttl = "1m"
  }
  ```

### `internal.metrics.histogram_buckets` block

Optional subsection for histogram bucket overrides. Omit the block to use default buckets for all histograms. Each key is the full metric name.

Mermin provides several histogram metrics that track distributions of values (durations, batch sizes, etc.). By default, these metrics use pre-configured bucket sizes optimized for typical workloads.
You can customize these bucket sizes inside a `histogram_buckets` block.

- `mermin_pipeline_duration_seconds` attribute

  Custom buckets for the `mermin_pipeline_duration_seconds` histogram metric. This metric tracks processing duration by pipeline stage (eBPF ring buffer processing, Kubernetes decoration, export operations).

  **Type:** Array of numbers

  **Default:** `[0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]`

  The default buckets cover a range from 10μs to 60s to capture both fast operations (eBPF ring buffer processing, typically microseconds to milliseconds) and slow operations (export, which can take seconds).

  **Example:** Focus on sub-second operations

  ```hcl
  internal "metrics" {
    histogram_buckets {
      mermin_pipeline_duration_seconds = [0.0001, 0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0]
    }
  }
  ```

- `mermin_export_batch_size` attribute

  Custom buckets for the `mermin_export_batch_size` histogram metric. This metric tracks the number of spans per export batch.

  **Type:** Array of numbers

  **Default:** `[1, 10, 50, 100, 250, 500, 1000]`

  The default buckets cover batch sizes from 1 to 1000 spans, which is suitable for most deployments.

  **Example:** Custom batch size buckets

  ```hcl
  internal "metrics" {
    histogram_buckets {
      mermin_export_batch_size = [10, 50, 100, 500, 1000]
    }
  }
  ```

- `mermin_k8s_watcher_ip_index_update_duration_seconds` attribute

  Custom buckets for the `mermin_k8s_watcher_ip_index_update_duration_seconds` histogram metric. This metric tracks the duration of Kubernetes IP index updates.

  **Type:** Array of numbers

  **Default:** `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]`

  The default buckets cover durations from 1ms to 1s, which is typical for IP index updates.

  **Example:** Custom IP index update duration buckets

  ```hcl
  internal "metrics" {
    histogram_buckets {
      mermin_k8s_watcher_ip_index_update_duration_seconds = [0.001, 0.01, 0.1, 0.5, 1.0]
    }
  }
  ```

- `mermin_taskmanager_shutdown_duration_seconds` attribute

  Custom buckets for the `mermin_taskmanager_shutdown_duration_seconds` histogram metric. This metric tracks the duration of shutdown operations.

  **Type:** Array of numbers

  **Default:** `[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0]`

  {% hint style="info" %}
  Only present when debug metrics are enabled (`internal.metrics.debug_metrics_enabled = true`).
  {% endhint %}

  The default buckets cover durations from 100ms to 120s, which accommodates both quick shutdowns and longer graceful shutdowns.

  **Examples:**

  - Custom shutdown duration buckets

    ```hcl
    internal "metrics" {
      debug_metrics_enabled = true
      histogram_buckets {
        mermin_taskmanager_shutdown_duration_seconds = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
      }
    }
    ```

  - Multiple bucket configurations

    ```hcl
    internal "metrics" {
      debug_metrics_enabled = true
      histogram_buckets {
        mermin_pipeline_duration_seconds                        = [0.0001, 0.001, 0.01, 0.1, 1.0, 5.0, 10.0]
        mermin_export_batch_size                                = [10, 50, 100, 500, 1000]
        mermin_k8s_watcher_ip_index_update_duration_seconds     = [0.001, 0.01, 0.1, 0.5, 1.0]
        mermin_taskmanager_shutdown_duration_seconds            = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
      }
    }
    ```

#### Bucket Configuration Best Practices

1. **Bucket boundaries should be sorted**: Buckets must be provided in ascending order. Prometheus will reject invalid configurations.

2. **Cover your expected range**: Ensure your buckets cover the full range of values you expect to observe. Values outside the bucket range will be counted in the `+Inf` bucket.

3. **Balance granularity and cardinality**: More buckets provide finer granularity but increase metric cardinality. Typically, 5-15 buckets is sufficient.

4. **Consider your SLOs**: Align bucket boundaries with your service level objectives (SLOs) to make it easier to calculate percentiles and set alerts.

## Authentication and Security

Currently, the metrics endpoints do not support neither authentication nor TLS encryption. Use network policies or service mesh policies to restrict access.

For production environments:

1. Use network policies to limit access
2. Do not expose metrics endpoints externally
3. Use port-forwarding for manual access: `kubectl port-forward pod/mermin-xxx 10250:10250`

## Troubleshooting

### Metrics Not Scraped by Prometheus

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

- [**Mermin Internal Metrics**](../internal-monitoring/internal-metrics.md): Mermin metrics documentation
