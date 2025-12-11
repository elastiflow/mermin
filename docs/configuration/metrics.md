# Metrics

Mermin provides HTTP endpoints Prometheus metrics. This page documents metrics configuration.
Endpoints available:

- `/metrics` - All metrics (standard + debug if `metrics.debug_metrics_enabled` is `true`)
- `/metrics/standard` - Standard metrics only (aggregated, no high-cardinality labels)
- `/metrics/debug` - Debug metrics only (returns 404 if `metrics.debug_metrics_enabled` is `false`)

## Configuration

Full configuration example may be found in the [Default Config](https://github.com/elastiflow/mermin/tree/beta/charts/mermin/config/default/config.hcl)

## Configuration Options

### `enabled`

**Type:** Boolean **Default:** `true`

Enable or disable the metrics server.

**Example:**

```hcl
metrics {
  enabled = false  # Disable metrics
}
```

### `listen_address`

**Type:** String (IP address) **Default:** `"0.0.0.0"`

IP address the metrics server binds to.

**Example:**

```hcl
metrics {
  listen_address = "127.0.0.1"  # Localhost only
}
```

### `port`

**Type:** Integer **Default:** `10250`

TCP port the metrics server listens on.

**Example:**

```hcl
metrics {
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
metrics {
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
metrics {
  stale_metric_ttl = "1m" # Cleanup after 1 minute
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

1. Verify `metrics.enabled = true`
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
