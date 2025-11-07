---
hidden: true
---

# API and Metrics

Mermin provides HTTP endpoints for health checks and Prometheus metrics. This page documents how to configure these services.

## API Server Configuration

The API server provides health check endpoints used by Kubernetes and monitoring systems.

### Configuration

```hcl
api {
  enabled = true
  listen_address = "0.0.0.0"
  port = 8080
}
```

### Configuration Options

#### `enabled`

**Type:** Boolean **Default:** `true`

Enable or disable the API server. When disabled, health check endpoints are not available.

**Example:**

```hcl
api {
  enabled = false  # Disable API server
}
```

{% hint style="warning" %}
Disabling the API server prevents Kubernetes liveness and readiness probes from functioning, which may cause pods to be restarted.
{% endhint %}

#### `listen_address`

**Type:** String (IP address) **Default:** `"0.0.0.0"`

IP address the API server binds to.

**Common Values:**

* `"0.0.0.0"`: Listen on all interfaces (default, recommended for Kubernetes)
* `"127.0.0.1"`: Listen only on localhost (for local testing)
* Specific IP: Listen on specific interface

**Example:**

```hcl
api {
  listen_address = "127.0.0.1"  # Localhost only
}
```

#### `port`

**Type:** Integer **Default:** `8080`

TCP port the API server listens on.

**Example:**

```hcl
api {
  port = 9090  # Custom port
}
```

## Health Check Endpoints

### `/livez` - Liveness Probe

Indicates whether Mermin is alive and running.

**Request:**

```bash
curl http://localhost:8080/livez
```

**Response:**

* **200 OK**: Mermin is alive
* **503 Service Unavailable**: Mermin is not responsive

**Returns:** Plain text `ok` or error message

**Use Case:**

* Kubernetes liveness probe
* Determines if pod should be restarted

**Kubernetes Configuration:**

```yaml
livenessProbe:
  httpGet:
    path: /livez
    port: api
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

### `/readyz` - Readiness Probe

Indicates whether Mermin is ready to accept traffic.

**Request:**

```bash
curl http://localhost:8080/readyz
```

**Response:**

* **200 OK**: Mermin is ready (eBPF programs loaded, informers synced)
* **503 Service Unavailable**: Mermin is not ready

**Returns:** Plain text `ok` or error message

**Use Case:**

* Kubernetes readiness probe
* Determines if pod should receive traffic
* Useful for deployment coordination

**Kubernetes Configuration:**

```yaml
readinessProbe:
  httpGet:
    path: /readyz
    port: api
  initialDelaySeconds: 15
  periodSeconds: 5
  timeoutSeconds: 5
  failureThreshold: 3
```

### `/startup` - Startup Probe

Indicates whether Mermin has completed initial startup.

**Request:**

```bash
curl http://localhost:8080/startup
```

**Response:**

* **200 OK**: Startup complete
* **503 Service Unavailable**: Still starting up

**Returns:** Plain text `ok` or error message

**Use Case:**

* Kubernetes startup probe
* Delays liveness checks until initial startup is complete
* Prevents premature restarts during slow startup

**Kubernetes Configuration:**

```yaml
startupProbe:
  httpGet:
    path: /startup
    port: api
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 5
  failureThreshold: 30  # Allow up to 150s for startup
```

## Metrics Server Configuration

The metrics server exposes Prometheus-compatible metrics for monitoring Mermin's performance and health.

### Configuration

```hcl
metrics {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250
}
```

### Configuration Options

#### `enabled`

**Type:** Boolean **Default:** `true`

Enable or disable the metrics server.

**Example:**

```hcl
metrics {
  enabled = false  # Disable metrics
}
```

#### `listen_address`

**Type:** String (IP address) **Default:** `"0.0.0.0"`

IP address the metrics server binds to.

**Example:**

```hcl
metrics {
  listen_address = "127.0.0.1"  # Localhost only
}
```

#### `port`

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

## Metrics Endpoint

### `/metrics` - Prometheus Metrics

Exposes Prometheus-compatible metrics in text format.

**Request:**

```bash
curl http://localhost:10250/metrics
```

**Response:** Prometheus text format metrics

**Example Metrics:**

```prometheus
# HELP mermin_flows_total Total number of flows processed
# TYPE mermin_flows_total counter
mermin_flows_total{direction="ingress"} 12543

# HELP mermin_packets_total Total number of packets captured
# TYPE mermin_packets_total counter
mermin_packets_total{interface="eth0"} 98234

# HELP mermin_packets_dropped_total Total number of packets dropped
# TYPE mermin_packets_dropped_total counter
mermin_packets_dropped_total{reason="channel_full"} 12

# HELP mermin_flow_table_size Current number of active flows
# TYPE mermin_flow_table_size gauge
mermin_flow_table_size 456

# HELP mermin_export_errors_total Total number of export errors
# TYPE mermin_export_errors_total counter
mermin_export_errors_total{exporter="otlp"} 3

# HELP mermin_export_latency_seconds Export latency in seconds
# TYPE mermin_export_latency_seconds histogram
mermin_export_latency_seconds_bucket{le="0.01"} 1234
mermin_export_latency_seconds_bucket{le="0.05"} 2345
mermin_export_latency_seconds_bucket{le="0.1"} 3456
mermin_export_latency_seconds_sum 456.78
mermin_export_latency_seconds_count 3456
```

## Prometheus Integration

### Service Monitor (Prometheus Operator)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mermin
  labels:
    app.kubernetes.io/name: mermin
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: mermin
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
```

### Pod Annotations (Prometheus Scraping)

```yaml
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "10250"
  prometheus.io/path: "/metrics"
```

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'mermin'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        action: keep
        regex: mermin
      - source_labels: [__meta_kubernetes_pod_ip]
        action: replace
        target_label: __address__
        replacement: $1:10250
```

## Monitoring Dashboards

### Key Metrics to Monitor

**Flow Processing:**

* `rate(mermin_flows_total[5m])`: Flows per second
* `rate(mermin_packets_total[5m])`: Packets per second
* `mermin_flow_table_size`: Active flow count

**Performance:**

* `rate(mermin_packets_dropped_total[5m])`: Packet drop rate
* `mermin_export_latency_seconds`: Export latency
* CPU and memory usage from container metrics

**Errors:**

* `rate(mermin_export_errors_total[5m])`: Export failure rate
* Log error count from log aggregation

**Resource Usage:**

* `container_cpu_usage_seconds_total`: CPU usage
* `container_memory_working_set_bytes`: Memory usage

### Grafana Dashboard Example

```json
{
  "dashboard": {
    "title": "Mermin Network Flows",
    "panels": [
      {
        "title": "Flows per Second",
        "targets": [
          {
            "expr": "rate(mermin_flows_total[5m])"
          }
        ]
      },
      {
        "title": "Packet Drop Rate",
        "targets": [
          {
            "expr": "rate(mermin_packets_dropped_total[5m])"
          }
        ]
      },
      {
        "title": "Active Flows",
        "targets": [
          {
            "expr": "mermin_flow_table_size"
          }
        ]
      }
    ]
  }
}
```

## Security Considerations

### Network Policies

Restrict access to API and metrics endpoints:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mermin-api-access
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: mermin
  policyTypes:
    - Ingress
  ingress:
    # Allow health checks from kubelet
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 8080
    # Allow metrics scraping from Prometheus
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 10250
```

### Authentication

Currently, the API and metrics endpoints do not support authentication. Use network policies or service mesh policies to restrict access.

For production environments:

1. Use network policies to limit access
2. Do not expose endpoints externally
3. Use port-forwarding for manual access: `kubectl port-forward pod/mermin-xxx 8080:8080`

## Complete Configuration Example

```hcl
# API server for health checks
api {
  enabled = true
  listen_address = "0.0.0.0"
  port = 8080
}

# Metrics server for Prometheus
metrics {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250
}
```

## Troubleshooting

### API Endpoints Not Responding

**Symptoms:** Health check requests timeout

**Solutions:**

1. Verify `api.enabled = true`
2. Check port is not blocked by firewall
3. Verify pod is running: `kubectl get pods`
4. Check logs: `kubectl logs <pod-name>`

### Metrics Not Scraped by Prometheus

**Symptoms:** No Mermin metrics in Prometheus

**Solutions:**

1. Verify `metrics.enabled = true`
2. Check Prometheus configuration
3. Verify pod annotations or ServiceMonitor
4. Test manual scrape: `curl http://pod-ip:10250/metrics`
5. Check network policies

### High Metrics Cardinality

**Symptoms:** Too many unique metric series

**Solutions:**

1. Limit labels in metrics
2. Use aggregation in queries
3. Adjust Prometheus retention

## Next Steps

* [**Global Options**](global-options.md): Configure logging and performance
* [**Flow Span Options**](span-options.md): Tune flow generation
* [**OTLP Exporter**](export-otlp.md): Configure flow export
* [**Troubleshooting Performance**](../troubleshooting/performance.md): Diagnose issues
