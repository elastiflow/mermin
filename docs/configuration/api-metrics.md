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

Mermin provides both HTTP health check endpoints (for Kubernetes probes) and Prometheus health metrics (for monitoring). The HTTP endpoints return simple HTTP status codes, while the health metrics provide more granular component-level status information.

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

### Health Status Metrics

In addition to the HTTP health check endpoints above, Mermin exposes detailed health status metrics via the `/metrics` endpoint. These metrics provide component-level health information for monitoring and alerting.

{% hint style="info" %}
Health metrics are gauges where `1` indicates healthy and `0` indicates unhealthy. These complement the HTTP health check endpoints by providing more granular status information to Prometheus.
{% endhint %}

#### `mermin_health_overall`

A combined health status gauge for the entire application.

**Type:** Gauge
**Values:** `1` (healthy) or `0` (unhealthy)

**Use Case:**
- Overall application health monitoring
- Top-level alerting on application status
- Quick health check via metrics

**Prometheus Alert Example:**
```yaml
alert: MerminDown
expr: mermin_health_overall == 0
for: 1m
labels:
  severity: critical
annotations:
  summary: "Mermin instance is unhealthy"
```

#### `mermin_health_ebpf_loaded`

Indicates if the eBPF programs are successfully loaded and attached.

**Type:** Gauge
**Values:** `1` (loaded) or `0` (not loaded)

**Use Case:**
- Verify eBPF program initialization
- Alert on eBPF program load failures
- Troubleshoot packet capture issues

**Prometheus Alert Example:**
```yaml
alert: MerminEBPFNotLoaded
expr: mermin_health_ebpf_loaded == 0
for: 30s
labels:
  severity: critical
annotations:
  summary: "Mermin eBPF programs failed to load"
```

#### `mermin_health_k8s`

Indicates if the Kubernetes informer caches are synced and ready.

**Type:** Gauge
**Values:** `1` (synced) or `0` (not synced)

**Use Case:**
- Monitor Kubernetes API connection health
- Verify metadata enrichment is available
- Alert on K8s integration issues

**Prometheus Alert Example:**
```yaml
alert: MerminK8sCachesNotSynced
expr: mermin_health_k8s == 0
for: 2m
labels:
  severity: warning
annotations:
  summary: "Mermin Kubernetes caches not synced"
  description: "Flow spans may lack Kubernetes metadata"
```

#### `mermin_health_ready_to_process`

Indicates if Mermin is fully initialized and ready to process network data.

**Type:** Gauge
**Values:** `1` (ready) or `0` (not ready)

**Use Case:**
- Verify complete initialization
- Coordinate deployments with other systems
- Monitor readiness for data processing

**Prometheus Alert Example:**
```yaml
alert: MerminNotReady
expr: mermin_health_ready_to_process == 0
for: 5m
labels:
  severity: warning
annotations:
  summary: "Mermin not ready to process data"
```

{% hint style="warning" %}
The `/readyz` HTTP endpoint and `mermin_health_ready_to_process` metric serve similar purposes but for different systems. Use the HTTP endpoint for Kubernetes readiness probes and the metric for Prometheus monitoring and alerting.
{% endhint %}

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

**Naming Convention:**

Metrics follow the pattern: `mermin_<subsystem>_<name>_<type>`

**Metric Subsystems:**

- **Application** (`mermin_*`): Build info and overall health
- **eBPF** (`mermin_ebpf_*`): Kernel-level packet capture
- **Userspace** (`mermin_userspace_*`): Ring buffer and channel processing  
- **Span** (`mermin_span_*`): Flow span generation and lifecycle
- **Kubernetes** (`mermin_k8s_*`): K8s API integration and metadata enrichment
- **Export** (`mermin_export_*`): OTLP and other exporter performance

**Metric Types:**

- `_total`: Counters that only increase
- `_bytes`: Byte counters
- `_seconds`: Duration histograms

**Request:**

```bash
curl http://localhost:10250/metrics
```

**Response:** Prometheus text format metrics

**Example Metrics:**

```prometheus
# HELP mermin_build_info Build information
# TYPE mermin_build_info gauge
mermin_build_info{version="0.1.0",git_sha="abc123"} 1

# HELP mermin_ebpf_programs_loaded eBPF program loaded status
# TYPE mermin_ebpf_programs_loaded gauge
mermin_ebpf_programs_loaded{program="ingress"} 1
mermin_ebpf_programs_loaded{program="egress"} 1

# HELP mermin_ebpf_ringbuf_packets_total Total packets from eBPF ring buffer
# TYPE mermin_ebpf_ringbuf_packets_total counter
mermin_ebpf_ringbuf_packets_total{type="received",interface="eth0"} 98234
mermin_ebpf_ringbuf_packets_total{type="malformed",interface="eth0"} 12

# HELP mermin_userspace_ringbuf_packets_total Total packets in userspace ring buffer
# TYPE mermin_userspace_ringbuf_packets_total counter
mermin_userspace_ringbuf_packets_total{type="received"} 98000
mermin_userspace_ringbuf_packets_total{type="dropped"} 12
mermin_userspace_ringbuf_packets_total{type="filtered"} 200

# HELP mermin_span_active Currently active flows
# TYPE mermin_span_active gauge
mermin_span_active 456

# HELP mermin_span_processed_total Total flows processed and expired
# TYPE mermin_span_processed_total counter
mermin_span_processed_total{reason="idle"} 8234
mermin_span_processed_total{reason="fin"} 3210
mermin_span_processed_total{reason="rst"} 89

# HELP mermin_span_sent_total Total spans sent to exporters
# TYPE mermin_span_sent_total counter
mermin_span_sent_total{status="sent",exporter="otlp"} 11533
mermin_span_sent_total{status="failed",exporter="otlp"} 3

# HELP mermin_k8s_informer_object_total Number of objects in informer cache
# TYPE mermin_k8s_informer_object_total gauge
mermin_k8s_informer_object_total{kind="Pod"} 145
mermin_k8s_informer_object_total{kind="Service"} 32

# HELP mermin_export_otlp_spans_sent_total Total OTLP spans sent
# TYPE mermin_export_otlp_spans_sent_total counter
mermin_export_otlp_spans_sent_total{status="success"} 11533
mermin_export_otlp_spans_sent_total{status="error"} 3

# HELP mermin_export_otlp_duration_seconds Export latency in seconds
# TYPE mermin_export_otlp_duration_seconds histogram
mermin_export_otlp_duration_seconds_bucket{le="0.01"} 1234
mermin_export_otlp_duration_seconds_bucket{le="0.05"} 2345
mermin_export_otlp_duration_seconds_bucket{le="0.1"} 3456
mermin_export_otlp_duration_seconds_sum 456.78
mermin_export_otlp_duration_seconds_count 3456

# HELP mermin_export_queue_size Current size of export queue
# TYPE mermin_export_queue_size gauge
mermin_export_queue_size{exporter="otlp"} 23
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

{% hint style="success" %}
Monitor these key metrics to ensure Mermin is operating correctly. Metrics are organized by subsystem for easier troubleshooting.
{% endhint %}

**eBPF Layer:**
- `mermin_ebpf_programs_loaded{program}`: eBPF program status (should be 1)
- `rate(mermin_ebpf_ringbuf_packets_total{type="received"}[5m])`: Packets captured per second
- `rate(mermin_ebpf_ringbuf_packets_total{type="malformed"}[5m])`: Malformed packet rate

**Userspace Processing:**
- `rate(mermin_userspace_ringbuf_packets_total{type="received"}[5m])`: Packets received per second
- `rate(mermin_userspace_ringbuf_packets_total{type="dropped"}[5m])`: Packet drop rate (should be near zero)
- `mermin_userspace_channel_size{channel} / mermin_userspace_channel_capacity{channel}`: Channel utilization

**Flow Span Generation:**
- `mermin_span_active`: Currently active flows
- `rate(mermin_span_processed_total[5m])`: Flows expired per second
- `rate(mermin_span_sent_total{status="sent"}[5m])`: Spans exported per second
- `rate(mermin_span_sent_total{status="failed"}[5m])`: Failed span exports (should be near zero)

**Kubernetes Integration:**
- `mermin_k8s_client_up`: Kubernetes API connection status (should be 1)
- `mermin_k8s_informer_object_total{kind}`: Number of cached Kubernetes objects
- `mermin_k8s_decorator_lookup_duration_seconds`: K8s metadata lookup latency
- `rate(mermin_k8s_decorator_spans_processed_total{status="fail"}[5m])`: Failed decoration rate

**Export Performance:**
- `rate(mermin_export_otlp_spans_sent_total{status="success"}[5m])`: Successful OTLP exports per second
- `rate(mermin_export_otlp_spans_sent_total{status="error"}[5m])`: Export errors (should be near zero)
- `mermin_export_otlp_duration_seconds`: Export latency histogram
- `mermin_export_queue_size{exporter}`: Export queue depth

**Application Health:**
- `mermin_build_info`: Build version and Git SHA
- `mermin_health_overall`: Overall health status (should be 1)

**Resource Usage:**
- `container_cpu_usage_seconds_total`: CPU usage from container metrics
- `container_memory_working_set_bytes`: Memory usage from container metrics

### Grafana Dashboard Example

{% hint style="info" %}
This example demonstrates a basic Grafana dashboard for monitoring Mermin. Consider organizing panels by subsystem (eBPF, Userspace, Span, K8s, Export) for easier troubleshooting.
{% endhint %}

```json
{
  "dashboard": {
    "title": "Mermin Network Flows",
    "panels": [
      {
        "title": "Packet Capture Rate (eBPF)",
        "targets": [
          {
            "expr": "rate(mermin_ebpf_ringbuf_packets_total{type=\"received\"}[5m])"
          }
        ]
      },
      {
        "title": "Packet Drop Rate (Userspace)",
        "targets": [
          {
            "expr": "rate(mermin_userspace_ringbuf_packets_total{type=\"dropped\"}[5m])"
          }
        ]
      },
      {
        "title": "Active Flows",
        "targets": [
          {
            "expr": "mermin_span_active"
          }
        ]
      },
      {
        "title": "Flow Processing Rate",
        "targets": [
          {
            "expr": "rate(mermin_span_processed_total[5m])"
          }
        ]
      },
      {
        "title": "Span Export Success Rate",
        "targets": [
          {
            "expr": "rate(mermin_span_sent_total{status=\"sent\"}[5m])"
          }
        ]
      },
      {
        "title": "OTLP Export Latency (p95)",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(mermin_export_otlp_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "K8s Objects Cached",
        "targets": [
          {
            "expr": "mermin_k8s_informer_object_total"
          }
        ]
      },
      {
        "title": "Export Queue Depth",
        "targets": [
          {
            "expr": "mermin_export_queue_size"
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

**Symptoms:** Too many unique metric series, Prometheus performance degradation

{% hint style="warning" %}
High cardinality can occur if labels have too many unique values. Mermin's metrics use bounded label sets (e.g., `program`, `status`, `reason`, `exporter`) to prevent cardinality explosion. Avoid adding custom high-cardinality labels like IP addresses or pod names in PromQL queries.
{% endhint %}

**Solutions:**
1. Use label aggregation in queries: `sum by (status) (rate(mermin_span_sent_total[5m]))`
2. Adjust Prometheus retention policies
3. Review metric recording rules to pre-aggregate high-frequency queries

## Next Steps

* [**Global Options**](global-options.md): Configure logging and performance
* [**Flow Span Options**](span-options.md): Tune flow generation
* [**OTLP Exporter**](export-otlp.md): Configure flow export
* [**Troubleshooting Performance**](../troubleshooting/performance.md): Diagnose issues
