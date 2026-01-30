# API and Metrics

Mermin provides HTTP endpoints for health checks and Prometheus metrics. This page documents how to configure the API server and health probes; for the Prometheus metrics server (port, endpoints, debug metrics), see [Metrics](metrics.md).

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

## Metrics Server

The metrics server (Prometheus scrape endpoint) is configured via the `internal "metrics"` block. Options include `enabled`, `listen_address`, `port` (default `10250`), and `debug_metrics_enabled`. See [Metrics](metrics.md) for full configuration and available endpoints.

## Health Check Endpoints

Health endpoints return JSON (`Content-Type: application/json`) with a `status` field (`"ok"` or `"unavailable"`) and a `checks` object with detailed state.

### `/livez` - Liveness Probe

Indicates whether Mermin is alive and running.

**Request:**

```bash
curl http://localhost:8080/livez
```

**Response:**

* **200 OK**: Mermin is alive
* **503 Service Unavailable**: Mermin is not responsive

**Response body (JSON):** `status` (`"ok"` or `"unavailable"`), `checks` (e.g. `ebpf_loaded`, `startup_complete`, `pipeline_healthy`), and `metrics.export_errors_total`.

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

{% hint style="info" %}
The examples use `port: api`, a named container port. Ensure your pod spec defines a port named `api`, or use the numeric port (e.g. `8080`) instead.
{% endhint %}

### `/readyz` - Readiness Probe

Indicates whether Mermin is ready to accept traffic.

**Request:**

```bash
curl http://localhost:8080/readyz
```

**Response:**

* **200 OK**: Mermin is ready (eBPF programs loaded, Kubernetes informers synced, pipeline ready to process)
* **503 Service Unavailable**: Mermin is not ready

**Response body (JSON):** `status`, `checks` (e.g. `ebpf_loaded`, `k8s_caches_synced`, `ready_to_process`, `pipeline_healthy`), and `metrics.export_errors_total`.

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

**Response body (JSON):** `status` and `checks` (e.g. `startup_complete`).

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

Adjust the `matchLabels` (e.g. `name: monitoring`) to match the namespace where your Prometheus runs.

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
internal "metrics" {
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

1. Verify the metrics server is enabled: `internal "metrics" { enabled = true }` in HCL (see [Metrics](metrics.md))
2. Check Prometheus configuration
3. Verify pod annotations or ServiceMonitor
4. Test manual scrape: `curl http://pod-ip:10250/metrics`
5. Check network policies

### High Metrics Cardinality

**Symptoms:** Too many unique metric series

**Solutions:**

1. Ensure debug metrics are disabled if not needed (see [Metrics](metrics.md)); limit labels where configurable
2. Use aggregation in queries
3. Adjust Prometheus retention

## Next Steps

* [**Metrics**](metrics.md): Configure Prometheus metrics server and endpoints
* [**Global Options**](global-options.md): Configure logging and performance
* [**Flow Span Options**](span.md): Tune flow generation
* [**OTLP Exporter**](export-otlp.md): Configure flow export
* [**Troubleshooting**](../troubleshooting/troubleshooting.md): Diagnose issues
