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
* [**Flow Span Options**](span.md): Tune flow generation
* [**OTLP Exporter**](export-otlp.md): Configure flow export
* [**Troubleshooting**](../troubleshooting/troubleshooting.md): Diagnose issues
