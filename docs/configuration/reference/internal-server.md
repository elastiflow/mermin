# Configure Internal Server

**Block:** `internal.server`

Mermin provides HTTP Server endpoints for health checks and Prometheus metrics. This page documents how to configure the HTTP server and health probes; for the Prometheus metrics server (port, endpoints, debug metrics), see [Metrics](internal-prometheus-metrics.md).

## Configuration

A full configuration example may be found in the [Default Configuration](../default/config.hcl).

### `internal.server` block

- `enabled` attribute

  Enable or disable the HTTP server. When disabled, health check endpoints are not available.

  **Type:** Boolean

  **Default:** `true`

  **Example:** Disable HTTP server

  ```hcl
  internal "server" {
    enabled = false
  }
  ```

  {% hint style="warning" %}
  Disabling the HTTP server prevents Kubernetes liveness and readiness probes from functioning, which may cause pods to be restarted.
  {% endhint %}

- `listen_address` attribute

  IP address the HTTP server binds to.

  **Type:** String

  **Default:** `"0.0.0.0"`

  **Common Values:**

  - `"0.0.0.0"`: Listen on all interfaces (default, recommended for Kubernetes)
  - `"127.0.0.1"`: Listen only on localhost (for local testing)
  - Specific IP: Listen on specific interface

  **Example:** Listen on localhost only

  ```hcl
  internal "server" {
    listen_address = "127.0.0.1"
  }
  ```

- `port` attribute

  TCP port the HTTP server listens on.

  **Type:** Integer

  **Default:** `8080`

  **Example:** Custom listening port

  ```hcl
  internal "server" {
    port = 9090
  }
  ```

## Metrics Server

The metrics server (Prometheus scrape endpoint) is configured via the `internal "metrics"` block. Options include `enabled`, `listen_address`, `port` (default `10250`), and `debug_metrics_enabled`.
See [Metrics](internal-prometheus-metrics.md) for full configuration and available endpoints.

### Health Check Endpoints

Health endpoints return JSON (`Content-Type: application/json`) with a `status` field (`"ok"` or `"unavailable"`) and a `checks` object with detailed state.

- `/livez` endpoint (Liveness Probe)

  Indicates whether Mermin is alive and running.

  **Request:**

  ```bash
  curl http://localhost:8080/livez
  ```

  **Response:**

  - **200 OK**: Mermin is alive
  - **503 Service Unavailable**: Mermin is not responsive

  **Response body (JSON):**

  ```json
  {
    "checks": {
      "ebpf_loaded": true,
      "pipeline_healthy": true,
      "startup_complete": true
    },
    "metrics": {
      "export_errors_total": 277
    },
    "status": "ok"
  }
  ```

  **Use Case:** Kubernetes [liveness probe](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/), enabled by default in the Helm chart.

- `/readyz` endpoint (Readiness Probe)

  Indicates whether Mermin is ready to accept traffic.

  **Request:**

  ```bash
  curl http://localhost:8080/readyz
  ```

  **Response:**

  - **200 OK**: Mermin is ready (eBPF programs loaded, Kubernetes informers synced, pipeline ready to process)
  - **503 Service Unavailable**: Mermin is not ready

  **Response body (JSON):**

  ```json
  {
    "checks": {
      "ebpf_loaded": true,
      "k8s_caches_synced": true,
      "pipeline_healthy": true,
      "ready_to_process": true
    },
    "metrics": {
      "export_errors_total": 277
    },
    "status": "ok"
  }
  ```

  **Use Case:** Kubernetes [readiness probe](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-readiness-probes), enabled by default in the Helm chart.

- `/startup` endpoint (Startup Probe)

  Indicates whether Mermin has completed initial startup.

  **Request:**

  ```bash
  curl http://localhost:8080/startup
  ```

  **Response:**

  - **200 OK**: Startup complete
  - **503 Service Unavailable**: Still starting up

  **Response body (JSON):**

  ```json
  {
    "checks": {
      "startup_complete": true
    },
    "status": "ok"
  }
  ```

  **Use Case:** Kubernetes [startup probe](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-startup-probes), enabled by default in the Helm chart.

## Security Considerations

### Network Policies

Restrict access to HTTP and metrics endpoints:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mermin-server-access
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

Currently, the HTTP and metrics endpoints do not support authentication. Use network policies or service mesh policies to restrict access.

For production environments:

1. Use network policies to limit access
2. Do not expose endpoints externally
3. Use port-forwarding for manual access: `kubectl port-forward pod/mermin-xxx 8080:8080`

## Troubleshooting

### HTTP Endpoints Not Responding

**Symptoms:** Health check requests timeout

**Steps:**

1. Verify `server.enabled = true`
2. Check port is not blocked by firewall
3. Verify pod is running: `kubectl get pods`
4. Check Mermin pod events: `kubectl describe pod mermin-xxx`
5. Check logs: `kubectl logs <pod-name>`

## Next Steps

{% tabs %}
{% tab title="Monitor" %}
1. [**Configure Prometheus Metrics**](internal-prometheus-metrics.md): Expose metrics for scraping
2. [**Enable Internal Tracing**](internal-tracing.md): Debug Mermin itself
{% endtab %}

{% tab title="Configure" %}
1. [**Tune Flow Generation**](flow-span-producer.md): Configure timeouts and thresholds
2. [**Configure OTLP Export**](opentelemetry-otlp-exporter.md): Send flows to your backend
{% endtab %}
{% endtabs %}

### Need Help?

- [**Troubleshoot Issues**](../../troubleshooting/troubleshooting.md): Diagnose health check failures
- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask about server configuration
