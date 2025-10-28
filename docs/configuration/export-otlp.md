# OTLP Exporter

This page documents the OpenTelemetry Protocol (OTLP) exporter configuration, which controls how Mermin exports flow records to your observability backend.

## Overview

OTLP is the standard protocol for OpenTelemetry telemetry data. Mermin exports network flows as OTLP trace spans, enabling integration with any OTLP-compatible backend including OpenTelemetry Collector, Grafana Tempo, Jaeger, and more.

## Configuration

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
    timeout = "10s"
    max_batch_size = 512
    max_batch_interval = "5s"
    max_queue_size = 2048
    max_concurrent_exports = 1
    max_export_timeout = "30s"

    auth = {
      basic = {
        user = "username"
        pass = "password"
      }
    }

    tls = {
      insecure_skip_verify = false
      ca_cert = "/etc/certs/ca.crt"
      client_cert = "/etc/certs/client.crt"
      client_key = "/etc/certs/client.key"
    }
  }
}
```

## Basic Configuration Options

### `endpoint`

**Type:** String (URL) **Default:** `"http://localhost:4317"`

OTLP collector endpoint URL.

**Format:**

* `http://hostname:port` for unencrypted gRPC
* `https://hostname:port` for TLS-encrypted gRPC
* Port 4317 is standard for gRPC
* Port 4318 is standard for HTTP

**Examples:**

```hcl
export "traces" {
  otlp = {
    # Local collector
    endpoint = "http://otel-collector:4317"

    # Remote collector with TLS
    # endpoint = "https://collector.example.com:4317"

    # HTTP protocol
    # endpoint = "http://collector.example.com:4318"
  }
}
```

**Kubernetes Service Discovery:**

```hcl
export "traces" {
  otlp = {
    # Service in same namespace
    endpoint = "http://otel-collector:4317"

    # Service in different namespace
    # endpoint = "http://otel-collector.observability:4317"

    # Headless service
    # endpoint = "http://otel-collector-0.otel-collector.observability:4317"
  }
}
```

### `protocol`

**Type:** String (enum) **Default:** `"grpc"`

OTLP transport protocol.

**Valid Values:**

* `"grpc"`: gRPC protocol (recommended, default)
* `"http_binary"`: HTTP with binary protobuf payload

**Examples:**

```hcl
export "traces" {
  otlp = {
    protocol = "grpc"  # Default, recommended

    # For HTTP protocol
    # protocol = "http_binary"
    # endpoint = "http://collector:4318"
  }
}
```

**Protocol Comparison:**

| Feature               | gRPC   | HTTP     |
| --------------------- | ------ | -------- |
| **Performance**       | Higher | Moderate |
| **Streaming**         | Yes    | No       |
| **Firewall Friendly** | Less   | More     |
| **Standard Port**     | 4317   | 4318     |
| **HTTP/2 Required**   | Yes    | No       |

### `timeout`

**Type:** Duration **Default:** `"10s"`

Timeout for individual OTLP export requests.

**Examples:**

```hcl
export "traces" {
  otlp = {
    timeout = "10s"  # Default

    # For slow networks
    # timeout = "30s"

    # For fast local networks
    # timeout = "5s"
  }
}
```

**Tuning:**

* **Fast networks**: 5s-10s
* **WAN/Internet**: 15s-30s
* **High latency**: 30s-60s

## Batching Configuration

Mermin batches flow records before export to reduce network overhead and improve efficiency.

### `max_batch_size`

**Type:** Integer **Default:** `512`

Maximum number of spans (flow records) per batch.

**Examples:**

```hcl
export "traces" {
  otlp = {
    max_batch_size = 512  # Default

    # For high-volume environments
    # max_batch_size = 1024

    # For low-latency requirements
    # max_batch_size = 128
  }
}
```

**Trade-offs:**

* **Larger batches**: Better efficiency, higher latency
* **Smaller batches**: Lower latency, more requests

### `max_batch_interval`

**Type:** Duration **Default:** `"5s"`

Maximum time to wait before exporting a partial batch.

**Examples:**

```hcl
export "traces" {
  otlp = {
    max_batch_interval = "5s"  # Default

    # For real-time monitoring
    # max_batch_interval = "1s"

    # For reduced export frequency
    # max_batch_interval = "10s"
  }
}
```

**Behavior:**

* Batch is exported when it reaches `max_batch_size` OR `max_batch_interval` (whichever comes first)
* Prevents indefinite waiting for partial batches

### `max_queue_size`

**Type:** Integer **Default:** `2048`

Maximum number of spans queued for export.

**Examples:**

```hcl
export "traces" {
  otlp = {
    max_queue_size = 2048  # Default

    # For higher burst tolerance
    # max_queue_size = 4096

    # For memory-constrained environments
    # max_queue_size = 1024
  }
}
```

**Queue Behavior:**

* Acts as buffer during temporary collector unavailability
* When full, oldest spans are dropped (not newest)
* Monitor `mermin_export_queue_size` and `mermin_export_drops_total` metrics

### `max_concurrent_exports`

**Type:** Integer **Default:** `1` **Status:** Experimental

Maximum number of concurrent export requests.

**Examples:**

```hcl
export "traces" {
  otlp = {
    max_concurrent_exports = 1  # Default

    # For high-throughput (experimental)
    # max_concurrent_exports = 4
  }
}
```

{% hint style="warning" %}
Values > 1 are experimental. Use with caution and monitor for ordering issues.
{% endhint %}

### `max_export_timeout`

**Type:** Duration **Default:** `"30s"` **Status:** Experimental

Maximum time for export operation including retries.

**Examples:**

```hcl
export "traces" {
  otlp = {
    max_export_timeout = "30s"  # Default
  }
}
```

## Authentication Configuration

### Basic Authentication

```hcl
export "traces" {
  otlp = {
    endpoint = "https://collector.example.com:4317"

    auth = {
      basic = {
        user = "mermin"
        pass = "secret_password"
      }
    }
  }
}
```

**Using Environment Variables:**

```bash
# Set environment variable
export OTLP_PASSWORD="secret_password"
```

```hcl
export "traces" {
  otlp = {
    auth = {
      basic = {
        user = "mermin"
        pass = "env(OTLP_PASSWORD)"  # Load from environment
      }
    }
  }
}
```

**Using Kubernetes Secrets:**

```bash
# Create secret
kubectl create secret generic mermin-otlp-auth \
  --from-literal=username=mermin \
  --from-literal=password=secret_password
```

```yaml
# Mount in pod
env:
  - name: OTLP_USER
    valueFrom:
      secretKeyRef:
        name: mermin-otlp-auth
        key: username
  - name: OTLP_PASSWORD
    valueFrom:
      secretKeyRef:
        name: mermin-otlp-auth
        key: password
```

## TLS Configuration

### TLS with System CA Certificates

For standard TLS using system root certificates:

```hcl
export "traces" {
  otlp = {
    endpoint = "https://collector.example.com:4317"
    protocol = "grpc"

    # TLS is automatically enabled for https:// endpoints
    # No tls block needed for standard certificates
  }
}
```

### TLS with Custom CA Certificate

For self-signed certificates or custom CAs:

```hcl
export "traces" {
  otlp = {
    endpoint = "https://collector.example.com:4317"

    tls = {
      insecure_skip_verify = false
      ca_cert = "/etc/mermin/certs/ca.crt"
    }
  }
}
```

**Mounting CA certificate in Kubernetes:**

```yaml
volumes:
  - name: ca-cert
    configMap:
      name: collector-ca-cert
      items:
        - key: ca.crt
          path: ca.crt

volumeMounts:
  - name: ca-cert
    mountPath: /etc/mermin/certs
    readOnly: true
```

### Mutual TLS (mTLS)

For client certificate authentication:

```hcl
export "traces" {
  otlp = {
    endpoint = "https://collector.example.com:4317"

    tls = {
      insecure_skip_verify = false
      ca_cert = "/etc/mermin/certs/ca.crt"
      client_cert = "/etc/mermin/certs/client.crt"
      client_key = "/etc/mermin/certs/client.key"
    }
  }
}
```

**Mounting client certificates in Kubernetes:**

```yaml
volumes:
  - name: client-certs
    secret:
      secretName: mermin-client-certs

volumeMounts:
  - name: client-certs
    mountPath: /etc/mermin/certs
    readOnly: true
```

### Insecure Mode (Development Only)

{% hint style="danger" %}
**Never use in production!** This disables all certificate verification and makes connections vulnerable to man-in-the-middle attacks.
{% endhint %}

```hcl
export "traces" {
  otlp = {
    endpoint = "https://collector.example.com:4317"

    tls = {
      insecure_skip_verify = true  # DEVELOPMENT ONLY
    }
  }
}
```

## Performance Tuning

### High-Throughput Configuration

For environments processing > 10,000 flows/second:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"

    # Large batches for efficiency
    max_batch_size = 1024
    max_batch_interval = "2s"

    # Large queue for burst handling
    max_queue_size = 8192

    # Aggressive timeouts
    timeout = "5s"
    max_export_timeout = "20s"

    # Multiple concurrent exports (experimental)
    max_concurrent_exports = 4
  }
}
```

### Low-Latency Configuration

For real-time monitoring:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"

    # Small batches for low latency
    max_batch_size = 128
    max_batch_interval = "1s"

    # Fast timeouts
    timeout = "5s"
    max_export_timeout = "10s"

    # Moderate queue
    max_queue_size = 2048
  }
}
```

### Reliable Export Configuration

For maximum reliability:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"

    # Standard batching
    max_batch_size = 512
    max_batch_interval = "5s"

    # Large queue for reliability
    max_queue_size = 4096

    # Long timeouts
    timeout = "30s"
    max_export_timeout = "60s"
  }
}
```

## Complete Configuration Examples

### Minimal (Local Development)

```hcl
export "traces" {
  otlp = {
    endpoint = "http://localhost:4317"
    protocol = "grpc"
  }
}
```

### Standard (Production)

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
    timeout = "10s"
    max_batch_size = 512
    max_batch_interval = "5s"
    max_queue_size = 2048
  }
}
```

### Secure (TLS + Auth)

```hcl
export "traces" {
  otlp = {
    endpoint = "https://collector.example.com:4317"
    protocol = "grpc"
    timeout = "15s"
    max_batch_size = 512
    max_batch_interval = "5s"
    max_queue_size = 2048

    auth = {
      basic = {
        user = "mermin"
        pass = "env(OTLP_PASSWORD)"
      }
    }

    tls = {
      insecure_skip_verify = false
      ca_cert = "/etc/mermin/certs/ca.crt"
      client_cert = "/etc/mermin/certs/client.crt"
      client_key = "/etc/mermin/certs/client.key"
    }
  }
}
```

## Monitoring Export Health

### Key Metrics

```prometheus
# Export success rate
rate(mermin_export_success_total[5m])

# Export errors
rate(mermin_export_errors_total[5m])

# Queue size
mermin_export_queue_size

# Export latency
histogram_quantile(0.95, mermin_export_latency_seconds_bucket)
```

### Healthy Indicators

* Zero or minimal export errors
* Queue size well below max
* Export latency < timeout
* No dropped spans

## Troubleshooting

### Connection Refused

**Symptoms:** `connection refused` errors

**Solutions:**

1. Verify collector is running: `kubectl get pods -l app=otel-collector`
2. Check endpoint URL and port
3. Verify network policies allow egress
4. Test connectivity: `kubectl exec <mermin-pod> -- wget -O- http://otel-collector:4317`

### TLS Certificate Errors

**Symptoms:** `certificate verify failed`, `x509` errors

**Solutions:**

1. Verify CA certificate is correct
2. Check certificate hasn't expired
3. Ensure hostname matches certificate CN/SAN
4. For self-signed certs, use `ca_cert` configuration

### Timeout Errors

**Symptoms:** `context deadline exceeded`, timeout errors

**Solutions:**

1. Increase `timeout` value
2. Check collector performance
3. Reduce `max_batch_size`
4. Verify network latency

### Queue Full / Dropped Spans

**Symptoms:** `mermin_export_drops_total` increasing

**Solutions:**

1. Increase `max_queue_size`
2. Increase collector capacity
3. Reduce `max_batch_interval` for faster export
4. Check collector for backpressure

## Next Steps

* [**Stdout Exporter**](export-stdout.md): Configure console output for debugging
* [**Integration Guides**](../integrations/integrations.md): Connect to specific backends
* [**Troubleshooting Export Issues**](../troubleshooting/export-issues.md): Diagnose problems
* [**OpenTelemetry Collector**](../integrations/opentelemetry-collector.md): Set up collector
