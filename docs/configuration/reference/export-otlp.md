# Configure OpenTelemetry OTLP Exporter

**Block:** `export.traces.otlp`

This page documents the OpenTelemetry Protocol (OTLP) exporter configuration, which controls how Mermin exports flow records to your observability backend.

## Overview

OTLP is the standard protocol for OpenTelemetry telemetry data. Mermin exports network flows as OTLP trace spans, enabling integration with any OTLP-compatible backend including OpenTelemetry Collector, Grafana Tempo, Jaeger, and more.

## Configuration

A full configuration example:

```hcl
export "traces" {
  otlp = {
    endpoint               = "http://otel-collector:4317"
    protocol               = "grpc"
    timeout                = "10s"
    max_batch_size         = 1024
    max_batch_interval     = "2s"
    max_queue_size         = 32768
    max_concurrent_exports = 4
    max_export_timeout     = "10s"

    auth = {
      basic = {
        user = "username"
        pass = "password"
      }
    }

    tls = {
      insecure_skip_verify = false
      ca_cert              = "/etc/certs/ca.crt"
      client_cert          = "/etc/certs/client.crt"
      client_key           = "/etc/certs/client.key"
    }
  }
}
```

### `export.traces.otlp` block

*   `endpoint` attribute

    OTLP collector endpoint URL.

    **Type:** String (URL)

    **Default:** `"http://localhost:4317"`

    **Format:**

    * `http://hostname:port` for unencrypted gRPC
    * `https://hostname:port` for TLS-encrypted gRPC
    * Port 4317 is standard for gRPC
    * Port 4318 is standard for HTTP

    **Examples:**

    *   Local collector

        ```hcl
        export "traces" {
          otlp = {
            endpoint = "http://otel-collector:4317"
          }
        }
        ```
    *   Remote collector with TLS

        ```hcl
        export "traces" {
          otlp = {
            endpoint = "https://collector.example.com:4317"
          }
        }
        ```
    *   Kubernetes service in different namespace

        ```hcl
        export "traces" {
          otlp = {
            endpoint = "http://otel-collector.observability:4317"
          }
        }
        ```
*   `protocol` attribute

    OTLP transport protocol.

    **Type:** String (enum)

    **Default:** `"grpc"`

    **Valid Values:**

    * `"grpc"`: gRPC protocol (recommended, default)
    * `"http_binary"`: HTTP with binary protobuf payload

    **Protocol Comparison:**

    | Feature               | gRPC   | HTTP     |
    | --------------------- | ------ | -------- |
    | **Performance**       | Higher | Moderate |
    | **Streaming**         | Yes    | No       |
    | **Firewall Friendly** | Less   | More     |
    | **Standard Port**     | 4317   | 4318     |
    | **HTTP/2 Required**   | Yes    | No       |

    **Example:** Use HTTP protocol

    ```hcl
    export "traces" {
      otlp = {
        protocol = "http_binary"
        endpoint = "http://collector:4318"
      }
    }
    ```
*   `timeout` attribute

    Timeout for individual OTLP export requests.

    **Type:** Duration

    **Default:** `"10s"`

    **Tuning:**

    * **Fast networks**: 5s-10s
    * **WAN/Internet**: 15s-30s
    * **High latency**: 30s-60s

    **Example:** Slow network timeout

    ```hcl
    export "traces" {
      otlp = {
        timeout = "30s"
      }
    }
    ```

#### Batching Configuration

Mermin uses batching for efficient exports of flow spans. The processor queues spans asynchronously and exports them in batches, providing natural backpressure when the queue fills up.

*   `max_batch_size` attribute

    Maximum number of spans (flow records) per batch.

    **Type:** Integer

    **Default:** `1024`

    **Trade-offs:**

    * **Larger batches**: Better efficiency, higher latency
    * **Smaller batches**: Lower latency, more requests

    **Examples:**

    *   High-volume environment

        ```hcl
        export "traces" {
          otlp = {
            max_batch_size = 2048
          }
        }
        ```
    *   Low-latency requirements

        ```hcl
        export "traces" {
          otlp = {
            max_batch_size = 128
          }
        }
        ```
*   `max_batch_interval` attribute

    Maximum time to wait before exporting a partial batch.

    **Type:** Duration

    **Default:** `"2s"`

    **Behavior:**

    * Batch is exported when it reaches `max_batch_size` OR `max_batch_interval` (whichever comes first)
    * Prevents indefinite waiting for partial batches

    **Examples:**

    *   Real-time monitoring

        ```hcl
        export "traces" {
          otlp = {
            max_batch_interval = "1s"
          }
        }
        ```
    *   Reduced export frequency

        ```hcl
        export "traces" {
          otlp = {
            max_batch_interval = "10s"
          }
        }
        ```
*   `max_queue_size` attribute

    Maximum number of spans queued in the batch processor before they are exported.

    **Type:** Integer

    **Default:** `32768`

    **Critical for High Throughput:**

    This is the internal queue capacity of the batch processor. When this queue fills up:

    * New spans are **dropped silently** (OpenTelemetry will log a warning)
    * The queue uses `try_send` which is **non-blocking**, so your pipeline won't deadlock
    * This provides natural backpressure during export slowdowns

    **Queue Behavior:**

    * Acts as buffer during temporary collector unavailability or slow exports
    * When the queue is full, new spans are **dropped** (OpenTelemetry uses non-blocking send); export workers send batches and may block on the network call up to the configured timeout
    * Default (32768) buffers on the order of seconds at high throughput (e.g. \~6s at 5K flows/sec); increase for burst tolerance
    * Monitor `mermin_export_flow_spans_total{exporter="otlp",status="error"}` and `mermin_export_timeouts_total` for export health

    **Examples:**

    *   Very high throughput (>10K flows/sec)

        ```hcl
        export "traces" {
          otlp = {
            max_queue_size = 65536
          }
        }
        ```
    *   Memory-constrained environment

        ```hcl
        export "traces" {
          otlp = {
            max_queue_size = 2048
          }
        }
        ```
*   `max_concurrent_exports` attribute

    Maximum number of concurrent export requests to the backend.

    **Type:** Integer

    **Default:** `4`

    **Tuning for Throughput:**

    This setting is **critical** for high-throughput scenarios. With the defaults:

    * `1024 spans/batch × 100 batches/sec/worker = 102,400 flows/sec capacity`
    * Each worker needs \~40ms per export (including network + backend processing)
    * If exports take longer, increase this value

    **Recommendations:**

    * **2-4:** Good for most scenarios (default is 4)
    * **6-8:** High backend latency (>50ms per export)
    * **1:** Low-latency, high-performance backends only

    **Example:** High-throughput

    ```hcl
    export "traces" {
      otlp = {
        max_concurrent_exports = 8
      }
    }
    ```
*   `max_export_timeout` attribute

    Maximum time for export operation including retries.

    **Type:** Duration

    **Default:** `"10s"`

    **Example:** High-latency networks or slow backends

    ```hcl
    export "traces" {
      otlp = {
        max_export_timeout = "30s"
      }
    }
    ```

### `export.traces.otlp.auth` block

Configure authentication for the OTLP endpoint. Supports HTTP Basic authentication or Bearer token authentication.

*   `basic` block

    Configure HTTP Basic authentication for the OTLP endpoint.

    *   `user` attribute

        Username for basic authentication.

        **Type:** String

        **Default:** None (required if basic auth is used)
    *   `pass` attribute

        Password for basic authentication. Supports environment variable interpolation via `env(VAR_NAME)`.

        **Type:** String

        **Default:** None (required if basic auth is used)

    **Examples:**

    *   Basic authentication

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
    *   Using environment variables

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
                pass = "env(OTLP_PASSWORD)"
              }
            }
          }
        }
        ```
    *   Using Kubernetes Secrets

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
*   `bearer` attribute

    Bearer token for authentication. Use instead of basic authentication when the backend expects a bearer token.

    **Type:** String

    **Default:** None (optional)

    **Example:** Bearer authentication

    ```hcl
    export "traces" {
      otlp = {
        endpoint = "https://collector.example.com:4317"

        auth = {
          bearer = "secret_password"
        }
      }
    }
    ```

### `export.traces.otlp.tls` block

TLS is automatically enabled for `https://` endpoints. Use the `tls` block to configure custom certificates or disable verification.

*   `insecure_skip_verify` attribute

    Skip TLS certificate verification.

    **Type:** Boolean

    **Default:** `false`

    <div data-gb-custom-block data-tag="hint" data-style="danger" class="hint hint-danger"><p><strong>Never use <code>insecure_skip_verify = true</code> in production!</strong> This disables all certificate verification and makes connections vulnerable to man-in-the-middle attacks.</p></div>

    **Example:** Insecure mode (development only)

    ```hcl
    export "traces" {
      otlp = {
        endpoint = "https://collector.example.com:4317"

        tls = {
          insecure_skip_verify = true
        }
      }
    }
    ```
*   `ca_cert` attribute

    Path to custom CA certificate file for verifying the server's certificate.

    **Type:** String (file path)

    **Default:** None (uses system CA certificates)

    **Examples:**

    *   Custom CA certificate

        ```hcl
        export "traces" {
          otlp = {
            endpoint = "https://collector.example.com:4317"

            tls = {
              insecure_skip_verify = false
              ca_cert              = "/etc/mermin/certs/ca.crt"
            }
          }
        }
        ```
    *   Mounting CA certificate in Kubernetes

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
*   `client_cert` attribute

    Path to client certificate file for mutual TLS (mTLS) authentication.

    **Type:** String (file path)

    **Default:** None (optional)
*   `client_key` attribute

    Path to client private key file for mutual TLS (mTLS) authentication.

    **Type:** String (file path)

    **Default:** None (optional)

    **Examples:**

    *   Mutual TLS (mTLS)

        ```hcl
        export "traces" {
          otlp = {
            endpoint = "https://collector.example.com:4317"

            tls = {
              insecure_skip_verify = false
              ca_cert              = "/etc/mermin/certs/ca.crt"
              client_cert          = "/etc/mermin/certs/client.crt"
              client_key           = "/etc/mermin/certs/client.key"
            }
          }
        }
        ```
    *   Mounting client certificates in Kubernetes

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
    max_queue_size = 65536

    # Aggressive timeouts
    timeout = "5s"
    max_export_timeout = "20s"

    # Multiple concurrent exports
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
    timeout            = "30s"
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
    endpoint           = "http://otel-collector:4317"
    protocol           = "grpc"
    timeout            = "10s"
    max_batch_size     = 512
    max_batch_interval = "5s"
    max_queue_size     = 2048
  }
}
```

### Secure (TLS + Auth)

```hcl
export "traces" {
  otlp = {
    endpoint           = "https://collector.example.com:4317"
    protocol           = "grpc"
    timeout            = "15s"
    max_batch_size     = 512
    max_batch_interval = "5s"
    max_queue_size     = 2048

    auth = {
      basic = {
        user = "mermin"
        pass = "env(OTLP_PASSWORD)"
      }
    }

    tls = {
      insecure_skip_verify = false
      ca_cert              = "/etc/mermin/certs/ca.crt"
      client_cert          = "/etc/mermin/certs/client.crt"
      client_key           = "/etc/mermin/certs/client.key"
    }
  }
}
```

## Monitoring Export Health

### Key Metrics to Monitor

* `mermin_export_flow_spans_total{exporter="otlp",status="ok"}` - OTLP export success rate
* `mermin_export_flow_spans_total{exporter="otlp",status="error"}` - OTLP export errors
* `mermin_channel_entries{channel="producer_output"}` / `mermin_channel_capacity{channel="producer_output"}` - Channel utilization
* `mermin_pipeline_duration_seconds{stage="export_out"}` - Export-stage latency
* `mermin_channel_sends_total{channel="decorator_output",status="error"}` - Channel send failures (indicates dropped spans)

See the [Internal Metrics](../../internal-monitoring/internal-metrics.md) guide for complete Prometheus query examples.

### Healthy Indicators

* Zero or minimal export errors
* Queue size well below max
* Export latency < timeout
* No channel send errors

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

**Symptoms:** `mermin_channel_sends_total{channel="decorator_output",status="error"}` or `mermin_channel_sends_total{channel="producer_output",status="error"}` increasing

**Solutions:**

1. Increase `max_queue_size` in exporter configuration
2. Increase collector capacity
3. Reduce `max_batch_interval` for faster export
4. Monitor `mermin_channel_entries{channel="decorator_output"}` to see queue depth
5. Check collector for backpressure

## Next Steps

* [**Stdout Exporter**](export-stdout.md): Configure console output for debugging
* [**Observability Backends**](https://github.com/elastiflow/mermin/blob/beta/docs/observability/backends.md): Set up collector and connect to backends
* [**Troubleshooting**](../../troubleshooting/troubleshooting.md): Diagnose problems
