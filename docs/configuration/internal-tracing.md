# Configure Internal Tracing Exporter

**Block:** `internal.traces`

Mermin can export traces about its own operation for self-monitoring and debugging. This is separate from network flow export and is primarily used for Mermin development and advanced troubleshooting.

**Enables you to:**

- Monitor Mermin's internal performance
- Debug issues with flow processing
- Track eBPF program execution
- Observe internal component interactions

## Configuration

A full configuration example may be found in the [Default Configuration](./default/config.hcl).

### Configuration Structure

The internal traces configuration is organized as follows:

```hcl
internal "traces" {
  # Span format
  span_fmt = "full"

  # Optional: stdout exporter
  stdout = {
    format = "text_indent"
  }

  # Optional: OTLP exporter
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

## Configuration Options

### `internal.traces` block

- `span_fmt` attribute

  Span event format for internal traces.

  **Type:** String (enum)

  **Default:** `"full"`

  **Valid Values:**

  - `"full"`: Record all span events (enter, exit, close). The value `"plain"` is accepted and treated as `"full"`.

  **Example:** Complete span lifecycle

  ```hcl
  internal "traces" {
    span_fmt = "full"
  }
  ```

- `stdout` attribute

  Stdout exporter configuration for internal traces.

  **Type:** Object

  **Default:** `null` (disabled)

  **Sub-options:**

  - `format`: String (enum). Valid values: `"text_indent"`

  **Example:** Enable stdout export with text indent format

  ```hcl
  internal "traces" {
    stdout = {
      format = "text_indent"
    }
  }
  ```

- `otlp` attribute

  OTLP exporter configuration for internal traces. Uses same configuration options as main OTLP exporter (see [OTLP Exporter](export-otlp.md)).

  **Type:** Object

  **Default:** `null` (disabled)

  **Examples:**

  - Basic OTLP export

    ```hcl
    internal "traces" {
      otlp = {
        endpoint = "http://otel-collector:4317"
        protocol = "grpc"
      }
    }
    ```

  - OTLP export with authentication

    ```hcl
    internal "traces" {
      otlp = {
        endpoint = "http://otel-collector:4318"
        protocol = "http_binary"
        timeout = "10s"
        max_batch_size = 512
        max_batch_interval = "5s"

        auth = {
          basic = {
            user = "mermin-internal"
            pass = "password"
          }
        }
      }
    }
    ```

## Use Cases

### Debugging Mermin Issues

Enable internal traces to debug Mermin behavior:

```hcl
log_level = "debug"

internal "traces" {
  span_fmt = "full"
  stdout = {
    format = "text_indent"
  }
}
```

**Useful for:**

- eBPF program loading issues
- Flow processing bottlenecks
- Informer synchronization problems
- Export pipeline issues

### Performance Analysis

Send internal traces to OTLP for performance analysis:

```hcl
internal "traces" {
  span_fmt = "full"
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

**Analyze:**

- Span duration for operations
- Bottlenecks in processing pipeline
- Resource usage patterns

### Mermin Development

Essential for developing and testing Mermin:

```hcl
log_level = "trace"

internal "traces" {
  span_fmt = "full"
  stdout = {
    format = "text_indent"
  }
}
```

## Separating Network Flows and Internal Traces

You can send network flows and internal traces to different backends:

```hcl
# Network flows to production collector
export "traces" {
  otlp = {
    endpoint = "http://flow-collector:4317"
    protocol = "grpc"
  }
}

# Internal traces to development collector
internal "traces" {
  otlp = {
    endpoint = "http://debug-collector:4317"
    protocol = "grpc"
  }
}
```

**Benefits:**

- Separate production Flow Traces from debug data
- Different retention policies
- Isolate development traffic

Safe to enable in production for troubleshooting.

## Disabling Internal Traces

To completely disable internal traces:

```hcl
# No internal block = internal traces disabled
# Or explicitly:
# internal "traces" {}
```

This is the default.

## Troubleshooting

### Internal Traces Not Appearing

**Symptoms:** No internal trace data visible

**Solutions:**

1. Verify `internal "traces"` block is configured
2. Check exporter configuration (stdout or otlp)
3. Ensure log level is sufficient: `log_level = "debug"`
4. Check OTLP collector is receiving data

### Internal Traces Interfering with Flow Traces

**Symptoms:** Internal traces mixed with network Flow Traces

**Solutions:**

1. Send internal traces to a different endpoint than flow traces (e.g. separate OTLP collectors)
2. Use different collector instances for internal vs flow export
3. Filter by span name or attributes in your backend: both internal and flow traces use `service.name="mermin"`,
   so distinguish them by span name (e.g. internal spans like `load_ebpf_program`, `process_packet`, `sync_k8s_informers` vs flow span names from your flow data)

## Best Practices

1. **Use separate collectors**: Don't mix with production Flow Traces
2. **Enable for debugging**: Temporarily enable for troubleshooting
3. **Monitor overhead**: Watch resource usage if enabled
4. **Document usage**: Note why internal traces are enabled

## Complete Configuration Examples

### Disabled (Default)

```hcl
# No internal block = disabled (recommended for production)
```

### Stdout Only (Debugging)

```hcl
log_level = "debug"

internal "traces" {
  span_fmt = "full"
  stdout = {
    format = "text_indent"
  }
}
```

### OTLP Export (Development)

```hcl
internal "traces" {
  span_fmt = "full"
  otlp = {
    endpoint = "http://debug-collector:4317"
    protocol = "grpc"
    timeout = "10s"
  }
}
```

### Both Stdout and OTLP

```hcl
internal "traces" {
  span_fmt = "full"

  stdout = {
    format = "text_indent"
  }

  otlp = {
    endpoint = "http://debug-collector:4317"
    protocol = "grpc"
  }
}
```

## Next Steps

- [**Global Options**](reference/README.md#configure-global-agent-options): Configure log levels
- Internal [**Server**](reference/internal-server.md) and [**Metrics**](metrics.md): Monitor with Prometheus
- [**Troubleshooting**](../troubleshooting/troubleshooting.md): Debug common issues
- [**OTLP Exporter**](export-otlp.md): Configure trace export
