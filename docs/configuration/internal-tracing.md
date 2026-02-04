# Configure the Internal Tracing Exporter

This page documents the `internal "traces"` configuration (config path: `internal.traces`), which controls how Mermin exports its own telemetry data for self-monitoring and debugging.
Mermin accepts HCL or YAML; the examples below use HCL (see [Configuration Overview](configuration.md#file-format) for format details).

## Overview

Mermin can export traces about its own operation, enabling you to:

* Monitor Mermin's internal performance
* Debug issues with flow processing
* Track eBPF program execution
* Observe internal component interactions

This is separate from network flow export and is primarily used for Mermin development and advanced troubleshooting.

## Configuration

```hcl
internal "traces" {
  span_fmt = "full"

  stdout = {
    format = "text_indent"
  }

  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

## Configuration Options

### `span_fmt`

**Type:** String (enum) **Default:** `"full"`

Span event format for internal traces.

**Valid Values:**

* `"full"`: Record all span events (enter, exit, close). The value `"plain"` is accepted and treated as `"full"`.

**Example:**

```hcl
internal "traces" {
  span_fmt = "full"  # Complete span lifecycle
}
```

### `stdout`

**Type:** Object **Default:** `null` (disabled)

Stdout exporter configuration for internal traces.

**Sub-options:**

#### `format`

**Type:** String (enum) **Valid Values:** `"text_indent"`

**Example:**

```hcl
internal "traces" {
  stdout = {
    format = "text_indent"
  }
}
```

### `otlp`

**Type:** Object **Default:** `null` (disabled)

OTLP exporter configuration for internal traces.

Uses same configuration options as main OTLP exporter (see [OTLP Exporter](export-otlp.md)).

**Example:**

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

* eBPF program loading issues
* Flow processing bottlenecks
* Informer synchronization problems
* Export pipeline issues

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

* Span duration for operations
* Bottlenecks in processing pipeline
* Resource usage patterns

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

## Internal Trace Examples

### eBPF Program Loading

```text
Span: load_ebpf_program
  Start: 2025-10-27T15:30:00.000Z
  Duration: 250ms
  Attributes:
    program.name: mermin
    program.type: classifier
    interface: eth0
  Events:
    - attach_to_interface (eth0)
    - verify_program_loaded
```

### Flow Processing

```text
Span: process_packet
  Start: 2025-10-27T15:30:01.234Z
  Duration: 0.5ms
  Attributes:
    packet.size: 1500
    flow.exists: true
    flow.state: established
  Events:
    - lookup_flow_table
    - update_counters
    - check_timeouts
```

### Kubernetes Informer Sync

```text
Span: sync_k8s_informers
  Start: 2025-10-27T15:30:05.000Z
  Duration: 2.5s
  Attributes:
    informer.type: pod
    resources.count: 1234
  Events:
    - connect_to_api_server
    - list_resources
    - populate_cache
    - watch_started
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

* Separate production Flow Traces from debug data
* Different retention policies
* Isolate development traffic

## Performance Impact

Internal tracing has minimal performance overhead:

**Stdout only:**

* CPU: < 1%
* Memory: Negligible

**OTLP export:**

* CPU: < 2%
* Memory: \~10-20 MB (for buffering)

Safe to enable in production for troubleshooting.

## Disabling Internal Traces

To completely disable internal traces:

```hcl
# No internal block = internal traces disabled
# Or explicitly:
# internal "traces" {}
```

This is the default and recommended for most deployments.

## Troubleshooting

### Internal Traces Not Appearing

**Symptoms:** No internal trace data visible

**Solutions:**

1. Verify `internal "traces"` block is configured
2. Check exporter configuration (stdout or otlp)
3. Ensure log level is sufficient: `log_level = "debug"`
4. Check OTLP collector is receiving data

### Too Much Internal Trace Data

**Symptoms:** Overwhelming volume of internal traces

**Solutions:**

1. Disable internal traces if not needed
2. Send to separate collector
3. Use sampling (if supported)
4. Filter by span name in collector

### Internal Traces Interfering with Flow Traces

**Symptoms:** Internal traces mixed with network Flow Traces

**Solutions:**

1. Send internal traces to a different endpoint than flow traces (e.g. separate OTLP collectors)
2. Use different collector instances for internal vs flow export
3. Filter by span name or attributes in your backend: both internal and flow traces use `service.name="mermin"`,
   so distinguish them by span name (e.g. internal spans like `load_ebpf_program`, `process_packet`, `sync_k8s_informers` vs flow span names from your flow data)

## Best Practices

1. **Disable by default**: Only enable when needed
2. **Use separate collectors**: Don't mix with production Flow Traces
3. **Enable for debugging**: Temporarily enable for troubleshooting
4. **Monitor overhead**: Watch resource usage if enabled
5. **Document usage**: Note why internal traces are enabled

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

## Integration with Observability Stack

Internal and flow traces both use `service.name="mermin"`. To find internal traces in your backend, filter by span name or other attributes (e.g. internal span names like `load_ebpf_program`, `process_packet`, `sync_k8s_informers`).

### Grafana Tempo

Query internal traces in Tempo using TraceQL (Tempo's trace query language, not PromQL):

```traceql
# Find internal spans for Mermin (filter by span name)
{ resource.service.name="mermin" && name=~"load_ebpf_program|process_packet|sync_k8s_informers" }

# Find slow internal operations (duration filter)
{ resource.service.name="mermin" && name=~"load_ebpf_program|process_packet|sync_k8s_informers" } | duration > 1s
```

### Jaeger

Filter internal traces:

* **Service:** `mermin` (same as flow traces; use operation/span name to narrow)
* **Operation (span name):** `load_ebpf_program`, `process_packet`, `sync_k8s_informers`, etc.

## Next Steps

* [**Global Options**](global-options.md): Configure logging levels
* [**API**](api.md) and [**Metrics**](metrics.md): Monitor Mermin with Prometheus
* [**Troubleshooting**](../troubleshooting/troubleshooting.md): Debug common issues
* [**OTLP Exporter**](export-otlp.md): Configure trace export
