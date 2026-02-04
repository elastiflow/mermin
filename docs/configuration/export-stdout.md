# Configure OpenTelemetry Console Exporter

**Block:** `export.traces.stdout`

The stdout exporter outputs flow records directly to the console (standard output), making it ideal for development, debugging, and initial testing of Mermin.

## Overview

While OTLP export is used for production observability, the stdout exporter provides immediate, human-readable visibility into captured flows without requiring an external collector.

## Configuration

```hcl
export "traces" {
  stdout = "text_indent"
}
```

Alternatively, use the object form (required in YAML):

```hcl
export "traces" {
  stdout = {
    format = "text_indent"
  }
}
```

### `export.traces.stdout` block

- `stdout` attribute

  Output format for stdout exporter. In HCL you can use the shorthand `stdout = "text_indent"` or the object form `stdout = { format = "text_indent" }`. In YAML use the object form with a `format` key.

  **Type:** String (enum), object with `format` key, or null

  **Default:** `null` (disabled)

  **Valid Values:**

  - `"text_indent"`: Human-readable, indented text format (recommended)
  - `null`: Disable stdout export

  **Examples:**

  - Enable stdout exporter

    ```hcl
    export "traces" {
      stdout = "text_indent"
    }
    ```

  - Disable stdout exporter

    ```hcl
    export "traces" {
      # stdout export disabled
    }
    ```

## Output Format

### Text Indent Format

The `text_indent` format provides structured, readable output:

```text
Flow Record:
  Timestamp: 2025-10-27T15:30:45.123Z
  Duration: 15.234s
  Direction: bidirectional

  Source:
    IP: 10.244.1.5
    Port: 45678
    Pod: nginx-deployment-abc123
    Namespace: default
    Labels:
      app: nginx
      version: v1.0

  Destination:
    IP: 10.96.0.10
    Port: 80
    Service: nginx-service
    Namespace: default

  Network:
    Protocol: TCP
    Interface: eth0
    Tunnel: none

  Statistics:
    Packets Sent: 245
    Packets Received: 242
    Bytes Sent: 125640
    Bytes Received: 3468900

  TCP:
    Flags: SYN, ACK, FIN
    State: ESTABLISHED

  Community ID: 1:LQU9qZlK+B5F3KDmev6m5PMibrg=
```

## Use Cases

### Development and Testing

Use stdout during initial development:

```hcl
# Local development config
log_level = "debug"

discovery "instrument" {
  interfaces = ["eth0"]
}

export "traces" {
  stdout = "text_indent"  # See flows immediately
}
```

**Benefits:**

- No external dependencies
- Immediate feedback
- Easy debugging
- Simple setup

### Debugging Flow Issues

Enable stdout temporarily to debug flow capture:

```hcl
export "traces" {
  stdout = "text_indent"  # Add for debugging

  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

**Workflow:**

1. Enable stdout exporter
2. Deploy or reload configuration
3. View logs: `kubectl logs -f <pod-name>`
4. Inspect flow records
5. Disable stdout when done

### Quick Start and Demos

Use stdout for quick demonstrations:

```hcl
# Demo configuration
log_level = "info"

export "traces" {
  stdout = "text_indent"  # Show flows in real-time
}

# Minimal config for demo
discovery "instrument" {
  interfaces = ["eth*"]
}
```

### Pipeline Validation

Verify flow generation before setting up full OTLP pipeline:

```hcl
export "traces" {
  stdout = "text_indent"  # Validate flows are captured

  # Add OTLP after validation
  # otlp = {
  #   endpoint = "http://otel-collector:4317"
  #   protocol = "grpc"
  # }
}
```

## Combined with OTLP

You can enable both stdout and OTLP exporters simultaneously:

```hcl
export "traces" {
  # Debug output to console
  stdout = "text_indent"

  # Production export to collector
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

**When to use both:**

- Debugging export issues
- Comparing local vs. exported data
- Validating flow enrichment
- Troubleshooting transformations

## Troubleshooting

### No Output Visible

**Symptoms:** Stdout exporter enabled but no flow records in logs

**Solutions:**

1. Verify stdout is set (e.g. `stdout = "text_indent"` or `stdout = { format = "text_indent" }`)
2. Check log level includes info: `log_level = "info"`
3. Verify flows are being captured: check metrics
4. Confirm log output destination

### Too Much Output

**Symptoms:** Logs filling up quickly, hard to read

**Solutions:**

1. Add flow filters (see [Filtering](filtering.md))
2. Reduce monitored interfaces
3. Use grep to filter relevant flows
4. Disable stdout after debugging

### Output Format Issues

**Symptoms:** Truncated or malformed output

**Solutions:**

1. Check log collection limits
2. Verify container logs aren't being truncated
3. Increase log line length limits if needed

## Best Practices

1. **Disable in production**: Use OTLP for production environments
2. **Enable temporarily**: Turn on only when needed for debugging
3. **Use with filters**: Combine with flow filters to reduce volume
4. **Document usage**: Note when/why stdout is enabled

## Configuration Examples

### Development Only

```hcl
# Development configuration
log_level = "debug"

export "traces" {
  stdout = "text_indent"  # Console output only
}
```

### Debugging with OTLP

```hcl
# Debugging configuration
export "traces" {
  stdout = "text_indent"  # Temporary debug output

  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

## Next Steps

- [**Configuration Overview**](overview.md): Config file format and structure
- [**OTLP Exporter**](export-otlp.md): Configure production export
- [**Flow Filtering**](filtering.md): Reduce log volume
- [**Internal Tracing**](internal-tracing.md): Monitor Mermin itself
- [**Observability Backends**](../observability/backend-integrations.md): Set up observability backends
