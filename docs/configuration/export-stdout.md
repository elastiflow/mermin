# Configure OpenTelemetry Console Exporter

**Block:** `export.traces.stdout`

The stdout exporter outputs flow records directly to the console (standard output), making it ideal for development, debugging, and verifying flow capture without an external backend.

## Overview

The stdout exporter transforms flow spans into a readable format. While OTLP export is used for production observability, the stdout exporter provides immediate, human-readable visibility into the data Mermin is processing.

## Configuration

A complete configuration example can be found in the [Default Configuration](./default/config.hcl).

```hcl
export "traces" {
  stdout = "text_indent"
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

  **Syntax Variations:** 
  The exporter supports both a shorthand string and a structured object format to maintain compatibility across HCL and YAML.

  - HCL Shorthand (Recommended)

    ```hcl
    export "traces" {
      stdout = "text_indent"
    }
    ```

  - Object Form (Required for YAML)

    ```hcl
    export "traces" {
      stdout = {
        format = "text_indent"
      }
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

### Development and Quick Start
Use this configuration to see flows immediately during initial setup or demos without external dependencies.

```hcl
# Development configuration
log_level = "debug"

discovery "instrument" {
  interfaces = ["eth0"]
}

export "traces" {
  stdout = "text_indent"  # Immediate human-readable feedback
}
```

### Dual Export
Use this configuration to verify that flows are being captured correctly while simultaneously sending them to a production OTLP backend. This is useful for troubleshooting pipeline issues.

```hcl
# Debugging / Pipeline Validation
export "traces" {
  stdout = "text_indent" 
  
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
