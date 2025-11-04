# Stdout Exporter

The stdout exporter outputs flow records directly to the console (standard output), making it ideal for development, debugging, and initial testing of Mermin.

## Overview

While OTLP export is used for production observability, the stdout exporter provides immediate, human-readable visibility into captured flows without requiring an external collector.

## Configuration

```hcl
export "traces" {
  stdout = "text_indent"
}
```

## Configuration Option

### `stdout`

**Type:** String (enum) or null **Default:** `null` (disabled)

Output format for stdout exporter.

**Valid Values:**

* `"text_indent"`: Human-readable, indented text format (recommended)
* `null`: Disable stdout export

**Examples:**

Enable stdout exporter:

```hcl
export "traces" {
  stdout = "text_indent"
}
```

Disable stdout exporter:

```hcl
export "traces" {
  # stdout export disabled
}
```

## Output Format

### Text Indent Format

The `text_indent` format provides structured, readable output:

```
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

* No external dependencies
* Immediate feedback
* Easy debugging
* Simple setup

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

* Debugging export issues
* Comparing local vs. exported data
* Validating flow enrichment
* Troubleshooting transformations

## Viewing Stdout Output

### Kubernetes

View logs from Mermin pods:

```bash
# Single pod
kubectl logs -f <pod-name>

# All Mermin pods
kubectl logs -f -l app.kubernetes.io/name=mermin

# Specific container (if multi-container pod)
kubectl logs -f <pod-name> -c mermin

# Last N lines
kubectl logs --tail=50 <pod-name>

# Filter for specific source IP
kubectl logs <pod-name> | grep "Source IP: 10.244.1.5"
```

### Docker (Bare Metal)

View logs from Docker container:

```bash
# Follow logs
docker logs -f mermin

# Last N lines
docker logs --tail=100 mermin

# Since timestamp
docker logs --since=10m mermin
```

### Systemd

View logs from systemd service:

```bash
# Follow logs
journalctl -u mermin -f

# Last N lines
journalctl -u mermin -n 100

# Since timestamp
journalctl -u mermin --since "10 minutes ago"
```

## Filtering Stdout Output

### Using grep

Filter flows by criteria:

```bash
# Flows from specific IP
kubectl logs <pod> | grep "Source IP: 10.244.1.5"

# TCP flows only
kubectl logs <pod> | grep "Protocol: TCP"

# Flows to specific port
kubectl logs <pod> | grep "Destination Port: 443"

# Flows involving specific pod
kubectl logs <pod> | grep "nginx-deployment"
```

### Using jq (if JSON format available)

While Mermin currently supports text\_indent format, future JSON support would enable:

```bash
# Example for future JSON support
kubectl logs <pod> | jq 'select(.source.port == 443)'
```

## Performance Considerations

### Log Volume

Stdout output can generate significant log volume:

**Typical flow rate:** 1,000 flows/second **Text indent size:** \~500 bytes per flow **Log rate:** \~500 KB/second = \~1.8 GB/hour

**Recommendations:**

* Use stdout only for development/debugging
* Disable for production environments
* Configure log rotation if enabled long-term

### CPU Impact

Formatting flow records for stdout has minimal CPU overhead:

* Text formatting: < 1% CPU
* Logging I/O: < 2% CPU

Enable stdout without significant performance impact for debugging.

### Log Rotation

Configure log rotation to prevent disk filling:

**Docker:**

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  }
}
```

**Kubernetes:**

```yaml
# Relies on node-level log rotation
# Typically handled by kubelet
# Check: /var/log/pods/
```

## Troubleshooting

### No Output Visible

**Symptoms:** Stdout exporter enabled but no flow records in logs

**Solutions:**

1. Verify `stdout = "text_indent"` is set
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
4. **Monitor disk space**: Ensure adequate disk for logs
5. **Automate cleanup**: Configure log rotation
6. **Document usage**: Note when/why stdout is enabled

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

### Production (Stdout Disabled)

```hcl
# Production configuration
export "traces" {
  # stdout disabled

  otlp = {
    endpoint = "https://collector.example.com:4317"
    protocol = "grpc"
  }
}
```

## Comparison with OTLP

| Feature              | Stdout         | OTLP                 |
| -------------------- | -------------- | -------------------- |
| **Setup Complexity** | None           | Requires collector   |
| **Storage**          | Logs/ephemeral | Persistent backend   |
| **Query Capability** | grep only      | Full query language  |
| **Production Ready** | No             | Yes                  |
| **Resource Usage**   | Low            | Moderate             |
| **Scalability**      | Poor           | Excellent            |
| **Visualization**    | None           | Dashboards available |

## Next Steps

* [**OTLP Exporter**](export-otlp.md): Configure production export
* [**Flow Filtering**](filtering.md): Reduce log volume
* [**Internal Tracing**](internal-tracing.md): Monitor Mermin itself
* [**Integration Guides**](../observability/backends.md): Set up observability backends
