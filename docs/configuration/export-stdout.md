# Configure OpenTelemetry Console Exporter

**Block:** `export.traces`

The stdout exporter outputs flow records directly to the console (standard output), providing immediate, human-readable visibility into the data Mermin is processing. While OTLP export is the standard for production observability,
the stdout exporter is ideal for development, debugging, and verifying flow capture without requiring an external backend.

## Configuration

A complete configuration example can be found in the [Default Configuration](default/config.hcl).

### `export.traces` block

- `stdout` attribute

  Output format for stdout exporter. In HCL you can use the shorthand `stdout = "text_indent"` or the object form `stdout = { format = "text_indent" }`. In YAML use the object form with a `format` key.

  **Type:** String (enum), object with `format` key, or null

  **Default:** `null` (disabled)

  **Valid Values:**

  - `"text_indent"`: Human-readable, indented text format (recommended)
  - `null`: Disable stdout export

  **Syntax Variations:** The exporter supports both a shorthand string and a structured object format to maintain compatibility across HCL and YAML.

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
Span #1
        Instrumentation Scope
                Name         : "mermin"

        Name         : flow_ipv4_icmp
        TraceId      : 25532f1af4ef46087ab38fd181e8c409
        SpanId       : 0e610e187627dfac
        TraceFlags   : TraceFlags(1)
        ParentSpanId : f5bc1abf5a703419
        Kind         : Server
        Start time   : 2026-02-04 18:57:36.295385
        End time     : 2026-02-04 18:57:38.297897
        Status       : Unset
        Attributes:
                 ->  flow.community_id: String(Owned("1:a962MiVftHsve9ogcQKeY0/p9bc="))
                 ->  network.type: String(Static("ipv4"))
                 ->  network.transport: String(Static("icmp"))
                 ->  source.address: String(Owned("8.8.8.8"))
                 ->  source.port: I64(0)
                 ->  destination.address: String(Owned("10.244.2.4"))
                 ->  destination.port: I64(0)
                 ->  flow.bytes.delta: I64(98)
                 ->  flow.bytes.total: I64(98)
                 ->  flow.packets.delta: I64(1)
                 ->  flow.packets.total: I64(1)
                 ->  flow.reverse.bytes.delta: I64(0)
                 ->  flow.reverse.bytes.total: I64(0)
                 ->  flow.reverse.packets.delta: I64(0)
                 ->  flow.reverse.packets.total: I64(0)
                 ->  flow.end_reason: String(Static("idle timeout"))
                 ->  network.interface.index: I64(14)
                 ->  network.interface.name: String(Owned("veth8ef8af66"))
                 ->  network.interface.mac: String(Owned("1a:b2:da:f1:5d:d3"))
                 ->  flow.ip.dscp.id: I64(0)
                 ->  flow.ip.dscp.name: String(Owned("df"))
                 ->  flow.ip.ecn.id: I64(0)
                 ->  flow.ip.ecn.name: String(Owned("non-ect"))
                 ->  flow.ip.ttl: I64(62)
                 ->  flow.reverse.ip.ttl: I64(0)
                 ->  flow.reverse.ip.dscp.id: I64(0)
                 ->  flow.reverse.ip.ecn.id: I64(0)
                 ->  flow.icmp.type.id: I64(0)
                 ->  flow.icmp.type.name: String(Owned("echo_reply"))
                 ->  flow.icmp.code.id: I64(0)
                 ->  flow.icmp.code.name: String(Owned(""))
                 ->  flow.reverse.icmp.type.id: I64(0)
                 ->  flow.reverse.icmp.type.name: String(Owned("echo_reply"))
                 ->  flow.reverse.icmp.code.id: I64(0)
                 ->  flow.reverse.icmp.code.name: String(Owned(""))
                 ->  client.address: String(Owned("10.244.2.4"))
                 ->  client.port: I64(0)
                 ->  server.address: String(Owned("dns.google"))
                 ->  server.port: I64(0)
                 ->  destination.k8s.namespace.name: String(Owned("default"))
                 ->  destination.k8s.pod.name: String(Owned("test-pod"))
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

## Next Steps

- [**Configuration Overview**](overview.md): Config file format and structure
- [**OTLP Exporter**](export-otlp.md): Configure production export
- [**Flow Filtering**](filtering.md): Reduce log volume
- [**Internal Tracing**](internal-tracing.md): Monitor Mermin itself
- [**Observability Backends**](../observability/backend-integrations.md): Set up observability backends
