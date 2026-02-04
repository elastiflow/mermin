# Configure the Flow Span Producer

Mermin groups captured packets into bidirectional flows and exports each flow as an OpenTelemetry span. The `span` block controls when flows are closed and when they emit records,
plus Community ID hashing, trace ID correlation, and hostname resolution. Add a top-level `span { }` block in your [configuration file](configuration.md); there are no CLI or environment overrides for span options.

Flow semantics (how flows become OpenTelemetry spans and what attributes they carry) are in [Semantic Conventions](../spec/semantic-conventions.md) and [Attribute Reference](../spec/attribute-reference.md).

## Configuration

Place a `span { }` block alongside `pipeline`, `export`, and other blocks. Omit the block to use built-in defaults for all options. Durations use HCL duration strings (e.g. `"30s"`, `"5m"`, `"24h"`).

```hcl
span {
  max_record_interval   = "60s"
  generic_timeout       = "30s"
  icmp_timeout          = "10s"
  tcp_timeout           = "20s"
  tcp_fin_timeout       = "5s"
  tcp_rst_timeout       = "5s"
  udp_timeout           = "60s"
  community_id_seed     = 0
  trace_id_timeout      = "24h"
  enable_hostname_resolution = true
  hostname_resolve_timeout   = "100ms"
}
```

## Option Reference

### Timeouts and intervals

| Option                | Type     | Default | Description                                                                                                                                                                                                                                     |
|-----------------------|----------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `max_record_interval` | duration | `60s`   | Maximum time an active flow can run without exporting a record. When this interval is reached, a record is emitted and the flow continues. Long-lived flows are therefore split into multiple spans.                                            |
| `generic_timeout`     | duration | `30s`   | Inactivity timeout for protocols that have no dedicated timeout: GRE, ESP, AH, and other IP protocols. After this period with no packets, the flow is closed. Flows with at least one packet are exported; flows with zero packets are dropped. |
| `icmp_timeout`        | duration | `10s`   | Inactivity timeout for ICMP (e.g. ping, traceroute).                                                                                                                                                                                            |
| `tcp_timeout`         | duration | `20s`   | Inactivity timeout for TCP when no FIN or RST has been seen (connection still open).                                                                                                                                                            |
| `tcp_fin_timeout`     | duration | `5s`    | After a FIN is seen (graceful close), the flow is exported after this period so final ACKs can be included.                                                                                                                                     |
| `tcp_rst_timeout`     | duration | `5s`    | After an RST is seen (abrupt close), the flow is exported after this period.                                                                                                                                                                    |
| `udp_timeout`         | duration | `60s`   | Inactivity timeout for UDP. UDP is connectionless; a longer value suits sporadic traffic.                                                                                                                                                       |

For TCP, the effective timeout is chosen per flow: `tcp_timeout` for established connections with no FIN/RST, `tcp_fin_timeout` once a FIN is seen, and `tcp_rst_timeout` once an RST is seen.

### Community ID and trace correlation

| Option              | Type             | Default | Description                                                                                                                                                                                                                                                                          |
|---------------------|------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `community_id_seed` | integer (uint16) | `0`     | Seed for [Community ID](https://github.com/corelight/community-id-spec) hashing of the flow five-tuple. Use the same seed everywhere for correlation across agents and tools. The result is exported as `flow.community_id` ([Attribute Reference](../spec/attribute-reference.md)). |
| `trace_id_timeout`  | duration         | `24h`   | How long the same Community ID keeps the same trace ID. Bounds memory while still allowing correlation across flow records for the same logical flow.                                                                                                                                |

### Hostname resolution

| Option                       | Type     | Default | Description                                                                                                                                           |
|------------------------------|----------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enable_hostname_resolution` | bool     | `true`  | When true, `client.address` and `server.address` may be reverse-DNS hostnames instead of IPs ([Attribute Reference](../spec/attribute-reference.md)). |
| `hostname_resolve_timeout`   | duration | `100ms` | Timeout for each reverse-DNS lookup. Results are cached.                                                                                              |

## When a flow span is exported

A flow span is exported when any of these is true:

1. **Max interval**: The flow has been active for `max_record_interval` without emitting a record. A record is emitted and the flow continues (may emit again at the next interval).
2. **Protocol timeout**: No packets for the protocol-specific timeout (generic, ICMP, TCP, or UDP). The flow is closed and removed from the flow table.
3. **TCP close**: A FIN or RST was seen and the corresponding `tcp_fin_timeout` or `tcp_rst_timeout` has elapsed. The flow is closed and exported.

Exported spans are sent to the targets configured in your export block ([OTLP export](export-otlp.md), [stdout export](export-stdout.md), etc.).
Workers poll flow state on an interval defined in [pipeline](pipeline.md) (`flow_producer.flow_store_poll_interval`). The flow table is backed by the eBPF `FLOW_STATS` map and in-memory state;
its capacity is set in [pipeline](pipeline.md) (`flow_capture.flow_stats_capacity`).

## Tuning

Shorter intervals and timeouts mean more exports and higher storage and [OTLP export](export-otlp.md) load; longer values reduce volume and improve aggregation at the cost of slower visibility.

Example for low-latency monitoring (only overrides shown; the rest use defaults):

```hcl
span {
  max_record_interval = "10s"
  generic_timeout     = "10s"
  tcp_timeout         = "10s"
  tcp_fin_timeout     = "2s"
  tcp_rst_timeout     = "2s"
  udp_timeout         = "20s"
}
```

For high-throughput or memory-constrained nodes, use longer or shorter timeouts accordingly. To reduce the number of flows tracked,use [flow filters](filtering.md).
[Troubleshooting](../troubleshooting/troubleshooting.md) and [Pipeline](pipeline.md) cover backpressure, export tuning, and pipeline sizing.

## Monitoring

Flow and eBPF map metrics are in [Internal Metrics](../observability/app-metrics.md): `mermin_flow_spans_active_total`, `mermin_flow_spans_created_total`, and `mermin_ebpf_map_size` / `mermin_ebpf_map_capacity` with `map="FLOW_STATS"`.
If the flow table or memory grows without bound, lower timeouts or `max_record_interval`, or reduce tracked flows with [flow filters](filtering.md). If you need more headroom for legitimate load,
increase `flow_capture.flow_stats_capacity` in [pipeline](pipeline.md).
