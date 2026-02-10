# Configure Producing of Flow Spans

**Block:** `span`

Mermin groups captured packets into bidirectional flows and exports each flow as an OpenTelemetry span. The `span` block controls when flows are closed and when they emit records,
plus Community ID hashing, trace ID correlation, and hostname resolution. Add a top-level `span { }` block in your [configuration file](../overview.md); there are no CLI or environment overrides for span options.

The span block lets you configure:

- **Timeouts and record interval**: when flows are closed (protocol-specific inactivity timeouts) and how often long-lived flows emit records (`max_record_interval`)
- **Community ID and trace correlation**: five-tuple hashing for correlation across agents and how long the same Community ID keeps the same trace ID
- **Hostname resolution**: whether to resolve IPs to hostnames for `client.address` and `server.address` and the lookup timeout

Flow semantics (how flows become OpenTelemetry spans and what attributes they carry) are in [Semantic Conventions](../../concepts/semantic-conventions.md) and [Attribute Reference](../../getting-started/attribute-reference.md).

## Configuration

A full configuration example can be found in the [Default Configuration](../default/config.hcl).

- `max_record_interval` attribute

  Maximum time an active flow can run without exporting a record. When this interval is reached, a record is emitted and the flow continues. Long-lived flows are therefore split into multiple spans.

  **Type:** Duration

  **Default:** `60s`

  **Example:** Emit records more frequently for long-lived flows (e.g. streaming)

  ```hcl
  span {
    max_record_interval = "30s"
  }
  ```

- `generic_timeout` attribute

  Inactivity timeout for protocols that have no dedicated timeout: GRE, ESP, AH, and other IP protocols. After this period with no packets, the flow is closed. Flows with at least one packet are exported; flows with zero packets are dropped.

  **Type:** Duration

  **Default:** `30s`

  **Example:** Shorter timeout for non-TCP/UDP/ICMP protocols

  ```hcl
  span {
    generic_timeout = "15s"
  }
  ```

- `icmp_timeout` attribute

  Inactivity timeout for ICMP (e.g. ping, traceroute).

  **Type:** Duration

  **Default:** `10s`

  **Example:** Longer ICMP timeout for slow traceroutes

  ```hcl
  span {
    icmp_timeout = "20s"
  }
  ```

- `tcp_timeout` attribute

  Inactivity timeout for TCP flows that remain open (no FIN or RST observed). When this timeout elapses without traffic, the flow is considered inactive and will be closed.
  For each TCP flow, `tcp_timeout` applies as long as no FIN or RST has been seen.

  **Type:** Duration

  **Default:** `20s`

  **Example:** Shorter TCP inactivity timeout

  ```hcl
  span {
    tcp_timeout = "10s"
  }
  ```

- `tcp_fin_timeout` attribute

  After a FIN (graceful close) is observed on a TCP flow, the exporter waits for this timeout before exporting the flow.
  This allows late-arriving final ACKs to be captured. For each TCP flow, once a FIN is seen, `tcp_fin_timeout` determines when the flow is closed and exported.

  **Type:** Duration

  **Default:** `5s`

  **Example:** Shorter delay after FIN before exporting

  ```hcl
  span {
    tcp_fin_timeout = "2s"
  }
  ```

- `tcp_rst_timeout` attribute

  When a TCP RST (reset) is observed — indicating an abrupt connection termination — the flow waits for the specified `tcp_rst_timeout` before being exported.
  This timeout is evaluated for each flow individually after an RST is detected, ensuring even abruptly closed connections are accounted for with a brief post-RST delay before export.

  **Type:** Duration

  **Default:** `5s`

  **Example:** Shorter delay after RST before exporting

  ```hcl
  span {
    tcp_rst_timeout = "2s"
  }
  ```

- `udp_timeout` attribute

  Inactivity timeout for UDP. UDP is connectionless; a longer value suits sporadic traffic.

  **Type:** Duration

  **Default:** `60s`

  **Example:** Shorter UDP timeout when you only care about short-lived UDP flows

  ```hcl
  span {
    udp_timeout = "30s"
  }
  ```

- `community_id_seed` attribute

  Seed for [Community ID](https://github.com/corelight/community-id-spec) hashing of the flow five-tuple. Use the same seed everywhere for correlation across agents and tools. The result is exported as `flow.community_id` ([Attribute Reference](../../getting-started/attribute-reference.md)).

  **Type:** Integer (uint16)

  **Default:** `0`

  **Example:** Use a custom seed to align with another tool (e.g. Zeek) that uses a non-zero seed

  ```hcl
  span {
    community_id_seed = 1
  }
  ```

- `trace_id_timeout` attribute

  How long the same Community ID keeps the same trace ID. Bounds memory while still allowing correlation across flow records for the same logical flow.

  **Type:** Duration

  **Default:** `24h`

  **Example:** Shorter trace correlation window to reduce memory

  ```hcl
  span {
    trace_id_timeout = "1h"
  }
  ```

- `enable_hostname_resolution` attribute

  When true, `client.address` and `server.address` may be reverse-DNS hostnames instead of IPs ([Attribute Reference](../../getting-started/attribute-reference.md)).

  **Type:** Boolean

  **Default:** `true`

  **Example:** Disable hostname resolution to avoid DNS lookups and use IPs only

  ```hcl
  span {
    enable_hostname_resolution = false
  }
  ```

- `hostname_resolve_timeout` attribute

  Timeout for each reverse-DNS lookup. Results are cached.

  **Type:** Duration

  **Default:** `100ms`

  **Example:** Increase timeout for slow or high-latency DNS

  ```hcl
  span {
    hostname_resolve_timeout = "500ms"
  }
  ```

## When is a Flow Span Exported

Understanding when spans are exported helps with tuning and capacity planning. A flow span is exported when any of these is true:

1. **Max interval**: The flow has been active for `max_record_interval` without emitting a record. A record is emitted and the flow continues (may emit again at the next interval).
2. **Protocol timeout**: No packets for the protocol-specific timeout (generic, ICMP, TCP, or UDP). The flow is closed and removed from the flow table.
3. **TCP close**: A FIN or RST was seen and the corresponding `tcp_fin_timeout` or `tcp_rst_timeout` has elapsed. The flow is closed and exported.

Exported spans are sent to the targets configured in your export block ([OTLP export](opentelemetry-otlp-exporter.md), [stdout export](opentelemetry-console-exporter.md), etc.).
Workers poll flow state on an interval defined in [pipeline](flow-processing-pipeline.md) (`flow_producer.flow_store_poll_interval`). The flow table is backed by the eBPF `FLOW_STATS` map and in-memory state;
its max capacity is set in [pipeline](flow-processing-pipeline.md) (`flow_capture.flow_stats_capacity`).

## Tuning

Shorter intervals and timeouts mean more exports and higher storage and [OTLP export](opentelemetry-otlp-exporter.md) load; longer values reduce volume and improve aggregation at the cost of slower visibility.

For high-throughput or memory-constrained nodes, use longer or shorter timeouts accordingly. To reduce the number of flows tracked, use [flow filters](flow-span-filters.md).

[Troubleshooting](../../troubleshooting/troubleshooting.md) and [Pipeline](flow-processing-pipeline.md) cover backpressure, export tuning, and pipeline sizing.

## Monitoring

Flow and eBPF map metrics are in [Internal Metrics](../../internal-monitoring/internal-metrics.md): `mermin_flow_spans_active_total`, `mermin_flow_spans_created_total`, and `mermin_ebpf_map_size` / `mermin_ebpf_map_capacity` with `map="FLOW_STATS"`.

If the flow table or memory grows without bound, lower timeouts or `max_record_interval`, or reduce tracked flows with [flow filters](flow-span-filters.md).
If you need more headroom for legitimate load, increase the max capacity via `flow_capture.flow_stats_capacity` in [pipeline](flow-processing-pipeline.md).

## Next Steps

{% tabs %}
{% tab title="Configure More" %}
1. [**Filter Flows Before Export**](flow-span-filters.md): Reduce volume and focus on relevant traffic
2. [**Configure OTLP Export**](opentelemetry-otlp-exporter.md): Send flows to your backend
{% endtab %}

{% tab title="Examples" %}
1. [**Review Complete Configurations**](../examples.md): Production-ready examples
2. [**Tune the Pipeline**](flow-processing-pipeline.md): Optimize for high-throughput
{% endtab %}
{% endtabs %}

### Need Help?

- [**Troubleshoot Flow Issues**](../../troubleshooting/troubleshooting.md): Diagnose flow generation problems
- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask about timeout tuning
