# Introduction to Flow Traces

## Introduction

This document is a non-normative, user-friendly introduction to the Flow Trace semantic convention.
It is intended for those who want to understand the core concepts and motivation behind representing network flow data within OpenTelemetry without reading the full specification.

---

## What is a Flow Trace?

A **Flow Trace** is an OpenTelemetry trace that represents a network connection. It is composed of one or more **Flow Trace Spans**, where each span captures a measurement interval of the network conversation.

Unlike traditional OpenTelemetry traces that focus on application-level requests (HTTP calls, database queries, etc.),
a Flow Trace captures the network conversation itself—the bidirectional exchange of packets between two endpoints as observed by an independent monitoring point like an eBPF agent.

### Flow Trace vs. Flow Trace Span

- **Flow Trace Span**: A single OpenTelemetry span representing one flow record—a snapshot of the network conversation during a specific observation window.
When a flow is active, the agent exports periodic spans (e.g., every 60 seconds) with delta metrics for that interval.

- **Flow Trace**: The complete collection of related Flow Trace Spans that together represent the full lifecycle of a network connection—from the first packet to the last.

Think of it like a long-running database connection: individual spans might represent periodic health checks or query batches, but the trace as a whole represents the connection's lifetime.

---

## Why Introduce Flow Traces?

### The Observability Gap

The modern observability stack—Metrics, Events, Logs, and Traces (MELT)—excels at application-level visibility. APM traces show you request latency, error rates, and service dependencies.'
Network monitoring gives you bandwidth utilization and interface statistics.

But there's a gap between these two worlds:

- When a trace shows a slow network span, you have no way to correlate that with actual network flow data.
- When network teams see congestion, they can't map it back to specific services, pods, or applications.
- Traditional flow protocols (NetFlow, IPFIX) don't integrate with modern observability platforms.

**Flow Traces bridge this gap** by bringing connection-level network data into the OpenTelemetry ecosystem.

### Why Traces?

Representing network flows as OpenTelemetry traces—rather than logs, events, or metrics—is a deliberate choice that unlocks capabilities the other signal types cannot provide.

#### Traces Preserve Temporal Context

Unlike logs or flat events, traces have explicit start and end times that represent real duration. This temporal aspect is critical for network analysis:

- **Connection lifecycle visibility**: See exactly when a connection started, how long it lasted, and when it ended.
- **Smooth, continuous export**: Flow Trace Spans are exported based on timeouts (active/inactive), spreading data evenly rather than dumping all tracked flows in bursts.

Treating flows as logs or events loses this timing precision—you get timestamps, but not duration or the natural parent-child relationships traces provide.

#### Traces Are Richer Than Metrics

Metrics are great for dashboards and alerting, but they aggregate away the details netops teams need for investigation. A metric telling you "these two IPs exchanged X bytes over some period" answers one question: *are they talking?*

Flow Traces preserve connection-level detail that metrics cannot:

- **TCP flags and retransmits**: Correlate network behavior (retransmissions, RST flags) with application symptoms.
- **Bidirectional statistics**: See bytes/packets in both directions within a single record.
- **Per-connection timing**: Analyze handshake latency, round-trip time, and jitter for individual flows.
- **Full five-tuple context**: Every flow is tied to specific source/destination addresses and ports.

This is the kind of data network engineers are used to from traditional flow tools—but now it's available in your observability platform alongside your application traces.

#### Native OTel Ecosystem Integration

By using OTLP traces as the export format, Flow Traces slot directly into the OpenTelemetry ecosystem:

- **Standard trace pipelines**: Works with Jaeger, Grafana Tempo, Elastic APM, and any OTLP-compatible backend.
- **No translation layer**: No need for specialized NetFlow/IPFIX collectors or format converters.
- **Unified tooling**: Query, visualize, and alert on network flows using the same tools you use for application traces.

### Why Not Just Use Existing Conventions?

Existing OpenTelemetry network conventions are designed from the perspective of an instrumented application—capturing a client's outbound request or a server's inbound response. They model a single side of a single request.

Network flow observability is fundamentally different:

1. **Third-Party Observation**: The observer (an eBPF agent or network device) is independent of both endpoints. It sees the complete, bidirectional conversation without being a participant.

2. **Bidirectional by Nature**: A network flow inherently includes both directions—packets from source to destination *and* packets from destination back to source. Both must be captured together.

3. **Continuous Measurement**: Unlike request/response traces that have clear start and end points, network connections can persist for hours or days. Flow Traces handle this through periodic span exports with delta metrics.

This convention fills that gap by providing a standard way to represent rich, third-party network observations.

### The "Sweet Spot": Why Flow Data?

Observability involves trade-offs between granularity and overhead. Flow data occupies an ideal position:

- **Not Raw Packet Capture**: Full PCAP is expensive to store and query, capturing every byte of every packet. Flow Traces aggregate packets into connection-level summaries.

- **Not Just Counters**: Metrics tell you bandwidth usage but lose connection context—timing, retransmissions, TCP flags, and directionality are all lost in aggregation.

Flow data provides **granular, connection-level detail that's lightweight enough to run always-on in production**.

---

## Goals of This Convention

- **Standardize Network Flow Data**: Provide a single, consistent model for network flows within the OpenTelemetry ecosystem.

- **Enable Correlation**: Create a clear path for correlating high-level application traces with the underlying network conversations that support them.

- **Provide Full Context**: Capture not just the five-tuple, but also bidirectional metrics, performance data (latency/jitter), tunnel information, and rich Kubernetes metadata.

- **Backend Flexibility**: Use standard OTLP export so Flow Traces work with any OpenTelemetry-compatible observability platform—no specialized NetFlow collectors required.

---

## Core Concepts

### Flow Record as a Span

The fundamental mapping is straightforward: one flow record becomes one span.

- The **span's start and end times** represent the observation window of the flow record.
- The **span's attributes** contain all the details of the flow—endpoints, protocol, metrics, and metadata.
- The **span kind** (`CLIENT`, `SERVER`, or `INTERNAL`) indicates the observer's inferred direction of the connection.

### Bidirectional Metrics

Network conversations are two-way. To represent this, we capture metrics for both directions of the flow within a single span:

- `flow.bytes.delta` / `flow.packets.delta`: Traffic from source to destination.
- `flow.reverse.bytes.delta` / `flow.reverse.packets.delta`: Traffic from destination back to source.

This bidirectional model eliminates the need to correlate separate spans for each direction.

### Attribute Namespaces

Attributes are organized into logical groups to keep the convention clean and queryable:

| Namespace                    | Purpose                                                                                       |
|------------------------------|-----------------------------------------------------------------------------------------------|
| `flow.*`                     | The conversation itself—metrics, state, and metadata that can change over the flow's lifetime |
| `network.*`                  | Protocol-specific details that remain static for the flow (IP version, transport protocol)    |
| `source.*` / `destination.*` | Information about the two endpoints, including addresses, ports, and Kubernetes metadata      |
| `tunnel.*`                   | Encapsulation details when traffic is tunneled (VXLAN, Geneve, WireGuard, etc.)               |

### Kubernetes Enrichment

When running in Kubernetes, Flow Traces can be decorated with rich metadata:

- Pod, Namespace, Node names and UIDs
- Owning workloads (Deployments, StatefulSets, DaemonSets, Jobs)
- Services that select the endpoints
- Labels and annotations

This transforms raw IP addresses into meaningful service identities: instead of `10.42.0.5 → 10.42.0.8`, you see `frontend-service → redis-cache`.

---

## Example

Here is what a simple Flow Trace Span might look like in OTLP JSON format. It represents a TCP flow between two Kubernetes pods:

```json
{
  "name": "flow_ipv4_tcp",
  "kind": "SPAN_KIND_CLIENT",
  "startTimeUnixNano": "1727149620000000000",
  "endTimeUnixNano": "1727149680000000000",
  "attributes": [
    { "key": "flow.community_id", "value": { "stringValue": "1:LQU9qZlK+B+2dM2I2n1kI/M5a/g=" } },
    { "key": "flow.direction", "value": { "stringValue": "forward" } },
    { "key": "flow.bytes.delta", "value": { "intValue": "1024" } },
    { "key": "flow.reverse.bytes.delta", "value": { "intValue": "32768" } },
    { "key": "flow.packets.delta", "value": { "intValue": "10" } },
    { "key": "flow.reverse.packets.delta", "value": { "intValue": "85" } },
    { "key": "source.address", "value": { "stringValue": "10.1.1.5" } },
    { "key": "source.port", "value": { "intValue": "54211" } },
    { "key": "source.k8s.pod.name", "value": { "stringValue": "frontend-abcde" } },
    { "key": "source.k8s.namespace.name", "value": { "stringValue": "production" } },
    { "key": "destination.address", "value": { "stringValue": "10.1.2.10" } },
    { "key": "destination.port", "value": { "intValue": "80" } },
    { "key": "destination.k8s.pod.name", "value": { "stringValue": "backend-xyz" } },
    { "key": "network.transport", "value": { "stringValue": "tcp" } },
    { "key": "network.type", "value": { "stringValue": "ipv4" } }
  ]
}
```

Key observations:

- The span represents a 60-second observation window (start to end time).
- Bidirectional metrics show this is primarily a download: 1KB sent, 32KB received.
- Kubernetes metadata identifies the pods by name, not just IP address.
- The `SPAN_KIND_CLIENT` indicates the source initiated the connection (ephemeral port → service port).

---

## Learn More

For the complete specification including all attributes, requirement levels, and detailed semantics, see the [Semantic Conventions](semantic-conventions.md).
