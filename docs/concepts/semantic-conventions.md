# Flow Trace Semantic Conventions

This document proposes semantic conventions for representing network flow data as traces. The existing network conventions are primarily designed for unidirectional, client/server interactions within an instrumented application.
This proposal addresses the need to represent a network flow as a complete, bidirectional conversation, typically observed by a third party (like a network device or eBPF agent).

The core concept of this proposal is to represent each network flow record as a single **Span**. This model elevates traces from purely application-level signals to comprehensive flow spans that capture detailed data about network traffic,
creating a new standard for network observability within the OpenTelemetry ecosystem.

***

## Core Concepts

Each network flow record is represented as a single OpenTelemetry **Span**. This "flow span" has the following key characteristics:

- **Span Name**: To clearly distinguish flow spans from application spans, the name SHOULD follow the format `flow_<network.type>_<network.transport>`. For example, a typical TCP flow over IPv4 would be named `flow_ipv4_tcp`.
- **Span Kind**: The Span Kind MUST be `CLIENT`, `SERVER`, or `INTERNAL`. Using `CLIENT` or `SERVER` provides crucial directional context that the generic `INTERNAL` kind lacks,
   eliminating the need for separate attributes like `flow.initiator: source/destination` or `flow.biflow_direction: initiator/reverseInitiator`.
  - `CLIENT`: Represents the perspective of the connection initiator. An agent infers this when observing an outbound connection that originates from an ephemeral (non-listening) port or through protocol-specific logic.
    - **Example (TCP)**: A host sends a packet from an ephemeral source port (e.g., 54211) to a destination service port (e.g., 443).
    - **Example (ICMP)**: A host sends an ICMP "Echo Request" packet.
  - `SERVER`: Represents the perspective of the connection receiver. An agent infers this when observing an inbound connection directed to a port that a local process is actively listening on.
    - **Example (TCP)**: A host sends a packet from a source port that is also a listening port (e.g., 443) to an ephemeral destination port (e.g., 54211).
    - **Example (ICMP)**: A host sends an ICMP "Echo Reply" packet.
  - `INTERNAL`: Used as a fallback when the client/server relationship cannot be determined.

### Flow Direction

While Span Kind provides directional context for traces, metrics do not carry Span Kind. To enable consistent direction signaling across all OpenTelemetry signals (traces, metrics, and logs), this convention defines the `flow.direction` attribute.

The values mirror [IPFIX biflow](https://datatracker.ietf.org/doc/html/rfc5103) concepts:

| Value     | Description                                                                                                                 |
|-----------|-----------------------------------------------------------------------------------------------------------------------------|
| `forward` | The flow record describes traffic in the forward direction — from the connection initiator to the responder (client → server) |
| `reverse` | The flow record describes traffic in the reverse direction — from the responder back to the initiator (server → client)       |
| `unknown` | The direction could not be reliably determined                                                                              |

The `flow.direction` attribute MUST be consistent with the Span Kind when both are present:

| Span Kind  | `flow.direction` |
| ---------- | ---------------- |
| `CLIENT`   | `forward`        |
| `SERVER`   | `reverse`        |
| `INTERNAL` | `unknown`        |

**Why both Span Kind and `flow.direction`?**

Span Kind is the idiomatic way to express direction in OpenTelemetry traces and enables proper trace visualization in backends. However, when the same flow data is exported as metrics (e.g., for dashboards or alerting), Span Kind is not available.
The `flow.direction` attribute ensures that direction information is preserved regardless of signal type, enabling:

- Consistent queries across traces and metrics (e.g., "show all forward flows to this service")
- Metric-based dashboards that distinguish inbound vs. outbound traffic
- Correlation between flow traces and flow metrics using the same direction semantics

### Attribute Namespaces

To ensure clarity, this convention uses and defines specific attribute namespaces:

- **`flow.*`**: Describes the network conversation itself, including metrics and metadata that change over the lifetime of the flow (e.g., flow.bytes.total, flow.end\_reason).
- **`source.*` / `destination.*`**: Standard OTel namespaces that describe the two endpoints of the flow, including L3/L4 addresses and enriched metadata like Kubernetes pod names.
- **`network.*`**: The existing OTel namespace for protocol-specific attributes that are static for the duration of the flow (e.g., network.transport, network.type).
- **`tunnel.*`**: Describes tunneling protocols and encapsulation metadata (e.g., tunnel.type, tunnel.id). This is always the outer-most tunnel or encapsulation.
- **`process.*` / `container.*`**: Existing OTel namespaces used to identify the host process or container associated with the flow's socket.

The `flow.*` namespace is critical for creating a clear semantic distinction. It separates attributes of a flow — a dynamic conversation between two endpoints over time — from attributes of a network entity, like a physical interface,
whose properties are generally static. Overloading the existing network.\* namespace with dynamic flow concepts would create ambiguity.

### Why `source.k8s.*` Instead of `k8s.source.*`?

This convention uses `source.k8s.*` / `destination.k8s.*` (e.g., `source.k8s.pod.name`) rather than `k8s.source.*` / `k8s.destination.*`. This is a deliberate design choice driven by the nature of network flow data:

1. **The entity being described is the flow endpoint, not Kubernetes itself.** In flow telemetry, the primary entity is the connection between two endpoints. Each endpoint has many attributes: an IP address, a port,
and potentially Kubernetes metadata (pod name, namespace, etc.). Grouping all attributes of an endpoint under its directional prefix (`source.*` or `destination.*`) keeps related data together semantically.
The question "what do I know about the source?" is answered by querying `source.*`, yielding address, port, and all k8s enrichment in one logical group.
2. **Symmetry of bidirectional flows.** Unlike client/server metrics where telemetry is recorded from a single perspective, network flow observability (especially eBPF-based) captures both directions of a conversation symmetrically.
There is no privileged "recording side." The `source`/`destination` prefixes establish a consistent frame of reference for the entire flow record, and all enrichment attributes naturally belong under that frame.
3. **Consistency with networking industry conventions.** Traditional flow protocols (NetFlow, IPFIX, sFlow) and eBPF-based tools universally structure directional metadata with the direction first.
   Using `source.k8s.*` aligns with these patterns, making the schema intuitive for network engineers.
4. **Query ergonomics and grouping.** Placing the directional prefix first enables efficient queries like `source.k8s.*` to retrieve all Kubernetes context for one side of the flow. If the hierarchy were inverted (`k8s.source.*`),
querying "all source endpoint attributes" would require combining `source.address`, `source.port`, and `k8s.source.*` — three separate prefix patterns instead of one.
5. **Avoiding OTel resource attribute ambiguity.** Standard OTel `k8s.*` attributes (e.g., `k8s.pod.name`) describe the resource where telemetry originates — typically the observing agent's own pod. For flow data,
we need to describe _two_ remote endpoints, neither of which is necessarily the agent itself. Using `source.k8s.*` / `destination.k8s.*` clearly distinguishes flow endpoint metadata from resource-level attributes,
preventing confusion about which entity is being described.

This pattern intentionally diverges from the OTel `client.*`/`server.*` [guidance](https://opentelemetry.io/docs/specs/semconv/general/naming/#client-and-server-metrics), which assumes telemetry recorded from a single side's perspective.
For symmetric, connection-centric observability, direction-first prefixing provides clearer semantics.

A simple litmus test can help:

* If an attribute's value can change during the lifetime of a flow (like a byte count), it belongs in the `flow.\*` namespace (e.g., `flow.bytes.total`).
* If an attribute's value is static for the duration of the flow (like the transport protocol), it belongs in the `network.\*` namespace (e.g., network.transport).

This separation prevents ambiguity. For instance, an attribute like `network.byte_count` could be misinterpreted as the total bytes for an entire network interface,
whereas `flow.bytes.total` clearly refers to the byte count for a specific five-tuple flow. This makes the resulting telemetry data more accurate and easier to query.

***

{% include "../.gitbook/includes/attributes.md" %}

***

## Example Flow Trace Span (OTLP JSON)

{% include "../.gitbook/includes/example-flow-trace.md" %}

***

## Next Steps

{% tabs %}
{% tab title="Learn More" %}
1. [**Learn About Flow Traces**](introduction-to-flow-traces.md): High-level overview of what Flow Traces represent
2. [**Understand the Architecture**](agent-architecture.md): How Mermin generates Flow Traces
{% endtab %}

{% tab title="Get Started" %}
1. [**Connect to Your Backend**](../getting-started/backend-integrations.md): Send Flow Traces to Grafana, Elastic, or Jaeger
2. [**Deploy Mermin**](../getting-started/quickstart-guide.md): Capture your first Flow Traces
{% endtab %}
{% endtabs %}

### Using Flow Traces in Queries

With these semantic conventions, build powerful queries in your observability backend:

- Filter by Kubernetes workload: `k8s.deployment.name = "frontend"`
- Find high-bandwidth flows: `flow.bytes.total > 1000000`
- Identify connection issues: `flow.tcp.flags.rst = true`

### Need Help?

- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask questions about Flow Trace semantics
