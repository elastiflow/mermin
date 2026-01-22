# Semantic Conventions

> **Quick Reference**: For a concise table of commonly used fields, see the [Field Reference](../reference/field-reference.md).

This document proposes semantic conventions for representing network flow data as traces. The existing network conventions are primarily designed for unidirectional, client/server interactions within an instrumented application. This proposal addresses the need to represent a network flow as a complete, bidirectional conversation, typically observed by a third party (like a network device or eBPF agent).

The core concept of this proposal is to represent each network flow record as a single **Span**. This model elevates traces from purely application-level signals to comprehensive flow spans that capture detailed data about network traffic, creating a new standard for network observability within the OpenTelemetry ecosystem.

## Table of Contents

* [1. Core Concepts](semantic-conventions.md#1-core-concepts)
  * [Flow Direction](semantic-conventions.md#flow-direction)
  * [Attribute Namespaces](semantic-conventions.md#attribute-namespaces)
  * [Why `source.k8s.*` Instead of `k8s.source.*`?](semantic-conventions.md#why-sourcek8s-instead-of-k8ssource)
* [2. Proposed Attributes](semantic-conventions.md#2-proposed-attributes)
  * [General Flow Attributes](semantic-conventions.md#general-flow-attributes)
  * [L2-L4 Attributes](semantic-conventions.md#l2-l4-attributes)
  * [Flow Metrics](semantic-conventions.md#flow-metrics)
  * [Performance Metrics](semantic-conventions.md#performance-metrics)
  * [Tunnel & IP-in-IP & IPSec Attributes](semantic-conventions.md#tunnel--ip-in-ip--ipsec-attributes)
  * [Kubernetes Attributes](semantic-conventions.md#kubernetes-attributes)
  * [Network Policy Attributes](semantic-conventions.md#network-policy-attributes)
  * [Process & Container Attributes](semantic-conventions.md#process--container-attributes)
* [3. Example Span (OTLP JSON)](semantic-conventions.md#3-example-span-otlp-json)

***

## 1. Core Concepts

Each network flow record is represented as a single OpenTelemetry **Span**. This "flow span" has the following key characteristics:

* **Span Name**: To clearly distinguish flow spans from application spans, the name SHOULD follow the format `flow_<network.type>_<network.transport>`. For example, a typical TCP flow over IPv4 would be named `flow_ipv4_tcp`.
* **Span Kind**: The Span Kind MUST be `CLIENT`, `SERVER`, or `INTERNAL`. Using `CLIENT` or `SERVER` provides crucial directional context that the generic `INTERNAL` kind lacks, eliminating the need for separate attributes like `flow.initiator: source/destination` or `flow.biflow_direction: initiator/reverseInitiator`.
  * `CLIENT`: Represents the perspective of the connection initiator. An agent infers this when observing an outbound connection that originates from an ephemeral (non-listening) port or through protocol-specific logic.
    * **Example (TCP)**: A host sends a packet from an ephemeral source port (e.g., 54211) to a destination service port (e.g., 443).
    * **Example (ICMP)**: A host sends an ICMP "Echo Request" packet.
  * `SERVER`: Represents the perspective of the connection receiver. An agent infers this when observing an inbound connection directed to a port that a local process is actively listening on.
    * **Example (TCP)**: A host sends a packet from a source port that is also a listening port (e.g., 443) to an ephemeral destination port (e.g., 54211).
    * **Example (ICMP)**: A host sends an ICMP "Echo Reply" packet.
  * `INTERNAL`: Used as a fallback when the client/server relationship cannot be determined.

### Flow Direction

While Span Kind provides directional context for traces, metrics do not carry Span Kind. To enable consistent direction signaling across all OpenTelemetry signals (traces, metrics, and logs), this convention defines the `flow.direction` attribute.

The values mirror [IPFIX biflow](https://datatracker.ietf.org/doc/html/rfc5103) concepts:

| Value     | Description                                                                                                                 |
| --------- | --------------------------------------------------------------------------------------------------------------------------- |
| `forward` | The flow record describes traffic in the forward direction—from the connection initiator to the responder (client → server) |
| `reverse` | The flow record describes traffic in the reverse direction—from the responder back to the initiator (server → client)       |
| `unknown` | The direction could not be reliably determined                                                                              |

The `flow.direction` attribute MUST be consistent with the Span Kind when both are present:

| Span Kind  | `flow.direction` |
| ---------- | ---------------- |
| `CLIENT`   | `forward`        |
| `SERVER`   | `reverse`        |
| `INTERNAL` | `unknown`        |

**Why both Span Kind and `flow.direction`?**

Span Kind is the idiomatic way to express direction in OpenTelemetry traces and enables proper trace visualization in backends. However, when the same flow data is exported as metrics (e.g., for dashboards or alerting), Span Kind is not available. The `flow.direction` attribute ensures that direction information is preserved regardless of signal type, enabling:

* Consistent queries across traces and metrics (e.g., "show all forward flows to this service")
* Metric-based dashboards that distinguish inbound vs. outbound traffic
* Correlation between flow traces and flow metrics using the same direction semantics

### Attribute Namespaces

To ensure clarity, this convention uses and defines specific attribute namespaces:

* **`flow.*`**: Describes the network conversation itself, including metrics and metadata that change over the lifetime of the flow (e.g., flow.bytes.total, flow.end\_reason).
* **`source.*` / `destination.*`**: Standard OTel namespaces that describe the two endpoints of the flow, including L3/L4 addresses and enriched metadata like Kubernetes pod names.
* **`network.*`**: The existing OTel namespace for protocol-specific attributes that are static for the duration of the flow (e.g., network.transport, network.type).
* **`tunnel.*`**: Describes tunneling protocols and encapsulation metadata (e.g., tunnel.type, tunnel.id). This is always the outer-most tunnel or encapsulation.
* **`process.*` / `container.*`**: Existing OTel namespaces used to identify the host process or container associated with the flow's socket.

The `flow.*` namespace is critical for creating a clear semantic distinction. It separates attributes of a flow—a dynamic conversation between two endpoints over time—from attributes of a network entity, like a physical interface, whose properties are generally static. Overloading the existing network.\* namespace with dynamic flow concepts would create ambiguity.

### Why `source.k8s.*` Instead of `k8s.source.*`?

This convention uses `source.k8s.*` / `destination.k8s.*` (e.g., `source.k8s.pod.name`) rather than `k8s.source.*` / `k8s.destination.*`. This is a deliberate design choice driven by the nature of network flow data:

1. **The entity being described is the flow endpoint, not Kubernetes itself.** In flow telemetry, the primary entity is the connection between two endpoints. Each endpoint has many attributes: an IP address, a port, and potentially Kubernetes metadata (pod name, namespace, etc.). Grouping all attributes of an endpoint under its directional prefix (`source.*` or `destination.*`) keeps related data together semantically. The question "what do I know about the source?" is answered by querying `source.*`, yielding address, port, and all k8s enrichment in one logical group.
2. **Symmetry of bidirectional flows.** Unlike client/server metrics where telemetry is recorded from a single perspective, network flow observability (especially eBPF-based) captures both directions of a conversation symmetrically. There is no privileged "recording side." The `source`/`destination` prefixes establish a consistent frame of reference for the entire flow record, and all enrichment attributes naturally belong under that frame.
3. **Consistency with networking industry conventions.** Traditional flow protocols (NetFlow, IPFIX, sFlow) and eBPF-based tools universally structure directional metadata with the direction first: `src_addr`, `dst_port`, `src_as`, `dst_geo_country`, etc. Using `source.k8s.*` aligns with these established patterns, making the schema intuitive for network engineers and reducing cognitive overhead when correlating with other flow data sources.
4. **Query ergonomics and grouping.** Placing the directional prefix first enables efficient queries like `source.k8s.*` to retrieve all Kubernetes context for one side of the flow. If the hierarchy were inverted (`k8s.source.*`), querying "all source endpoint attributes" would require combining `source.address`, `source.port`, and `k8s.source.*`—three separate prefix patterns instead of one.
5. **Avoiding OTel resource attribute ambiguity.** Standard OTel `k8s.*` attributes (e.g., `k8s.pod.name`) describe the resource where telemetry originates—typically the observing agent's own pod. For flow data, we need to describe _two_ remote endpoints, neither of which is necessarily the agent itself. Using `source.k8s.*` / `destination.k8s.*` clearly distinguishes flow endpoint metadata from resource-level attributes, preventing confusion about which entity is being described.

This pattern intentionally diverges from the OTel `client.*`/`server.*` [guidance](https://opentelemetry.io/docs/specs/semconv/general/naming/#client-and-server-metrics), which assumes telemetry recorded from a single side's perspective. For symmetric, connection-centric observability, direction-first prefixing provides clearer semantics.

A simple litmus test can help:

* If an attribute's value can change during the lifetime of a flow (like a byte count), it belongs in the flow.\* namespace (e.g., flow.bytes.total).
* If an attribute's value is static for the duration of the flow (like the transport protocol), it belongs in the network.\* namespace (e.g., network.transport).

This separation prevents ambiguity. For instance, an attribute like network.byte\_count could be misinterpreted as the total bytes for an entire network interface, whereas flow.bytes.total clearly refers to the byte count for a specific five-tuple flow. This makes the resulting telemetry data more accurate and easier to query.

***

## 2. Proposed Attributes

The following tables detail the proposed attributes for the flow span.

### Requirement Level Legend

The following symbols are used in the "Required" column to indicate [OpenTelemetry attribute requirement levels](https://opentelemetry.io/docs/specs/semconv/general/attribute-requirement-level/):

| Symbol | Requirement Level      | Description                                                      |
|--------|------------------------|------------------------------------------------------------------|
| ✓      | Required               | All instrumentations MUST populate the attribute                 |
| ?      | Conditionally Required | MUST populate when the specified condition is satisfied          |
| \~     | Recommended            | SHOULD add by default if readily available and efficient         |
| ○      | Opt-In                 | SHOULD populate only if user configures instrumentation to do so |

### General Flow Attributes

> Note on Timestamps: The span's standard `start_time_unix_nano` and `end_time_unix_nano` fields are used to mark the beginning and end of the flow span's observation window. These are analogous to the `flowStart*` and `flowEnd*` fields in IPFIX records and are not duplicated as attributes.

| Proposed Field Name     | Data Type | Description                                                                               | Notes / Decisions                                                                                                                                        | Std OTel | Required   |
|-------------------------|-----------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|----------|------------|
| `flow.community_id`     | `string`  | The Community ID hash of the flow's five-tuple.                                           | A common way to identify a network flow across different monitoring points.                                                                              |          | ✓          |
| `flow.direction`        | `string`  | The inferred direction of the flow from the observer's perspective.                       | One of: `forward`, `reverse`, or `unknown`. Mirrors IPFIX biflow concepts. See [Flow Direction](semantic-conventions.md#flow-direction) for details.     |          | ✓          |
| `flow.connection.state` | `string`  | The state of the connection (e.g., TCP state) at the time the flow was generated.         | For TCP, this would be one of the standard states like `established`, `time_wait`, etc. Similar to network.connection.state but from a flow perspective. |          | ? TCP only |
| `flow.end_reason`       | `string`  | The reason the flow record was exported (e.g., `active_timeout`, `end_of_flow_detected`). | Stored as a human-readable text enum based on [ipfix end reason](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason).              |          | ✓          |

### L2-L4 Attributes

| Proposed Field Name           | Data Type  | Description                                                                             | Notes / Decisions                                                      | Std OTel | Required          |
|-------------------------------|------------|-----------------------------------------------------------------------------------------|------------------------------------------------------------------------|----------|-------------------|
| `source.address`              | `string`   | Source IP address.                                                                      |                                                                        | ✓        | ✓                 |
| `source.port`                 | `long`     | Source port number.                                                                     |                                                                        | ✓        | ✓                 |
| `destination.address`         | `string`   | Destination IP address.                                                                 |                                                                        | ✓        | ✓                 |
| `destination.port`            | `long`     | Destination port number.                                                                |                                                                        | ✓        | ✓                 |
| `client.address`              | `string`   | Client IP address or hostname.                                                          | Hostname if resolution enabled, otherwise IP. Complements source/dest. | ✓        | ? direction known |
| `client.port`                 | `long`     | Client port number.                                                                     | Complements source/dest port.                                          | ✓        | ? direction known |
| `server.address`              | `string`   | Server IP address or hostname.                                                          | Hostname if resolution enabled, otherwise IP. Complements source/dest. | ✓        | ? direction known |
| `server.port`                 | `long`     | Server port number.                                                                     | Complements source/dest port.                                          | ✓        | ? direction known |
| `network.transport`           | `string`   | The transport protocol of the flow (e.g., `tcp`, `udp`).                                | Lowercase IANA protocol name string.                                   | ✓        | ✓                 |
| `network.type`                | `string`   | The network protocol type (EtherType) of the flow (e.g., `ipv4`, `ipv6`).               |                                                                        | ✓        | ✓                 |
| `network.interface.index`     | `long`     | The index value of the network interface where the flow was observed.                   |                                                                        | ✓        | \~                |
| `network.interface.name`      | `string`   | The name of the network interface where the flow was observed.                          |                                                                        | ✓        | \~                |
| `network.interface.mac`       | `string`   | Source MAC address.                                                                     | Lowercased, 6 hexadecimal values separated by colons.                  |          | \~                |
| `flow.ip.dscp.id`             | `long`     | Differentiated Services Code Point (DSCP) value from the IP header (forward direction). | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.ip.dscp.name`           | `string`   | Lowercase DSCP standard name (forward direction).                                       | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.ip.ecn.id`              | `long`     | Explicit Congestion Notification (ECN) value from the IP header (forward direction).    | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.ip.ecn.name`            | `string`   | Lowercase ECN standard name (forward direction).                                        | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.ip.ttl`                 | `long`     | Time to Live (IPv4) or Hop Limit (IPv6) value (forward direction).                      | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.ip.flow_label`          | `long`     | Flow Label from the IPv6 header (forward direction).                                    | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.ip.dscp.id`     | `long`     | Differentiated Services Code Point (DSCP) value from the IP header (reverse direction). | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.ip.dscp.name`   | `string`   | Lowercase DSCP standard name (reverse direction).                                       | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.ip.ecn.id`      | `long`     | Explicit Congestion Notification (ECN) value from the IP header (reverse direction).    | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.ip.ecn.name`    | `string`   | Lowercase ECN standard name (reverse direction).                                        | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.ip.ttl`         | `long`     | Time to Live (IPv4) or Hop Limit (IPv6) value (reverse direction).                      | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.ip.flow_label`  | `long`     | Flow Label from the IPv6 header (reverse direction).                                    | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.icmp.type.id`           | `long`     | ICMP message type id.                                                                   | Based on IANA standard names.                                          |          | \~                |
| `flow.icmp.type.name`         | `string`   | Lowercase ICMP message type name.                                                       | Based on IANA standard names.                                          |          | \~                |
| `flow.icmp.code.id`           | `long`     | ICMP message code id.                                                                   | Based on IANA standard names.                                          |          | \~                |
| `flow.icmp.code.name`         | `string`   | ICMP message code name.                                                                 | Based on IANA standard names.                                          |          | \~                |
| `flow.reverse.icmp.type.id`   | `long`     | ICMP message type id (reverse direction).                                               | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.icmp.type.name` | `string`   | Lowercase ICMP message type name (reverse direction).                                   | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.icmp.code.id`   | `long`     | ICMP message code id (reverse direction).                                               | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.reverse.icmp.code.name` | `string`   | ICMP message code name (reverse direction).                                             | First packet per direction per export interval. Reset between exports. |          | \~                |
| `flow.tcp.flags.bits`         | `long`     | The integer representation of all TCP flags seen during the observation window.         | Accumulated across entire flow lifetime (never reset).                 |          | \~                |
| `flow.tcp.flags.tags`         | `string[]` | An array of TCP flag names (e.g., `["SYN", "ACK"]`) for all flags set.                  | Accumulated across entire flow lifetime (never reset).                 |          | \~                |
| `flow.reverse.tcp.flags.bits` | `long`     | The integer representation of all TCP flags seen in reverse direction.                  | Accumulated across entire flow lifetime (never reset).                 |          | \~                |
| `flow.reverse.tcp.flags.tags` | `string[]` | An array of TCP flag names for reverse direction (e.g., `["SYN", "ACK"]`).              | Accumulated across entire flow lifetime (never reset).                 |          | \~                |

### Flow Metrics

| Proposed Field Name          | Data Type | Description                                                               | Notes / Decisions                                        | Std OTel | Required |
|------------------------------|-----------|---------------------------------------------------------------------------|----------------------------------------------------------|----------|----------|
| `flow.bytes.delta`           | `long`    | Number of bytes observed in the last measurement interval for the flow.   |                                                          |          | ✓        |
| `flow.bytes.total`           | `long`    | Total number of bytes observed for this flow since its start.             | The term `bytes` is preferred over `octets` for clarity. |          | \~       |
| `flow.packets.delta`         | `long`    | Number of packets observed in the last measurement interval for the flow. |                                                          |          | ✓        |
| `flow.packets.total`         | `long`    | Total number of packets observed for this flow since its start.           |                                                          |          | \~       |
| `flow.reverse.bytes.delta`   | `long`    | Delta bytes in the reverse direction of the flow.                         |                                                          |          | ✓        |
| `flow.reverse.bytes.total`   | `long`    | Total bytes in the reverse direction of the flow since its start.         |                                                          |          | \~       |
| `flow.reverse.packets.delta` | `long`    | Delta packets in the reverse direction of the flow.                       |                                                          |          | ✓        |
| `flow.reverse.packets.total` | `long`    | Total packets in the reverse direction of the flow since its start.       |                                                          |          | \~       |

### Performance Metrics

Time-based metrics calculated for the flow, stored in nanoseconds (`ns`).

| Proposed Field Name          | Data Type | Description                                                                                                                    | Notes / Decisions | Std OTel | Required |
|------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------|-------------------|----------|----------|
| `flow.tcp.handshake.latency` | `long`    | The latency of the first part of the TCP handshake (SYN to SYN/ACK), from the **client's perspective**. (Server network delay) | Unit: `ns`.       |          | \~       |
| `flow.tcp.svc.latency`       | `long`    | The application/service processing time, as measured on the **server side**.                                                   | Unit: `ns`.       |          | \~       |
| `flow.tcp.svc.jitter`        | `long`    | The jitter of the application/service processing time, as measured on the **server side**.                                     | Unit: `ns`.       |          | \~       |
| `flow.tcp.rndtrip.latency`   | `long`    | The full round-trip time (client to server + app to client), from the **client's perspective**.                                | Unit: `ns`.       |          | \~       |
| `flow.tcp.rndtrip.jitter`    | `long`    | The jitter of the full round-trip time, from the **client's perspective**.                                                     | Unit: `ns`.       |          | \~       |

### Tunnel & Ip-in-Ip & IPSec Attributes

| Proposed Field Name            | Data Type | Description                                                                 | Notes / Decisions                                        | Std OTel | Required           |
|--------------------------------|-----------|-----------------------------------------------------------------------------|----------------------------------------------------------|----------|--------------------|
| `flow.ipsec.ah.spi`            | `long`    | Security Parameters Index for AH headers.                                   | SPI from the outermost header (after a tunnel)           |          | ○                  |
| `flow.ipsec.esp.spi`           | `long`    | Security Parameters Index for ESP headers.                                  | SPI from the outermost header (after a tunnel)           |          | ○                  |
| `flow.ipsec.sender_index`      | `long`    | The sender index from a WireGuard header.                                   |                                                          |          | ○                  |
| `flow.ipsec.receiver_index`    | `long`    | The receiver index from a WireGuard header.                                 |                                                          |          | ○                  |
| `ipip.network.type`            | `string`  | The network protocol type (EtherType) of the flow (e.g., `ipv4`, `ipv6`).   |                                                          |          | ○                  |
| `ipip.network.transport`       | `string`  | The transport protocol of the encapsulated flow (e.g., `tcp`, `udp`).       |                                                          |          | ○                  |
| `ipip.source.address`          | `string`  | The source IP address of the tunnel's outer header.                         | Ip-in-Ip is always the outermost header.                 |          | ○                  |
| `ipip.destination.address`     | `string`  | The destination IP address of the tunnel's outer header.                    |                                                          |          | ○                  |
| `ipip.bytes.delta`             | `long`    | Number of outer header bytes observed in the last measurement interval.     |                                                          |          | ? IP-in-IP present |
| `ipip.bytes.total`             | `long`    | Total number of outer header bytes observed since flow start.               | The term `bytes` is preferred over `octets` for clarity. |          | \~                 |
| `ipip.reverse.bytes.delta`     | `long`    | Delta outer header bytes in the reverse direction.                          |                                                          |          | ? IP-in-IP present |
| `ipip.reverse.bytes.total`     | `long`    | Total outer header bytes in the reverse direction since flow start.         |                                                          |          | \~                 |
| `tunnel.type`                  | `string`  | The type of tunnel protocol (e.g., `vxlan`, `geneve`, `gre`).               | Tunnel is always the outermost header.                   |          | ○                  |
| `tunnel.network.interface.mac` | `string`  | Source MAC address of tunnel.                                               | Lowercased, 6 hexadecimal values separated by colons.    |          | \~                 |
| `tunnel.network.type`          | `string`  | The network protocol type (EtherType) of the flow (e.g., `ipv4`, `ipv6`).   |                                                          |          | ○                  |
| `tunnel.network.transport`     | `string`  | The transport protocol of the flow (e.g., `tcp`, `udp`).                    |                                                          |          | ○                  |
| `tunnel.source.address`        | `string`  | The source IP address of the tunnel's outer header.                         |                                                          |          | ○                  |
| `tunnel.source.port`           | `long`    | The source port of the tunnel's outer header.                               |                                                          |          | ○                  |
| `tunnel.destination.address`   | `string`  | The destination IP address of the tunnel's outer header.                    |                                                          |          | ○                  |
| `tunnel.destination.port`      | `long`    | The destination port of the tunnel's outer header.                          |                                                          |          | ○                  |
| `tunnel.id`                    | `string`  | The identifier for the tunnel (e.g., VNI for VXLAN/Geneve, Key ID for GRE). |                                                          |          | ○                  |
| `tunnel.ipsec.ah.spi`          | `long`    | Security Parameters Index for AH headers.                                   | SPI from the outermost header.                           |          | ○                  |
| `tunnel.ipsec.esp.spi`         | `long`    | Security Parameters Index for ESP headers.                                  | SPI from the outermost header.                           |          | ○                  |
| `tunnel.bytes.delta`           | `long`    | Number of tunnel overhead bytes observed in the last measurement interval.  |                                                          |          | ? tunnel present   |
| `tunnel.bytes.total`           | `long`    | Total number of tunnel overhead bytes observed since flow start.            | The term `bytes` is preferred over `octets` for clarity. |          | \~                 |
| `tunnel.reverse.bytes.delta`   | `long`    | Delta tunnel overhead bytes in the reverse direction.                       |                                                          |          | ? tunnel present   |
| `tunnel.reverse.bytes.total`   | `long`    | Total tunnel overhead bytes in the reverse direction since flow start.      |                                                          |          | \~                 |

### Kubernetes Attributes

> **Note:** These attributes use `source.k8s.*` / `destination.k8s.*` prefixes rather than standard OTel `k8s.*` attributes. See [Why `source.k8s.*` Instead of `k8s.source.*`?](semantic-conventions.md#why-sourcek8s-instead-of-k8ssource) for the rationale.

| Proposed Field Name                             | Data Type | Description                                                 | Notes / Decisions | Std OTel  | Required |
|-------------------------------------------------|-----------|-------------------------------------------------------------|-------------------|-----------|----------|
| `source.k8s.cluster.name`                       | `string`  | The name of the Kubernetes cluster for the source.          |                   | partially | \~       |
| `source.k8s.cluster.uid`                        | `string`  | The UID of the Kubernetes cluster for the source.           |                   | partially | ○        |
| `source.k8s.node.name`                          | `string`  | The name of the Kubernetes Node for the source.             |                   | partially | \~       |
| `source.k8s.node.uid`                           | `string`  | The UID of the Kubernetes Node for the source.              |                   | partially | ○        |
| `source.k8s.node.annotations.<key>`             | `string`  | Dynamic annotations from the source Node.                   | Flattened map.    | partially | ○        |
| `source.k8s.namespace.name`                     | `string`  | The name of the Kubernetes Namespace for the source.        |                   | partially | \~       |
| `source.k8s.pod.name`                           | `string`  | The name of the Kubernetes Pod for the source.              |                   | partially | \~       |
| `source.k8s.pod.uid`                            | `string`  | The UID of the Kubernetes Pod for the source.               |                   | partially | ○        |
| `source.k8s.pod.annotations.<key>`              | `string`  | Dynamic annotations from the source Pod.                    | Flattened map.    | partially | ○        |
| `source.k8s.container.name`                     | `string`  | The name of the Container from Pod specification.           |                   | partially | \~       |
| `source.k8s.deployment.name`                    | `string`  | The name of the Kubernetes Deployment for the source.       |                   | partially | \~       |
| `source.k8s.deployment.uid`                     | `string`  | The UID of the Kubernetes Deployment for the source.        |                   | partially | ○        |
| `source.k8s.deployment.annotations.<key>`       | `string`  | Dynamic annotations from the source Deployment.             | Flattened map.    | partially | ○        |
| `source.k8s.replicaset.name`                    | `string`  | The name of the Kubernetes ReplicaSet for the source.       |                   | partially | \~       |
| `source.k8s.replicaset.uid`                     | `string`  | The UID of the Kubernetes ReplicaSet for the source.        |                   | partially | ○        |
| `source.k8s.replicaset.annotations.<key>`       | `string`  | Dynamic annotations from the source ReplicaSet.             | Flattened map.    | partially | ○        |
| `source.k8s.statefulset.name`                   | `string`  | The name of the Kubernetes StatefulSet for the source.      |                   | partially | \~       |
| `source.k8s.statefulset.uid`                    | `string`  | The UID of the Kubernetes StatefulSet for the source.       |                   | partially | ○        |
| `source.k8s.statefulset.annotations.<key>`      | `string`  | Dynamic annotations from the source StatefulSet.            | Flattened map.    | partially | ○        |
| `source.k8s.daemonset.name`                     | `string`  | The name of the Kubernetes DaemonSet for the source.        |                   | partially | \~       |
| `source.k8s.daemonset.uid`                      | `string`  | The UID of the Kubernetes DaemonSet for the source.         |                   | partially | ○        |
| `source.k8s.daemonset.annotations.<key>`        | `string`  | Dynamic annotations from the source DaemonSet.              | Flattened map.    | partially | ○        |
| `source.k8s.job.name`                           | `string`  | The name of the Kubernetes Job for the source.              |                   | partially | \~       |
| `source.k8s.job.uid`                            | `string`  | The UID of the Kubernetes Job for the source.               |                   | partially | ○        |
| `source.k8s.job.annotations.<key>`              | `string`  | Dynamic annotations from the source Job.                    | Flattened map.    | partially | ○        |
| `source.k8s.cronjob.name`                       | `string`  | The name of the Kubernetes CronJob for the source.          |                   | partially | \~       |
| `source.k8s.cronjob.uid`                        | `string`  | The UID of the Kubernetes CronJob for the source.           |                   | partially | ○        |
| `source.k8s.cronjob.annotations.<key>`          | `string`  | Dynamic annotations from the source CronJob.                | Flattened map.    | partially | ○        |
| `source.k8s.service.name`                       | `string`  | The name of the Kubernetes Service for the source.          |                   | partially | \~       |
| `source.k8s.service.uid`                        | `string`  | The UID of the Kubernetes Service for the source.           |                   | partially | ○        |
| `source.k8s.service.annotations.<key>`          | `string`  | Dynamic annotations from the source Service.                | Flattened map.    | partially | ○        |
| `destination.k8s.cluster.name`                  | `string`  | The name of the Kubernetes cluster for the destination.     |                   | partially | \~       |
| `destination.k8s.cluster.uid`                   | `string`  | The UID of the Kubernetes cluster for the destination.      |                   | partially | ○        |
| `destination.k8s.node.name`                     | `string`  | The name of the Kubernetes Node for the destination.        |                   | partially | \~       |
| `destination.k8s.node.uid`                      | `string`  | The UID of the Kubernetes Node for the destination.         |                   | partially | ○        |
| `destination.k8s.node.annotations.<key>`        | `string`  | Dynamic annotations from the destination Node.              | Flattened map.    | partially | ○        |
| `destination.k8s.namespace.name`                | `string`  | The name of the Kubernetes Namespace for the destination.   |                   | partially | \~       |
| `destination.k8s.pod.name`                      | `string`  | The name of the Kubernetes Pod for the destination.         |                   | partially | \~       |
| `destination.k8s.pod.uid`                       | `string`  | The UID of the Kubernetes Pod for the destination.          |                   | partially | ○        |
| `destination.k8s.pod.annotations.<key>`         | `string`  | Dynamic annotations from the destination Pod.               | Flattened map.    | partially | ○        |
| `destination.k8s.container.name`                | `string`  | The name of the Container from Pod specification.           |                   | partially | \~       |
| `destination.k8s.deployment.name`               | `string`  | The name of the Kubernetes Deployment for the destination.  |                   | partially | \~       |
| `destination.k8s.deployment.uid`                | `string`  | The UID of the Kubernetes Deployment for the destination.   |                   | partially | ○        |
| `destination.k8s.deployment.annotations.<key>`  | `string`  | Dynamic annotations from the destination Deployment.        | Flattened map.    | partially | ○        |
| `destination.k8s.replicaset.name`               | `string`  | The name of the Kubernetes ReplicaSet for the destination.  |                   | partially | \~       |
| `destination.k8s.replicaset.uid`                | `string`  | The UID of the Kubernetes ReplicaSet for the destination.   |                   | partially | ○        |
| `destination.k8s.replicaset.annotations.<key>`  | `string`  | Dynamic annotations from the destination ReplicaSet.        | Flattened map.    | partially | ○        |
| `destination.k8s.statefulset.name`              | `string`  | The name of the Kubernetes StatefulSet for the destination. |                   | partially | \~       |
| `destination.k8s.statefulset.uid`               | `string`  | The UID of the Kubernetes StatefulSet for the destination.  |                   | partially | ○        |
| `destination.k8s.statefulset.annotations.<key>` | `string`  | Dynamic annotations from the destination StatefulSet.       | Flattened map.    | partially | ○        |
| `destination.k8s.daemonset.name`                | `string`  | The name of the Kubernetes DaemonSet for the destination.   |                   | partially | \~       |
| `destination.k8s.daemonset.uid`                 | `string`  | The UID of the Kubernetes DaemonSet for the destination.    |                   | partially | ○        |
| `destination.k8s.daemonset.annotations.<key>`   | `string`  | Dynamic annotations from the destination DaemonSet.         | Flattened map.    | partially | ○        |
| `destination.k8s.job.name`                      | `string`  | The name of the Kubernetes Job for the destination.         |                   | partially | \~       |
| `destination.k8s.job.uid`                       | `string`  | The UID of the Kubernetes Job for the destination.          |                   | partially | ○        |
| `destination.k8s.job.annotations.<key>`         | `string`  | Dynamic annotations from the destination Job.               | Flattened map.    | partially | ○        |
| `destination.k8s.cronjob.name`                  | `string`  | The name of the Kubernetes CronJob for the destination.     |                   | partially | \~       |
| `destination.k8s.cronjob.uid`                   | `string`  | The UID of the Kubernetes CronJob for the destination.      |                   | partially | ○        |
| `destination.k8s.cronjob.annotations.<key>`     | `string`  | Dynamic annotations from the destination CronJob.           | Flattened map.    | partially | ○        |
| `destination.k8s.service.name`                  | `string`  | The name of the Kubernetes Service for the destination.     |                   | partially | \~       |
| `destination.k8s.service.uid`                   | `string`  | The UID of the Kubernetes Service for the destination.      |                   | partially | ○        |
| `destination.k8s.service.annotations.<key>`     | `string`  | Dynamic annotations from the destination Service.           | Flattened map.    | partially | ○        |

### Network Policy Attributes

| Proposed Field Name      | Data Type  | Description                                               | Notes / Decisions                | Std OTel | Required |
|--------------------------|------------|-----------------------------------------------------------|----------------------------------|----------|----------|
| `network.policy.ingress` | `string[]` | A list of network policy names affecting ingress traffic. | This could be multiple policies. |          | ○        |
| `network.policy.egress`  | `string[]` | A list of network policy names affecting egress traffic.  | This could be multiple policies. |          | ○        |

### Process & Container Attributes

| Proposed Field Name                | Data Type | Description                                                               | Notes / Decisions                               | Std OTel | Required |
|------------------------------------|-----------|---------------------------------------------------------------------------|-------------------------------------------------|----------|----------|
| `process.executable.name`          | `string`  | The name of the binary associated with the socket for this flow.          | Provides application-level identification.      | ✓        | \~       |
| `process.pid`                      | `long`    | The PID of the process associated with the socket for this flow.          | Provides application-level identification.      | ✓        | \~       |
| `source.container.name`            | `string`  | The container runtime name for the source (e.g., from Docker/containerd). | Distinct from `source.k8s.container.name`.      | ✓        | \~       |
| `source.container.image.name`      | `string`  | The image name of the source container (e.g., `nginx:1.21`).              | From K8s Pod spec container image.              |          | \~       |
| `destination.container.name`       | `string`  | The container runtime name for the destination.                           | Distinct from `destination.k8s.container.name`. | ✓        | \~       |
| `destination.container.image.name` | `string`  | The image name of the destination container (e.g., `app:v1.0.0`).         | From K8s Pod spec container image.              |          | \~       |

***

## 3. Example Span (OTLP JSON)

Below is an example of what a resulting flow span might look like in OTLP JSON format.

```json
{
  "name": "flow_ipv4_tcp",
  "kind": "SPAN_KIND_CLIENT",
  "startTimeUnixNano": "1727149620000000000",
  "endTimeUnixNano": "1727149680000000000",
  "attributes": [
    { "key": "flow.community_id", "value": { "stringValue": "1:LQU9qZlK+B+2dM2I2n1kI/M5a/g=" } },
    { "key": "flow.direction", "value": { "stringValue": "forward" } },
    { "key": "flow.end_reason", "value": { "stringValue": "active_timeout" } },
    { "key": "flow.bytes.delta", "value": { "intValue": "1024" } },
    { "key": "flow.packets.delta", "value": { "intValue": "10" } },
    { "key": "flow.reverse.bytes.delta", "value": { "intValue": "32768" } },
    { "key": "flow.reverse.packets.delta", "value": { "intValue": "85" } },
    { "key": "source.address", "value": { "stringValue": "10.1.1.5" } },
    { "key": "source.port", "value": { "intValue": "54211" } },
    { "key": "source.k8s.pod.name", "value": { "stringValue": "frontend-abcde" } },
    { "key": "source.k8s.namespace.name", "value": { "stringValue": "production" } },
    { "key": "destination.address", "value": { "stringValue": "10.1.2.10" } },
    { "key": "destination.port", "value": { "intValue": "80" } },
    { "key": "destination.k8s.pod.name", "value": { "stringValue": "backend-xyz" } },
    { "key": "destination.k8s.namespace.name", "value": { "stringValue": "production" } },
    { "key": "client.address", "value": { "stringValue": "frontend-abcde.production.svc.cluster.local" } },
    { "key": "client.port", "value": { "intValue": "54211" } },
    { "key": "server.address", "value": { "stringValue": "backend-xyz.production.svc.cluster.local" } },
    { "key": "server.port", "value": { "intValue": "80" } },
    { "key": "network.transport", "value": { "stringValue": "tcp" } },
    { "key": "network.type", "value": { "stringValue": "ipv4" } },
    { "key": "flow.tcp.flags.bits", "value": { "intValue": "18" } },
    { "key": "flow.tcp.flags.tags", "value": { "arrayValue": { "values": [
      { "stringValue": "SYN" },
      { "stringValue": "ACK" }
    ]}}},
    { "key": "flow.reverse.tcp.flags.bits", "value": { "intValue": "18" } },
    { "key": "flow.reverse.tcp.flags.tags", "value": { "arrayValue": { "values": [
      { "stringValue": "SYN" },
      { "stringValue": "ACK" }
    ]}}},
    { "key": "flow.tcp.rndtrip.latency", "value": { "intValue": "2500000" } }
  ]
}
```
