This document proposes a semantic convention for representing network flow data as traces. The existing network conventions are primarily designed for unidirectional, client/server interactions within an instrumented application. This proposal addresses the need to represent a network flow as a complete, bidirectional conversation, typically observed by a third party (like a network device or eBPF agent).

The core of this proposal is to represent each finalized flow record as a single **Span**, creating a new standard for network observability within the OpenTelemetry ecosystem.

---

### 1. Core Concepts

A network flow record will be represented as a single **Span** with the following characteristics:

* **Span Name**: The name of the span SHOULD be `flow_<network.type>_<network.transport>` — for example, `flow_ipv4_tcp`. This is more semantically accurate, establishing a clear separation between app spans and flow spans.
* **Span Kind**: The kind of the span MUST be `INTERNAL`. A flow is an internal operation within the network infrastructure and does not represent the start or end of a request from an instrumented application's perspective.

#### Attribute Namespaces

To ensure clarity, this convention uses & defines several primary namespaces:

* **`flow.*`**: Attributes that describe the flow as a whole (e.g., `flow.bytes.total`, `flow.io.direction`, `flow.end_reason`).
* **`source.*` / `destination.*`**: Standard OTel namespaces used to describe the two endpoints of the flow, including L3/L4 addresses and enriched Kubernetes metadata.
* **`network.*`**: The existing OTel namespace used for protocol-specific attributes that are not specific to the source or destination endpoint (e.g., `network.transport`, `network.type.ip.dscp`, `flow.tunnel.id`).
* **`tunnel.*`**: Attributes that describe tunneling protocols and encapsulation metadata when the flow is observed within or across tunnel infrastructure (e.g., `tunnel.type`, `tunnel.id`, `tunnel.endpoint`).
* **`process.*`**: The existing OTel namespace used for identifying the host process associated with the flow's socket.
* **`container.*`**: The existing OTel namespace used for identifying the container associated with the flow's socket.

The `flow.*` namespace is to create a clear semantic distinction between a flow of traffic—a conversation between two endpoints over time—and a network entity, such as a physical interface. The existing network namespace is already used for attributes describing network entities, and overloading it with flow-specific concepts creates ambiguity.
A good litmus test to understand when an attribute belong in the network or the flow namespace, consider the following. Attributes that change over the lifetime of a flow span should be in the flow namespace, while attributes that stay static over that same lifetime are good candidates for the network namespace.
For example, a metric like `network.byte_count` could be misinterpreted as the total bytes for an interface rather than for a specific five-tuple flow.
By using flow.* for attributes that describe the conversation itself (like `flow.bytes.total` or `flow.end_reason`), we avoid overloading too many different concepts into one place, making the data more accurate and easier to understand.

---

### 2. Proposed Attributes

The following tables detail the proposed attributes for the flow span.

#### Requirement Level Legend

The following symbols are used in the "Required" column to indicate [OpenTelemetry attribute requirement levels](https://opentelemetry.io/docs/specs/semconv/general/attribute-requirement-level/):

| Symbol | Requirement Level | Description |
|:-------|:------------------|:------------|
| ✓      | Required          | All instrumentations MUST populate the attribute |
| ?      | Conditionally Required | MUST populate when the specified condition is satisfied |
| ~      | Recommended       | SHOULD add by default if readily available and efficient |
| ○      | Opt-In            | SHOULD populate only if user configures instrumentation to do so |

#### General Flow Attributes

| Proposed Field Name     | Data Type | Description                                                                               | Notes / Decisions                                                                                                                           | Std OTel | Required   |
|:------------------------|:----------|:------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------|:---------|:-----------|
| `flow.community_id`     | `string`  | The Community ID hash of the flow's five-tuple.                                           | A common way to identify a network flow across different monitoring points.                                                                 |          | ✓          |
| `flow.initiator`        | `string`  | Indicates which side of the flow initiated the connection.                                | Enum values: `source`, `destination`. This is modeled after biflowDirection in IANA.                                                        |          | ✓          |
| `flow.connection.state` | `string`  | The state of the connection (e.g., TCP state) at the time the flow was generated.         | For TCP, this would be one of the standard states like `established`, `time_wait`, etc.                                                     |          | ? TCP only |
| `flow.end_reason`       | `string`  | The reason the flow record was exported (e.g., `active_timeout`, `end_of_flow_detected`). | Stored as a human-readable text enum based on [ipfix end reason](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason). |          | ✓          |

> start_time and end_time are set on the span itself and is not considered attribute on spans. However, start_time and end_time are used to mark the beginning and end time of a flow span, much like flowStart* and flowEnd* fields in IPFIX records.

#### L2-L4 Attributes

| Proposed Field Name       | Data Type  | Description                                                                     | Notes / Decisions                                     | Std OTel | Required |
|:--------------------------|:-----------|:--------------------------------------------------------------------------------|:------------------------------------------------------|:---------|:---------|
| `source.address`          | `string`   | Source IP address.                                                              |                                                       | ✓        | ✓        |
| `source.port`             | `long`     | Source port number.                                                             |                                                       | ✓        | ✓        |
| `destination.address`     | `string`   | Destination IP address.                                                         |                                                       | ✓        | ✓        |
| `destination.port`        | `long`     | Destination port number.                                                        |                                                       | ✓        | ✓        |
| `network.transport`       | `string`   | The transport protocol of the flow (e.g., `tcp`, `udp`).                        | Lowercase IANA protocol name string.                  | ✓        | ✓        |
| `network.type`            | `string`   | The network protocol type (EtherType) of the flow (e.g., `ipv4`, `ipv6`).       |                                                       | ✓        | ✓        |
| `network.interface.index` | `long`     | The index value of the network interface where the flow was observed.           |                                                       | ✓        | ~        |
| `network.interface.name`  | `string`   | The name of the network interface where the flow was observed.                  |                                                       | ✓        | ~        |
| `network.interface.mac`   | `string`   | Source MAC address.                                                             | Lowercased, 6 hexidecimal values separated by colons. | ✓        | ~        |
| `flow.ip.dscp.id`         | `long`     | Differentiated Services Code Point (DSCP) value from the IP header.             |                                                       |          | ~        |
| `flow.ip.dscp.name`       | `string`   | Lowercase DSCP standard name.                                                   |                                                       |          | ~        |
| `flow.ip.ecn.id`          | `long`     | Explicit Congestion Notification (ECN) value from the IP header.                |                                                       |          | ~        |
| `flow.ip.ecn.name`        | `string`   | Lowercase ECN standard name.                                                    |                                                       |          | ~        |
| `flow.ip.ttl`             | `long`     | Time to Live (IPv4) or Hop Limit (IPv6) value.                                  |                                                       |          | ~        |
| `flow.ip.flow_label`      | `long`     | Flow Label from the IPv6 header.                                                |                                                       |          | ~        |
| `flow.icmp.type.id`       | `long`     | ICMP message type id.                                                           | Based on IANA standard names.                         |          | ~        |
| `flow.icmp.type.name`     | `string`   | Lowercase ICMP message type name.                                               | Based on IANA standard names.                         |          | ~        |
| `flow.icmp.code.id`       | `long`     | ICMP message code id.                                                           | Based on IANA standard names.                         |          | ~        |
| `flow.icmp.code.name`     | `string`   | ICMP message code name.                                                         | Based on IANA standard names.                         |          | ~        |
| `flow.tcp.flags.bits`     | `long`     | The integer representation of all TCP flags seen during the observation window. |                                                       |          | ~        |
| `flow.tcp.flags.tags`     | `string[]` | An array of TCP flag names (e.g., `["SYN", "ACK"]`) for all flags set.          |                                                       |          | ~        |

#### Flow Metrics

| Proposed Field Name          | Data Type | Description                                                               | Notes / Decisions                                        | Std OTel | Required |
|:-----------------------------|:----------|:--------------------------------------------------------------------------|:---------------------------------------------------------|:---------|:---------|
| `flow.bytes.total`           | `long`    | Total number of bytes observed for this flow since its start.             | The term `bytes` is preferred over `octets` for clarity. |          | ~        |
| `flow.bytes.delta`           | `long`    | Number of bytes observed in the last measurement interval for the flow.   |                                                          |          | ✓        |
| `flow.packets.total`         | `long`    | Total number of packets observed for this flow since its start.           |                                                          |          | ~        |
| `flow.packets.delta`         | `long`    | Number of packets observed in the last measurement interval for the flow. |                                                          |          | ✓        |
| `flow.reverse.bytes.total`   | `long`    | Total bytes in the reverse direction of the flow since its start.         |                                                          |          | ✓        |
| `flow.reverse.bytes.delta`   | `long`    | Delta bytes in the reverse direction of the flow.                         |                                                          |          | ✓        |
| `flow.reverse.packets.total` | `long`    | Total packets in the reverse direction of the flow since its start.       |                                                          |          | ✓        |
| `flow.reverse.packets.delta` | `long`    | Delta packets in the reverse direction of the flow.                       |                                                          |          | ✓        |

### Performance Metrics

Time-based metrics calculated for the flow, stored in nanoseconds (`ns`). The span's standard start and end timestamps represent the flow record's observation window.

| Proposed Field Name              | Data Type | Description                                                                                                                     | Notes / Decisions | Std OTel | Required |
|:---------------------------------|:----------|:--------------------------------------------------------------------------------------------------------------------------------|:------------------|:---------|:---------|
| `flow.tcp.handshake.snd.latency` | `long`    | The latency of the first part of the TCP handshake (SYN to SYN/ACK), from the **client's perspective**. (Server network delay)  | Unit: `ns`.       |          | ~        |
| `flow.tcp.handshake.snd.jitter`  | `long`    | The jitter of the first part of the TCP handshake (SYN to SYN/ACK), from the **client's perspective**. (Server network delay)   | Unit: `ns`.       |          | ~        |
| `flow.tcp.handshake.cnd.latency` | `long`    | The latency of the second part of the TCP handshake (SYN/ACK to ACK), from the **server's perspective**. (Client network delay) | Unit: `ns`.       |          | ~        |
| `flow.tcp.handshake.cnd.jitter`  | `long`    | The jitter of the second part of the TCP handshake (SYN/ACK to ACK), from the **server's perspective**. (Client network delay)  | Unit: `ns`.       |          | ~        |
| `flow.tcp.svc.latency`           | `long`    | The application/service processing time, as measured on the **server side**.                                                    | Unit: `ns`.       |          | ~        |
| `flow.tcp.svc.jitter`            | `long`    | The jitter of the application/service processing time, as measured on the **server side**.                                      | Unit: `ns`.       |          | ~        |
| `flow.tcp.rndtrip.latency`       | `long`    | The full round-trip time (client to server + app to client), from the **client's perspective**.                                 | Unit: `ns`.       |          | ~        |
| `flow.tcp.rndtrip.jitter`        | `long`    | The jitter of the full round-trip time, from the **client's perspective**.                                                      | Unit: `ns`.       |          | ~        |

#### Tunnel & Encapsulation Attributes

| Proposed Field Name          | Data Type | Description                                                                                          | Notes / Decisions                      | Std OTel | Required |
|:-----------------------------|:----------|:-----------------------------------------------------------------------------------------------------|:---------------------------------------|:---------|:---------|
| `tunnel.type`                | `string`  | The type of tunnel protocol (e.g., `vxlan`, `geneve`, `gre`, `wireguard`, `ipip`, `ah`, `esp`, etc). | Tunnel is always the outermost header. |          | ○        |
| `tunnel.source.address`      | `string`  | The source IP address of the tunnel's outer header.                                                  |                                        |          | ○        |
| `tunnel.source.port`         | `long`    |                                                                                                      |                                        |          | ○        |
| `tunnel.destination.address` | `string`  | The destination IP address of the tunnel's outer header.                                             |                                        |          | ○        |
| `tunnel.destination.port`    | `long`    | The network protocol type (EtherType) of the flow (e.g., `ipv4`, `ipv6`).                            |                                        |          | ○        |
| `tunnel.network.transport`   | `string`  | The transport protocol of the flow (e.g., `tcp`, `udp`).                                             |                                        |          | ○        |
| `tunnel.network.type`        | `string`  |                                                                                                      |                                        |          | ○        |
| `tunnel.id`                  | `string`  | The identifier for the tunnel (e.g., VNI for VXLAN/Geneve/GRE).                                      |                                        |          | ○        |
| `tunnel.key`                 | `string`  | The key identifier present in some GRE headers.                                                      |                                        |          | ○        |
| `tunnel.sender_index`        | `long`    | The sender index from a WireGuard header.                                                            |                                        |          | ○        |
| `tunnel.receiver_index`      | `long`    | The receiver index from a WireGuard header.                                                          |                                        |          | ○        |
| `tunnel.spi`                 | `string`  | Security Parameters Index for ESP or AH headers.                                                     |                                        |          | ○        |

### Kubernetes & Application Attributes

| Proposed Field Name                | Data Type  | Description                                                             | Notes / Decisions                                               | Std OTel | Required |
|:-----------------------------------|:-----------|:------------------------------------------------------------------------|-----------------------------------------------------------------|:---------|:---------|
| `source.k8s.cluster.name`          | `string`   | The name of the Kubernetes cluster for the source.                      |                                            | ✓        | ○        |
| `source.k8s.namespace.name`        | `string`   | The name of the Kubernetes Namespace for the source.                    |                                            | ✓        | ○        |
| `source.k8s.node.name`             | `string`   | The name of the Kubernetes Node for the source.                         |                                            | ✓        | ○        |
| `source.k8s.pod.name`              | `string`   | The name of the Kubernetes Pod for the source.                          |                                            | ✓        | ○        |
| `source.k8s.container.name`        | `string`   | The name of the Kubernetes Container for the source.                    |                                            | ✓        | ○        |
| `source.k8s.deployment.name`       | `string`   | The name of the Kubernetes Deployment for the source.                   |                                            | ✓        | ○        |
| `source.k8s.replicaset.name`       | `string`   | The name of the Kubernetes ReplicaSet for the source.                   |                                            | ✓        | ○        |
| `source.k8s.statefulset.name`      | `string`   | The name of the Kubernetes StatefulSet for the source.                  |                                            | ✓        | ○        |
| `source.k8s.daemonset.name`        | `string`   | The name of the Kubernetes DaemonSet for the source.                    |                                            | ✓        | ○        |
| `source.k8s.job.name`              | `string`   | The name of the Kubernetes Job for the source.                          |                                            | ✓        | ○        |
| `source.k8s.cronjob.name`          | `string`   | The name of the Kubernetes CronJob for the source.                      |                                            | ✓        | ○        |
| `source.k8s.service.name`          | `string`   | The name of the Kubernetes Service for the source.                      |                                            | ✓        | ○        |
| `source.k8s.container.name`        | `string`   | The name of the container name on a Kubernetes Pod for the source.      | Provides application-level identification. | ✓        | ○        |
| `destination.k8s.cluster.name`     | `string`   | The name of the Kubernetes cluster for the destination.                 |                                            | ✓        | ○        |
| `destination.k8s.namespace.name`   | `string`   | The name of the Kubernetes Namespace for the destination.               |                                            | ✓        | ○        |
| `destination.k8s.node.name`        | `string`   | The name of the Kubernetes Node for the destination.                    |                                            | ✓        | ○        |
| `destination.k8s.pod.name`         | `string`   | The name of the Kubernetes Pod for the destination.                     |                                            | ✓        | ○        |
| `destination.k8s.container.name`   | `string`   | The name of the Kubernetes Container for the destination.               |                                            | ✓        | ○        |
| `destination.k8s.deployment.name`  | `string`   | The name of the Kubernetes Deployment for the destination.              |                                            | ✓        | ○        |
| `destination.k8s.replicaset.name`  | `string`   | The name of the Kubernetes ReplicaSet for the destination.              |                                            | ✓        | ○        |
| `destination.k8s.statefulset.name` | `string`   | The name of the Kubernetes StatefulSet for the destination.             |                                            | ✓        | ○        |
| `destination.k8s.daemonset.name`   | `string`   | The name of the Kubernetes DaemonSet for the destination.               |                                            | ✓        | ○        |
| `destination.k8s.job.name`         | `string`   | The name of the Kubernetes Job for the destination.                     |                                            | ✓        | ○        |
| `destination.k8s.cronjob.name`     | `string`   | The name of the Kubernetes CronJob for the destination.                 |                                            | ✓        | ○        |
| `destination.k8s.service.name`     | `string`   | The name of the Kubernetes Service for the destination.                 |                                            | ✓        | ○        |
| `destination.k8s.container.name`   | `string`   | The name of the container name on a Kubernetes Pod for the destination. | Provides application-level identification. | ✓        | ○        |
| `network.policy.ingress`           | `string[]` | A list of network policy names affecting ingress traffic.               | This could be multiple policies.           | ✓        | ○        |
| `network.policy.egress`            | `string[]` | A list of network policy names affecting egress traffic.                | This could be multiple policies.           | ✓        | ○        |
| `process.executable.name`          | `string`   | The name of the binary associated with the socket for this flow.        | Provides application-level identification. | ✓        | ○        |
| `container.image.name`             | `string`   | The name of the container image (e.g., `nginx:1.21`, `app:v1.0.0`).     | Provides application-level identification. | ✓        | ○        |
| `container.name`                   | `string`   | The name of the container instance.                                     | Provides application-level identification. | ✓        | ○        |

---

### 3. Example Span (OTLP JSON)

Below is an example of what a resulting flow span might look like in OTLP JSON format.

```json
{
  "name": "flow_ipv4_tcp",
  "kind": "SPAN_KIND_INTERNAL",
  "startTimeUnixNano": "1727149620000000000",
  "endTimeUnixNano": "1727149680000000000",
  "attributes": [
    { "key": "flow.community_id", "value": { "stringValue": "1:LQU9qZlK+B+2dM2I2n1kI/M5a/g=" } },
    { "key": "flow.direction", "value": { "stringValue": "initiator" } },
    { "key": "flow.bytes.delta", "value": { "intValue": "1024" } },
    { "key": "flow.packets.delta", "value": { "intValue": "10" } },
    { "key": "source.address", "value": { "stringValue": "10.1.1.5" } },
    { "key": "source.port", "value": { "intValue": "54211" } },
    { "key": "source.k8s.pod.name", "value": { "stringValue": "frontend-abcde" } },
    { "key": "source.k8s.namespace.name", "value": { "stringValue": "production" } },
    { "key": "destination.address", "value": { "stringValue": "10.1.2.10" } },
    { "key": "destination.port", "value": { "intValue": "80" } },
    { "key": "destination.k8s.pod.name", "value": { "stringValue": "backend-xyz" } },
    { "key": "network.transport", "value": { "stringValue": "tcp" } },
    { "key": "network.type", "value": { "stringValue": "ipv4" } },
    { "key": "flow.tcp.svc.latency", "value": { "intValue": "500" } }
  ]
}
