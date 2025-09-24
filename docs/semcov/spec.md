This document proposes a semantic convention for representing network flow data as traces. The existing network conventions are primarily designed for unidirectional, client/server interactions within an instrumented application. This proposal addresses the need to represent a network flow as a complete, bidirectional conversation, typically observed by a third party (like a network device or eBPF agent).

The core of this proposal is to represent each finalized flow record as a single **Span**, creating a new standard for network observability within the OpenTelemetry ecosystem.

---
### 1. Core Concepts

A network flow record will be represented as a single **Span** with the following characteristics:

* **Span Name**: The name of the span SHOULD be `flow`. This is more semantically accurate, establishing a clear separation between a flow of traffic and a network entity.
* **Span Kind**: The kind of the span MUST be `INTERNAL`. A flow is an internal operation within the network infrastructure and does not represent the start or end of a request from an instrumented application's perspective.

#### Attribute Namespaces
To ensure clarity, this convention uses & defines several primary namespaces:

* **`flow.*`**: Attributes that describe the flow as a whole (e.g., `flow.bytes.total`, `flow.io.direction`, `flow.end_reason`).
* **`source.*` / `destination.*`**: Standard OTel namespaces used to describe the two endpoints of the flow, including L3/L4 addresses and enriched Kubernetes metadata.
* **`network.*`**: The existing OTel namespace used for protocol-specific attributes that are not specific to the source or destination endpoint (e.g., `network.transport`, `network.ip.dscp`, `network.tunnel.id`).
* **`process.*`**: The existing OTel namespace used for identifying the host process associated with the flow's socket.

The `flow.*` namespace is to create a clear semantic distinction between a flow of traffic—a conversation between two endpoints over time—and a network entity, such as a physical interface. The existing network namespace is already used for attributes describing network entities, and overloading it with flow-specific concepts creates ambiguity. For example, a metric like

`network.byte_count` could be misinterpreted as the total bytes for an interface rather than for a specific five-tuple flow. By using

flow.* for attributes that describe the conversation itself (like `flow.bytes.total` or `flow.end_reason`), we avoid overloading too many different concepts into one place, making the data more accurate and easier to understand.

---
### 2. Proposed Attributes

The following tables detail the proposed attributes for the `flow` span.

#### General Flow Attributes
| Proposed Field Name     | Data Type | Description                                                                       | Notes / Decisions                                                                       | Required |
|:------------------------|:----------|:----------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------|----------|
| `flow.community_id`     | `string`  | The Community ID hash of the flow's five-tuple.                                   | A common way to identify a network flow across different monitoring points.             | *        |
| `flow.io.direction`     | `string`  | Indicates which side of the flow initiated the connection.                        | Enum values: `initiator`, `reverse_initiator`. This follows the biflow model.           | *        |
| `flow.connection.state` | `string`  | The state of the connection (e.g., TCP state) at the time the flow was generated. | For TCP, this would be one of the standard states like `ESTABLISHED`, `TIME_WAIT`, etc. | *        |
| `flow.end_reason`       | `string`  | The reason the flow record was exported (e.g., `active_timeout`, `end_of_flow`).  | Stored as a human-readable text enum.                                                   | *        |

#### L2-L4 Attributes
| Proposed Field Name       | Data Type  | Description                                                                     | Notes / Decisions                    | Required |
|:--------------------------|:-----------|:--------------------------------------------------------------------------------|:-------------------------------------|----------|
| `source.address`          | `string`   | Source IP address.                                                              | Standard OTel field.                 | *        |
| `source.port`             | `int`      | Source port number.                                                             | Standard OTel field.                 | *        |
| `source.mac`              | `string`   | Source MAC address.                                                             |                                      |          |
| `destination.address`     | `string`   | Destination IP address.                                                         | Standard OTel field.                 | *        |
| `destination.port`        | `int`      | Destination port number.                                                        | Standard OTel field.                 | *        |
| `destination.mac`         | `string`   | Destination MAC address.                                                        |                                      |          |
| `network.transport`       | `string`   | The transport protocol of the flow (e.g., `tcp`, `udp`).                        | Lowercase IANA protocol name string. | *        |
| `network.type`            | `string`   | The network protocol type (EtherType) of the flow (e.g., `ipv4`, `ipv6`).       |                                      |          |
| `network.interface.name`  | `string`   | The name of the network interface where the flow was observed.                  |                                      |          |
| `network.ip.dscp`         | `int`      | Differentiated Services Code Point (DSCP) value from the IP header.             |                                      |          |
| `network.ip.ecn`          | `int`      | Explicit Congestion Notification (ECN) value from the IP header.                |                                      |          |
| `network.ip.ttl`          | `int`      | Time to Live (IPv4) or Hop Limit (IPv6) value.                                  |                                      |          |
| `network.ipv6.flow_label` | `int`      | Flow Label from the IPv6 header.                                                |                                      |          |
| `network.icmp.type`       | `string`   | ICMP message type name.                                                         | Based on IANA standard names.        |          |
| `network.icmp.code`       | `string`   | ICMP message code name.                                                         | Based on IANA standard names.        |          |
| `network.tcp.flags.bits`  | `int`      | The integer representation of all TCP flags seen during the observation window. |                                      |          |
| `network.tcp.flags.tags`  | `string[]` | An array of TCP flag names (e.g., `["SYN", "ACK"]`) for all flags set.          |                                      |          |

#### Flow Metrics
| Proposed Field Name          | Data Type | Description                                                               | Notes / Decisions                                        | Required |
|:-----------------------------|:----------|:--------------------------------------------------------------------------|:---------------------------------------------------------|----------|
| `flow.bytes.total`           | `long`    | Total number of bytes observed for this flow since its start.             | The term `bytes` is preferred over `octets` for clarity. |          |
| `flow.bytes.delta`           | `long`    | Number of bytes observed in the last measurement interval for the flow.   |                                                          |          |
| `flow.packets.total`         | `long`    | Total number of packets observed for this flow since its start.           |                                                          |          |
| `flow.packets.delta`         | `long`    | Number of packets observed in the last measurement interval for the flow. |                                                          |          |
| `flow.reverse.bytes.total`   | `long`    | Total bytes in the reverse direction of the flow since its start.         |                                                          |          |
| `flow.reverse.bytes.delta`   | `long`    | Delta bytes in the reverse direction of the flow.                         |                                                          |          |
| `flow.reverse.packets.total` | `long`    | Total packets in the reverse direction of the flow since its start.       |                                                          |          |
| `flow.reverse.packets.delta` | `long`    | Delta packets in the reverse direction of the flow.                       |                                                          |          |


### Performance Metrics
Time-based metrics calculated for the flow, stored in microseconds (`us`). The span's standard start and end timestamps represent the flow record's observation window.

| Proposed Field Name                 | Data Type | Description                                                                                              | Notes / Decisions | Required |
|:------------------------------------|:----------|:---------------------------------------------------------------------------------------------------------|:------------------|----------|
| `network.tcp.handshake.snd.latency` | `long`    | The latency of the first part of the TCP handshake (SYN to SYN/ACK), from the **client's perspective**.  | Unit: `us`.       |          |
| `network.tcp.handshake.snd.jitter`  | `long`    | The jitter of the first part of the TCP handshake (SYN to SYN/ACK), from the **client's perspective**.   | Unit: `us`.       |          |
| `network.tcp.handshake.cnd.latency` | `long`    | The latency of the second part of the TCP handshake (SYN/ACK to ACK), from the **server's perspective**. | Unit: `us`.       |          |
| `network.tcp.handshake.cnd.jitter`  | `long`    | The jitter of the second part of the TCP handshake (SYN/ACK to ACK), from the **server's perspective**.  | Unit: `us`.       |          |
| `network.tcp.svc.latency`           | `long`    | The application/service processing time, as measured on the **server side**.                             | Unit: `us`.       |          |
| `network.tcp.svc.jitter`            | `long`    | The jitter of the application/service processing time, as measured on the **server side**.               | Unit: `us`.       |          |
| `network.tcp.rndtrip.latency`       | `long`    | The full round-trip time (client to server + app to client), from the **client's perspective**.          | Unit: `us`.       |          |
| `network.tcp.rndtrip.jitter`        | `long`    | The jitter of the full round-trip time, from the **client's perspective**.                               | Unit: `us`.       |          |


#### Tunnel & Encapsulation Attributes
| Proposed Field Name                  | Data Type | Description                                                 | Notes / Decisions                      | Required |
|:-------------------------------------|:----------|:------------------------------------------------------------|:---------------------------------------|----------|
| `network.tunnel.source.address`      | `string`  | The source IP address of the tunnel's outer header.         | Tunnel is always the outermost header. |          |
| `network.tunnel.destination.address` | `string`  | The destination IP address of the tunnel's outer header.    |                                        |          |
| `network.tunnel.id`                  | `string`  | The identifier for the tunnel (e.g., VNI for VXLAN/Geneve). |                                        |          |
| `network.ipsec.spi`                  | `string`  | Security Parameters Index for ESP or AH headers.            |                                        |          |
| `network.gre.key`                    | `string`  | The key identifier present in some GRE headers.             |                                        |          |
| `network.gre.vsid`                   | `string`  | Virtual Subnet ID from a GRE header.                        |                                        |          |
| `network.wireguard.sender_index`     | `int`     | The sender index from a WireGuard header.                   |                                        |          |
| `network.wireguard.receiver_index`   | `int`     | The receiver index from a WireGuard header.                 |                                        |          |


### Kubernetes & Application Attributes

| Proposed Field Name                      | Data Type  | Description                                                      | Notes / Decisions                          | Required |
|:-----------------------------------------|:-----------|:-----------------------------------------------------------------|--------------------------------------------|----------|
| `source.kubernetes.cluster.name`         | `string`   | The name of the Kubernetes cluster for the source.               |                                            |          |
| `source.k8s.namespace.name`              | `string`   | The name of the Kubernetes Namespace for the source.             |                                            |          |
| `source.k8s.node.name`                   | `string`   | The name of the Kubernetes Node for the source.                  |                                            |          |
| `source.k8s.pod.name`                    | `string`   | The name of the Kubernetes Pod for the source.                   |                                            |          |
| `source.k8s.container.name`              | `string`   | The name of the Kubernetes Container for the source.             |                                            |          |
| `source.k8s.deployment.name`             | `string`   | The name of the Kubernetes Deployment for the source.            |                                            |          |
| `source.k8s.replicaset.name`             | `string`   | The name of the Kubernetes ReplicaSet for the source.            |                                            |          |
| `source.k8s.statefulset.name`            | `string`   | The name of the Kubernetes StatefulSet for the source.           |                                            |          |
| `source.k8s.daemonset.name`              | `string`   | The name of the Kubernetes DaemonSet for the source.             |                                            |          |
| `source.k8s.job.name`                    | `string`   | The name of the Kubernetes Job for the source.                   |                                            |          |
| `source.k8s.cronjob.name`                | `string`   | The name of the Kubernetes CronJob for the source.               |                                            |          |
| `source.k8s.service.name`                | `string`   | The name of the Kubernetes Service for the source.               |                                            |          |
| `destination.k8s.cluster.name`           | `string`   | The name of the Kubernetes cluster for the destination.          |                                            |          |
| `destination.k8s.namespace.name`         | `string`   | The name of the Kubernetes Namespace for the destination.        |                                            |          |
| `destination.k8s.node.name`              | `string`   | The name of the Kubernetes Node for the destination.             |                                            |          |
| `destination.k8s.pod.name`               | `string`   | The name of the Kubernetes Pod for the destination.              |                                            |          |
| `destination.k8s.container.name`         | `string`   | The name of the Kubernetes Container for the destination.        |                                            |          |
| `destination.k8s.deployment.name`        | `string`   | The name of the Kubernetes Deployment for the destination.       |                                            |          |
| `destination.k8s.replicaset.name`        | `string`   | The name of the Kubernetes ReplicaSet for the destination.       |                                            |          |
| `destination.k8s.statefulset.name`       | `string`   | The name of the Kubernetes StatefulSet for the destination.      |                                            |          |
| `destination.k8s.daemonset.name`         | `string`   | The name of the Kubernetes DaemonSet for the destination.        |                                            |          |
| `destination.k8s.job.name`               | `string`   | The name of the Kubernetes Job for the destination.              |                                            |          |
| `destination.k8s.cronjob.name`           | `string`   | The name of the Kubernetes CronJob for the destination.          |                                            |          |
| `destination.k8s.service.name`           | `string`   | The name of the Kubernetes Service for the destination.          |                                            |          |
| `flow.kubernetes.network_policy.ingress` | `string[]` | A list of network policy names affecting ingress traffic.        | This could be multiple policies.           |          |
| `flow.kubernetes.network_policy.egress`  | `string[]` | A list of network policy names affecting egress traffic.         | This could be multiple policies.           |          |
| `process.executable.name`                | `string`   | The name of the binary associated with the socket for this flow. | Provides application-level identification. |          |


---
### 3. Example Span (OTLP JSON)

Below is an example of what a resulting `flow` span might look like in OTLP JSON format.
```json
{
  "name": "flow",
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
    { "key": "source.kubernetes.pod.name", "value": { "stringValue": "frontend-abcde" } },
    { "key": "source.kubernetes.namespace.name", "value": { "stringValue": "production" } },
    { "key": "destination.address", "value": { "stringValue": "10.1.2.10" } },
    { "key": "destination.port", "value": { "intValue": "80" } },
    { "key": "destination.kubernetes.pod.name", "value": { "stringValue": "backend-xyz" } },
    { "key": "network.transport", "value": { "stringValue": "tcp" } },
    { "key": "network.type", "value": { "stringValue": "ipv4" } },
    { "key": "flow.latency.round_trip", "value": { "intValue": "500" } }
  ]
}
