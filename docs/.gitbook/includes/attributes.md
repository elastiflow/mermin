---
title: Flow Trace Attributes
---

# Attributes

## Requirement Level Legend

The following symbols are used in the "Required" column to indicate [OpenTelemetry attribute requirement levels](https://opentelemetry.io/docs/specs/semconv/general/attribute-requirement-level/):

| Symbol | Requirement Level      | Description                                                      |
| ------ | ---------------------- | ---------------------------------------------------------------- |
| ✓      | Required               | All instrumentations MUST populate the attribute                 |
| ?      | Conditionally Required | MUST populate when the specified condition is satisfied          |
| \~     | Recommended            | SHOULD add by default if readily available and efficient         |
| ○      | Opt-In                 | SHOULD populate only if user configures instrumentation to do so |

## General Flow Attributes

> Note on Timestamps: The span's standard `start_time_unix_nano` and `end_time_unix_nano` fields are used to mark the beginning and end of the flow span's observation window. These are analogous to the `flowStart*` and `flowEnd*` fields in IPFIX records and are not duplicated as attributes.

| Proposed Field Name     | Data Type | Description                                                                               | Notes / Decisions                                                                                                                                        | Std OTel | Required   |
| ----------------------- | --------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ---------- |
| `flow.community_id`     | `string`  | The Community ID hash of the flow's five-tuple.                                           | A common way to identify a network flow across different monitoring points.                                                                              |          | ✓          |
| `flow.direction`        | `string`  | The inferred direction of the flow from the observer's perspective.                       | One of: `forward`, `reverse`, or `unknown`. Mirrors IPFIX biflow concepts. See [Flow Direction](semantic-conventions.md#flow-direction) for details.     |          | ✓          |
| `flow.connection.state` | `string`  | The state of the connection (e.g., TCP state) at the time the flow was generated.         | For TCP, this would be one of the standard states like `established`, `time_wait`, etc. Similar to network.connection.state but from a flow perspective. |          | ? TCP only |
| `flow.end_reason`       | `string`  | The reason the flow record was exported (e.g., `active_timeout`, `end_of_flow_detected`). | Stored as a human-readable text enum based on [ipfix end reason](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason).              |          | ✓          |

## L2-L4 Attributes

| Proposed Field Name           | Data Type  | Description                                                                             | Notes / Decisions                                                      | Std OTel | Required          |
| ----------------------------- | ---------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | -------- | ----------------- |
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

## Flow Metrics

| Proposed Field Name          | Data Type | Description                                                               | Notes / Decisions                                        | Std OTel | Required |
| ---------------------------- | --------- | ------------------------------------------------------------------------- | -------------------------------------------------------- | -------- | -------- |
| `flow.bytes.delta`           | `long`    | Number of bytes observed in the last measurement interval for the flow.   |                                                          |          | ✓        |
| `flow.bytes.total`           | `long`    | Total number of bytes observed for this flow since its start.             | The term `bytes` is preferred over `octets` for clarity. |          | \~       |
| `flow.packets.delta`         | `long`    | Number of packets observed in the last measurement interval for the flow. |                                                          |          | ✓        |
| `flow.packets.total`         | `long`    | Total number of packets observed for this flow since its start.           |                                                          |          | \~       |
| `flow.reverse.bytes.delta`   | `long`    | Delta bytes in the reverse direction of the flow.                         |                                                          |          | ✓        |
| `flow.reverse.bytes.total`   | `long`    | Total bytes in the reverse direction of the flow since its start.         |                                                          |          | \~       |
| `flow.reverse.packets.delta` | `long`    | Delta packets in the reverse direction of the flow.                       |                                                          |          | ✓        |
| `flow.reverse.packets.total` | `long`    | Total packets in the reverse direction of the flow since its start.       |                                                          |          | \~       |

## Performance Metrics

Time-based metrics calculated for the flow, stored in nanoseconds (`ns`).

| Proposed Field Name          | Data Type | Description                                                                                                                    | Notes / Decisions | Std OTel | Required |
| ---------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------- | -------- | -------- |
| `flow.tcp.handshake.latency` | `long`    | The latency of the first part of the TCP handshake (SYN to SYN/ACK), from the **client's perspective**. (Server network delay) | Unit: `ns`.       |          | \~       |
| `flow.tcp.svc.latency`       | `long`    | The application/service processing time, as measured on the **server side**.                                                   | Unit: `ns`.       |          | \~       |
| `flow.tcp.svc.jitter`        | `long`    | The jitter of the application/service processing time, as measured on the **server side**.                                     | Unit: `ns`.       |          | \~       |
| `flow.tcp.rndtrip.latency`   | `long`    | The full round-trip time (client to server + app to client), from the **client's perspective**.                                | Unit: `ns`.       |          | \~       |
| `flow.tcp.rndtrip.jitter`    | `long`    | The jitter of the full round-trip time, from the **client's perspective**.                                                     | Unit: `ns`.       |          | \~       |

## Tunnel & Ip-in-Ip & IPSec Attributes

| Proposed Field Name            | Data Type | Description                                                                 | Notes / Decisions                                        | Std OTel | Required           |
| ------------------------------ | --------- | --------------------------------------------------------------------------- | -------------------------------------------------------- | -------- | ------------------ |
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

## Kubernetes Attributes

> **Note:** These attributes use `source.k8s.*` / `destination.k8s.*` prefixes rather than standard OTel `k8s.*` attributes. See [Why `source.k8s.*` Instead of `k8s.source.*`?](semantic-conventions.md#why-sourcek8s-instead-of-k8ssource) for the rationale.

| Proposed Field Name                             | Data Type | Description                                                 | Notes / Decisions | Std OTel  | Required |
| ----------------------------------------------- | --------- | ----------------------------------------------------------- | ----------------- | --------- | -------- |
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

## Network Policy Attributes

| Proposed Field Name      | Data Type  | Description                                               | Notes / Decisions                | Std OTel | Required |
| ------------------------ | ---------- | --------------------------------------------------------- | -------------------------------- | -------- | -------- |
| `network.policy.ingress` | `string[]` | A list of network policy names affecting ingress traffic. | This could be multiple policies. |          | ○        |
| `network.policy.egress`  | `string[]` | A list of network policy names affecting egress traffic.  | This could be multiple policies. |          | ○        |

## Process & Container Attributes

| Proposed Field Name                | Data Type | Description                                                               | Notes / Decisions                               | Std OTel | Required |
| ---------------------------------- | --------- | ------------------------------------------------------------------------- | ----------------------------------------------- | -------- | -------- |
| `process.executable.name`          | `string`  | The name of the binary associated with the socket for this flow.          | Provides application-level identification.      | ✓        | \~       |
| `process.pid`                      | `long`    | The PID of the process associated with the socket for this flow.          | Provides application-level identification.      | ✓        | \~       |
| `source.container.name`            | `string`  | The container runtime name for the source (e.g., from Docker/containerd). | Distinct from `source.k8s.container.name`.      | ✓        | \~       |
| `source.container.image.name`      | `string`  | The image name of the source container (e.g., `nginx:1.21`).              | From K8s Pod spec container image.              |          | \~       |
| `destination.container.name`       | `string`  | The container runtime name for the destination.                           | Distinct from `destination.k8s.container.name`. | ✓        | \~       |
| `destination.container.image.name` | `string`  | The image name of the destination container (e.g., `app:v1.0.0`).         | From K8s Pod spec container image.              |          | \~       |
