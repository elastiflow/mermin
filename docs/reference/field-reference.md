# Field Reference

This page provides a quick reference for commonly used fields in Mermin Flow Traces. For the complete specification of all available fields, see the [Semantic Conventions](../spec/semantic-conventions.md).

## Network Addresses and Ports

| Field Name | Data Type | Description | Notes |
|------------|----------|-------------|-------|
| `source.address` | `string` | Source IP address | Can be pod IP, node IP, service IP, or external IP depending on Kubernetes matching |
| `source.port` | `long` | Source port number | |
| `destination.address` | `string` | Destination IP address | Can be pod IP, node IP, service IP, or external IP depending on Kubernetes matching |
| `destination.port` | `long` | Destination port number | |
| `client.address` | `string` | Client IP address or hostname | Hostname if resolution enabled, otherwise IP |
| `client.port` | `long` | Client port number | |
| `server.address` | `string` | Server IP address or hostname | Hostname if resolution enabled, otherwise IP |
| `server.port` | `long` | Server port number | |
| `network.transport` | `string` | Transport protocol | Values: `tcp`, `udp`, `icmp`, etc. |
| `network.type` | `string` | Network protocol type | Values: `ipv4`, `ipv6` |

## Flow Metrics

| Field Name | Data Type | Description | Notes |
|------------|----------|-------------|-------|
| `flow.bytes.delta` | `long` | Bytes in last measurement interval | |
| `flow.bytes.total` | `long` | Total bytes since flow start | |
| `flow.packets.delta` | `long` | Packets in last measurement interval | |
| `flow.packets.total` | `long` | Total packets since flow start | |
| `flow.reverse.bytes.delta` | `long` | Reverse direction bytes in last interval | |
| `flow.reverse.bytes.total` | `long` | Total reverse direction bytes | |
| `flow.reverse.packets.delta` | `long` | Reverse direction packets in last interval | |
| `flow.reverse.packets.total` | `long` | Total reverse direction packets | |
| `flow.direction` | `string` | Flow direction | Values: `forward`, `reverse`, `unknown` |
| `flow.community_id` | `string` | Community ID hash of the flow's five-tuple | |

## Kubernetes Metadata - Source

| Field Name | Data Type | Description | Notes |
|------------|----------|-------------|-------|
| `source.k8s.pod.name` | `string` | Pod name for the source | |
| `source.k8s.pod.uid` | `string` | Pod UID for the source | |
| `source.k8s.namespace.name` | `string` | Namespace name for the source | |
| `source.k8s.container.name` | `string` | Container name for the source | |
| `source.k8s.node.name` | `string` | Node name for the source | |
| `source.k8s.service.name` | `string` | Service name for the source | |
| `source.k8s.deployment.name` | `string` | Deployment name for the source | |
| `source.k8s.replicaset.name` | `string` | ReplicaSet name for the source | |
| `source.k8s.statefulset.name` | `string` | StatefulSet name for the source | |
| `source.k8s.daemonset.name` | `string` | DaemonSet name for the source | |

## Kubernetes Metadata - Destination

| Field Name | Data Type | Description | Notes |
|------------|----------|-------------|-------|
| `destination.k8s.pod.name` | `string` | Pod name for the destination | |
| `destination.k8s.pod.uid` | `string` | Pod UID for the destination | |
| `destination.k8s.namespace.name` | `string` | Namespace name for the destination | |
| `destination.k8s.container.name` | `string` | Container name for the destination | |
| `destination.k8s.node.name` | `string` | Node name for the destination | |
| `destination.k8s.service.name` | `string` | Service name for the destination | |
| `destination.k8s.deployment.name` | `string` | Deployment name for the destination | |
| `destination.k8s.replicaset.name` | `string` | ReplicaSet name for the destination | |
| `destination.k8s.statefulset.name` | `string` | StatefulSet name for the destination | |
| `destination.k8s.daemonset.name` | `string` | DaemonSet name for the destination | |

## Understanding `source.address` and `destination.address`

The `source.address` and `destination.address` fields represent the IP addresses observed in the network flow. The actual value depends on what Kubernetes resource (if any) matches the IP:

- **Pod IP**: When the IP matches a pod's `status.podIP` or `status.podIPs[*]`
- **Node IP**: When the IP matches a node's `status.addresses[*].address`
- **Service IP**: When the IP matches a service's `spec.clusterIP`, `spec.clusterIPs[*]`, or `spec.externalIPs[*]`
- **External IP**: When the IP doesn't match any Kubernetes resource

The matching logic is configured in the [Flow Attributes](../configuration/attributes.md) configuration. When a match is found, additional Kubernetes metadata fields (like `source.k8s.pod.name`) are populated.

## TCP-Specific Fields

| Field Name | Data Type | Description | Notes |
|------------|----------|-------------|-------|
| `flow.tcp.flags.bits` | `long` | Integer representation of all TCP flags seen | Accumulated across entire flow lifetime |
| `flow.tcp.flags.tags` | `string[]` | Array of TCP flag names | Example: `["SYN", "ACK"]` |
| `flow.tcp.handshake.latency` | `long` | TCP handshake latency (SYN to SYN/ACK) | Unit: nanoseconds |
| `flow.tcp.rndtrip.latency` | `long` | Full round-trip time | Unit: nanoseconds |
| `flow.tcp.svc.latency` | `long` | Application/service processing time | Unit: nanoseconds |

## Network Interface

| Field Name | Data Type | Description | Notes |
|------------|----------|-------------|-------|
| `network.interface.name` | `string` | Name of the network interface where flow was observed | |
| `network.interface.index` | `long` | Index value of the network interface | |

## Learn More

For the complete specification of all available fields, including tunnel attributes, ICMP fields, and performance metrics, see the [Semantic Conventions](../spec/semantic-conventions.md) document.
