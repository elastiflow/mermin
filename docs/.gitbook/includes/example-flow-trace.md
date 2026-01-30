---
title: Flow Trace Example - OTLP JSON Format
---

Below is an example of what a flow span might look like in OTLP JSON format.

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
