# Architecture

This page explains how Mermin works, its architecture, and the flow of data from network packets to Flow Traces in your observability backend.

## What are Flow Traces?

**Flow Traces** are OpenTelemetry trace spans that represent network flows with NetFlow-like semantics. Unlike traditional NetFlow or IPFIX:

- **OpenTelemetry Native**: Flow Traces are OTLP trace spans, not proprietary flow protocols
- **Bidirectional**: A single span represents both directions of a flow
- **Rich Metadata**: Includes Kubernetes context (pods, services, deployments, labels)
- **Standardized Format**: Works with any OTLP-compatible observability platform

Mermin generates Flow Traces by capturing network packets, aggregating them into flows, enriching with Kubernetes metadata, and exporting as OpenTelemetry spans.

## High-Level Architecture

Mermin is deployed as a DaemonSet in Kubernetes, with one agent instance running on each node in your cluster. Each agent independently captures and processes network traffic from its host node.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                       │
│                                                                  │
│  ┌──────────────┐         ┌──────────────┐                     │
│  │    Node 1    │         │    Node 2    │                     │
│  │              │         │              │                     │
│  │  ┌────────┐  │         │  ┌────────┐  │                     │
│  │  │ Mermin │  │         │  │ Mermin │  │                     │
│  │  │ Agent  │  │         │  │ Agent  │  │                     │
│  │  └───┬────┘  │         │  └───┬────┘  │                     │
│  │      │ eBPF  │         │      │ eBPF  │                     │
│  │      ↓       │         │      ↓       │                     │
│  │  [Network]   │         │  [Network]   │                     │
│  │  [Packets]   │         │  [Packets]   │                     │
│  └──────────────┘         └──────────────┘                     │
│         │                        │                              │
│         └────────────┬───────────┘                              │
│                      │ OTLP                                     │
└──────────────────────┼──────────────────────────────────────────┘
                       ↓
              ┌─────────────────┐
              │ OpenTelemetry   │
              │   Collector     │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
   ┌────────┐    ┌─────────┐    ┌────────┐
   │Elastic │    │ Grafana │    │ Jaeger │
   │ Stack  │    │  Tempo  │    │        │
   └────────┘    └─────────┘    └────────┘
```

## Components

### eBPF Programs

Mermin uses eBPF (extended Berkeley Packet Filter) programs loaded into the Linux kernel to capture network packets with minimal overhead. These programs:

- Attach to network interfaces specified in your configuration
- Capture packets at the TC (Traffic Control) layer
- Perform initial packet parsing for protocol headers
- Send packet data to userspace via eBPF ring buffers

eBPF provides several advantages:

- **High Performance**: Executes directly in the kernel, avoiding context switches
- **Low Overhead**: Processes only necessary packet headers, not full payloads
- **Safety**: Verified by the kernel to ensure it cannot crash or hang the system
- **No Kernel Modules**: No need to compile or load custom kernel modules

### Flow Generation Engine

The userspace Mermin agent receives packets from eBPF and aggregates them into network flows:

- **Bidirectional Flows**: Groups packets by 5-tuple (source IP/port, dest IP/port, protocol)
- **State Tracking**: Maintains connection state for TCP (SYN, FIN, RST flags)
- **Timeout Management**: Expires inactive flows based on configurable timeouts
- **Protocol Parsing**: Deep packet inspection for tunneling protocols (VXLAN, Geneve, WireGuard)
- **Community ID**: Generates standard Community ID hashes for flow correlation

A flow record includes:

- Source and destination IP addresses and ports
- Network protocol (TCP, UDP, ICMP, etc.)
- Packet and byte counters (bidirectional)
- TCP flags and connection state
- Flow start and end timestamps
- Community ID hash

### Kubernetes Integration

Mermin deeply integrates with Kubernetes to enrich flows with contextual metadata:

#### Informers

Mermin uses Kubernetes informers (watch APIs) to maintain an in-memory cache of cluster resources:

- Pods, Services, Deployments, ReplicaSets, StatefulSets, DaemonSets
- Jobs, CronJobs, NetworkPolicies
- Endpoints, EndpointSlices, Ingresses, Gateways

This cache is continuously updated as resources change, ensuring metadata is always current.

#### Flow Attribution

For each network flow, Mermin:

1. **Identifies Pods**: Matches source/destination IPs to pod IPs
2. **Extracts Metadata**: Retrieves pod name, namespace, labels, annotations
3. **Walks Owner References**: Follows ownerReferences from Pod → ReplicaSet → Deployment
4. **Selector Matching**: Finds Services and NetworkPolicies that select the pod
5. **Enriches Flows**: Attaches all relevant metadata to the flow record

This provides full context for each network flow, enabling powerful filtering and analysis.

### OTLP Exporter

Mermin exports enriched flows as **Flow Traces** using the OpenTelemetry Protocol (OTLP):

- **Flow Traces as Spans**: Each network flow becomes an OpenTelemetry trace span
- **Standard Protocol**: OTLP is an industry-standard telemetry protocol
- **Flexible Transport**: Supports both gRPC and HTTP protocols
- **Batching**: Aggregates multiple Flow Traces before sending to reduce network overhead
- **Backpressure Handling**: Queues Flow Traces if the backend is unavailable
- **Authentication**: Supports Basic Auth, TLS client certificates
- **Secure Transport**: TLS encryption with custom CA certificate support

Flow Traces are exported as OTLP trace spans, allowing them to be processed by any OTLP-compatible backend without requiring NetFlow collectors.

## Data Flow

Let's trace a network packet through Mermin's pipeline:

### 1. Packet Capture (eBPF)

```
Network Interface (eth0)
         ↓
   TC Hook (eBPF)
         ↓
   Parse Headers (IP, TCP/UDP, Tunnels)
         ↓
   Ring Buffer
```

- eBPF program attached to `eth0` captures incoming and outgoing packets
- Parses Ethernet, IP, TCP/UDP, and tunnel protocol headers
- Extracts 5-tuple and other flow identifiers
- Sends packet metadata to userspace via ring buffer (not full payload)

### 2. Flow Aggregation (Userspace)

```
Ring Buffer Reader
         ↓
   Flow Table Lookup
         ↓
   Update Flow State
         ↓
   Check Timeout/Completion
```

- Mermin reads packet metadata from ring buffer
- Looks up existing flow in flow table by 5-tuple
- Updates packet/byte counters, flags, timestamps
- Checks if flow should be exported (timeout, connection close, max duration)

### 3. Kubernetes Enrichment

```
Flow Ready for Export
         ↓
   IP to Pod Lookup
         ↓
   Extract Pod Metadata
         ↓
   Walk Owner References
         ↓
   Match Selectors
         ↓
   Enriched Flow Record
```

- Source IP: `10.244.1.5` → Pod: `nginx-abc123` → ReplicaSet: `nginx-xyz` → Deployment: `nginx`
- Destination IP: `10.96.0.1` → Service: `kubernetes`
- Attaches labels, annotations, namespace, and other metadata

### 4. OTLP Export

```
Enriched Flow
         ↓
   Batch Accumulator
         ↓
   OTLP Trace Span
         ↓
   gRPC/HTTP Transport
         ↓
   OpenTelemetry Collector
```

- Flow is converted to an OTLP trace span (Flow Trace)
- Batched with other Flow Traces to reduce network overhead
- Sent to configured OTLP endpoint
- Collector receives and processes the Flow Traces

## Performance Characteristics

### Resource Usage

Mermin is designed to be efficient in production environments:

- **CPU**: Typically 0.1-0.5 cores per agent, varies with traffic volume
- **Memory**: Base usage ~100-200 MB, grows with flow table size
- **Network**: Outbound OTLP traffic depends on flow rate and batching settings
- **Kernel**: eBPF programs have minimal impact (< 1% CPU overhead)

### Scalability

- **Flow Rate**: Can handle 10,000+ flows/second per agent on modern hardware
- **Packet Rate**: Processes 100,000+ packets/second with minimal packet loss
- **Cluster Size**: Scales linearly – each node runs its own independent agent
- **Flow Table Size**: Configurable, defaults support ~100,000 concurrent flows

### Tunability

Mermin provides extensive configuration for performance tuning:

- `packet_channel_capacity`: Buffer size between eBPF and userspace
- `packet_worker_count`: Number of parallel flow processors
- `span.*_timeout`: Flow expiration times affect memory usage
- `export.otlp.max_batch_size`: Larger batches reduce network overhead
- `export.otlp.max_queue_size`: Backpressure buffer for slow backends

See [Configuration Reference](configuration/README.md) for details.

## Security Considerations

### Privileges Required

Mermin requires elevated privileges to operate:

- **Privileged Container**: Needed to load eBPF programs
- **Host Network**: Must access host network interfaces
- **Capabilities**: Requires `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_BPF`

These privileges are necessary for eBPF and cannot be reduced.

### Data Privacy

- **No Payload Capture**: Mermin only captures packet headers, not application data
- **Metadata Only**: Flow records contain IPs, ports, protocols – not packet contents
- **Configurable Filtering**: Filter out sensitive traffic before export
- **TLS Transport**: All OTLP exports can be encrypted with TLS

### RBAC

Mermin needs Kubernetes RBAC permissions to:

- Read pods, services, deployments, and other resources (for metadata enrichment)
- List and watch resources across all namespaces
- Access the Kubernetes API server

See the Helm chart's ClusterRole for the minimal required permissions.

## Failure Modes and Resilience

### Agent Failure

If a Mermin agent crashes or is terminated:

- **Local Impact Only**: Only flows from that node are affected
- **Kubernetes Restart**: DaemonSet controller automatically restarts the pod
- **No Data Loss**: Flow state is ephemeral; new flows are captured after restart
- **No Cluster Impact**: Other nodes continue operating normally

### Backend Unavailability

If the OTLP backend is unavailable:

- **Queuing**: Flows are queued up to `max_queue_size`
- **Backpressure**: If queue fills, oldest flows are dropped (not newest)
- **Automatic Retry**: Mermin retries failed exports with exponential backoff
- **Graceful Degradation**: Agent continues capturing flows

### Network Issues

- **Interface Unavailable**: Mermin logs a warning and continues monitoring other interfaces
- **eBPF Load Failure**: Agent fails to start; check kernel version and eBPF support
- **High Packet Loss**: Increase `packet_channel_capacity` or reduce monitored interfaces

## Comparison with Alternatives

### vs. Packet Capture Tools (tcpdump, Wireshark)

- **Mermin**: Continuous, structured flow records with K8s metadata
- **tcpdump**: Manual, per-packet capture without flow aggregation

### vs. Service Mesh (Istio, Linkerd)

- **Mermin**: No application changes, captures all traffic (including host network)
- **Service Mesh**: Requires sidecar injection, limited to mesh traffic

### vs. NetFlow/IPFIX Exporters

- **Mermin Flow Traces**: OpenTelemetry spans with K8s metadata, OTLP export, modern observability stack integration
- **Traditional NetFlow/IPFIX**: Legacy protocols, no K8s metadata, requires specialized collectors, limited backend options

### vs. eBPF Observability Tools (Cilium Hubble, Pixie)

- **Mermin**: Lightweight, OTLP-focused, flexible backend integration
- **Others**: Often tightly coupled to specific platforms or backends

## Next Steps

Now that you understand how Mermin generates Flow Traces:

1. **[Deploy to Production](deployment/README.md)**: Choose your deployment model
2. **[Configure Mermin](configuration/README.md)**: Customize for your environment
3. **[Integrate with Backends](integrations/README.md)**: Send Flow Traces to your observability platform
4. **[Troubleshoot Issues](troubleshooting/README.md)**: Diagnose and resolve problems
