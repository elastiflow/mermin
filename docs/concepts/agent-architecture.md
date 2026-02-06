# Mermin Agent Architecture

Understand how Mermin works, its architecture, and the data flow from network packets to Flow Traces in your observability backend.

## What are Flow Traces?

**Flow Traces** are OpenTelemetry traces, which are combined from multiple Flow Trace Spans and represent a long-lived connection.
**Flow Trace Spans** are OpenTelemetry trace spans that represent network flows with NetFlow-like semantics. Unlike traditional NetFlow or IPFIX:

- **OpenTelemetry Native**: Flow Traces are OTLP trace spans, not proprietary flow protocols
- **Bidirectional**: A single span represents both directions of a flow
- **Rich Metadata**: Includes Kubernetes context (pods, services, deployments, labels)
- **Standardized Format**: Works with any OTLP-compatible observability platform

Mermin generates Flow Trace Spans by capturing network packets, aggregating them into flows, decorating with Kubernetes metadata, and exporting as OpenTelemetry spans.

```text
network packet → Mermin → flow span (network flow) → flow trace (network connection)
```

## High-Level Architecture

Mermin deploys as a DaemonSet in Kubernetes, with one agent instance per node. Each agent independently captures and processes network traffic from its host node.

```text
┌─────────────────────────────────────────────┐
│             Kubernetes Cluster              │
│                                             │
│  ┌──────────────┐         ┌──────────────┐  │
│  │    Node 1    │         │    Node 2    │  │
│  │              │         │              │  │
│  │  ┌────────┐  │         │  ┌────────┐  │  │
│  │  │ Mermin │  │         │  │ Mermin │  │  │
│  │  │ Agent  │  │         │  │ Agent  │  │  │
│  │  └───┬────┘  │         │  └───┬────┘  │  │
│  │      │ eBPF  │         │      │ eBPF  │  │
│  │      ↓       │         │      ↓       │  │
│  │  [Network]   │         │  [Network]   │  │
│  │  [Packets]   │         │  [Packets]   │  │
│  └──────────────┘         └──────────────┘  │
│         │                        │          │
│         └────────────┬───────────┘          │
│                      │ OTLP                 │
└──────────────────────┼──────────────────────┘
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

Data pipeline overview, more details on the pipeline are documented in the [data-flow block](agent-architecture.md#data-flow)

```text
            <kernel space>
              eBPF TC
                  ↓
          Network Interface
            ↓           ↓
            <kernel space>
Flow Stats (hashmap)   Flow Events (ring buffer)   Listening Ports (hashmap)
            <user space>
                  ↓
            Flow Producer
                  ↓
            K8s Decorator
                  ↓
            OTLP Export
```

### eBPF Programs

Mermin uses [eBPF](https://ebpf.io/what-is-ebpf/) (extended Berkeley Packet Filter) programs loaded into the Linux kernel to capture network packets with minimal overhead. These programs:

- Attach to network interfaces specified in your configuration
- Capture packets at the TC (Traffic Control) layer
- Aggregate packet data into flow statistics within the `FLOW_STATS` eBPF HashMap
- Notify userspace of new flows via the `FLOW_EVENTS` ring buffer
- Track listening ports (servers) in the `LISTENING_PORTS` eBPF HashMap for client/server direction inference
- For encapsulated or tunneled packets, send inner packet headers to userspace via `FLOW_EVENTS` for decoding

<details>

<summary><b>eBPF provides several advantages</b></summary>

- **High Performance**: Executes directly in the kernel, avoiding context switches
- **Low Overhead**: Processes only necessary packet headers, not full payloads
- **Safety**: Verified by the kernel to ensure it cannot crash or hang the system
- **No Kernel Modules**: No need to compile or load custom kernel modules

</details>

### Flow Span Generation Engine

The userspace Mermin agent receives packets from eBPF and aggregates them into network flow trace spans:

- **Bidirectional Flow Spans**: Groups packets by 5-tuple (source IP/port, dest IP/port, protocol)
- **State Tracking**: Maintains connection state for TCP (SYN, FIN, RST flags)
- **Timeout Management**: Expires inactive flows based on [configurable timeouts](../configuration/reference/flow-span-producer.md)
- **Protocol Parsing**: Deep packet inspection for tunneling protocols (VXLAN, Geneve, WireGuard)
- **Community ID**: Generates standard [Community ID](https://github.com/corelight/community-id-spec) hashes — a deterministic identifier based on the flow's five-tuple that enables correlation across different monitoring points

A [Flow Trace Span](semantic-conventions.md) includes:

- Source and destination IP addresses and ports
- Network protocol (TCP, UDP, ICMP, etc.)
- Packet and byte counters (bidirectional)
- TCP flags and connection state
- Flow start and end timestamps
- Community ID hash

#### State Persistence

Mermin preserves flow state across pod restarts through eBPF map pinning, ensuring continuous visibility without data loss:

- **Map Pinning**: `FLOW_STATS`, `FLOW_EVENTS`, and `LISTENING_PORTS` maps are pinned to `/sys/fs/bpf/` when writable (requires `/sys/fs/bpf` mount, refer to the [security-considerations](security-considerations.md#host-mounts-required) document)
- **Schema Versioning**: Maps use versioned paths (e.g., `mermin_flow_stats_map_v1`) to prevent incompatible format reuse across upgrades
- **State Continuity**: Flow statistics and listening port data persist across mermin restarts, eliminating visibility gaps during rolling updates
- **Format Validation**: Pinned maps are reused only if schema version and format match current version
- **Graceful Degradation**: If pinning fails, mermin continues with unpinned maps (logged as warning)
- **Upgrade Safety**: When struct layouts change, increment `EBPF_MAP_SCHEMA_VERSION` to create new versioned maps

This ensures:

- No flow data loss during pod restarts or rolling updates
- Existing flows continue to accumulate statistics across restarts
- Listening port information is preserved for accurate direction inference
- Safe upgrades without corrupt data reuse
- Easy rollbacks (old map versions remain available)

### Kubernetes Integration

Mermin integrates with Kubernetes to decorate flows with contextual metadata:

#### Informers

Mermin uses Kubernetes informers (watch APIs) to maintain an in-memory cache of cluster resources:

- Pods, Services, Deployments, ReplicaSets, StatefulSets, DaemonSets
- Jobs, CronJobs, NetworkPolicies
- Endpoints, EndpointSlices, Ingresses, Gateways

The cache updates continuously as resources change, keeping metadata current.

#### Flow Attribution

For each network flow, Mermin:

1. **Identifies Pods**: Matches source/destination IPs to pod IPs
2. **Extracts Metadata**: Retrieves pod name, namespace, labels, annotations
3. **Walks Owner References**: Follows ownerReferences from Pod, for example `Pod → ReplicaSet → Deployment`
4. **Selector Matching**: Finds Services and NetworkPolicies that select the pod via its selectors.
5. **Decorates Traces**: Attaches all relevant metadata to the Flow Trace Span

This process provides full context for each network flow, enabling powerful filtering and analysis.

To learn more about attribution configuration options, see the [Kubernetes informer](../configuration/reference/kubernetes-informer-discovery.md) documentation.

### OTLP Exporter

Mermin exports flows as **Flow Traces** using the OpenTelemetry Protocol (OTLP):

- **Flow Traces as Spans**: Each network flow becomes an OpenTelemetry trace span
- **Standard Protocol**: OTLP is an industry-standard telemetry protocol (OTel [docs](https://opentelemetry.io/docs/), [vendors](https://opentelemetry.io/ecosystem/vendors/))
- **Flexible Transport**: Supports both gRPC and HTTP protocols
- **Batching**: Aggregates multiple Flow Trace Spans before sending to reduce network overhead
- **Backpressure Handling**: Queues Flow Traces if the backend is unavailable
- **Authentication**: Supports Basic Auth, TLS client certificates
- **Secure Transport**: TLS encryption with custom CA certificate support

Flow Traces are exported as OTLP trace spans, allowing them to be processed by any OTLP-compatible backend without requiring NetFlow collectors.

To learn more about the exporter configuration options, see the [OTLP exporter](../configuration/reference/opentelemetry-otlp-exporter.md) documentation.

## Performance Characteristics

### Resource Usage

Mermin operates efficiently in production environments:

- **CPU**: Typically 0.1-0.5 cores (100-500 mCPUs) per agent, varies with traffic volume
- **Memory**: Base usage ~100-200 MB, grows with flow table size
- **Network**: Outbound OTLP traffic depends on flow rate and batching settings
- **Kernel**: eBPF programs have minimal impact (< 1% CPU overhead)

### Scalability

- **Flow Rate**: Can handle 10,000+ flows/second per agent on modern hardware
- **Packet Rate**: Processes 100,000+ packets/second with minimal packet loss
- **Cluster Size**: Scales linearly – each node runs its own independent agent
- **Flow Table Size**: Configurable, defaults support ~100,000 concurrent flows

### Tunability

Mermin provides extensive configuration for performance tuning under the `pipeline` block, please refer the [pipeline](../configuration/reference/flow-processing-pipeline.md) documentation for the details.

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

## Comparison with Alternatives

### vs. eBPF Observability Tools (Cilium Hubble, Pixie)

**Mermin provides:**

- **Flow-level granularity**: Every individual network flow exported as a Flow Trace with full metadata
- **CNI Agnostic**: Not tied to a specific CNI implementation (works with Cilium, Calico, Flannel, etc.)
- Pure OTLP export to any OpenTelemetry-compatible backend
- Lightweight, focused solely on network flow observability
- No vendor lock-in or platform dependencies
- Flexible backend choice (Elastic, Grafana, Jaeger, cloud providers)
- Historical flow analysis and long-term storage in your observability backend

**Cilium Hubble provides:**

- Aggregated network metrics (connection rates, error rates, latencies)
- Deep integration with Cilium CNI and network policies
- Service map visualization with Hubble UI
- Layer 7 protocol visibility (HTTP, gRPC, Kafka, DNS)
- Requires Cilium as the CNI
- Limited historical data retention (ephemeral, in-memory)

**Pixie provides:**

- Aggregated network metrics with short-term retention
- Full application observability (traces, logs, metrics, profiling)
- Auto-instrumentation for multiple languages
- In-cluster data processing and querying
- Requires Pixie platform deployment
- Limited long-term storage (auto-deletes data after hours/days)

**Key Insight:** **Mermin is the only tool that provides flow-level granularity** - each individual network flow becomes a Flow Trace with complete metadata (source/dest pods,
services, deployments, labels, packet/byte counts, TCP flags, etc.). Hubble and Pixie provide aggregated network metrics (requests/sec, error rates), which are useful for dashboards
but don't give you the raw flow data needed for deep investigation, compliance, or security forensics.

**Trade-off:** Hubble and Pixie offer broader observability features (L7 protocols, application tracing) but with platform coupling and metric aggregation. Mermin prioritizes
CNI/backend flexibility and flow-level detail, enabling long-term storage and granular analysis of every network connection.

### vs. NetFlow/IPFIX Exporters

**Mermin Flow Traces provide:**

- OpenTelemetry-native format (OTLP trace spans)
- Kubernetes metadata: pods, services, deployments, labels, owner references
- Modern observability backend integration (Tempo, Jaeger, Elastic, OpenSearch)
- No specialized NetFlow collectors required
- **CNI Agnostic**: Captures flows regardless of CNI implementation
- Cloud-native architecture (DaemonSet, Helm charts)

**Traditional NetFlow/IPFIX provides:**

- Established protocol with decades of tooling
- Hardware switch/router support
- Legacy network monitoring platform compatibility
- SNMP integration for traditional network management

**Trade-off:** NetFlow/IPFIX is ideal for traditional network infrastructure. Mermin is purpose-built for cloud-native Kubernetes environments with modern observability stacks.

### vs. Packet Capture Tools (tcpdump, Wireshark)

**Mermin provides:**

- Continuous, automated flow capture without manual intervention
- Bidirectional flow aggregation with packet/byte counters
- Kubernetes metadata enrichment (pods, services, deployments)
- Efficient OTLP export to any observability backend
- Production-ready with minimal performance overhead

**tcpdump/Wireshark provide:**

- Full packet payload capture for deep inspection
- Interactive analysis and filtering (Wireshark GUI)
- Protocol dissection for debugging specific issues
- Manual, on-demand troubleshooting

**Trade-off:** Use Mermin for continuous observability; use packet capture tools for deep troubleshooting of specific issues.

### vs. Service Mesh (Istio, Linkerd)

> **Note:** These are fundamentally different tools for different jobs. **Service meshes are for traffic management and security**. **Mermin is for network observability**. They are complementary, not alternatives.

**Mermin provides (Observability):**

- Network flow visibility across your entire cluster
- Zero application changes or sidecar injection required
- Captures all traffic: pod-to-pod, pod-to-external, host network, non-mesh workloads
- **CNI Agnostic**: Works with any CNI (Cilium, Calico, Flannel, cloud-native CNIs)
- Lower resource overhead (no sidecar per pod)
- Network-layer (L3/L4) flow telemetry

**Service Mesh provides (Traffic Management & Security):**

- Layer 7 (HTTP, gRPC) traffic control and policy enforcement
- Traffic management (retries, timeouts, circuit breaking, canary deployments)
- Mutual TLS encryption between services
- Service-to-service authorization and authentication
- Request routing and load balancing strategies
- (Also includes L7 observability metrics as a side benefit)

**Key Insight:** You can run Mermin alongside a service mesh. Mermin observes network flows (L3/L4) across all workloads, while the service mesh manages application traffic (L7) for enrolled services. Many organizations use both together.

## Next Steps

Now that you understand how Mermin generates Flow Traces, choose your path:

{% tabs %}
{% tab title="Deploy" %}
1. [**Plan Your Production Deployment**](../deployment/overview.md): Resource allocation, security, and best practices
2. [**Review Security Considerations**](security-considerations.md): Understand required privileges and data privacy
{% endtab %}

{% tab title="Configure" %}
1. [**Master Configuration Options**](../configuration/overview.md): Network interfaces, metadata enrichment, and export
2. [**Connect to Your Backend**](../getting-started/backend-integrations.md): Send Flow Traces to Grafana, Elastic, or Jaeger
{% endtab %}

{% tab title="Troubleshoot" %}
1. [**Diagnose Common Issues**](../troubleshooting/troubleshooting.md): Pod logs, health checks, and metrics
2. [**Resolve eBPF Errors**](../troubleshooting/common-ebpf-errors.md): Quick reference for verifier failures
{% endtab %}
{% endtabs %}

### Join the Community

Have questions about the architecture or want to contribute?

- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask questions and share experiences
- [**Contribute to Mermin**](../CONTRIBUTING.md): Help improve the project
