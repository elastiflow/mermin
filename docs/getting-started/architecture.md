---
hidden: true
---

# Architecture

This page explains how Mermin works, its architecture, and the flow of data from network packets to Flow Traces in your observability backend.

## What are Flow Traces?

**Flow Traces** are OpenTelemetry trace spans that represent network flows with NetFlow-like semantics. Unlike traditional NetFlow or IPFIX:

* **OpenTelemetry Native**: Flow Traces are OTLP trace spans, not proprietary flow protocols
* **Bidirectional**: A single span represents both directions of a flow
* **Rich Metadata**: Includes Kubernetes context (pods, services, deployments, labels)
* **Standardized Format**: Works with any OTLP-compatible observability platform

Mermin generates Flow Traces by capturing network packets, aggregating them into flows, decorating with Kubernetes metadata, and exporting as OpenTelemetry spans.

## High-Level Architecture

Mermin is deployed as a DaemonSet in Kubernetes, with one agent instance running on each node in your cluster. Each agent independently captures and processes network traffic from its host node.

```
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

### eBPF Programs

Mermin uses eBPF (extended Berkeley Packet Filter) programs loaded into the Linux kernel to capture network packets with minimal overhead. These programs:

* Attach to network interfaces specified in your configuration
* Capture packets at the TC (Traffic Control) layer
* Perform initial packet parsing for protocol headers
* Send packet data to userspace via eBPF ring buffers

eBPF provides several advantages:

* **High Performance**: Executes directly in the kernel, avoiding context switches
* **Low Overhead**: Processes only necessary packet headers, not full payloads
* **Safety**: Verified by the kernel to ensure it cannot crash or hang the system
* **No Kernel Modules**: No need to compile or load custom kernel modules

### Flow Generation Engine

The userspace Mermin agent receives packets from eBPF and aggregates them into network flows:

* **Bidirectional Flows**: Groups packets by 5-tuple (source IP/port, dest IP/port, protocol)
* **State Tracking**: Maintains connection state for TCP (SYN, FIN, RST flags)
* **Timeout Management**: Expires inactive flows based on configurable timeouts
* **Protocol Parsing**: Deep packet inspection for tunneling protocols (VXLAN, Geneve, WireGuard)
* **Community ID**: Generates standard Community ID hashes for flow correlation

A Flow Trace includes:

* Source and destination IP addresses and ports
* Network protocol (TCP, UDP, ICMP, etc.)
* Packet and byte counters (bidirectional)
* TCP flags and connection state
* Flow start and end timestamps
* Community ID hash

// TODO: LINK TO FLOW TRACE SPEC

#### State Persistence

Mermin preserves flow state across pod restarts through eBPF map pinning, ensuring continuous visibility without data loss:

* **Map Pinning**: `FLOW_STATS_MAP` and `FLOW_EVENTS` are pinned to `/sys/fs/bpf/` when writable (requires `/sys/fs/bpf` hostPath mount)
* **Schema Versioning**: Maps use versioned paths (e.g., `mermin_flow_stats_map_v1`) to prevent incompatible format reuse across upgrades
* **State Continuity**: Flow statistics persist across mermin restarts, eliminating visibility gaps during rolling updates
* **Format Validation**: Pinned maps are reused only if schema version and format match current version
* **Graceful Degradation**: If pinning fails, mermin continues with unpinned maps (logged as warning)
* **Upgrade Safety**: When struct layouts change, increment `EBPF_MAP_SCHEMA_VERSION` to create new versioned maps

This ensures:

* *No flow data loss during pod restarts or rolling updates
* *Existing flows continue to accumulate statistics across restarts
* *Safe upgrades without corrupt data reuse
* *Easy rollbacks (old map versions remain available)

### Kubernetes Integration

Mermin deeply integrates with Kubernetes to decorate flows with contextual metadata:

#### Informers

Mermin uses Kubernetes informers (watch APIs) to maintain an in-memory cache of cluster resources:

* Pods, Services, Deployments, ReplicaSets, StatefulSets, DaemonSets
* Jobs, CronJobs, NetworkPolicies
* Endpoints, EndpointSlices, Ingresses, Gateways

This cache is continuously updated as resources change, ensuring metadata is always current.

#### Flow Attribution

For each network flow, Mermin:

1. **Identifies Pods**: Matches source/destination IPs to pod IPs
2. **Extracts Metadata**: Retrieves pod name, namespace, labels, annotations
3. **Walks Owner References**: Follows ownerReferences from Pod → ReplicaSet → Deployment
4. **Selector Matching**: Finds Services and NetworkPolicies that select the pod
5. **Decorates Traces**: Attaches all relevant metadata to the Flow Trace

This provides full context for each network flow, enabling powerful filtering and analysis.

### OTLP Exporter

Mermin exports flows as **Flow Traces** using the OpenTelemetry Protocol (OTLP):

* **Flow Traces as Spans**: Each network flow becomes an OpenTelemetry trace span
* **Standard Protocol**: OTLP is an industry-standard telemetry protocol
* **Flexible Transport**: Supports both gRPC and HTTP protocols
* **Batching**: Aggregates multiple Flow Traces before sending to reduce network overhead
* **Backpressure Handling**: Queues Flow Traces if the backend is unavailable
* **Authentication**: Supports Basic Auth, TLS client certificates
* **Secure Transport**: TLS encryption with custom CA certificate support

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

* eBPF program attached to `eth0` captures incoming and outgoing packets
* Parses Ethernet, IP, TCP/UDP, and tunnel protocol headers
* Extracts 5-tuple and other flow identifiers
* Sends packet metadata to userspace via ring buffer (not full payload)

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

* Mermin reads packet metadata from ring buffer
* Looks up existing flow in flow table by 5-tuple
* Updates packet/byte counters, flags, timestamps
* Checks if flow should be exported (timeout, connection close, max duration)

### 3. Kubernetes Decoration

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
   Decorate Trace Record
```

* Source IP: `10.244.1.5` → Pod: `nginx-abc123` → ReplicaSet: `nginx-xyz` → Deployment: `nginx`
* Destination IP: `10.96.0.1` → Service: `kubernetes`
* Attaches labels, annotations, namespace, and other metadata

### 4. OTLP Export

```
Trace Flow
         ↓
   Batch Accumulator
         ↓
   OTLP Trace Span
         ↓
   gRPC/HTTP Transport
         ↓
   OpenTelemetry Collector
```

* Flow is converted to an OTLP trace span (Flow Trace)
* Batched with other Flow Traces to reduce network overhead
* Sent to configured OTLP endpoint
* Collector receives and processes the Flow Traces

## Performance Characteristics

### Resource Usage

Mermin is designed to be efficient in production environments:

* **CPU**: Typically 0.1-0.5 cores per agent, varies with traffic volume
* **Memory**: Base usage \~100-200 MB, grows with flow table size
* **Network**: Outbound OTLP traffic depends on flow rate and batching settings
* **Kernel**: eBPF programs have minimal impact (< 1% CPU overhead)

### Scalability

* **Flow Rate**: Can handle 10,000+ flows/second per agent on modern hardware
* **Packet Rate**: Processes 100,000+ packets/second with minimal packet loss
* **Cluster Size**: Scales linearly – each node runs its own independent agent
* **Flow Table Size**: Configurable, defaults support \~100,000 concurrent flows

### Tunability

Mermin provides extensive configuration for performance tuning under the `pipeline` block:

* `pipeline.ring_buffer_capacity`: eBPF ring buffer size between kernel and userspace
* `pipeline.worker_count`: Number of parallel flow worker threads
* `pipeline.k8s_decorator_threads`: Dedicated threads for Kubernetes metadata decoration
* `span.*_timeout`: Flow expiration times affect memory usage
* `export.otlp.max_batch_size`: Larger batches reduce network overhead
* `export.otlp.max_queue_size`: Backpressure buffer for slow backends

See [Configuration Reference](../configuration/configuration.md) for details.

## Security Considerations

### Host Mounts Required

#### TCX Mode and BPF Filesystem (Kernel >= 6.6)

{% hint style="info" %}
**Linux Kernel 6.6+** introduced TCX (TC eXpress), an improved TC attachment mechanism that supports multiple programs per hook. Mermin automatically uses TCX when available.
{% endhint %}

For **orphan cleanup support** on pod restarts (highly recommended for production), mount `/sys/fs/bpf` as a hostPath volume is required.
When a Mermin pod crashes unexpectedly (OOM, node failure, etc.), its TC programs remain attached to interfaces. On restart, Mermin can clean up these "orphaned" programs by loading pinned links from `/sys/fs/bpf`.

**Verifying TCX mode:**

Check Mermin logs on startup:

```bash
kubectl logs <mermin-pod> | grep tcx_mode
# Should show: kernel.tcx_mode=true (kernel >= 6.6)
```

**For older kernels (< 6.6):** Mermin uses netlink-based TC attachment, which includes automatic orphan cleanup without requiring `/sys/fs/bpf`.

### Privileges Required

Mermin requires elevated privileges to operate:

* **Host PID Namespace**: Required to access `/proc/1/ns/net` for namespace switching
* **Linux Capabilities**: Requires specific capabilities instead of full privileged mode:
  * `CAP_NET_ADMIN` - Attach TC (traffic control) programs to network interfaces
  * `CAP_BPF` - Load eBPF programs (kernel 5.8+)
  * `CAP_PERFMON` - Access eBPF ring buffers (kernel 5.8+)
  * `CAP_SYS_ADMIN` - Switch network namespaces and access BPF filesystem
  * `CAP_SYS_PTRACE` - Access other processes' namespace files (`/proc/1/ns/net`)
  * `CAP_SYS_RESOURCE` - Increase memlock limits for eBPF maps

#### Network Namespace Switching

Mermin uses a sophisticated approach to monitor host network interfaces without requiring `hostNetwork: true`:

1. **Startup**: Mermin starts in its own pod network namespace
2. **Attachment**: Temporarily switches to host network namespace to attach eBPF programs
3. **Operation**: Switches back to pod namespace for all other operations

This approach provides:

* **Network isolation**: Pod has its own network namespace
* **Kubernetes DNS**: Can resolve service names for OTLP endpoints
* **Host monitoring**: eBPF programs remain attached to host interfaces

The eBPF programs execute in kernel space and remain attached regardless of the userspace process's namespace.

### Data Privacy

* **No Payload Capture**: Mermin only captures packet headers, not application data
* **Metadata Only**: Flow records contain IPs, ports, protocols – not packet contents
* **Configurable Filtering**: Filter out sensitive or noisy traffic before export
* **TLS Transport**: All OTLP exports can be encrypted with TLS

### RBAC

Mermin needs Kubernetes RBAC permissions to:

* Read pods, services, deployments, and other resources (for metadata enrichment)
* List and watch resources across all namespaces
* Access the Kubernetes API server

See the Helm chart's ClusterRole for the minimal required permissions.

## Failure Modes and Resilience

### Agent Failure

If a Mermin agent crashes or is terminated:

* **Local Impact Only**: Only flows from that node are affected
* **Kubernetes Restart**: DaemonSet controller automatically restarts the pod
* **No Data Loss**: Flow state is ephemeral; new flows are captured after restart
* **No Cluster Impact**: Other nodes continue operating normally

### Backend Unavailability

If the OTLP backend is unavailable:

* **Queuing**: Flows are queued up to `max_queue_size`
* **Backpressure**: If queue fills, oldest flows are dropped (not newest)
* **Automatic Retry**: Mermin retries failed exports with exponential backoff
* **Graceful Degradation**: Agent continues capturing flows

### Network Issues

* **Interface Unavailable**: Mermin logs a warning and continues monitoring other interfaces
* **eBPF Load Failure**: Agent fails to start; check kernel version and eBPF support
* **High Packet Loss**: Increase `pipeline.ring_buffer_capacity` or reduce monitored interfaces

## Comparison with Alternatives

### vs. eBPF Observability Tools (Cilium Hubble, Pixie)

**Mermin provides:**

* **Flow-level granularity**: Every individual network flow exported as a Flow Trace with full metadata
* **CNI Agnostic**: Not tied to a specific CNI implementation (works with Cilium, Calico, Flannel, etc.)
* Pure OTLP export to any OpenTelemetry-compatible backend
* Lightweight, focused solely on network flow observability
* No vendor lock-in or platform dependencies
* Flexible backend choice (Elastic, Grafana, Jaeger, cloud providers)
* Historical flow analysis and long-term storage in your observability backend

**Cilium Hubble provides:**

* Aggregated network metrics (connection rates, error rates, latencies)
* Deep integration with Cilium CNI and network policies
* Service map visualization with Hubble UI
* Layer 7 protocol visibility (HTTP, gRPC, Kafka, DNS)
* Requires Cilium as the CNI
* Limited historical data retention (ephemeral, in-memory)

**Pixie provides:**

* Aggregated network metrics with short-term retention
* Full application observability (traces, logs, metrics, profiling)
* Auto-instrumentation for multiple languages
* In-cluster data processing and querying
* Requires Pixie platform deployment
* Limited long-term storage (auto-deletes data after hours/days)

**Key Insight:** **Mermin is the only tool that provides flow-level granularity** - each individual network flow becomes a Flow Trace with complete metadata (source/dest pods, services, deployments, labels, packet/byte counts, TCP flags, etc.). Hubble and Pixie provide aggregated network metrics (requests/sec, error rates), which are useful for dashboards but don't give you the raw flow data needed for deep investigation, compliance, or security forensics.

**Trade-off:** Hubble and Pixie offer broader observability features (L7 protocols, application tracing) but with platform coupling and metric aggregation. Mermin prioritizes CNI/backend flexibility and flow-level detail, enabling long-term storage and granular analysis of every network connection.

### vs. NetFlow/IPFIX Exporters

**Mermin Flow Traces provide:**

* OpenTelemetry-native format (OTLP trace spans)
* Kubernetes metadata: pods, services, deployments, labels, owner references
* Modern observability backend integration (Tempo, Jaeger, Elastic, OpenSearch)
* No specialized NetFlow collectors required
* **CNI Agnostic**: Captures flows regardless of CNI implementation
* Cloud-native architecture (DaemonSet, Helm charts)

**Traditional NetFlow/IPFIX provides:**

* Established protocol with decades of tooling
* Hardware switch/router support
* Legacy network monitoring platform compatibility
* SNMP integration for traditional network management

**Trade-off:** NetFlow/IPFIX is ideal for traditional network infrastructure. Mermin is purpose-built for cloud-native Kubernetes environments with modern observability stacks.

### vs. Packet Capture Tools (tcpdump, Wireshark)

**Mermin provides:**

* Continuous, automated flow capture without manual intervention
* Bidirectional flow aggregation with packet/byte counters
* Kubernetes metadata enrichment (pods, services, deployments)
* Efficient OTLP export to any observability backend
* Production-ready with minimal performance overhead

**tcpdump/Wireshark provide:**

* Full packet payload capture for deep inspection
* Interactive analysis and filtering (Wireshark GUI)
* Protocol dissection for debugging specific issues
* Manual, on-demand troubleshooting

**Trade-off:** Use Mermin for continuous observability; use packet capture tools for deep troubleshooting of specific issues.

### vs. Service Mesh (Istio, Linkerd)

> **Note:** These are fundamentally different tools for different jobs. **Service meshes are for traffic management and security**. **Mermin is for network observability**. They are complementary, not alternatives.

**Mermin provides (Observability):**

* Network flow visibility across your entire cluster
* Zero application changes or sidecar injection required
* Captures all traffic: pod-to-pod, pod-to-external, host network, non-mesh workloads
* **CNI Agnostic**: Works with any CNI (Cilium, Calico, Flannel, cloud-native CNIs)
* Lower resource overhead (no sidecar per pod)
* Network-layer (L3/L4) flow telemetry

**Service Mesh provides (Traffic Management & Security):**

* Layer 7 (HTTP, gRPC) traffic control and policy enforcement
* Traffic management (retries, timeouts, circuit breaking, canary deployments)
* Mutual TLS encryption between services
* Service-to-service authorization and authentication
* Request routing and load balancing strategies
* (Also includes L7 observability metrics as a side benefit)

**Key Insight:** You can run Mermin alongside a service mesh. Mermin observes network flows (L3/L4) across all workloads, while the service mesh manages application traffic (L7) for enrolled services. Many organizations use both together.

## Next Steps

Now that you understand how Mermin generates Flow Traces:

1. [**Deploy to Production**](../deployment/deployment.md): Choose your deployment model
2. [**Configure Mermin**](../configuration/configuration.md): Customize for your environment
3. [**Choose Your Backend**](../observability/backends.md): Send Flow Traces to your observability platform
4. [**Troubleshoot Issues**](../troubleshooting/troubleshooting.md): Diagnose and resolve problems
