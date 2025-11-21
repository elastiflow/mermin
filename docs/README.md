# Overview

Welcome to the Mermin documentation! Mermin is a powerful, Kubernetes-native network observability tool that uses eBPF to efficiently capture network traffic and export it as **Flow Traces** via the OpenTelemetry Protocol (OTLP). It provides deep visibility into your cluster's network communications with zero application changes required.

---

## Why Mermin?

### The Problem

Your APM traces show application behavior. Your network monitoring shows IP-level statistics. But there's a gap: when a trace shows a slow network span, you have no way to correlate that with actual network flow data. When network teams see congestion, they can't map it back to specific services or pods.

The MELT stack (Metrics, Events, Logs, Traces) is missing network flow data—connection-level information that bridges application performance with network reality.

### What Mermin Does

Mermin captures network traffic using eBPF and exports it as **Flow Traces**—network flows represented as OpenTelemetry spans. This brings network visibility into the OTel ecosystem using a standard signal type.

**The "Sweet Spot": Why Flow Data?**

Observability involves trade-offs between granularity and overhead. Flow data sits between two extremes:

- **Not Raw PCAP**: Full packet capture is expensive to store and query. Mermin aggregates packets into flows—you get connection-level detail without payload overhead.
- **Not Just Counters**: Metrics tell you bandwidth usage but miss connection context—timing, retransmissions, directionality.

Flow data provides **granular, connection-level detail that's lightweight enough to run always-on in production.**

## What are Flow Traces?

Flow Traces are OpenTelemetry trace spans that represent network flows with NetFlow-like behavior. Unlike traditional NetFlow or IPFIX, Flow Traces leverage the OpenTelemetry standard, providing bidirectional flow statistics, rich Kubernetes metadata, and native integration with modern observability platforms.

## Quick Start

The fastest way to get started with Mermin is to deploy it to a local Kubernetes cluster using our quickstart guide:

**[📚 Follow the Complete Quickstart Guide](getting-started/quickstart.md)**

Or deploy directly with Helm:

```shell
helm repo add elastiflow https://elastiflow.github.io/mermin
helm install mermin elastiflow/mermin --namespace mermin --create-namespace
```

Once deployed, Mermin runs as a DaemonSet with one pod per node, automatically capturing network traffic and exporting Flow Traces to your configured OTLP endpoint.

## Key Capabilities

- **Auto-Instrumentation for Your Network Stack**: Just as eBPF-based APM tools auto-instrument application code, Mermin auto-instruments your network layer. Deploy once per node, get visibility into all traffic—no per-service configuration required.
- **Kubernetes-Native Enrichment**: Flows include Pod, Service, and Deployment metadata. You see `frontend-service` → `redis-cache`, not `10.42.0.5` → `10.42.0.8`.
- **Zero Code Changes**: eBPF captures traffic transparently—no sidecars, no application modifications, no service mesh required.
- **Standards-Based Export**: Native OTLP output integrates with your existing observability stack (Tempo, Jaeger, Elastic, etc.).
- **Production-Ready**: Low-overhead kernel-level capture designed for always-on operation.
- **Comprehensive Protocol Support**: Parses and tracks TCP, UDP, ICMP traffic, with support for common tunneling protocols (VXLAN, Geneve, WireGuard).
- **Flexible Filtering**: Configure fine-grained filters to control which network flows are captured and exported.

## How It Compares

| Feature                | Mermin             | eBPF APM Agents      | Traditional NetFlow/IPFIX | Service Mesh (Istio/Linkerd) | Packet Capture Tools  |
|------------------------|--------------------|----------------------|---------------------------|------------------------------|-----------------------|
| Kubernetes Context     | ✅ Native           | ✅ Native             | ❌ None                    | ✅ Native                     | ❌ None                |
| Application Changes    | ✅ Zero             | ✅ Zero               | ✅ Zero                    | ❌ Sidecar injection          | ✅ Zero                |
| Network Data Type      | ✅ Flow Records     | ❌ Counters only      | ✅ Flow Records            | ⚠️ Request/response           | ✅ Full packets        |
| Connection Context     | ✅ Full details     | ❌ Aggregated metrics | ✅ Full details            | ⚠️ L7 only                    | ✅ Full packets        |
| Performance Overhead   | ✅ Minimal (eBPF)   | ✅ Minimal (eBPF)     | ✅ Low                     | ⚠️ Moderate (sidecars)        | ❌ High (full capture) |
| Standards-Based Export | ✅ OTLP Traces      | ⚠️ OTLP Metrics       | ⚠️ NetFlow/IPFIX           | ⚠️ Prometheus/vendor-specific | ❌ PCAP files          |
| Bidirectional Flows    | ✅ Yes              | ❌ Separate counters  | ✅ Yes                     | ⚠️ Limited                    | ❌ Packet-level only   |
| Deployment Complexity  | ✅ Simple DaemonSet | ✅ Simple DaemonSet   | ✅ Simple                  | ⚠️ Complex                    | ✅ Simple              |

**Key Differentiators:**

- **vs eBPF APM Agents**: Exports flow records (with timing, flags, directionality) as traces, not aggregated counter metrics
- **vs NetFlow/IPFIX**: Adds Kubernetes context and uses modern OTLP standard
- **vs Service Meshes**: No application changes, lower overhead, but L3/L4 only (not L7)
- **vs Packet Capture**: Aggregated flows instead of raw packets, with metadata enrichment

## What You Can Expect

This documentation is designed to help you successfully deploy, configure, and operate Mermin in your environment. You'll find:

- [**Quick Start Guide**](getting-started/quickstart.md): Get Mermin running in minutes on a local Kubernetes cluster.
- [**Architecture Overview**](getting-started/architecture.md): Understand how Mermin works and its data flow.
- [**Deployment Guides**](deployment/deployment.md): Detailed instructions for various deployment scenarios (Kubernetes, cloud platforms, bare metal).
- [**Configuration Reference**](configuration/configuration.md): Comprehensive documentation of all configuration options.
- [**Observability Backends**](observability/backends.md): Understand how to send Flow Traces to Elastic, Grafana Tempo, Jaeger, and other OTLP-compatible platforms.
- [**Troubleshooting**](troubleshooting/troubleshooting.md): Solutions to common issues and diagnostic approaches
- [**Development Guides**](development/contributor-guide.md): Build, test, and contribute to Mermin

## Development & Contributing

For developers who want to contribute to Mermin or build it locally:

- [**Contributor Guide**](development/contributor-guide.md): Complete guide for setting up your development environment
- [**Debugging eBPF Programs**](development/debugging-ebpf.md): Advanced eBPF program inspection and optimization techniques
- [**Debugging Network Traffic**](development/debugging-network.md): Live packet capture with Wireshark

## System Requirements

Mermin requires:

- **Linux Kernel**: Version 5.14 or newer with eBPF support enabled
- **Kubernetes**: Version 1.20 or newer (for Kubernetes deployments)
- **Container Runtime**: Docker, containerd, or CRI-O
- **Privileges**: Requires privileged mode to load eBPF programs and access network interfaces

## Architecture at a Glance

Mermin operates as a DaemonSet in Kubernetes (or as a privileged container on bare metal), with one instance running on each node:

1. **Packet Capture**: eBPF programs attached to network interfaces capture packets at the kernel level.
2. **Flow Aggregation**: Packets are aggregated into bidirectional network flows with connection state tracking.
3. **Metadata Enrichment**: Flows are decorated with Kubernetes metadata (pods, services, deployments, labels).
4. **Flow Traces Export**: Flows are converted to OpenTelemetry trace spans and exported via OTLP
5. **Observability Backend**: Flow Traces are stored, analyzed, and visualized in your platform (Elastic, Grafana Tempo, Jaeger, etc.)

## Getting Help

If you encounter issues or have questions:

- [**GitHub Issues**](https://github.com/elastiflow/mermin/issues): Report bugs or request features.
- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask questions and engage with the community.
- [**Slack Channel**](https://join.slack.com/t/elastiflowcommunity/shared_invite/zt-23jpnlw9g-Q4nKOwKKOE1N2MjfA2mXpg): Live chat with us or other beta users.
- [**Troubleshooting Guide**](troubleshooting/troubleshooting.md): Check common issues and solutions.

## Next Steps

Ready to get started? Follow our [**Quick Start Guide**](getting-started/quickstart.md) to deploy Mermin on a local Kubernetes cluster in minutes.

For production deployments, review the [**Deployment Overview**](deployment/deployment.md) to understand your deployment options and best practices.
