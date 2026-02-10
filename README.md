<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/elastiflow-cloudinary/image/upload/v1762568258/mermin/Mermin_Primary_Logo_Gradient_Light_uljb3t.png">
    <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/elastiflow-cloudinary/image/upload/v1762568258/mermin/Mermin_Primary_Logo_Gradient_Dark_vmjdoq.png">
    <img alt="Mermin" src="https://res.cloudinary.com/elastiflow-cloudinary/image/upload/v1762568258/mermin/Mermin_Primary_Logo_Gradient_Dark_vmjdoq.png">
  </picture>
</h1>

**Mermin** is a powerful, Kubernetes-native network observability tool that uses eBPF to efficiently capture network traffic and export it as **Flow Traces** via the OpenTelemetry Protocol (OTLP). It provides deep visibility into your cluster's network communications with zero application changes required.

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

### Key Capabilities

- **Auto-Instrumentation for Your Network Stack**: Just as eBPF-based APM tools auto-instrument application code, Mermin auto-instruments your network layer. Deploy once per node, get visibility into all traffic—no per-service configuration required.
- **Kubernetes-Native Enrichment**: Flows include Pod, Service, and Deployment metadata. You see `frontend-service` → `redis-cache`, not `10.42.0.5` → `10.42.0.8`.
- **Zero Code Changes**: eBPF captures traffic transparently—no sidecars, no application modifications, no service mesh required.
- **Standards-Based Export**: Native OTLP output integrates with your existing observability stack (Tempo, Jaeger, Elastic, etc.).
- **Production-Ready**: Low-overhead kernel-level capture designed for always-on operation.

## Quick Start

The fastest way to get started with Mermin is to deploy it to a local Kubernetes cluster using our quickstart guide:

**[Follow the Complete Quickstart Guide](https://docs.mermin.dev/getting-started/quickstart-guide)**

Or deploy directly with Helm:

```shell
helm repo add elastiflow https://elastiflow.github.io/mermin
helm install mermin elastiflow/mermin --namespace mermin --create-namespace
```

Once deployed, Mermin runs as a DaemonSet with one pod per node, automatically capturing network traffic and exporting Flow Traces to your configured OTLP endpoint.

## How It Compares

| Feature                | Mermin                 | eBPF APM Agents        | Traditional NetFlow/IPFIX | Service Mesh (Istio/Linkerd) | Packet Capture Tools  |
|------------------------|------------------------|------------------------|---------------------------|------------------------------|-----------------------|
| Kubernetes Context     | ✅ Native               | ✅ Native               | ❌ None                    | ✅ Native                     | ❌ None                |
| Application Changes    | ✅ Zero                 | ✅ Zero                 | ✅ Zero                    | ❌ Sidecar injection          | ✅ Zero                |
| Network Data Type      | ✅ Flow Records         | ❌ Counters only        | ✅ Flow Records            | ⚠️ Request/response           | ✅ Full packets        |
| Connection Context     | ✅ Full details         | ❌ Aggregated metrics   | ✅ Full details            | ⚠️ L7 only                    | ✅ Full packets        |
| Performance Overhead   | ✅ Minimal (eBPF)       | ✅ Minimal (eBPF)       | ✅ Low                     | ⚠️ Moderate (sidecars)        | ❌ High (full capture) |
| Standards-Based Export | ✅ OTLP Traces          | ⚠️ OTLP Metrics         | ⚠️ NetFlow/IPFIX           | ⚠️ Prometheus/vendor-specific | ❌ PCAP files          |
| Bidirectional Flows    | ✅ Yes                  | ❌ Separate counters    | ✅ Yes                     | ⚠️ Limited                    | ❌ Packet-level only   |
| Deployment Complexity  | ✅ Simple DaemonSet     | ✅ Simple DaemonSet     | ✅ Simple                  | ⚠️ Complex                    | ✅ Simple              |

**Key Differentiators:**

- **vs eBPF APM Agents**: Exports flow records (with timing, flags, directionality) as traces, not aggregated counter metrics
- **vs NetFlow/IPFIX**: Adds Kubernetes context and uses modern OTLP standard
- **vs Service Meshes**: No application changes, lower overhead, but L3/L4 only (not L7)
- **vs Packet Capture**: Aggregated flows instead of raw packets, with metadata enrichment

## Architecture at a Glance

Mermin operates as a DaemonSet in Kubernetes (or as a privileged container on bare metal), with one instance running on each node:

1. **Packet Capture**: eBPF programs attached to network interfaces capture packets at the kernel level.
2. **Flow Aggregation**: Packets are aggregated into bidirectional network flows with connection state tracking.
3. **Metadata Enrichment**: Flows are decorated with Kubernetes metadata (pods, services, deployments, labels).
4. **Flow Traces Export**: Flows are converted to OpenTelemetry trace spans and exported via OTLP
5. **Observability Backend**: Flow Traces are stored, analyzed, and visualized in your platform (Elastic, Grafana Tempo, Jaeger, etc.)

For a deeper dive into Mermin's architecture, see our [Architecture Overview](docs/concepts/agent-architecture.md).

## Documentation

Comprehensive documentation is available in the `docs/` directory and via [docs.mermin.dev](https://docs.mermin.dev):

### Getting Started

- [Quickstart Guide](docs/getting-started/quickstart-guide.md) - Get up and running in minutes
- [Architecture Overview](docs/concepts/agent-architecture.md) - Understand how Mermin works

### Deployment

- [Deployment Guide](docs/deployment/overview.md) - Deployment strategies and best practices
- [Kubernetes with Helm](docs/deployment/kubernetes-helm.md) - Kubernetes deployment details
- [Cloud Platforms](docs/deployment/cloud-platforms.md) - AWS, GCP, Azure specifics
- [Docker & Bare Metal](docs/deployment/docker-bare-metal.md) - Non-Kubernetes deployments

### Configuration

- [Configuration Reference](docs/configuration/overview.md) - Complete configuration options
- [OTLP Export](docs/configuration/reference/opentelemetry-otlp-exporter.md) - Configure OpenTelemetry export
- [Filtering](docs/configuration/reference/flow-span-filters.md) - Control which flows are captured
- [Kubernetes Metadata](docs/configuration/reference/kubernetes-informer-discovery.md) - Kubernetes integration options

### Observability Backends

- [Supported Backends](docs/getting-started/backend-integrations.md) - Elastic, Grafana, Tempo, Jaeger, and more

### Troubleshooting

- [Troubleshooting Guide](docs/troubleshooting/troubleshooting.md) - Common issues and solutions
- [Deployment Issues](docs/troubleshooting/deployment-issues.md) - Pod startup and configuration problems
- [Interface Visibility](docs/troubleshooting/interface-visibility-and-traffic-decapsulation.md) - Traffic capture and CNI configuration
- [Common eBPF Errors](docs/troubleshooting/common-ebpf-errors.md) - Verifier failures and kernel compatibility

### Development & Contributing

- [Contributing Guide](docs/CONTRIBUTING.md) - How to contribute to Mermin
- [Development Workflow](docs/contributor-guide/development-workflow.md) - Build, test, and contribute
- [Debugging eBPF Programs](docs/contributor-guide/debugging-ebpf.md) - eBPF debugging techniques
- [Debugging Network Traffic](docs/contributor-guide/debugging-network.md) - Wireshark and packet analysis

## Contributing

We welcome contributions from the community! Whether you're fixing bugs, adding features, improving documentation, or sharing feedback, your contributions help make Mermin better for everyone.

### Ways to Contribute

- 🐛 **Report bugs** via [GitHub Issues](https://github.com/elastiflow/mermin/issues).
- 💡 **Request features** or share ideas in [GitHub Discussions](https://github.com/elastiflow/mermin/discussions).
- 📝 **Improve documentation** - PRs for doc improvements are always welcome.
- 🔧 **Submit code** - See our [Development Workflow](docs/contributor-guide/development-workflow.md) to get started.
- 💬 **Help others** - Answer questions in Discussions or Slack.

### Getting Started as a Contributor

1. **Read the [Development Workflow](docs/contributor-guide/development-workflow.md)** - Learn how to build, test, and develop Mermin.
2. **Check out [Good First Issues](https://github.com/elastiflow/mermin/labels/good%20first%20issue)** - Find beginner-friendly tasks.
3. **Join the conversation** - Connect with us on Slack or GitHub Discussions.

All contributors are expected to follow our code of conduct and maintain a welcoming, inclusive environment.

## Community & Support

**Get Help:**

- Slack Channel: https://join.slack.com/t/elastiflowcommunity/shared_invite/zt-23jpnlw9g-Q4nKOwKKOE1N2MjfA2mXpg - Live chat with maintainers and community.
- 💭 [GitHub Discussions](https://github.com/elastiflow/mermin/discussions) - Ask questions and share knowledge.
- 🐛 [GitHub Issues](https://github.com/elastiflow/mermin/issues) - Report bugs and track feature requests.
- 📖 [Documentation](docs/README.md) - Comprehensive guides and references.

### Stay Updated

- ⭐ Star the repo on GitHub to stay notified of new releases.
- 📢 Follow us for announcements and updates.
- 🔔 Watch the repository for issue and discussion notifications.

### Enterprise Support

- For commercial support, visit [ElastiFlow](https://www.elastiflow.com).

## Artifacts

Docker images are available in the GitHub Container Registry:

### Standard Production Image

```shell
docker pull ghcr.io/elastiflow/mermin:latest
```

### Debug Image (includes shell and debugging tools)

```shell
docker pull ghcr.io/elastiflow/mermin:latest-debug
```

The debug image is built using the `gcr.io/distroless/cc-debian12:debug` base image and provides additional debugging tools compared to the standard image.

## License

With the exception of eBPF code, Mermin is distributed under the terms of the [Apache License](LICENSE-APACHE) (version 2.0).

Any contribution intentionally submitted for inclusion in this crate by you, shall be licensed Apache-2.0, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under the terms of the [GNU General Public License, Version 2](LICENSE-GPL2).

Any contribution intentionally submitted for inclusion in this project by you, shall be dual licensed GPL-2, without any additional terms or conditions.
