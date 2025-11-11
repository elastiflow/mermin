# Overview

Welcome to the Mermin documentation! Mermin is a powerful, Kubernetes-native network traffic observability tool that uses eBPF (Extended Berkeley Packet Filter) technology to efficiently capture network traffic and export it as **Flow Traces** using the OpenTelemetry Protocol (OTLP).

## What is Mermin?

Mermin is a kernel-level packet capture tool that generates Flow Traces (OpenTelemetry trace spans with network flow semantics) enriched with Kubernetes metadata and exports them via the OpenTelemetry Protocol (OTLP) to your preferred observability backend. Mermin enables increased visibility into the network communications of Kubernetes clusters by leveraging eBPF to capture network traffic that is typically invisible with traditional network observability techniques.

## What are Flow Traces?

Flow Traces are OpenTelemetry trace spans that represent network flows with NetFlow-like behavior. Unlike traditional NetFlow or IPFIX, Flow Traces leverage the OpenTelemetry standard, providing bidirectional flow statistics, rich Kubernetes metadata, and native integration with modern observability platforms.

## Mermin Key Features

* **eBPF-Based Packet Capture**: Leverages eBPF technology for high-performance, low-overhead network monitoring directly in the Linux kernel.
* **Kubernetes-Native**: Integration with Kubernetes, automatically enriching network flows with pod, service, deployment, and other resource metadata.
* **OpenTelemetry Protocol**: Standards-based OTLP export ensures compatibility with a wide ecosystem of observability platforms.
* **Zero Application Changes**: Operates transparently without requiring any modifications to your applications.
* **Comprehensive Protocol Support**: Parses and tracks TCP, UDP, ICMP traffic, with support for common tunneling protocols (VXLAN, Geneve, WireGuard).
* **Flexible Filtering**: Configure fine-grained filters to control which network flows are captured and exported.
* **Resource Configuration Support**: Optimized for production use with configurable resource limits and batching sizes.

## What You Can Expect

This documentation is designed to help you successfully deploy, configure, and operate Mermin in your environment. You'll find:

* [**Quick Start Guide**](getting-started/quickstart.md): Get Mermin running in minutes on a local Kubernetes cluster.
* [**Architecture Overview**](getting-started/architecture.md): Understand how Mermin works and its data flow.
* [**Deployment Guides**](deployment/deployment.md): Detailed instructions for various deployment scenarios (Kubernetes, cloud platforms, bare metal).
* [**Configuration Reference**](configuration/configuration.md): Comprehensive documentation of all configuration options.
* [**Observability Backends**](observability/backends.md): Understand how to send Flow Traces to Elastic, Grafana Tempo, Jaeger, and other OTLP-compatible platforms.
* [**Troubleshooting**](troubleshooting/troubleshooting.md): Solutions to common issues and diagnostic approaches

## System Requirements

Mermin requires:

* **Linux Kernel**: Version 5.14 or newer with eBPF support enabled
* **Kubernetes**: Version 1.20 or newer (for Kubernetes deployments)
* **Container Runtime**: Docker, containerd, or CRI-O
* **Privileges**: Requires privileged mode to load eBPF programs and access network interfaces

## Quick Architecture Overview

Mermin operates as a DaemonSet in Kubernetes (or as a privileged container on bare metal), with one instance running on each node:

1. **Packet Capture**: eBPF programs attached to network interfaces capture packets at the kernel level.
2. **Flow Generation**: Packets are aggregated into bidirectional network flows with connection state tracking.
3. **Metadata Decoration**: Flows are decorated with Kubernetes metadata (pods, services, deployments, labels, etc).
4. **Flow Traces Export**: Flows are converted to Flow Traces (OpenTelemetry compliant trace spans) and exported via OTLP.
5. **Observability Backend**: Flow Traces are stored, analyzed, and visualized on your chosen platform (e.g., Elastic, Grafana, Tempo).

## Getting Help

If you encounter issues or have questions:

* [**GitHub Issues**](https://github.com/elastiflow/mermin/issues): Report bugs or request features
* [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask questions and engage with the community
* [Slack Channel](https://elastiflowcommunity.slack.com/archives/C09MANJTSP3): Live chat with us or other beta users
* [**Troubleshooting Guide**](troubleshooting/troubleshooting.md): Check common issues and solutions

## Next Steps

Ready to get started? Follow our [**Quick Start Guide**](getting-started/quickstart.md) to deploy Mermin on a local Kubernetes cluster in minutes.

For production deployments, review the [**Deployment Overview**](deployment/deployment.md) to understand your deployment options and best practices.
