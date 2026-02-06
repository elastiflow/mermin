# Table of contents

## Welcome

* [Mermin Documentation](README.md "Introduction")

## Getting Started

* [Quickstart Guide](getting-started/quickstart-guide.md)
* [Export to Your Observability Backend](getting-started/backend-integrations.md "Backend Integrations")
* [Attribute Reference](getting-started/attribute-reference.md)

## Deployment

* [Deployment Overview](deployment/overview.md "Overview")
* [Kubernetes with Helm](deployment/kubernetes-helm.md)
* [Cloud Platforms](deployment/cloud-platforms.md)
* [Advanced Scenarios](deployment/advanced-scenarios.md)
* [Docker on Bare Metal](deployment/docker-bare-metal.md)
* [Examples](deployment/examples/README.md)
  * [Mermin with OpenTelemetry Collector](deployment/examples/local_otel/README.md)
  * [Mermin with NetObserv Flow and OpenSearch](deployment/examples/netobserv_os_simple_svc/README.md)
  * [Mermin with NetObserv Flow and OpenSearch in GKE with Gateway](deployment/examples/netobserv_os_simple_gke_gw/README.md)
  * [Mermin with GreptimeDB](deployment/examples/greptimedb_simple_svc/README.md)

## Configuration

* [Configuration Overview](configuration/overview.md "Overview")
* [Configuration Examples](configuration/examples.md "Examples")
* [Configuration Reference](configuration/reference/README.md "Configuration Reference")
  * [Configure Discovery of Network Interfaces](configuration/reference/network-interface-discovery.md "Network Interface Discovery")
  * [Configure Parsing of Network Packets](configuration/reference/network-packet-parser.md "Network Packet Parser")
  * [Configure Producing of Flow Spans](configuration/reference/flow-span-producer.md "Flow Span Producer")
  * [Configure Filtering of Flow Spans](configuration/reference/flow-span-filters.md "Flow Span Filters")
  * [Configure OpenTelemetry OTLP Exporter](configuration/reference/opentelemetry-otlp-exporter.md "OpenTelemetry OTLP Exporter")
  * [Configure OpenTelemetry Console Exporter](configuration/reference/opentelemetry-console-exporter.md "OpenTelemetry Console Exporter")
  * [Configure Kubernetes Attribution of Flow Spans](configuration/reference/flow-span-kubernetes-attribution.md "Flow Span Kubernetes Attribution")
  * [Configure Discovery of Kubernetes Informer](configuration/reference/kubernetes-informer-discovery.md "Kubernetes Informer Discovery")
  * [Configure Owner Relations of Kubernetes Resources](configuration/reference/kubernetes-owner-relations.md "Kubernetes Owner Relations")
  * [Configure Selector Relations of Kubernetes Resources](configuration/reference/kubernetes-selector-relations.md "Kubernetes Selector Relations")
  * [Configure Flow Processing Pipeline](configuration/reference/flow-processing-pipeline.md "Flow Processing Pipeline")
  * [Configure Internal Server](configuration/reference/internal-server.md "Internal Server")
  * [Configure Internal Prometheus Metrics Server](configuration/reference/internal-prometheus-metrics.md "Internal Prometheus Metrics")
  * [Configure Internal Tracing Exporter](configuration/reference/internal-tracing.md "Internal Tracing")

## Internal Monitoring

* [Internal Metrics](internal-monitoring/internal-metrics.md "Metrics")

## Concepts

* [Introduction to Flow Traces](concepts/introduction-to-flow-traces.md)
* [Flow Trace Semantic Conventions](concepts/semantic-conventions.md "Semantic Conventions")
* [Mermin Agent Architecture](concepts/agent-architecture.md "Agent Architecture")
* [eBPF Security Considerations](concepts/security-considerations.md)

## Troubleshooting

* [Troubleshooting Overview](troubleshooting/troubleshooting.md "Overview")
* [Deployment Issues](troubleshooting/deployment-issues.md)
* [Interface Visibility and Traffic Decapsulation](troubleshooting/interface-visibility-and-traffic-decapsulation.md)
* [Common eBPF Errors](troubleshooting/common-ebpf-errors.md)

## Contributor Guide

* [Contributing to Mermin](CONTRIBUTING.md)
* [Development Workflow](contributor-guide/development-workflow.md)
* [Debugging eBPF](contributor-guide/debugging-ebpf.md)
* [Debugging Network](contributor-guide/debugging-network.md)
* [Code of Conduct](CODE-OF-CONDUCT.md)
* [Security Policy](SECURITY.md)
