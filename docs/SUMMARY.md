# Table of contents

## Welcome

* [Mermin Documentation](README.md "Introduction")
* [Beta Program](welcome/beta-program.md)

## Getting Started

* [Quickstart Guide](getting-started/quickstart-guide.md)
* [Agent Architecture](getting-started/agent-architecture.md)
* [Security Considerations](getting-started/security-considerations.md)
* [Attribute Reference](getting-started/attribute-reference.md)

## Observability

* [Backend Integrations](observability/backend-integrations.md)

## Deployment

* [Overview](deployment/overview.md)
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

* [Overview](configuration/overview.md "Configuration Overview")
* [Examples](configuration/examples.md)
* [Global Agent Options](configuration/global-options.md)
* [Configuration References](configuration/configuration-references/README.md)
  * [Network Interface Discovery](configuration/discovery-instrument.md)
  * [Network Packet Parser](configuration/parser.md)
  * [Flow Span Producer](configuration/span.md)
  * [OTLP Exporter](configuration/export-otlp.md)
  * [Stdout Exporter](configuration/export-stdout.md)
  * [Flow Span Kubernetes Attribution](configuration/attributes.md)
  * [Kubernetes Owner Relations](configuration/owner-relations.md)
  * [Kubernetes Informer Discovery](configuration/discovery-kubernetes-informer.md)
  * [Kubernetes Selector Relations](configuration/selector-relations.md)
  * [Agent Pipeline](configuration/pipeline.md)
  * [Agent Pipeline Filters](configuration/filtering.md)
  * [Internal API](configuration/api.md)
  * [Internal Prometheus Metrics](configuration/metrics.md)
  * [Internal Tracing](configuration/internal-tracing.md)

## Internal Monitoring

* [Metrics](internal-monitoring/internal-metrics.md "Metrics")

## Troubleshooting

* [Overview](troubleshooting/troubleshooting.md)
* [Deployment Issues](troubleshooting/deployment-issues.md)
* [Interface Visibility and Traffic Decapsulation](troubleshooting/interface-visibility-and-traffic-decapsulation.md)
* [Common eBPF Errors](troubleshooting/common-ebpf-errors.md)

## Flow Trace Specification

* [Introduction to Flow Traces](spec/introductory-primer.md)
* [Semantic Conventions](spec/semantic-conventions.md)

## Security

* [Security Policy](SECURITY.md)

## Contributor Guide

* [Contributing to Mermin](CONTRIBUTING.md)
* [Development Workflow](contributor-guide/development-workflow.md)
* [Debugging eBPF](contributor-guide/debugging-ebpf.md)
* [Debugging Network](contributor-guide/debugging-network.md)
* [Code of Conduct](CODE-OF-CONDUCT.md)
