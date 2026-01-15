# Table of contents

## Welcome

* [Overview](README.md)
* [Beta Program](welcome/beta-program.md)

## Getting Started

* [Quick Start](getting-started/quickstart.md)
* [Architecture](getting-started/architecture.md)
* [Security Considerations](getting-started/security-considerations.md)

## Flow Trace Specification

* [Primer](semconv/primer.md)
* [Semantic Conventions](semconv/spec.md)

## Deployment

* [Deployment Overview](deployment/deployment.md)
* [Kubernetes with Helm](deployment/kubernetes-helm.md)
* [Cloud Platforms](deployment/cloud-platforms.md)
* [Advanced Scenarios](deployment/advanced-scenarios.md)
* [Docker on Bare Metal](deployment/docker-bare-metal.md)
* [Helm Examples](deployment/helm-examples/README.md)
  * [Mermin with OpenTelemetry Collector](deployment/examples/local_otel/README.md)
  * [Mermin with NetObserv Flow and OpenSearch](deployment/examples/netobserv_os_simple_svc/README.md)
  * [Mermin with NetObserv Flow and OpenSearch in GKE with Gateway](deployment/examples/netobserv_os_simple_gke_gw/README.md)

## Observability

* [Backends](observability/backends.md)
* [Mermin Application Metrics](observability/app-metrics.md)

## Configuration

* [Configuration Overview](configuration/configuration.md)
* [Global Options](configuration/global-options.md)
* [API](configuration/api.md)
* [Metrics](configuration/metrics.md)
* [Parser Configuration](configuration/parser.md)
* [Pipeline Configuration](configuration/pipeline.md)
* [Network Interface Discovery](configuration/discovery-instrument.md)
* [Kubernetes Informers](configuration/discovery-kubernetes-informer.md)
* [Owner Relations](configuration/owner-relations.md)
* [Selector Relations](configuration/selector-relations.md)
* [Flow Attributes](configuration/attributes.md)
* [Flow Filtering](configuration/filtering.md)
* [Flow Span Producer](configuration/span.md)
* [OTLP Exporter](configuration/export-otlp.md)
* [Stdout Exporter](configuration/export-stdout.md)
* [Internal Tracing](configuration/internal-tracing.md)
* [Configuration Examples](configuration/examples.md)

## Troubleshooting

* [Overview](troubleshooting/troubleshooting.md)
* [Deployment Issues](troubleshooting/deployment-issues.md)
* [Interface Visibility and Traffic Decapsulation](troubleshooting/interface-visibility-and-traffic-decapsulation.md)
* [Common eBPF Errors](troubleshooting/common-ebpf-errors.md)

## Contributor Guide

* [Contributing to Mermin](CONTRIBUTING.md)
* [Development Workflow](contributor-guide/development-workflow.md)
* [Debugging eBPF](contributor-guide/debugging-ebpf.md)
* [Debugging Network](contributor-guide/debugging-network.md)
* [Code of Conduct](CODE-OF-CONDUCT.md)
