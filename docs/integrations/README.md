# Integration Overview

Mermin exports Flow Traces via the OpenTelemetry Protocol (OTLP), enabling integration with any OTLP-compatible observability backend.

## What are Flow Traces?

Flow Traces are OpenTelemetry trace spans that represent network flows with NetFlow-like semantics. Each Flow Trace contains:
- Bidirectional flow statistics (bytes/packets sent and received)
- Network 5-tuple (source/dest IPs, ports, protocol)
- Kubernetes metadata (pods, services, deployments, etc.)
- TCP connection state and flags
- Flow timing information

This standardized format allows Mermin to integrate seamlessly with any OpenTelemetry-compatible backend.

## OTLP-Compatible Backends

Mermin works with:

- **[OpenTelemetry Collector](opentelemetry-collector.md)**: Central telemetry hub
- **[Elastic Stack](elastic.md)**: Elasticsearch + Kibana
- **[OpenSearch](opensearch.md)**: OpenSearch + Dashboards
- **[Grafana](grafana.md)**: Visualization platform
- **[Grafana Tempo](tempo.md)**: Distributed tracing backend
- **[Jaeger](jaeger.md)**: Distributed tracing platform

## General Integration Pattern

All integrations follow this pattern:

1. **Deploy Mermin**: Configure network interfaces and Kubernetes informers
2. **Configure OTLP Export**: Point to your collector/backend
3. **Deploy Collector** (if needed): OpenTelemetry Collector as intermediary
4. **Configure Backend**: Set up data ingestion and storage
5. **Create Visualizations**: Dashboards and queries for Flow Traces

## Data Model

Mermin exports network flows as OTLP trace spans with:

**Span Attributes:**
- Source/destination IPs and ports
- Network protocol (TCP, UDP, ICMP)
- Packet and byte counters
- Kubernetes metadata (pod, service, deployment, etc.)
- TCP flags and connection state
- Community ID for flow correlation

**Resource Attributes:**
- Kubernetes cluster name
- Node name
- Namespace

## Choosing an Integration

| Backend | Best For | Complexity |
|---------|----------|------------|
| **OTel Collector** | Flexible routing, multi-backend | Low |
| **Elastic** | Full-text search, APM integration | Medium |
| **OpenSearch** | Open-source alternative to Elastic | Medium |
| **Grafana** | Visualization, dashboards | Low |
| **Tempo** | Trace storage, TraceQL queries | Low |
| **Jaeger** | Distributed tracing, service maps | Low |

## Quick Start

For quick testing, use stdout exporter:

```hcl
export "traces" {
  stdout = "text_indent"
}
```

For production, start with OpenTelemetry Collector:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

## Next Steps

Choose your backend and follow the integration guide:

- **[OpenTelemetry Collector](opentelemetry-collector.md)**: Start here for most deployments
- **[Elastic Stack](elastic.md)**: Enterprise search and analytics
- **[Grafana Tempo](tempo.md)**: Scalable trace storage
- **[Jaeger](jaeger.md)**: Comprehensive tracing platform
