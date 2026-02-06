---
hidden: true
---

# Export to Your Observability Backend

Mermin exports Flow Traces via the **OpenTelemetry Protocol (OTLP)**, compatible with any OTLP-enabled observability backend or collector.

## What You Need

To receive Flow Traces from Mermin, you need one of:

1. **OTLP-Enabled Collector**: OpenTelemetry Collector that receives OTLP and forwards to your backend(s)
2. **OTLP Data Platform**: An observability platform with native OTLP ingestion

## OpenTelemetry Collector (Recommended)

The OpenTelemetry Collector provides the most flexibility:

- Receives OTLP from Mermin via gRPC or HTTP
- Processes, batches, and transforms telemetry data
- Exports to multiple backends simultaneously
- Provides buffering and retry logic

**Example Configuration:** See [Mermin with OpenTelemetry Collector](../deployment/examples/local-otel/README.md) for a complete setup with OpenTelemetry Collector, including Mermin configuration and collector pipeline.

### Basic Mermin Configuration

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"  # Collector's OTLP gRPC endpoint
    protocol = "grpc" # Optional; Mermin defaults to "grpc".
  }
}
```

## OTLP-Compatible Data Platforms

Flow Traces work with any platform supporting OTLP trace ingestion:

### Elastic Stack

Elasticsearch with APM Server or OpenTelemetry Collector ingests OTLP traces.

**Use Case:** Full-text search, complex aggregations, APM integration, machine learning

**How to Connect:**

- Point Mermin → OpenTelemetry Collector → Elasticsearch exporter
- Or point Mermin → Elastic APM Server (OTLP endpoint)

**Example:** See [`docs/deployment/examples/netobserv-os-simple-svc/`](../deployment/examples/netobserv-os-simple-svc/README.md) for OpenSearch (Elastic-compatible) deployment

### OpenSearch

Open-source alternative to Elasticsearch with native OTLP support via OpenTelemetry Collector.

**Use Case:** Open-source search and analytics, cost-effective storage

**Examples:**

- [`docs/deployment/examples/netobserv-os-simple-svc/`](../deployment/examples/netobserv-os-simple-svc/README.md) - Basic OpenSearch setup
- [`docs/deployment/examples/netobserv-os-simple-gke-gw/`](../deployment/examples/netobserv-os-simple-gke-gw/README.md) - GKE deployment with Gateway API

### Greptime Ingestion

Greptime is a database designed for high-cardinality time series data that supports OTLP ingestion.

```hcl
export "traces" {
  otlp = {
    endpoint = "http://greptime-standalone-instance:4000/v1/otlp/v1/traces"
    protocol = "http_binary"

    headers = {
      "x-greptime-db-name"       = "public"
      "x-greptime-pipeline-name" = "greptime_trace_v1"
    }
  }
}
```

**Example:** [`docs/deployment/examples/greptime_simple_svc`](../deployment/examples/greptimedb-simple-svc/README.md)

### Grafana Cloud, Datadog, New Relic, Honeycomb, etc

Most commercial observability platforms support OTLP ingestion.

**How to Connect:**

1. Obtain your platform's OTLP endpoint URL
2. Configure authentication (usually API key or bearer token)
3. Point Mermin to the endpoint with auth

```hcl
export "traces" {
  otlp = {
    endpoint = "https://otlp.provider.com:4317"
    headers = {
      "authorization" = "Bearer ${API_TOKEN}"
    }
  }
}
```

**Examples:** Coming soon...

## Flow Trace Data Model

Each Flow Trace is an OpenTelemetry span containing:

**Span Attributes:**

- Network 5-tuple: source/dest IPs, ports, protocol
- Bidirectional counters: bytes sent/received, packets sent/received
- TCP state: flags (SYN, FIN, RST), connection state
- Kubernetes metadata: pod, service, deployment, namespace, labels
- [Community ID](https://github.com/corelight/community-id-spec) for flow correlation across monitoring points

**Resource Attributes:**

- Kubernetes cluster name
- Node name
- Mermin version

Query Flow Traces using native backend query languages (TraceQL, KQL, Lucene).

## Testing with Stdout

For local development and testing, output Flow Traces to stdout instead of OTLP:

```hcl
export "traces" {
  stdout = {
    format = "text_indent"  # Human-readable format
  }
}
```

View traces in Mermin logs:

```bash
kubectl logs -f -l app.kubernetes.io/name=mermin
```

## Next Steps

{% tabs %}
{% tab title="Configure Export" %}
1. [**Configure OTLP Export**](../configuration/reference/opentelemetry-otlp-exporter.md): Set up endpoints, authentication, and TLS
2. [**Review Example Configurations**](../deployment/examples/README.md): Complete deployment examples with backends
{% endtab %}

{% tab title="Optimize" %}
1. [**Filter Flows Before Export**](../configuration/reference/flow-span-filters.md): Reduce volume and focus on critical traffic
2. [**Tune Export Batching**](../configuration/reference/opentelemetry-otlp-exporter.md#batching): Optimize for your backend's ingestion rate
{% endtab %}
{% endtabs %}

### Need Help?

- [**Troubleshoot Export Issues**](../troubleshooting/troubleshooting.md): Diagnose connection and authentication problems
- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Share your backend setup and get community advice
