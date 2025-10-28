# Elastic Stack Integration

Integrate Mermin with Elasticsearch and Kibana for powerful search, analysis, and visualization of Flow Traces.

## Overview

The Elastic Stack (Elasticsearch + Kibana) provides:
- Full-text search across flow metadata
- Aggregations and analytics
- Customizable dashboards
- APM integration
- Machine learning anomaly detection

## Architecture

```
Mermin → OpenTelemetry Collector → Elasticsearch → Kibana
```

## Prerequisites

- Elasticsearch 7.x or 8.x
- Kibana (matching Elasticsearch version)
- OpenTelemetry Collector with Elasticsearch exporter

## OpenTelemetry Collector Configuration

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
    timeout: 5s
    send_batch_size: 1024

exporters:
  elasticsearch:
    endpoints: ["http://elasticsearch:9200"]
    logs_index: "mermin-flows"

    # For Elasticsearch 8.x with security
    # auth:
    #   authenticator: basicauth

    # TLS configuration
    # tls:
    #   insecure: false
    #   ca_file: /etc/certs/ca.crt

# If using basic auth
extensions:
  basicauth/elastic:
    client_auth:
      username: elastic
      password: ${ELASTIC_PASSWORD}

service:
  extensions: [basicauth/elastic]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [elasticsearch]
```

## Kibana Dashboards

Create visualizations in Kibana:

1. Navigate to **Discover**
2. Create index pattern: `mermin-flows-*`
3. Explore Flow Traces

**Common Queries:**
```
source.pod.name: "nginx-*"
destination.port: 443
network.protocol: "TCP"
```

## Next Steps

- **[OpenTelemetry Collector](opentelemetry-collector.md)**: Set up collector
- **[Configuration Examples](../configuration/examples.md)**: Optimize for Elastic
