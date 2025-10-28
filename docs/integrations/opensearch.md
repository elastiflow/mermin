# OpenSearch Integration

Integrate Mermin with OpenSearch for open-source search, analysis, and visualization of Flow Traces.

## Overview

OpenSearch (fork of Elasticsearch) provides:
- Full-text search and analytics
- OpenSearch Dashboards for visualization
- Alerting and notifications
- Community-driven development

## Architecture

```
Mermin → OpenTelemetry Collector → OpenSearch → OpenSearch Dashboards
```

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

exporters:
  opensearch:
    http:
      endpoint: http://opensearch:9200
      tls:
        insecure: true

    index: mermin-flows

    # Authentication
    # auth:
    #   authenticator: basicauth

extensions:
  basicauth/opensearch:
    client_auth:
      username: admin
      password: ${OPENSEARCH_PASSWORD}

service:
  extensions: [basicauth/opensearch]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [opensearch]
```

## OpenSearch Dashboards

Similar to Kibana workflow:
1. Create index pattern: `mermin-flows-*`
2. Build visualizations
3. Create dashboards

## Next Steps

- **[OpenTelemetry Collector](opentelemetry-collector.md)**: Set up collector
- **[Configuration Examples](../configuration/examples.md)**: Configuration templates
