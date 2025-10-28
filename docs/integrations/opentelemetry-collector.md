# OpenTelemetry Collector Integration

The OpenTelemetry Collector is a vendor-agnostic telemetry data pipeline that can receive, process, and export Mermin's Flow Traces to multiple backends.

## Overview

Using the OpenTelemetry Collector provides:
- Centralized telemetry collection
- Protocol translation (OTLP → other formats)
- Data processing and transformation
- Multi-backend fanout
- Buffering and retry logic

## Architecture

```
Mermin Agents → OpenTelemetry Collector → Backends
(per node)      (centralized)              (Elastic, Tempo, etc.)
```

## Deploying OpenTelemetry Collector

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-config
data:
  config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318

    processors:
      batch:
        timeout: 5s
        send_batch_size: 1024

    exporters:
      otlp:
        endpoint: tempo:4317
        tls:
          insecure: true

      logging:
        loglevel: info

    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [batch]
          exporters: [otlp, logging]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: otel-collector
  template:
    metadata:
      labels:
        app: otel-collector
    spec:
      containers:
        - name: otel-collector
          image: otel/opentelemetry-collector:latest
          args: ["--config=/etc/otel/config.yaml"]
          ports:
            - containerPort: 4317  # OTLP gRPC
            - containerPort: 4318  # OTLP HTTP
          volumeMounts:
            - name: config
              mountPath: /etc/otel
      volumes:
        - name: config
          configMap:
            name: otel-collector-config
---
apiVersion: v1
kind: Service
metadata:
  name: otel-collector
spec:
  selector:
    app: otel-collector
  ports:
    - name: otlp-grpc
      port: 4317
      protocol: TCP
    - name: otlp-http
      port: 4318
      protocol: TCP
```

### Configure Mermin

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

## Common Configurations

### Multiple Backends

```yaml
exporters:
  otlp/tempo:
    endpoint: tempo:4317

  otlp/jaeger:
    endpoint: jaeger:4317

  elasticsearch:
    endpoints: ["http://elasticsearch:9200"]

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/tempo, otlp/jaeger, elasticsearch]
```

### With Authentication

```yaml
exporters:
  otlp:
    endpoint: backend:4317
    headers:
      authorization: "Bearer ${API_TOKEN}"
```

## Next Steps

- **[Grafana Tempo](tempo.md)**: Backend for trace storage
- **[Jaeger](jaeger.md)**: Alternative backend
- **[Elastic](elastic.md)**: Send to Elasticsearch
