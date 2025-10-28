# Grafana Tempo Integration

Grafana Tempo is a scalable, cost-effective distributed tracing backend that natively supports OpenTelemetry.

## Overview

Tempo provides:
- High-scale trace ingestion and storage
- TraceQL query language
- Native Grafana integration
- S3/GCS/Azure object storage backends
- Cost-effective long-term retention

## Architecture

```
Mermin → OpenTelemetry Collector → Tempo → Grafana
```

## Deploying Tempo

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tempo-config
data:
  tempo.yaml: |
    server:
      http_listen_port: 3200

    distributor:
      receivers:
        otlp:
          protocols:
            grpc:
              endpoint: 0.0.0.0:4317
            http:
              endpoint: 0.0.0.0:4318

    ingester:
      trace_idle_period: 10s
      max_block_bytes: 1_000_000
      max_block_duration: 5m

    compactor:
      compaction:
        block_retention: 720h  # 30 days

    storage:
      trace:
        backend: local
        local:
          path: /var/tempo/traces
        wal:
          path: /var/tempo/wal
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tempo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tempo
  template:
    metadata:
      labels:
        app: tempo
    spec:
      containers:
        - name: tempo
          image: grafana/tempo:latest
          args:
            - "-config.file=/etc/tempo/tempo.yaml"
          ports:
            - containerPort: 3200  # HTTP
            - containerPort: 4317  # OTLP gRPC
            - containerPort: 4318  # OTLP HTTP
          volumeMounts:
            - name: config
              mountPath: /etc/tempo
            - name: storage
              mountPath: /var/tempo
      volumes:
        - name: config
          configMap:
            name: tempo-config
        - name: storage
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: tempo
spec:
  selector:
    app: tempo
  ports:
    - name: http
      port: 3200
      protocol: TCP
    - name: otlp-grpc
      port: 4317
      protocol: TCP
    - name: otlp-http
      port: 4318
      protocol: TCP
```

## Configure Mermin

Point Mermin directly to Tempo or via OpenTelemetry Collector:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://tempo:4317"
    protocol = "grpc"
  }
}
```

## Querying with TraceQL

Tempo supports TraceQL for powerful flow queries:

### Find flows from specific pod
```traceql
{ source.pod.name = "nginx-*" }
```

### High-bandwidth flows
```traceql
{ flow.bytes.sent > 1000000 }
```

### TCP flows to port 443
```traceql
{ network.protocol = "TCP" && destination.port = 443 }
```

### Flows between namespaces
```traceql
{ source.namespace = "frontend" && destination.namespace = "backend" }
```

## Grafana Data Source

Configure Tempo data source in Grafana:

1. **Configuration → Data Sources → Add data source**
2. Select **Tempo**
3. Configure:
   - Name: `Tempo`
   - URL: `http://tempo:3200`
4. **Save & Test**

## Production Storage Backends

For production, use object storage:

### S3 Backend

```yaml
storage:
  trace:
    backend: s3
    s3:
      bucket: my-tempo-traces
      endpoint: s3.amazonaws.com
      access_key: ${AWS_ACCESS_KEY_ID}
      secret_key: ${AWS_SECRET_ACCESS_KEY}
```

### GCS Backend

```yaml
storage:
  trace:
    backend: gcs
    gcs:
      bucket_name: my-tempo-traces
```

## Next Steps

- **[Grafana](grafana.md)**: Create dashboards
- **[OpenTelemetry Collector](opentelemetry-collector.md)**: Advanced pipeline
