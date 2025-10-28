# Jaeger Integration

Jaeger is a distributed tracing platform that can ingest and visualize Mermin's Flow Traces.

## Overview

Jaeger provides:
- Distributed trace visualization
- Service dependency graphs
- Performance monitoring
- Root cause analysis
- Native OTLP support

## Architecture

```
Mermin → Jaeger Collector (OTLP) → Storage → Jaeger Query UI
```

## Deploying Jaeger

### All-in-One Deployment (Development)

```bash
kubectl create deployment jaeger \
  --image=jaegertracing/all-in-one:latest \
  --port=16686 \
  --port=4317 \
  --port=4318

kubectl expose deployment jaeger \
  --port=16686 \
  --target-port=16686 \
  --name=jaeger-query

kubectl expose deployment jaeger \
  --port=4317 \
  --target-port=4317 \
  --name=jaeger-collector-grpc

kubectl expose deployment jaeger \
  --port=4318 \
  --target-port=4318 \
  --name=jaeger-collector-http
```

### Production Deployment with Operator

```yaml
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: jaeger-prod
spec:
  strategy: production
  storage:
    type: elasticsearch
    options:
      es:
        server-urls: http://elasticsearch:9200
  collector:
    maxReplicas: 5
    resources:
      limits:
        cpu: 2
        memory: 2Gi
  query:
    resources:
      limits:
        cpu: 1
        memory: 1Gi
```

## Configure Mermin

Point Mermin to Jaeger's OTLP endpoint:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://jaeger-collector-grpc:4317"
    protocol = "grpc"
  }
}
```

## Viewing Network Flows

Access Jaeger UI:

```bash
kubectl port-forward svc/jaeger-query 16686:16686
```

Navigate to `http://localhost:16686`

### Searching for Flows

1. **Service**: Select `mermin` or specific pod names
2. **Operation**: Network flow operations
3. **Tags**: Filter by:
   - `source.pod.name`
   - `destination.service.name`
   - `network.protocol`
   - `destination.port`

### Example Searches

**Find all TCP flows to port 443:**
- Tag: `network.protocol=TCP`
- Tag: `destination.port=443`

**Find flows from specific deployment:**
- Tag: `source.deployment.name=nginx`

**High latency flows:**
- Min Duration: `1s`

## Storage Backends

### Elasticsearch

```yaml
storage:
  type: elasticsearch
  options:
    es:
      server-urls: http://elasticsearch:9200
      index-prefix: jaeger
```

### Cassandra

```yaml
storage:
  type: cassandra
  options:
    cassandra:
      servers: cassandra:9042
      keyspace: jaeger_v1_production
```

## Service Performance Monitoring

Jaeger's SPM feature provides:
- Request rates (flows/second)
- Error rates
- Duration percentiles

Enable in Jaeger configuration:
```yaml
query:
  ui:
    monitor:
      menuEnabled: true
```

## Next Steps

- **[Grafana](grafana.md)**: Combine with Grafana dashboards
- **[OpenTelemetry Collector](opentelemetry-collector.md)**: Advanced routing
