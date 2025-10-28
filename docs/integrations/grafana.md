# Grafana Integration

Integrate Mermin with Grafana for visualization and dashboarding of Flow Traces.

## Overview

Grafana provides:
- Beautiful dashboards and visualizations
- Multiple data source support
- Alerting and notifications
- Explore interface for ad-hoc queries

## Architecture

```
Mermin → Tempo/Jaeger → Grafana
```

## Prerequisites

- Grafana 9.0+
- Data source: Tempo, Jaeger, or Elasticsearch
- Mermin configured to export to chosen backend

## Grafana Data Source Configuration

### Tempo Data Source

1. Navigate to **Configuration → Data Sources**
2. Add **Tempo** data source
3. Configure:
   - URL: `http://tempo:3200`
   - Save & Test

### Jaeger Data Source

1. Add **Jaeger** data source
2. Configure:
   - URL: `http://jaeger-query:16686`
   - Save & Test

## Example Dashboard Panels

### Flow Rate Over Time

**Query (PromQL if using Prometheus):**
```promql
rate(mermin_flows_total[5m])
```

### Top Talkers by Bytes

**TraceQL (Tempo):**
```traceql
{} | select(source.pod.name, sum(flow.bytes.sent))
```

### Network Traffic Heatmap

Visualize traffic patterns over time and across services.

## Creating Dashboards

1. **New Dashboard**
2. Add **Time Series** panel
3. Configure data source and query
4. Repeat for additional visualizations

## Next Steps

- **[Grafana Tempo](tempo.md)**: Backend for Grafana
- **[Jaeger](jaeger.md)**: Alternative backend
- **[OpenTelemetry Collector](opentelemetry-collector.md)**: Data pipeline
