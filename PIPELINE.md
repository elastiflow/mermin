# Flow Processing Pipeline

This document explains the channel-based flow processing pipeline in Mermin.

## Overview

Mermin uses a high-performance channel-based pipeline architecture that provides excellent performance, scalability, and fault tolerance by separating concerns and processing different aspects of network flows in parallel.

## Architecture

```
eBPF Ring Buffer → Packet Reader → Flow Processing Workers → Flow Store
                                ↓
                    Kubernetes Enrichment Workers → Enriched Events
                                ↓
                         OpenTelemetry/Logging Output
```

### Components

1. **Packet Reader Task**: Dedicated to reading packets from the eBPF ring buffer
2. **Flow Processing Workers**: Handle flow creation, updates, and expiration
3. **Enrichment Workers**: Add Kubernetes metadata to flow events
4. **Statistics Task**: Periodically logs pipeline performance metrics

## Configuration

The pipeline is always enabled and optimized for performance. You can configure various aspects:

### Channel Capacities

```yaml
pipeline:
  # Buffer size for packets from eBPF ring buffer
  packet_channel_capacity: 10000
  
  # Buffer size for enriched flow events
  enrichment_channel_capacity: 1000
```

### Worker Counts

```yaml
pipeline:
  # Number of concurrent flow processing workers
  flow_workers: 2
  
  # Number of Kubernetes enrichment workers
  enrichment_workers: 1
```

### Monitoring

```yaml
pipeline:
  # How often to log statistics
  stats_interval: 30s
  
  # Enable detailed performance metrics
  enable_metrics: false
```

### Backpressure Handling

```yaml
pipeline:
  # Handle channel overflow gracefully
  enable_backpressure: true
  
  # Timeout for graceful shutdown
  shutdown_timeout: 5s
```

## Performance Tuning

### High-Traffic Environments (>10K packets/sec)

```yaml
pipeline:
  packet_channel_capacity: 50000
  flow_workers: 4
  enrichment_workers: 2
  enable_backpressure: true
  enable_metrics: true
```

### Low-Traffic Environments (<1K packets/sec)

```yaml
pipeline:
  packet_channel_capacity: 5000
  enrichment_channel_capacity: 500
  flow_workers: 1
  enrichment_workers: 1
```

### Memory-Constrained Environments

```yaml
pipeline:
  packet_channel_capacity: 5000
  enrichment_channel_capacity: 500
  flow_workers: 1
  enrichment_workers: 1
  enable_metrics: false
```

### Development/Debugging

```yaml
pipeline:
  stats_interval: 10s
  enable_metrics: true
  
log_level: debug  # More verbose logging
```

## Monitoring and Observability

### Log Messages

The pipeline produces several types of log messages:

```
INFO  Flow processing pipeline initialized
INFO  Packet reader task started
INFO  Processed 1000 packets
INFO  Flow Pipeline Stats: 150 active flows, 500 total created, 350 total released, 1000 packets processed
INFO  New flow created: 1:wCb3OG7yAFWelaUydu0D+125CLM=
```

### Statistics

Pipeline statistics are logged periodically and include:

- **Active Flows**: Currently tracked flows
- **Total Created**: Lifetime flow creation count
- **Total Released**: Lifetime flow release count
- **Packets Processed**: Total packets processed

### Error Handling

The pipeline handles errors gracefully:

- **Channel Full**: Logs warnings or drops packets based on `enable_backpressure`
- **Worker Failures**: Individual workers can fail without affecting others
- **Kubernetes Unavailable**: Flow processing continues without enrichment

## Benefits

### Performance

- **Parallel Processing**: Multiple workers process flows simultaneously
- **Non-blocking**: Packet reading never waits for slow operations
- **High Throughput**: Can handle thousands of packets per second

### Scalability

- **Configurable Workers**: Scale processing based on available CPU cores
- **Tunable Buffers**: Adjust memory usage based on available RAM
- **Independent Scaling**: Scale flow processing and enrichment separately

### Reliability

- **Fault Isolation**: Component failures don't affect the entire pipeline
- **Backpressure Handling**: Prevents memory exhaustion under load
- **Graceful Degradation**: Continues operating even when components fail

### Observability

- **Component Metrics**: Monitor each pipeline stage independently
- **Queue Depths**: Track buffer utilization
- **Processing Rates**: Measure throughput at each stage

## Performance Tuning Guide

1. **Start with defaults**: The pipeline comes with sensible defaults for most workloads

2. **Monitor performance**:
   - Check log messages for statistics
   - Look for backpressure warnings
   - Monitor CPU and memory usage

3. **Tune based on workload**:
   - Increase workers for high CPU usage
   - Increase capacities for backpressure warnings
   - Decrease for memory constraints

4. **Iterate and optimize**: Monitor the effect of changes and adjust as needed

## Troubleshooting

### High Memory Usage

- Reduce `packet_channel_capacity` and `enrichment_channel_capacity`
- Set `enable_metrics: false`

### Packet Loss

- Increase `packet_channel_capacity`
- Add more `flow_workers`
- Set `enable_backpressure: true`

### High CPU Usage

- Reduce `flow_workers` and `enrichment_workers`
- Increase channel capacities to batch more work

### Slow Kubernetes Enrichment

- Increase `enrichment_workers`
- Increase `enrichment_channel_capacity`
- Consider disabling enrichment for high-traffic scenarios

## Future Enhancements

The pipeline architecture is designed for extensibility and enables several future improvements:

1. **Load Balancing**: Distribute flows across workers by Community ID hash
2. **Metrics Export**: Export detailed metrics to Prometheus/OpenTelemetry
3. **Circuit Breakers**: Automatically disable slow components under load
4. **Dynamic Scaling**: Automatically adjust worker counts based on traffic
5. **Flow Sharding**: Partition flows across multiple stores for better concurrency
6. **Priority Queues**: Prioritize certain types of flows or packets
7. **Stream Processing**: Integration with stream processing frameworks
8. **Distributed Pipeline**: Scale across multiple nodes in a cluster