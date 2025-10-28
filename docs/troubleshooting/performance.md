# Troubleshooting Performance Issues

This guide helps diagnose and resolve performance problems with Mermin, including high resource usage and packet/flow drops.

## High CPU Usage

### Symptom
Mermin pods consuming excessive CPU, potentially throttled.

### Diagnosis

Check resource usage:
```bash
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin
```

Check for CPU throttling:
```bash
kubectl describe pod mermin-xxxxx -n mermin | grep -i throttl
```

### Common Causes

#### 1. High Traffic Volume

**Solution**: Increase worker threads to parallelize processing:
```hcl
packet_worker_count = 8  # Default is 4, increase based on CPU cores
```

#### 2. Debug Logging Enabled

Debug logging significantly increases CPU usage.

**Solution**: Use `info` or `warn` level in production:
```hcl
log_level = "info"  # Not "debug"
```

#### 3. Large Kubernetes Clusters

Many Kubernetes objects increase informer overhead.

**Solution**: Filter informers to relevant namespaces:
```hcl
informer "k8s" {
  resources {
    namespace_selector = {
      match_names = ["production", "staging"]  # Not all namespaces
    }
  }
}
```

#### 4. Inefficient Flow Timeouts

Very short timeouts cause frequent flow exports.

**Solution**: Use reasonable timeout values:
```hcl
span {
  generic_timeout = "2m"      # Default is good for most cases
  tcp_timeout = "5m"
  udp_timeout = "1m"
}
```

## High Memory Usage

### Symptom
Mermin pods consuming excessive memory, potentially being OOMKilled.

### Diagnosis

Check memory usage:
```bash
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin
```

Check for OOMKills:
```bash
kubectl describe pod mermin-xxxxx -n mermin | grep -i oom
```

Check metrics:
```bash
curl http://localhost:10250/metrics | grep process_resident_memory_bytes
```

### Common Causes

#### 1. Large Flow Tables

High flow volume fills in-memory flow tables.

**Solution**: Reduce flow retention time:
```hcl
span {
  max_record_interval = "1m"  # Export long-lived flows more frequently
  generic_timeout = "1m"       # Timeout inactive flows sooner
}
```

#### 2. Large Kubernetes Object Cache

Informers cache all Kubernetes objects.

**Solution**: Reduce cached objects:
```hcl
informer "k8s" {
  resources {
    # Only watch necessary resource types
    pod = { enabled = true }
    service = { enabled = true }
    node = { enabled = true }
    # Disable unnecessary resources
    ingress = { enabled = false }
    gateway = { enabled = false }
  }

  # Filter by namespace
  resources {
    namespace_selector = {
      match_names = ["production"]
    }
  }
}
```

#### 3. Large Export Queue

Backpressure from slow OTLP endpoint fills export queue.

**Solution**: Reduce queue size or increase export rate:
```hcl
export "traces" {
  otlp = {
    max_queue_size = 1024           # Reduce if memory is constrained
    max_concurrent_exports = 4       # Increase to export faster
    max_batch_size = 512             # Larger batches = fewer exports
    max_batch_interval = "5s"        # More frequent exports
  }
}
```

#### 4. Memory Leak

Rare but possible software bug.

**Solution**:
1. Check Mermin version for known issues
2. Monitor memory over time
3. Report to GitHub if memory continuously grows

## Packet Loss / Flow Drops

### Symptom
Metrics show dropped packets or flows:
```
mermin_packets_dropped_total
mermin_flows_dropped_total
```

### Diagnosis

Check drop metrics:
```bash
curl http://localhost:10250/metrics | grep -E "(packets|flows)_dropped"
```

Check logs for backpressure warnings:
```bash
kubectl logs mermin-xxxxx -n mermin | grep -i "drop\|backpressure\|full"
```

### Common Causes

#### 1. Insufficient Worker Threads

Not enough workers to process packet rate.

**Solution**: Increase workers:
```hcl
packet_worker_count = 8  # Match or exceed number of CPU cores
```

#### 2. Small Channel Capacity

Internal channels between eBPF and userspace are full.

**Solution**: Increase capacity:
```hcl
packet_channel_capacity = 4096  # Default is 1024, increase for high throughput
```

#### 3. Slow OTLP Export

Export can't keep up with flow generation rate.

**Solution**: Optimize export configuration:
```hcl
export "traces" {
  otlp = {
    max_concurrent_exports = 8      # More parallel exports
    max_batch_size = 1024            # Larger batches
    max_batch_interval = "5s"        # More frequent batching
    timeout = "30s"                  # Increase if network is slow
  }
}
```

#### 4. Resource Limits Too Low

Kubernetes resource limits throttle Mermin.

**Solution**: Increase limits:
```yaml
# In values.yaml
resources:
  limits:
    cpu: 2        # Increase from 1
    memory: 1Gi   # Increase from 512Mi
```

## Resource Tuning Guidelines

### CPU Recommendations

| Traffic Volume | CPU Request | CPU Limit |
|----------------|-------------|-----------|
| Low (<1 Gbps) | 200m | 1 |
| Medium (1-10 Gbps) | 500m | 2 |
| High (>10 Gbps) | 1 | 4 |

### Memory Recommendations

| Cluster Size | Memory Request | Memory Limit |
|--------------|----------------|--------------|
| Small (<50 nodes) | 256Mi | 512Mi |
| Medium (50-200 nodes) | 512Mi | 1Gi |
| Large (>200 nodes) | 1Gi | 2Gi |

### Configuration for High-Throughput Environments

```hcl
# Optimize for high packet rate
packet_worker_count = 8
packet_channel_capacity = 8192

# Shorter flow retention
span {
  max_record_interval = "30s"
  generic_timeout = "1m"
  tcp_timeout = "3m"
}

# Aggressive batching
export "traces" {
  otlp = {
    max_batch_size = 2048
    max_batch_interval = "5s"
    max_concurrent_exports = 8
    max_queue_size = 4096
  }
}

# Filter unnecessary informers
informer "k8s" {
  resources {
    namespace_selector = {
      match_names = ["production"]  # Only watch production namespace
    }
  }
}
```

## Monitoring Mermin Performance

Key metrics to watch:

```bash
# Packet processing rate
mermin_packets_processed_total

# Packet drops
mermin_packets_dropped_total

# Flow export rate
mermin_flows_exported_total

# Export errors
mermin_export_errors_total

# Queue sizes
mermin_export_queue_size
```

Set up alerts for:
- Drop rate > 1%
- Export error rate > 0.1%
- Queue size near max

## Next Steps

- **[Configuration Examples](../configuration/examples.md)**: Optimized configurations
- **[Deployment Issues](deployment-issues.md)**: If performance issues prevent startup
- **[Export Issues](export-issues.md)**: If export is the bottleneck
