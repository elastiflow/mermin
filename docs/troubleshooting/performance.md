---
hidden: true
---

# Performance Issues

## Performance Troubleshooting

This guide helps diagnose and resolve performance problems with Mermin, including high resource usage and packet/flow drops.

### Quick Reference

#### Diagnostic Decision Tree

```
Is Mermin pod Running?
├─ NO  → See Deployment Issues
└─ YES → Continue below

Are flows being captured?
├─ NO  → See No Flow Traces guide
└─ YES → Continue below

What symptom are you seeing?
├─ High CPU usage (>80% consistently)
│   ├─ Check: kubectl top pods -l app.kubernetes.io/name=mermin
│   └─ Go to: High CPU Usage section
│
├─ High Memory usage or OOMKills
│   ├─ Check: kubectl top pods -l app.kubernetes.io/name=mermin
│   └─ Go to: High Memory Usage section
│
├─ Packet/Flow drops (missing data)
│   ├─ Check: curl http://localhost:10250/metrics | grep dropped
│   └─ Go to: Packet/Flow Drops section
│
└─ Slow export or backpressure
    ├─ Check: kubectl logs mermin-xxxxx | grep backpressure
    └─ Go to: Export Issues guide
```

#### Quick Diagnostic Commands

Run these commands to quickly assess Mermin health:

```bash
# 1. Check pod status and resource usage
kubectl get pods -l app.kubernetes.io/name=mermin -n mermin
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin

# 2. Check for drops and errors
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n mermin $POD -- wget -qO- http://localhost:10250/metrics | grep -E "(dropped|error)_total"

# 3. Check for CPU throttling
kubectl describe pod -n mermin $POD | grep -i throttl

# 4. Check for OOMKills
kubectl describe pod -n mermin $POD | grep -i oom

# 5. Check recent logs for warnings
kubectl logs -n mermin $POD --tail=50 | grep -i "warn\|error"
```

#### Comprehensive Health Check Script

Copy-paste this script for a full health assessment:

```bash
#!/bin/bash
NAMESPACE=${1:-mermin}
echo "=== Mermin Performance Health Check ==="
echo

echo "1. Pod Status:"
kubectl get pods -l app.kubernetes.io/name=mermin -n $NAMESPACE -o wide
echo

echo "2. Resource Usage:"
kubectl top pods -l app.kubernetes.io/name=mermin -n $NAMESPACE
echo

echo "3. Performance Metrics:"
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n $NAMESPACE $POD -- wget -qO- http://localhost:10250/metrics 2>/dev/null | grep -E "(packets_processed_total|packets_dropped_total|flows_exported_total|export_errors_total|export_queue_size)" | tail -10
echo

echo "4. CPU Throttling:"
kubectl describe pod -n $NAMESPACE $POD | grep -i throttl || echo "No throttling detected"
echo

echo "5. Memory Issues:"
kubectl describe pod -n $NAMESPACE $POD | grep -i oom || echo "No OOMKills detected"
echo

echo "6. Recent Warnings/Errors:"
kubectl logs -n $NAMESPACE $POD --tail=20 | grep -iE "warn|error|drop|backpressure" || echo "No recent warnings"
```

#### Severity Reference

| Issue               | Severity     | Impact                | Response Time    |
| ------------------- | ------------ | --------------------- | ---------------- |
| OOMKill / Pod crash | **Critical** | Data loss, no flows   | Immediate        |
| Packet drops >5%    | **High**     | Significant data loss | Within 1 hour    |
| CPU throttling      | **High**     | Degraded performance  | Within 4 hours   |
| Memory >80% limit   | **Medium**   | Risk of OOMKill       | Within 24 hours  |
| CPU >80% sustained  | **Medium**   | Potential throttling  | Within 24 hours  |
| Slow export         | **Low**      | Increased latency     | Next maintenance |

***

### High CPU Usage

**Severity:** High | **Impact:** Potential throttling, degraded capture rate

#### Symptoms

**What you'll see:**

* Mermin pods consuming >80% CPU consistently
* CPU throttling events in pod description
* Increased packet processing latency
* Potential packet drops under load

**Key metrics:**

```bash
# Check CPU usage
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin

# Check for throttling
kubectl describe pod mermin-xxxxx -n mermin | grep -A5 "State:\s*Running"
```

#### Quick Diagnosis

```bash
# One-command health check
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{.items[0].metadata.name}')
echo "CPU Usage:" && kubectl top pod -n mermin $POD
echo "Throttling:" && kubectl describe pod -n mermin $POD | grep -i throttl
echo "Log Level:" && kubectl logs -n mermin $POD --tail=100 | grep "log_level\|Starting mermin" | head -5
```

#### Root Causes (Ordered by Likelihood)

**1. Debug Logging Enabled (Most Common)**

**Likelihood:** Very High

Debug logging can increase CPU usage by 3-5x compared to info level.

**How to confirm:**

```bash
kubectl logs mermin-xxxxx -n mermin --tail=100 | grep -i "level.*debug"
```

**Solution:**

```hcl
log_level = "info"  # Change from "debug"
```

**Validation:**

```bash
# After restart, CPU should drop by 50-70%
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin
```

**Prevention:**

* Never use `debug` level in production
* Only enable debug temporarily for troubleshooting specific issues
* Set alerts if debug logging is enabled >1 hour

**2. High Traffic Volume**

**Likelihood:** High

Insufficient worker threads for packet processing rate.

**How to confirm:**

```bash
# Check packet rate (should be <10K packets/sec per worker)
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep packets_processed_total
```

**Solution:**

```hcl
pipeline {
  # Increase workers to match CPU cores
  worker_count = 8  # Default is 4, max recommended = CPU cores
}
```

**Validation:**

```bash
# CPU should distribute more evenly across cores
kubectl exec mermin-xxxxx -n mermin -- top -b -n 1 | head -15
```

**Prevention:**

* Size worker threads based on expected traffic: 1 worker per 10K pps
* Monitor packet rate and scale workers before CPU hits 70%

**3. Large Kubernetes Cluster**

**Likelihood:** Medium

Too many Kubernetes objects cached by informers.

**How to confirm:**

```bash
# Check number of pods being watched
kubectl logs mermin-xxxxx -n mermin | grep "informer.*synced" | tail -5
```

**Solution:**

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "Pod", namespaces = ["production", "staging"] },  # Limit namespaces
    { kind = "Service", namespaces = ["production", "staging"] },
    # Only include necessary resource types
  ]
}
```

**Validation:**

```bash
# CPU should drop by 10-20% after restart
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin
```

**Prevention:**

* Only watch namespaces that need flow monitoring
* Exclude system namespaces (kube-system, kube-public) unless needed

**4. Inefficient Flow Timeouts**

**Likelihood:**  Low

Very short timeouts cause frequent flow table scans and exports.

**How to confirm:**

```bash
# Check flow export rate (should be <100/sec typically)
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep flows_exported_total
```

**Solution:**

```hcl
span {
  generic_timeout = "2m"      # Don't go below 30s
  tcp_timeout = "5m"
  udp_timeout = "1m"
  max_record_interval = "2m"  # Export long-lived flows periodically
}
```

**Validation:**

```bash
# Flow export rate should decrease
watch 'kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep flows_exported_total'
```

**Prevention:**

* Use default timeouts unless you have specific requirements
* Balance between memory usage (longer timeouts) and CPU (shorter timeouts)

#### Related Issues

* High Memory Usage - Often correlated with high CPU
* Packet/Flow Drops - Can result from CPU exhaustion
* Export Issues - Slow export can back up and increase CPU load

***

### High Memory Usage

**Severity:** High (if >90% limit) / Medium (if 70-90%) | **Impact:** Risk of OOMKill and pod restart

#### Symptoms

**What you'll see:**

* Mermin pods consuming >70% of memory limit
* OOMKilled events in pod events
* Pod restarts with exit code 137 (OOMKilled)
* Memory usage steadily increasing over time

**Key metrics:**

```bash
# Check memory usage
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin

# Check for OOMKills
kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[0].lastState.terminated.reason}{"\n"}{end}'

# Check metrics
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n mermin $POD -- wget -qO- http://localhost:10250/metrics | grep process_resident_memory_bytes
```

#### Quick Diagnosis

```bash
# One-command health check
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{.items[0].metadata.name}')
echo "Memory Usage:" && kubectl top pod -n mermin $POD
echo "OOMKills:" && kubectl describe pod -n mermin $POD | grep -i oom
echo "Restarts:" && kubectl get pod -n mermin $POD -o jsonpath='{.status.containerStatuses[0].restartCount}'
```

#### Root Causes (Ordered by Likelihood)

**1. Large Flow Tables (Most Common)**

**Likelihood:** Very High

High flow volume or long-lived connections fill in-memory flow state table.

**How to confirm:**

```bash
# Check active flow count (each flow ~1-2KB memory)
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep mermin_active_flows
```

**Solution:**

```hcl
span {
  max_record_interval = "1m"  # Export long-lived flows more frequently
  generic_timeout = "1m"       # Timeout inactive flows sooner
  tcp_timeout = "3m"           # Shorter TCP timeout
  udp_timeout = "30s"          # Shorter UDP timeout
}
```

**Validation:**

```bash
# Memory usage should stabilize or decrease
watch -n 10 'kubectl top pod -n mermin $POD'

# Active flow count should stay below threshold
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep mermin_active_flows
```

**Prevention:**

* For high-traffic environments, use shorter timeouts
* Monitor active flow count and set alerts at 80% of memory capacity
* Estimate: \~50K concurrent flows per GB of memory

**2. Large Kubernetes Object Cache**

**Likelihood:**  High

Informers cache all selected Kubernetes objects in memory.

**How to confirm:**

```bash
# Check informer cache size in logs
kubectl logs mermin-xxxxx -n mermin | grep "informer.*synced" | tail -10

# Estimate: ~1KB per pod, ~500B per service
```

**Solution:**

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "Service", namespaces = ["production"] },
    { kind = "Pod", namespaces = ["production"] },
    # Remove unnecessary resource types
    # { kind = "Gateway" },    # Disable if not needed
    # { kind = "Ingress" },    # Disable if not needed
  ]
}
```

**Validation:**

```bash
# Memory should drop by 10-30% depending on cluster size
kubectl top pods -l app.kubernetes.io/name=mermin -n mermin
```

**Prevention:**

* Only watch namespaces and resources needed for your use case
* Large clusters (>1000 pods): filter to specific namespaces
* Estimate: 1MB per 1000 pods watched

**3. Large Export Queue**

**Likelihood:** Medium

Slow OTLP endpoint causes flows to queue in memory.

**How to confirm:**

```bash
# Check export queue size (should be <50% of max)
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep mermin_export_queue_size

# Check export errors
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep mermin_export_errors_total
```

**Solution:**

**Option A - Reduce queue size:**

```hcl
export "traces" {
  otlp = {
    max_queue_size = 1024      # Reduce from 2048, drop old flows if full
    max_batch_size = 512
    max_batch_interval = "5s"
  }
}
```

**Option B - Increase export rate (if collector can handle it):**

```hcl
export "traces" {
  otlp = {
    max_concurrent_exports = 4      # Increase parallelism
    max_batch_size = 1024           # Larger batches
    max_batch_interval = "2s"       # More frequent exports
    timeout = "15s"                 # Faster timeout
  }
}
```

**Validation:**

```bash
# Queue size should stay well below max_queue_size
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep mermin_export_queue_size

# Export errors should be zero or near-zero
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep mermin_export_errors_total
```

**Prevention:**

* Size export queue based on expected flow rate and export latency
* Monitor queue utilization and set alerts at 70%
* Formula: `max_queue_size > (flow_rate * export_latency_seconds)`

**4. Memory Leak**

**Likelihood:**  Very Low

Potential software bug causing memory to grow continuously.

**How to confirm:**

```bash
# Monitor memory over 6-24 hours
for i in {1..24}; do
  echo "$(date): $(kubectl top pod -n mermin $POD | tail -1)"
  sleep 600  # Every 10 minutes
done

# Memory should not grow continuously if load is stable
```

**Solution:**

1. Check Mermin version for known memory issues
2. Collect heap profile if available
3. Report to GitHub with:
   * Mermin version
   * Memory growth rate
   * Configuration
   * Traffic patterns

**When to restart vs. tune:**

* **Restart if:** Memory growing >10% per hour with stable traffic
* **Tune if:** Memory is high but stable

**Prevention:**

* Keep Mermin updated to latest version
* Monitor memory trends, not just current usage
* Set up automated restarts as temporary mitigation if leak confirmed

#### Related Issues

* High CPU Usage - Memory pressure can increase CPU from GC
* Packet/Flow Drops - Memory exhaustion can cause drops
* Kubernetes Metadata Issues - Informer cache issues

***

### Packet Loss / Flow Drops

**Severity:** High (if >5%) / Medium (if 1-5%) | **Impact:** Missing flow data, incomplete visibility

#### Symptoms

**What you'll see:**

* `mermin_packets_dropped_total` metric increasing
* `mermin_flows_dropped_total` metric increasing
* Gaps in flow data
* Log warnings about full channels or backpressure

**Key metrics:**

```bash
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{.items[0].metadata.name}')

# Check drop metrics
kubectl exec -n mermin $POD -- wget -qO- http://localhost:10250/metrics | grep -E "(packets|flows)_dropped_total"

# Calculate drop rate
kubectl exec -n mermin $POD -- wget -qO- http://localhost:10250/metrics | grep -E "packets_(processed|dropped)_total"
```

#### Quick Diagnosis

```bash
# One-command health check
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{.items[0].metadata.name}')
echo "Drop Metrics:" && kubectl exec -n mermin $POD -- wget -qO- http://localhost:10250/metrics | grep dropped_total
echo "Backpressure:" && kubectl logs -n mermin $POD --tail=100 | grep -i "drop\|backpressure\|full" | tail -5
echo "CPU/Memory:" && kubectl top pod -n mermin $POD
```

#### Impact Assessment

| Drop Rate | Impact                | Priority                                  |
| --------- | --------------------- | ----------------------------------------- |
| >10%      | Severe data loss      | **Critical** - Fix immediately            |
| 5-10%     | Significant data loss | **High** - Fix within 1 hour              |
| 1-5%      | Moderate data loss    | **Medium** - Fix within 24 hours          |
| <1%       | Minimal impact        | **Low** - Monitor, fix during maintenance |

#### Root Causes (Ordered by Likelihood)

**1. Insufficient Worker Threads (Most Common)**

**Likelihood:**  Very High

Not enough workers to process packet rate, causing channel overflow.

**How to confirm:**

```bash
# Check packet rate and worker count
kubectl logs mermin-xxxxx -n mermin | grep "worker_count\|Starting mermin"

# Workers should handle ~10K packets/sec each
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep packets_processed_total
```

**Solution:**

```hcl
pipeline {
  # Match or exceed CPU core count
  worker_count = 8  # Default is 4
}
```

**Validation:**

```bash
# Drops should stop or decrease dramatically
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep packets_dropped_total

# Check rate of change over 1 minute
watch -n 60 'kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep packets_dropped_total'
```

**Prevention:**

* Size workers based on traffic: 1 worker per 10K pps
* Set workers = CPU cores for optimal parallelism
* Monitor drop rate and scale proactively

**2. Small Channel Capacity**

**Likelihood:** High

Ring buffer between eBPF and userspace is too small for traffic bursts.

**How to confirm:**

```bash
# Drops correlate with traffic bursts
# Check if drops happen during specific times
kubectl logs mermin-xxxxx -n mermin --timestamps | grep -i "channel full\|ring buffer"
```

**Solution:**

```hcl
pipeline {
  # Increase buffer size (uses more memory)
  ring_buffer_capacity = 16384  # Default is 8192, can go higher for extreme traffic
}
```

**Validation:**

```bash
# Monitor for "channel full" messages (should disappear)
kubectl logs mermin-xxxxx -n mermin -f | grep -i "channel\|buffer"
```

**Prevention:**

* For bursty traffic, increase channel capacity
* Balance: Larger capacity = more memory, better burst handling
* Typical sizing: 2048 for moderate traffic, 4096+ for high-burst

**3. Slow OTLP Export**

**Likelihood:** Medium

Export can't keep up with flow generation, causing queue overflow.

**How to confirm:**

```bash
# Check export queue size and errors
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep -E "export_(queue_size|errors_total)"

# Check export latency
kubectl logs mermin-xxxxx -n mermin | grep -i "export.*slow\|timeout"
```

**Solution:**

**Step 1 - Optimize export configuration:**

```hcl
export "traces" {
  otlp = {
    max_concurrent_exports = 8      # More parallel exports
    max_batch_size = 1024            # Larger batches (fewer requests)
    max_batch_interval = "3s"        # More frequent batching
    timeout = "30s"                  # Increase if network is slow
    max_queue_size = 4096            # Larger queue (more memory)
  }
}
```

**Step 2 - Check OTLP collector:**

```bash
# Test connectivity and latency
kubectl exec mermin-xxxxx -n mermin -- time wget -qO- http://otel-collector:4317

# Check collector resource usage
kubectl top pods -l app=otel-collector
```

**Validation:**

```bash
# Export queue should stay below 70% of max
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep export_queue_size

# Export errors should be zero
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep export_errors_total
```

**Prevention:**

* Size export parallelism based on collector capacity
* Monitor export latency and queue utilization
* Scale collector before Mermin if export is bottleneck

**4. Resource Limits Too Low**

**Likelihood:**  Low

CPU throttling or memory pressure causes processing delays.

**How to confirm:**

```bash
# Check for throttling and memory pressure
kubectl describe pod mermin-xxxxx -n mermin | grep -A10 "State:\s*Running"
kubectl describe pod mermin-xxxxx -n mermin | grep -i "throttl\|oom"
```

**Solution:**

```yaml
# In Helm values.yaml
resources:
  requests:
    cpu: 1          # Increase request to reduce throttling
    memory: 512Mi
  limits:
    cpu: 2          # Increase limit
    memory: 1Gi     # Increase limit
```

**Validation:**

```bash
# No throttling should occur
kubectl describe pod mermin-xxxxx -n mermin | grep -i throttl

# Drops should decrease after restart
kubectl exec mermin-xxxxx -n mermin -- wget -qO- http://localhost:10250/metrics | grep dropped_total
```

**Prevention:**

* Set CPU request = typical usage to avoid throttling
* Set limits 2x requests for burst capacity
* Monitor actual usage and adjust proactively

#### Backpressure Detection Workflow

```
1. Confirm drops are occurring
   └─> kubectl exec mermin-xxxxx -- wget -qO- http://localhost:10250/metrics | grep dropped

2. Identify bottleneck
   ├─> High CPU or throttling?    → Add workers or increase CPU
   ├─> Export queue near max?     → Optimize export or scale collector
   ├─> Memory near limit?         → Increase memory or reduce flow retention
   └─> None of above?             → Increase channel capacity

3. Apply fix and validate
   └─> Monitor drop metrics for 10+ minutes to confirm resolution
```

#### Related Issues

* High CPU Usage - CPU exhaustion causes packet drops
* High Memory Usage - Memory pressure can cause drops
* Export Issues - Export bottleneck causes flow drops

***

### Resource Tuning Guidelines

#### Quick Sizing Table

| Cluster Size            | Traffic Volume | CPU Request | CPU Limit | Memory Request | Memory Limit | Workers | Channel |
| ----------------------- | -------------- | ----------- | --------- | -------------- | ------------ | ------- | ------- |
| **Small** <50 nodes     | <1 Gbps        | 200m        | 1         | 256Mi          | 512Mi        | 4       | 1024    |
| **Medium** 50-200 nodes | 1-10 Gbps      | 500m        | 2         | 512Mi          | 1Gi          | 6       | 2048    |
| **Large** >200 nodes    | >10 Gbps       | 1           | 4         | 1Gi            | 2Gi          | 8       | 4096    |

#### Configuration Templates

**Small Environment (<50 nodes, <1 Gbps)**

```hcl
# Minimal resource consumption
pipeline {
  ring_buffer_capacity = 2048
  worker_count = 2
}

span {
  max_record_interval = "2m"
  generic_timeout = "2m"
  tcp_timeout = "5m"
}

export "traces" {
  otlp = {
    max_batch_size = 512
    max_batch_interval = "5s"
    max_concurrent_exports = 2
    max_queue_size = 8192
  }
}
```

**Medium Environment (50-200 nodes, 1-10 Gbps)**

```hcl
# Balanced configuration
pipeline {
  ring_buffer_capacity = 4096
  worker_count = 4
}

span {
  max_record_interval = "1m"
  generic_timeout = "1m"
  tcp_timeout = "3m"
}

export "traces" {
  otlp = {
    max_batch_size = 1024
    max_batch_interval = "5s"
    max_concurrent_exports = 4
    max_queue_size = 16384
  }
}

# Filter to relevant namespaces
discovery "informer" "k8s" {
  selectors = [
    { kind = "Pod", namespaces = ["production", "staging"] },
    { kind = "Service", namespaces = ["production", "staging"] },
  ]
}
```

**Large Environment (>200 nodes, >10 Gbps)**

```hcl
# High-throughput configuration
pipeline {
  ring_buffer_capacity = 8192
  worker_count = 8
  k8s_decorator_threads = 12
}

span {
  max_record_interval = "30s"
  generic_timeout = "1m"
  tcp_timeout = "3m"
  udp_timeout = "30s"
}

export "traces" {
  otlp = {
    max_batch_size = 2048
    max_batch_interval = "3s"
    max_concurrent_exports = 8
    max_queue_size = 32768
  }
}

# Strict namespace filtering
discovery "informer" "k8s" {
  selectors = [
    { kind = "Pod", namespaces = ["production"] },
    { kind = "Service", namespaces = ["production"] },
    # Exclude unnecessary resources
  ]
}
```

***

### Prevention Best Practices

#### Pre-Production Checklist

Before deploying Mermin to production:

* [ ] **Resource Sizing**
  * [ ] CPU/memory limits match expected traffic volume
  * [ ] Worker count = CPU core count (or traffic-based)
  * [ ] Channel capacity sized for traffic bursts
* [ ] **Configuration Review**
  * [ ] Log level set to `info` (NOT `debug`)
  * [ ] Informers filtered to relevant namespaces
  * [ ] Flow timeouts appropriate for traffic patterns
  * [ ] Export configuration tested with target collector
* [ ] **Testing**
  * [ ] Load tested at 2x expected peak traffic
  * [ ] Drop rate <0.1% under load
  * [ ] Memory stable over 24 hours
  * [ ] No CPU throttling under normal load
* [ ] **Monitoring**
  * [ ] Alerts configured for drop rate >1%
  * [ ] Alerts configured for memory >80% limit
  * [ ] Alerts configured for export errors
  * [ ] Dashboard showing key metrics

#### Capacity Planning

**Estimating Resource Requirements**

**CPU:**

```
CPU cores needed = (packets_per_sec / 10000) + 0.5
```

Example: 50K pps → (50000/10000) + 0.5 = 5.5 cores → request 3, limit 6

**Memory:**

```
Memory MB = (active_flows * 1.5KB) + (pods_watched * 1KB) + 200MB baseline
```

Example: 10K flows + 500 pods → (10000 \* 1.5) + (500 \* 1) + 200 = \~16MB → request 512Mi, limit 1Gi

**Workers:**

```
workers = min(CPU_cores, packets_per_sec / 10000)
```

**Growth Planning**

| Metric       | Warning Threshold | Action                                      |
| ------------ | ----------------- | ------------------------------------------- |
| CPU usage    | >70% sustained    | Plan to add workers or CPU                  |
| Memory usage | >70% of limit     | Plan to increase memory or reduce retention |
| Drop rate    | >0.5%             | Immediate investigation, plan scaling       |
| Export queue | >70% of max       | Plan to scale export or collector           |

#### Monitoring Setup

**Essential Metrics**

```promql
# Drop rate (should be <1%)
rate(mermin_packets_dropped_total[5m]) / rate(mermin_packets_processed_total[5m]) * 100

# Memory usage percent
container_memory_usage_bytes{pod=~"mermin-.*"} / container_spec_memory_limit_bytes{pod=~"mermin-.*"} * 100

# CPU throttling
rate(container_cpu_cfs_throttled_seconds_total{pod=~"mermin-.*"}[5m])

# Export errors
rate(mermin_export_errors_total[5m])

# Active flows
mermin_active_flows

# Export queue utilization
mermin_export_queue_size / mermin_export_queue_max * 100
```

**Recommended Alerts**

```yaml
# Critical alerts
- alert: MerminHighDropRate
  expr: rate(mermin_packets_dropped_total[5m]) / rate(mermin_packets_processed_total[5m]) > 0.05
  for: 5m
  severity: critical

- alert: MerminOOMKill
  expr: kube_pod_container_status_last_terminated_reason{reason="OOMKilled", container="mermin"} == 1
  severity: critical

# Warning alerts
- alert: MerminHighMemory
  expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.8
  for: 10m
  severity: warning

- alert: MerminCPUThrottling
  expr: rate(container_cpu_cfs_throttled_seconds_total[5m]) > 0.1
  for: 10m
  severity: warning
```

***

### Real-World Troubleshooting Scenarios

#### Scenario 1: Sudden CPU Spike After Deployment

**Situation:** Mermin CPU jumped from 20% to 95% after routine deployment.

**Investigation:**

```bash
# Check recent configuration changes
kubectl get configmap mermin-config -o yaml

# Check log level
kubectl logs mermin-xxxxx | grep "log_level\|Starting mermin" | tail -1
```

**Root Cause:** Debug logging was accidentally enabled in new config.

**Resolution:**

```hcl
# Changed from:
log_level = "debug"

# To:
log_level = "info"
```

**Result:** CPU dropped from 95% to 18% within 2 minutes.

**Prevention:** Add pre-deployment config validation to CI/CD.

***

#### Scenario 2: Memory Growing to OOMKill

**Situation:** Mermin pods being OOMKilled every 6-8 hours.

**Investigation:**

```bash
# Check memory trend
kubectl logs mermin-xxxxx --previous | grep "memory\|heap"

# Check active flows
kubectl exec mermin-xxxxx -- wget -qO- http://localhost:10250/metrics | grep active_flows

# Found: 45K active flows growing continuously
```

**Root Cause:** Long-lived database connections with no timeout, filling flow table.

**Resolution:**

```hcl
span {
  max_record_interval = "1m"   # Export long-lived flows every minute
  tcp_timeout = "5m"            # Force timeout on idle TCP
}
```

**Result:** Memory stabilized at 60%, no more OOMKills.

**Prevention:** Monitor active flow count, set alerts at 80% of capacity.

***

#### Scenario 3: 15% Packet Drop Rate During Peak Hours

**Situation:** Packet drops only during 9am-5pm business hours.

**Investigation:**

```bash
# Check CPU and throttling during peak
kubectl top pods -l app.kubernetes.io/name=mermin
kubectl describe pod mermin-xxxxx | grep throttl

# Found: CPU limit causing throttling during bursts
```

**Root Cause:** CPU limit (1 core) too low for peak traffic bursts.

**Resolution:**

```yaml
resources:
  requests:
    cpu: 1
  limits:
    cpu: 2  # Increased from 1
```

**Result:** Drop rate went from 15% to <0.1% during peak.

**Prevention:** Size limits for peak traffic, not average.

***

#### Scenario 4: Export Queue Always Full

**Situation:** Export queue at 100%, flows being dropped.

**Investigation:**

```bash
# Check export metrics
kubectl exec mermin-xxxxx -- wget -qO- http://localhost:10250/metrics | grep export

# Check OTLP collector
kubectl top pods -l app=otel-collector

# Found: Collector at 100% CPU, can't keep up
```

**Root Cause:** Collector under-provisioned for flow volume.

**Resolution:**

**Option A - Scale collector:**

```bash
kubectl scale deployment otel-collector --replicas=3
```

**Option B - Reduce flow volume to collector:**

```hcl
export "traces" {
  otlp = {
    max_batch_size = 2048     # Larger batches
    max_batch_interval = "10s" # Less frequent
  }
}
```

**Result:** Export queue dropped to 20% utilization.

**Prevention:** Load test collector capacity before deploying Mermin at scale.

***

## Advanced Performance Monitoring

### Pipeline Backpressure Monitoring

Mermin includes metrics to monitor pipeline health and detect backpressure early.

#### Key Metrics

```prometheus
# Check for backpressure
rate(mermin_flow_events_dropped_backpressure_total[5m]) > 0

# Adaptive sampling activity
mermin_flow_events_sampling_rate > 0

# Channel utilization
mermin_channel_capacity_used_ratio{channel="flow_spans"} > 0.8

# Export channel drops
rate(mermin_flow_spans_dropped_export_failure_total[5m]) > 0

# Pipeline stage latency
histogram_quantile(0.95, rate(mermin_processing_latency_seconds_bucket[5m]))
```

#### Backpressure Runbook

**Symptoms:**

* `mermin_flow_events_dropped_backpressure_total` increasing
* `mermin_flow_events_sampling_rate` > 0
* Logs showing "worker channel backpressure"

**Diagnosis:**

```bash
# Check sampling rate per worker
kubectl exec $POD -- wget -qO- http://localhost:10250/metrics | grep sampling_rate

# Check channel utilization
kubectl exec $POD -- wget -qO- http://localhost:10250/metrics | grep channel_capacity_used_ratio

# Check where pipeline is bottlenecked
kubectl exec $POD -- wget -qO- http://localhost:10250/metrics | grep processing_latency | grep "0.95"
```

**Resolution:**

1. **If worker channels are full:**

```hcl
pipeline {
  # Increase workers for more parallelism
  worker_count = 8

  # Increase flow span channel to absorb bursts
  flow_span_channel_multiplier = 3.0
}
```

2. **If K8s decorator is slow:**

```hcl
pipeline {
  # Increase decorator parallelism
  k8s_decorator_threads = 8
}
```

3. **If export channel is full:**

```hcl
pipeline {
  # Larger export buffer
  decorated_span_channel_multiplier = 8.0
}

export "traces" {
  otlp = {
    # Faster export
    max_concurrent_exports = 4
    max_export_timeout = "5s"
  }
}
```

### Pipeline Health Dashboard

Create a Grafana dashboard with these queries:

```prometheus
# Backpressure Overview
sum(rate(mermin_flow_events_dropped_backpressure_total[5m])) by (pod)
sum(rate(mermin_flow_events_sampled_total[5m])) by (pod)

# Channel Health
mermin_channel_capacity_used_ratio

# Pipeline Latency p95
histogram_quantile(0.95,
  sum(rate(mermin_processing_latency_seconds_bucket[5m])) by (le, stage)
)

# Export Health
rate(mermin_flow_spans_dropped_export_failure_total[5m])
rate(mermin_spans_exported_total[5m])

# IP Index Update Performance
rate(mermin_k8s_ip_index_updates_total[5m])
histogram_quantile(0.95, rate(mermin_k8s_ip_index_update_duration_seconds_bucket[5m]))
```

### Health Thresholds

Set up alerts based on these thresholds:

| Metric              | Warning | Critical | Action                 |
|---------------------|---------|----------|------------------------|
| Backpressure rate   | > 1%    | > 5%     | Increase channel sizes |
| Channel utilization | > 80%   | > 95%    | Increase capacity      |
| p95 latency         | > 50ms  | > 100ms  | Optimize pipeline      |
| Export drops        | > 0     | > 10/min | Fix export config      |
| IP index update p95 | > 50ms  | > 100ms  | Optimize K8s config    |

***

### Next Steps

#### If Issues Persist

1. **Gather Diagnostic Bundle:**

```bash
# Create diagnostic archive
kubectl logs -l app.kubernetes.io/name=mermin -n mermin --tail=500 > mermin-logs.txt
kubectl describe pods -l app.kubernetes.io/name=mermin -n mermin > mermin-pods.txt
kubectl get configmap mermin-config -o yaml > mermin-config.yaml
POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n mermin -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n mermin $POD -- wget -qO- http://localhost:10250/metrics > mermin-metrics.txt
```

2. **Report Issue:**
   * GitHub: [https://github.com/elastiflow/mermin/issues](https://github.com/elastiflow/mermin/issues)
   * Include: Mermin version, Kubernetes version, CNI, diagnostic bundle

#### Related Documentation

* **Configuration Reference** - Complete config options
* **Deployment Issues** - If performance prevents startup
* **Export Issues** - OTLP export troubleshooting
* **No Flow Traces** - If no flows captured
* **Kubernetes Metadata Issues** - Missing metadata

#### Optimization Resources

* **Configuration Examples** - Pre-tuned configurations
* **OTLP Export Configuration** - Export tuning
* **Architecture Overview** - Understanding Mermin internals
