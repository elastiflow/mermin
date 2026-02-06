# Troubleshooting Overview

Diagnose and resolve common issues when deploying and operating Mermin.

## Quick Diagnostic Checklist

Start with these quick checks to identify issues:

1. **Pod Status**: Check if pods are running with `kubectl get pods -n mermin`
2. **Pod Logs**: Review logs using `kubectl logs -l app.kubernetes.io/name=mermin -n mermin`
3. **Configuration**: Verify your HCL syntax and configuration values
4. **Connectivity**: Test network access to your OTLP endpoints
5. **Permissions**: Confirm RBAC roles and Linux capabilities are properly set
6. **eBPF Support**: Verify your kernel version supports eBPF

## Common Issue Categories

Troubleshooting guides are organized into three categories:

### [Deployment Issues](deployment-issues.md)

Covers pod startup failures, permission errors, CNI conflicts, and TC/TCX priority configuration when Mermin fails to start or crashes.

{% hint style="warning" %}
eBPF load failures prevent startup. Verify your kernel version (5.14+) and confirm eBPF capabilities are enabled. For quick diagnosis, see the [Quick Reference Table](common-ebpf-errors.md#quick-reference) in Common eBPF Errors.
{% endhint %}

**Symptoms:**

- Pods stuck in `Pending`, `CrashLoopBackOff`, or `Error` states
- eBPF programs that fail to load
- Permission or capability errors
- TC priority conflicts with your CNI plugin
- Flow gaps after pod restarts

### [Common eBPF Errors](common-ebpf-errors.md)

Diagnose verifier failures, program loading errors, and kernel compatibility issues.

**Symptoms:**

- Verifier instruction limit exceeded errors
- Invalid memory access errors
- Kernel version incompatibilities
- BTF (BPF Type Format) support issues

### [Interface Visibility and Traffic Decapsulation](interface-visibility-and-traffic-decapsulation.md)

Explains traffic visibility at different network layers and correct interface monitoring configuration when expected traffic is missing.

> **Note:** If a configured interface is missing, Mermin logs a warning but continues monitoring other valid interfaces.

**Symptoms:**

- Missing or incomplete traffic capture
- Partial flow visibility
- CNI-specific interface configuration questions
- Understanding tunnel encapsulation behavior

## Diagnostic Commands

Use these commands to gather information and diagnose issues:

### View Pod Logs

Check what Mermin is reporting:

```bash
# View logs from all Mermin pods
kubectl logs -l app.kubernetes.io/name=mermin -n mermin

# Follow logs in real-time as they're generated
kubectl logs -f -l app.kubernetes.io/name=mermin -n mermin

# View logs from a crashed pod (previous instance)
kubectl logs mermin-xxxxx -n mermin --previous
```

### Enable Debug Logging

Enable debug mode in your configuration for detailed information:

```hcl
log_level = "debug"
```

### Health Check Endpoints

With the API server enabled, check Mermin's health status:

```bash
kubectl port-forward daemonset/mermin 8080:8080 -n mermin
curl http://localhost:8080/livez
curl http://localhost:8080/readyz
```

### Metrics Monitoring

Mermin exposes Prometheus metrics to identify performance issues and verify operations:

```bash
kubectl port-forward daemonset/mermin 10250:10250 -n mermin
curl http://localhost:10250/metrics
```

See the [Internal Metrics](../internal-monitoring/internal-metrics.md) guide for complete metrics documentation and Prometheus query examples.

Key metrics to monitor include:

- `mermin_flow_spans_created_total` - Total flow spans created
- `mermin_packets_total` - Total packets processed
- `mermin_export_flow_spans_total{exporter_type="otlp",status="error"}` - OTLP export failures (investigate if increasing)
- `mermin_export_flow_spans_total{exporter_type="stdout",status="error"}` - Stdout export failures (investigate if increasing)

#### Diagnosing Flow Span Drops

When flow spans are dropped, inspect internal metrics to identify the bottleneck stage:

- **Worker queue drops**: The kernel is producing events faster than userspace can consume them. Increase `pipeline.ebpf_ringbuf_worker_capacity` or `pipeline.worker_count`.
- **Flow span channel drops**: The enrichment stage is lagging. Increase `pipeline.flow_producer_channel_capacity` or add concurrency via `pipeline.k8s_decorator_threads`.
- **Decorated span channel drops**: There is backpressure from the export stage. Increase `pipeline.k8s_decorator_channel_capacity` or optimize your OTLP exporter settings.

If tuning does not resolve the issue, reduce the number of monitored interfaces or increase the CPU limits allocated to the agent.

### Test eBPF Capabilities

Use the `diagnose bpf` subcommand to validate eBPF support and test attach/detach operations:

```bash
# In a deployed cluster
POD=$(kubectl get pod -n mermin -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n mermin $POD -- mermin diagnose bpf

# On bare metal or in a debug pod
mermin diagnose bpf
```

This validates:

- Required Linux capabilities
- eBPF program loading and attach/detach operations
- BPF filesystem writeability
- Kernel version compatibility

For detailed usage, interpreting results, and troubleshooting failures, see [Deployment Issues: Test eBPF Attach/Detach Operations](deployment-issues.md#test-ebpf-attachdetach-operations).

## Getting Help

Additional support resources:

### Search Existing Issues

Check if someone else has encountered the same problem: [GitHub Issues](https://github.com/elastiflow/mermin/issues)

### Open a New Issue

When opening an issue, include:

- Mermin version and Kubernetes version
- Your CNI plugin (e.g., Calico, Cilium, Flannel)
- Complete error logs from affected pods
- Your configuration (with sensitive values removed)
- Steps to reproduce the issue

[Create an Issue →](https://github.com/elastiflow/mermin/issues/new)

### Ask Questions

For questions and best practices, join [GitHub Discussions](https://github.com/elastiflow/mermin/discussions).
