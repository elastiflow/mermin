# Troubleshooting

This guide will help you diagnose and resolve common issues when deploying and operating Mermin.

## Quick Diagnostic Checklist

When something goes wrong, start with these quick checks to identify the issue:

1. **Pod Status**: Check if pods are running with `kubectl get pods -n mermin`
2. **Pod Logs**: Review logs using `kubectl logs -l app.kubernetes.io/name=mermin -n mermin`
3. **Configuration**: Verify your HCL syntax and configuration values
4. **Connectivity**: Test network access to your OTLP endpoints
5. **Permissions**: Confirm RBAC roles and Linux capabilities are properly set
6. **eBPF Support**: Verify your kernel version supports eBPF

## Common Issue Categories

We've organized troubleshooting guides into three main categories based on the type of issue you're experiencing:

### [Deployment Issues](deployment-issues.md)

If Mermin won't start or keeps crashing, this guide covers pod startup failures, permission errors, CNI conflicts, and TC/TCX priority configuration.

**You'll want this guide if you're seeing:**

- Pods stuck in `Pending`, `CrashLoopBackOff`, or `Error` states
- eBPF programs that fail to load
- Permission or capability errors
- TC priority conflicts with your CNI plugin
- Flow gaps after pod restarts

### [Common eBPF Errors](common-ebpf-errors.md)

This guide helps you diagnose verifier failures, program loading errors, and kernel compatibility issues.

**Check this guide when you encounter:**

- Verifier instruction limit exceeded errors
- Invalid memory access errors
- Kernel version incompatibilities
- BTF (BPF Type Format) support issues

### [Interface Visibility and Traffic Decapsulation](interface-visibility-and-traffic-decapsulation.md)

Not seeing the traffic you expect? This guide explains traffic visibility at different network layers and how to configure interface monitoring correctly.

**This guide helps with:**

- Missing or incomplete traffic capture
- Partial flow visibility
- CNI-specific interface configuration questions
- Understanding tunnel encapsulation behavior

## Diagnostic Commands

These commands will help you gather information and diagnose issues:

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

If you need more detailed information, enable debug mode in your configuration:

```hcl
log_level = "debug"
```

### Health Check Endpoints

If you have the API server enabled, you can check Mermin's health status:

```bash
kubectl port-forward daemonset/mermin 8080:8080 -n mermin
curl http://localhost:8080/livez
curl http://localhost:8080/readyz
```

### Metrics Monitoring

Mermin exposes Prometheus metrics that can help identify performance issues and verify operations:

```bash
kubectl port-forward daemonset/mermin 10250:10250 -n mermin
curl http://localhost:10250/metrics
```

Key metrics to monitor include:

- `mermin_flow_spans_created_total` - Total flow spans created
- `mermin_packets_total` - Total packets processed
- `mermin_export_flow_spans_total{status="error"}` - Export failures (investigate if increasing)

<!-- TODO(GA Documentation): Iterate on the section -->
<!-- ## Troubleshooting

- **Interface Unavailable**: Mermin logs a warning and continues monitoring other interfaces
- **eBPF Load Failure**: Agent fails to start; check kernel version and eBPF support
- **High Packet Loss**: Increase `pipeline.ring_buffer_capacity` or reduce monitored interfaces -->
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

Still stuck? We're here to help!

### Search Existing Issues

Check if someone else has encountered the same problem: [GitHub Issues](https://github.com/elastiflow/mermin/issues)

### Open a New Issue

If you've found a bug or need help, open an issue and include:

- Mermin version and Kubernetes version
- Your CNI plugin (e.g., Calico, Cilium, Flannel)
- Complete error logs from affected pods
- Your configuration (with sensitive values removed)
- Steps to reproduce the issue

[Create an Issue →](https://github.com/elastiflow/mermin/issues/new)

### Ask Questions

Have a question or want to discuss best practices? Join the conversation in [GitHub Discussions](https://github.com/elastiflow/mermin/discussions).
