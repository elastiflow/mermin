# Troubleshooting Guide

This section helps you diagnose and resolve common issues when deploying and operating Mermin.

## Diagnostic Approaches

When troubleshooting Mermin:

1. **Check Pod Status**: Ensure Mermin pods are running
2. **Review Logs**: Examine Mermin agent logs for errors
3. **Verify Configuration**: Check HCL configuration syntax and values
4. **Test Connectivity**: Verify network access to OTLP endpoints
5. **Check Permissions**: Ensure RBAC and Linux capabilities are correct
6. **Validate eBPF**: Confirm kernel eBPF support

## Common Issue Categories

### [Deployment Issues](deployment-issues.md)

Problems getting Mermin pods to start or run correctly:
- Pod not starting
- eBPF program loading failures
- Permission errors
- Kernel compatibility issues
- CNI conflicts

### [No Flow Traces](no-flows.md)

Mermin is running but not capturing or exporting Flow Traces:
- No network flows being generated
- Interface not found errors
- eBPF attachment issues
- Verifying packet capture

### [Performance Issues](performance.md)

Mermin is consuming excessive resources or dropping data:
- High CPU usage
- High memory usage
- Packet loss / flow drops
- Tuning parameters
- Resource limits

### [Kubernetes Metadata Issues](kubernetes-metadata.md)

Missing or incomplete Kubernetes context in flows:
- Missing pod metadata
- Incomplete owner information
- Informer sync failures
- RBAC permission issues

### [Export Issues](export-issues.md)

Problems sending Flow Traces to observability backends:
- OTLP connection failures
- TLS certificate errors
- Authentication failures
- Batching and backpressure

## Getting Logs

### View Mermin Pod Logs

```bash
# All Mermin pods
kubectl logs -l app.kubernetes.io/name=mermin -n mermin

# Specific pod
kubectl logs mermin-xxxxx -n mermin

# Follow logs in real-time
kubectl logs -f -l app.kubernetes.io/name=mermin -n mermin

# Previous pod instance (after crash)
kubectl logs mermin-xxxxx -n mermin --previous
```

### Increase Log Verbosity

Set `log_level` to `debug` for detailed diagnostics:

```hcl
log_level = "debug"
```

Or via Helm:
```bash
helm upgrade mermin mermin/mermin -n mermin --set logLevel=debug
```

## Checking Mermin Health

If API server is enabled:

```bash
kubectl port-forward daemonset/mermin 8080:8080 -n mermin
curl http://localhost:8080/livez
curl http://localhost:8080/readyz
```

## Checking Metrics

If metrics server is enabled:

```bash
kubectl port-forward daemonset/mermin 10250:10250 -n mermin
curl http://localhost:10250/metrics
```

Key metrics to monitor:
- `mermin_flows_total`: Total flows captured
- `mermin_packets_processed_total`: Packets processed
- `mermin_export_errors_total`: Export failures

## Getting Help

If you can't resolve the issue:

1. **Search GitHub Issues**: Check if others have encountered the same problem
   - [https://github.com/elastiflow/mermin/issues](https://github.com/elastiflow/mermin/issues)

2. **Open a New Issue**: Provide:
   - Mermin version
   - Kubernetes version
   - CNI plugin
   - Full error logs
   - Configuration (sanitized)
   - Steps to reproduce

3. **Ask in Discussions**: For questions and general troubleshooting
   - [https://github.com/elastiflow/mermin/discussions](https://github.com/elastiflow/mermin/discussions)

## Next Steps

Choose the category that matches your issue:
- **[Deployment Issues](deployment-issues.md)**
- **[No Flow Traces](no-flows.md)**
- **[Performance Issues](performance.md)**
- **[Kubernetes Metadata Issues](kubernetes-metadata.md)**
- **[Export Issues](export-issues.md)**
