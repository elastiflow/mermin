---
hidden: true
---

# No Flow Traces

This guide helps diagnose issues where Mermin is running but not capturing or exporting Flow Traces.

## No Flow Traces Being Generated

### Symptom

Mermin pods are running, but logs show no Flow Trace activity or export attempts.

### Diagnosis

Check Mermin logs:

```bash
kubectl logs -f mermin-xxxxx -n mermin
```

Enable debug logging:

```hcl
log_level = "debug"
```

Check metrics:

```bash
kubectl port-forward daemonset/mermin 10250:10250 -n mermin
curl http://localhost:10250/metrics | grep mermin_packets_processed_total
```

If `mermin_packets_processed_total` is 0, no packets are being captured.

## Interface Not Found Errors

### Symptom

Logs show:

```
WARN Interface pattern 'eth0' did not match any interfaces
ERROR No interfaces found to instrument
```

### Diagnosis

List available interfaces on the node:

```bash
# Get node name from pod
kubectl get pod mermin-xxxxx -n mermin -o jsonpath='{.spec.nodeName}'

# Debug into node
kubectl debug node/worker-node -it --image=ubuntu -- ip link show
```

### Common Causes

#### 1. Incorrect Interface Pattern

**Solution**: Update interface patterns to match your environment:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "cni*"]  # Common patterns
}
```

For cloud providers:

* **GKE**: `["eth*", "gke-*"]`
* **EKS**: `["eth*"]`
* **AKS**: `["eth*", "cni*"]`

#### 2. CNI-Specific Interfaces Not Monitored

Intra-node traffic (pod-to-pod on same node) may use CNI-specific interfaces.

**Solution**: Add CNI bridge interfaces:

```hcl
discovery "instrument" {
  interfaces = [
    "eth*",     # Inter-node traffic
    "cni0",     # Intra-node traffic (common CNIs)
    "docker0",  # Docker bridge
  ]
}
```

See [Advanced Scenarios](../deployment/advanced-scenarios.md#custom-cni-configurations) for CNI-specific patterns.

## eBPF Attachment Issues

### Symptom

Logs show:

```
ERROR Failed to attach eBPF program to interface eth0: Invalid argument
```

### Common Causes

#### 1. Interface Not in Expected State

Some interfaces may not be ready when Mermin starts.

**Solution**: Mermin retries automatically. If persistent, check interface status:

```bash
kubectl debug node/worker-node -it --image=ubuntu -- ip link show eth0
```

Ensure interface is UP:

```bash
ip link set eth0 up
```

#### 2. Conflicting eBPF Programs

**Symptom**: `Device or resource busy`

Another eBPF program may already be attached to the interface.

**Diagnosis**:

```bash
# Check for existing eBPF programs
kubectl debug node/worker-node -it --image=ubuntu -- \
  ls -la /sys/fs/bpf/
```

**Solution**: Identify conflicting programs and either remove them or adjust Mermin's interface selection.

## Verifying Packet Capture

### Generate Test Traffic

Create test pods to generate traffic:

```bash
# Create test pods
kubectl run test-client --image=curlimages/curl --rm -it -- sh
kubectl run test-server --image=nginx

# From test-client, generate traffic
curl http://test-server
```

### Check Mermin Captures This Traffic

1. **Enable debug logging** to see packet processing:

```hcl
log_level = "debug"
```

2. **Watch Mermin logs** while generating traffic:

```bash
kubectl logs -f mermin-xxxxx -n mermin | grep -i "flow\|packet"
```

3. **Check metrics** for packet count increase:

```bash
curl http://localhost:10250/metrics | grep mermin_packets_processed_total
```

Expected output shows increasing counter values.

## No Kubernetes Metadata in Flows

### Symptom

Flows are captured but lack Kubernetes context (pod names, namespaces, etc.).

See [**Kubernetes Metadata Issues**](kubernetes-metadata.md) for detailed troubleshooting.

## Filtering Too Restrictive

### Symptom

Mermin captures packets but few or no flows are exported.

### Diagnosis

Check if you have flow filters configured:

```hcl
filter {
  source {
    address = ["10.0.0.0/8"]  # Only internal traffic
  }
}
```

### Solution

1. **Temporarily disable filters** to confirm they're the cause:

```hcl
# Comment out filter block
# filter { ... }
```

2. **Review and adjust filter rules**:
   * Check for overly restrictive address ranges
   * Verify port filters aren't blocking expected traffic
   * Consider using `exclude` patterns instead of `include`

See [Filtering Options](../configuration/filtering-options.md) for details.

## eBPF Map Size Limits

### Symptom

Logs show:

```
ERROR Failed to insert flow into map: No space left on device
```

### Solution

Increase eBPF map sizes (requires rebuilding Mermin):

```rust
// In mermin-ebpf code
#[map]
static FLOW_MAP: HashMap<FlowKey, FlowInfo> = HashMap::with_max_entries(100000, 0);
```

Or reduce flow retention:

```hcl
span {
  max_record_interval = "30s"  # Reduce from default
  generic_timeout = "1m"
}
```

## Next Steps

* [**Kubernetes Metadata Issues**](kubernetes-metadata.md): Missing pod/service information
* [**Export Issues**](export-issues.md): Flows captured but not exported
* [**Performance Issues**](performance.md): High packet loss
