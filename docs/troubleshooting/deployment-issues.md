---
hidden: true
---

# Deployment Issues

This guide helps resolve issues preventing Mermin pods from starting or running correctly.

## Pod Not Starting

### Symptom

Mermin pods stuck in `Pending`, `CrashLoopBackOff`, or `Error` state.

### Diagnosis

Check pod status:

```bash
kubectl get pods -l app.kubernetes.io/name=mermin -n mermin
kubectl describe pod mermin-xxxxx -n mermin
```

Check pod events:

```bash
kubectl get events -n mermin --field-selector involvedObject.name=mermin-xxxxx
```

### Common Causes

#### 1. Insufficient Node Resources

**Symptom**: Pod stuck in `Pending` state with event: `Insufficient cpu` or `Insufficient memory`

**Solution**: Adjust resource requests or add more nodes:

```yaml
# In values.yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 1
    memory: 512Mi
```

#### 2. Pod Security Policy Restrictions

**Symptom**: `Error: container has runAsNonRoot and image will run as root`

**Solution**: Mermin requires privileged mode for eBPF. Ensure your PSP/PSS allows privileged containers or create an exception for Mermin's namespace.

#### 3. Image Pull Failures

**Symptom**: `ImagePullBackOff` or `ErrImagePull`

**Solution**:

```bash
# Check image pull status
kubectl describe pod mermin-xxxxx -n mermin | grep -A5 Events

# Verify image exists
docker pull ghcr.io/elastiflow/mermin:latest

# Check image pull secrets if using private registry
kubectl get secrets -n mermin
```

## eBPF Program Loading Failures

### Symptom

Pod starts but logs show eBPF loading errors:

```
ERROR Failed to load eBPF program: Operation not permitted
```

### Diagnosis

Check pod logs:

```bash
kubectl logs mermin-xxxxx -n mermin | grep -i ebpf
```

### Common Causes

#### 1. Missing Linux Capabilities

**Symptom**: `Operation not permitted` when loading eBPF

**Solution**: Verify privileged mode and capabilities in DaemonSet:

```yaml
securityContext:
  privileged: true
  capabilities:
    add:
      - NET_ADMIN    # TC attachment
      - BPF          # eBPF operations (kernel 5.8+)
      - PERFMON      # Ring buffers (kernel 5.8+)
      - SYS_ADMIN    # Namespace switching and BPF filesystem access
      - SYS_PTRACE   # Access process namespaces (/proc/1/ns/net)
      - SYS_RESOURCE # memlock limits
```

#### 2. Kernel Version Too Old

**Symptom**: `Invalid argument` or `Function not implemented`

**Requirements**: Linux kernel 4.9+ (5.4+ recommended)

**Check kernel version**:

```bash
kubectl debug node/worker-node -it --image=ubuntu -- uname -r
```

**Solution**: Upgrade nodes to a newer kernel version.

#### 3. BTF (BPF Type Format) Not Available

**Symptom**: `BTF is not supported`

**Check BTF availability**:

```bash
kubectl debug node/worker-node -it --image=ubuntu -- ls /sys/kernel/btf/vmlinux
```

**Solution**: Use a kernel with BTF support or ensure BTF is enabled.

#### 4. eBPF File System Not Mounted

**Symptom**: `No such file or directory: /sys/fs/bpf`

**Solution**: Ensure eBPF filesystem is mounted on nodes:

```bash
mount -t bpf bpf /sys/fs/bpf
```

For persistent mounting, add to `/etc/fstab`:

```
bpf /sys/fs/bpf bpf defaults 0 0
```

#### 5. eBPF Verifier Rejection (Program Too Large)

**Symptom**: Pod starts but eBPF program fails to load with:

```
BPF program is too large. Processed 1000001 insn
verification time 3775231 usec
stack depth 0+144+0+0+0+0+32 processed 1000001 insns (limit 1000000)
```

**Root Cause**: The eBPF verifier analyzes all possible execution paths in the program. Complex packet parsing with deep header nesting can exceed the verifier's instruction limit, even though the static program size is small.

**Diagnosis**:

Check pod logs for verifier errors:

```bash
kubectl logs mermin-xxxxx -n mermin | grep -A20 "BPF program is too large"
```

This typically occurs in:
- K3s or other lightweight Kubernetes distributions
- Older kernel versions (<5.8)
- Complex networking with many encapsulation layers

**Solution**:

**Option 1 - Reduce parser depth** (most effective):

```hcl
parser {
  max_header_depth = 5  # Default is 6, reduce to 4-5
}
```

This limits how many nested protocol headers (e.g., Ethernet → IPv6 → UDP → VXLAN → Ethernet → IPv4 → TCP) the eBPF program will parse. Most Kubernetes environments work fine with depth 4-6.

**Option 2 - Verify IPv6 options are disabled** (default, but confirm):

```hcl
parser {
  # These should be false (default) unless specifically needed
  parse_ipv6_hopopt = false
  parse_ipv6_fragment = false
  parse_ipv6_routing = false
  parse_ipv6_dest_opts = false
}
```

**Option 3 - Upgrade kernel** (if possible):

Newer kernels (5.10+) have significantly improved verifier efficiency and higher instruction limits:

```bash
# Check current kernel version
kubectl debug node/worker-node -it --image=ubuntu -- uname -r
```

**Validation**:

After applying configuration changes and restarting:

```bash
# Pod should start successfully
kubectl get pods -l app.kubernetes.io/name=mermin -n mermin

# Check logs for successful eBPF load
kubectl logs mermin-xxxxx -n mermin | grep -i "ebpf.*loaded\|configured ebpf"
```

**Environment-Specific Recommendations**:

| Environment | Recommended `max_header_depth` | Notes |
|-------------|-------------------------------|-------|
| Standard K8s (Kind, cloud) | 6 (default) | Handles most scenarios |
| K3s | 4-5 | Lightweight, may need reduced depth |
| Edge/IoT | 4 | Minimal complexity |
| Complex multi-tunnel | 7-8 | May require kernel 5.10+ |

**Prevention**:

Test eBPF loading in target environment during development:

```bash
# Deploy to test cluster first
helm install mermin-test ./charts/mermin -n mermin-test --create-namespace

# Verify eBPF loads successfully
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mermin -n mermin-test --timeout=60s
```

See [Parser Configuration](../configuration/parser.md#ebpf-verifier-considerations) for detailed information on tuning parser settings.

## Permission Errors

### Symptom

Logs show Kubernetes API permission errors:

```
ERROR Failed to list pods: pods is forbidden: User "system:serviceaccount:mermin:mermin" cannot list resource "pods"
```

### Solution

Verify RBAC configuration:

```bash
# Check ServiceAccount
kubectl get sa -n mermin

# Check ClusterRole
kubectl get clusterrole mermin

# Check ClusterRoleBinding
kubectl get clusterrolebinding mermin
```

Ensure Mermin has required permissions:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "endpoints", "nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "watch"]
```

## CNI Conflicts

### Symptom

Mermin starts but cannot attach to network interfaces, or network connectivity issues occur.

### Diagnosis

Check which CNI you're using:

```bash
kubectl get pods -n kube-system | grep -i cni
```

### Solution

Configure Mermin to monitor the correct interfaces for your CNI:

**Cilium**:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "cilium_*"]
}
```

**Calico**:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "cali*"]
}
```

**Flannel**:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "cni*", "flannel*"]
}
```

See [Advanced Scenarios](../deployment/advanced-scenarios.md#custom-cni-configurations) for more CNI-specific configurations.

## Configuration Syntax Errors

### Symptom

Pod crashes immediately with configuration parsing error:

```
ERROR Failed to parse configuration: unexpected token at line 10
```

### Solution

1. Validate HCL syntax:

```bash
# Use an HCL formatter/validator
terraform fmt -check config.hcl
```

2. Check for common syntax mistakes:
   * Missing closing braces `}`
   * Mismatched quotes
   * Invalid key names (use underscores, not hyphens)
3. Enable debug logging to see full config parsing output.

## Next Steps

* [**No Flow Traces**](no-flows.md): If pods are running but not capturing flows
* [**Performance Issues**](performance.md): If Mermin is using too many resources
* [**Configuration Reference**](../configuration/configuration.md): Review configuration options
