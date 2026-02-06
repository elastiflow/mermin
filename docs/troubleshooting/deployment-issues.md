# Troubleshoot Deployment Issues

This guide will help you diagnose and resolve pod startup failures, eBPF loading errors, permission issues, and network interface configuration problems.

## Pod Not Starting

Mermin pods that fail to start typically show one of these states: `Pending`, `CrashLoopBackOff`, or `Error`.

### Check Pod Status

Gather information about the pod:

```bash
kubectl get pods -l app.kubernetes.io/name=mermin -n ${MERMIN_NAMESPACE}
kubectl describe pod mermin-xxxxx -n ${MERMIN_NAMESPACE}
kubectl get events -n ${MERMIN_NAMESPACE} --field-selector involvedObject.name=mermin-xxxxx
```

### Common Causes and Solutions

#### 1. Insufficient Node Resources

`Insufficient cpu` or `Insufficient memory` in the events indicates nodes lack available resources.

**Fix it by adjusting resource requests** in your Helm values:

```yaml
# In values.yaml
resources:
  requests:
    cpu: 200m
    memory: 220Mi
  limits:
    cpu: 1
    memory: 512Mi
```

**Note**: The Helm chart sets the default limits to prevent the Mermin pods from disrupting existing workloads, please see the [default values](https://github.com/elastiflow/mermin/blob/main/charts/mermin/values.yaml) for details.

#### 2. Pod Security Policy Restrictions

`Error: container has runAsNonRoot and image will run as root` indicates cluster security policies block the privileged access Mermin needs for eBPF programs.

**Solution**: Configure your Pod Security Policy (PSP) or Pod Security Standards (PSS) to allow privileged containers in the Mermin namespace. Mermin uses these privileges exclusively for eBPF operations and network monitoring.

The default Helm chart includes the necessary security context settings:

```yaml
# In charts/mermin/values.yaml
securityContext:
  privileged: true # Required for eBPF operations
  readOnlyRootFilesystem: true
  runAsNonRoot: false # Must run as root for eBPF
  runAsUser: 0
  runAsGroup: 0

hostPID: true # Required to access host network namespace
```

If your cluster uses Pod Security Standards (PSS), you may need to label the namespace appropriately:

```bash
# For PSS "privileged" policy
kubectl label namespace ${MERMIN_NAMESPACE} pod-security.kubernetes.io/enforce=privileged
```

#### 3. Image Pull Failures

`ImagePullBackOff` or `ErrImagePull` in the pod status indicates image pull failures.

**Troubleshoot with these commands**:

```bash
# Check image pull status
kubectl describe pod mermin-xxxxx -n ${MERMIN_NAMESPACE} | grep -A5 Events

# Get the image specified in the pod manifest
kubectl get pod mermin-xxxxx -o jsonpath='{ .spec.containers[*].image }'

# Verify image exists
docker pull ghcr.io/elastiflow/mermin:${IMAGE_TAG}
```

## eBPF Program Loading Failures

eBPF requires specific kernel features and permissions. If Mermin can't load its eBPF programs, you'll see errors like:

```text
ERROR Failed to load eBPF program: Operation not permitted
```

### Check the Logs

Search the logs for eBPF-related errors:

```bash
kubectl logs mermin-xxxxx -n ${MERMIN_NAMESPACE} | grep -i ebpf
```

### Test eBPF Attach/Detach Operations

You can use the `diagnose bpf` subcommand to validate eBPF capabilities in a deployed Mermin cluster:

**In a deployed Kubernetes cluster:**

```bash
# Get the pod name (replace 'mermin' with your namespace if different)
POD=$(kubectl get pod -n mermin -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')

# Test all interfaces (default behavior - useful for discovering available interfaces)
kubectl exec -n mermin $POD -- mermin diagnose bpf

# Test only a specific interface
kubectl exec -n mermin $POD -- mermin diagnose bpf --interface eth0

# Test with pattern filtering (matches your configuration)
kubectl exec -n mermin $POD -- mermin diagnose bpf --pattern "veth*" --skip "veth0"
```

**Before deploying (using a debug pod):**

```bash
# In a debug pod or directly on the node
kubectl debug node/worker-node -it --image=ghcr.io/elastiflow/mermin:latest -- sh

# Test all interfaces (default - useful for discovering available interfaces)
mermin diagnose bpf

# Test only a specific interface
mermin diagnose bpf --interface eth0

# Test with pattern filtering (matches your configuration)
mermin diagnose bpf --pattern "veth*" --skip "veth0"
```

**What the test validates:**

- Required Linux capabilities (BPF, NET_ADMIN, etc.)
- eBPF program loading and verification
- Attach/detach operations on network interfaces
- BPF filesystem writeability (for TCX link pinning)
- Kernel version and TCX vs netlink mode detection

**Interpreting results:**

- **All tests pass**: Your environment is ready for Mermin
- **Attach failures**: Check capabilities, kernel version, or interface availability
- **BPF FS not writable**: Mount `/sys/fs/bpf` or configure volume mounts (see [eBPF File System Not Mounted](#4-ebpf-file-system-not-mounted))
- **Capability errors**: Verify security context configuration (see [Missing Linux Capabilities](#1-missing-linux-capabilities))

The subcommand provides structured logging with clear success/failure indicators, making it easy to identify specific issues.

### Finding Available Interfaces

List interfaces in the pod:

```bash
# Get the pod name (replace 'mermin' with your namespace if different)
POD=$(kubectl get pod -n mermin -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')

# List all network interfaces
kubectl exec -n mermin $POD -- ip link show

# Get interface names only
kubectl exec -n mermin $POD -- ip -o link show | awk -F': ' '{print $2}'

# Check interface status (UP/DOWN)
kubectl exec -n mermin $POD -- ip link show | grep -E "^[0-9]+:|state"
```

### Debug Logging

Enable debug logging for detailed output:

```bash
# Get the pod name (replace 'mermin' with your namespace if different)
POD=$(kubectl get pod -n mermin -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')

# All interfaces with debug logging (default)
kubectl exec -n mermin $POD -- env MERMIN_LOG_LEVEL=debug mermin diagnose bpf

# Single interface with debug logging
kubectl exec -n mermin $POD -- env MERMIN_LOG_LEVEL=debug mermin diagnose bpf --interface eth0

# Pattern filtering with debug logging
kubectl exec -n mermin $POD -- env MERMIN_LOG_LEVEL=debug mermin diagnose bpf --pattern "eth*" --skip "eth0"
```

### What's Going Wrong?

#### 1. Missing Linux Capabilities

`Operation not permitted` indicates missing Linux capabilities—the most common issue.

**The Helm chart sets `privileged: true` by default**, which grants all necessary capabilities. This is the simplest and most reliable approach:

```yaml
# In charts/mermin/values.yaml (default configuration)
securityContext:
  privileged: true    # Grants all required capabilities
```

**If you can't use privileged mode** (due to security policies), you can grant specific capabilities instead. Refer to the [security considerations](../concepts/security-considerations.md#privileges-required) documentation for more information.

```yaml
# In charts/mermin/values.yaml (capability-based approach)
securityContext:
  privileged: false
  capabilities:
    add:
      - NET_ADMIN    # Attach TC programs to network interfaces
      - BPF          # Load and manage eBPF programs (kernel 5.8+)
      - PERFMON      # Performance monitoring and ring buffers (kernel 5.8+)
      - SYS_ADMIN    # Network namespace switching and kernel operations
      - SYS_PTRACE   # Access host network namespace via /proc/1/ns/net
      - SYS_RESOURCE # Modify resource limits (e.g., memlock rlimit)
```

**Note**: Using specific capabilities requires kernel 5.8+ for the `BPF` and `PERFMON` capabilities. On older kernels, `privileged: true` is required.

**Also required**: `hostPID: true` to access the host network namespace:

```yaml
# In charts/mermin/values.yaml
hostPID: true # Required to access /proc/1/ns/net (host network namespace)
```

Without `hostPID: true`, Mermin can't attach eBPF programs to host network interfaces.

#### 2. Kernel Version Too Old

`Invalid argument` or `Function not implemented` indicates a kernel too old for eBPF support.

**Check your kernel version**:

```bash
kubectl debug node/worker-node -it --image=ubuntu -- uname -r
```

**Requirements**: Mermin requires Linux kernel 5.14 or newer (6.6+ recommended). Upgrade nodes running older kernels.

#### 3. BTF (BPF Type Format) Not Available

BTF provides type information for eBPF programs. `BTF is not supported` indicates the kernel was compiled without BTF enabled.

**Check if BTF is available**:

```bash
kubectl debug node/worker-node -it --image=ubuntu -- ls /sys/kernel/btf/vmlinux
```

If the file does not exist, enable BTF in your kernel configuration or switch to a distribution with BTF support (most modern kernels include it).

#### 4. eBPF File System Not Mounted

Mermin pins eBPF maps to `/sys/fs/bpf` for state persistence. `No such file or directory: /sys/fs/bpf` indicates the BPF filesystem is not mounted.

**Quick fix on the host node**:

```bash
mount -t bpf bpf /sys/fs/bpf
```

To make this permanent across reboots, add it to `/etc/fstab`:

```text
bpf /sys/fs/bpf bpf defaults 0 0
```

**Better yet, configure it in Kubernetes**:

```yaml
# In your Helm values or DaemonSet spec
volumeMounts:
  - name: bpf-fs
    mountPath: /sys/fs/bpf
    mountPropagation: Bidirectional

volumes:
  - name: bpf-fs
    hostPath:
      path: /sys/fs/bpf
      type: DirectoryOrCreate
```

{% hint style="info" %}
Without writable `/sys/fs/bpf`, Mermin runs in best-effort mode (unpinned maps). Flow state will not persist across pod restarts.
{% endhint %}

**Test BPF filesystem writeability:**

Use the `diagnose bpf` subcommand to verify the BPF filesystem is writable in a deployed cluster:

```bash
# Get the pod name (replace 'mermin' with your namespace if different)
POD=$(kubectl get pod -n mermin -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')

# Test all interfaces (default)
kubectl exec -n mermin $POD -- mermin diagnose bpf

# Test only a specific interface
kubectl exec -n mermin $POD -- mermin diagnose bpf --interface eth0
```

**On bare metal or in a debug pod:**

```bash
# Test all interfaces (default)
sudo mermin diagnose bpf

# Test only a specific interface
sudo mermin diagnose bpf --interface eth0
```

The subcommand will report whether `/sys/fs/bpf` is writable. On kernels >= 6.6.0 (TCX mode), this is required for link pinning. If the test fails, ensure the BPF filesystem is properly mounted and the container has write permissions.

#### 5. eBPF Verifier Rejection (Program Too Large)

The eBPF verifier enforces program complexity limits. `Verifier instruction limit exceeded` indicates the program exceeds these limits.

For more detailed guidance on verifier errors, see [Common eBPF Errors](common-ebpf-errors.md).

## Permission Errors

RBAC permission errors appear when Mermin lacks access to Kubernetes resources:

```text
ERROR Failed to list pods: pods is forbidden: User "system:serviceaccount:mermin:mermin" cannot list resource "pods"
```

The service account lacks necessary permissions.

### Check Your RBAC Configuration

```bash
kubectl get sa -n ${MERMIN_NAMESPACE}
kubectl get clusterrole mermin -o yaml
kubectl get clusterrolebinding mermin
```

Make sure your ClusterRole has the required permissions, which can be found in the [Helm Chart template](https://github.com/elastiflow/mermin/blob/main/charts/mermin/templates/clusterrole.yaml):

## CNI and Interface Configuration

Missing expected traffic often indicates Mermin is not monitoring the correct network interfaces for your CNI plugin.

### Configure Interfaces for Your CNI

Each CNI plugin creates different interface types. Here's what to use:

- **Calico**: `interfaces = ["veth*", "cali*", "tunl*"]`
- **Cilium**: `interfaces = ["veth*", "cilium_*", "lxc*"]`
- **Flannel**: `interfaces = ["veth*", "flannel*"]`
- **GKE Dataplane V2**: `interfaces = ["gke*", "cilium_*", "lxc*"]`

Different interface types show different traffic - veth interfaces capture pod-to-pod traffic, while tunnel interfaces capture encapsulated traffic.

**Want to learn more?** Check out these guides:

- [Interface Visibility and Traffic Decapsulation](interface-visibility-and-traffic-decapsulation.md) - Understand what traffic each interface type captures
- [Advanced Scenarios: Custom CNI Configurations](../deployment/advanced-scenarios.md#custom-cni-configurations) - Complex CNI setups

## Understanding TC Priority

TC (Traffic Control) priority determines the order in which eBPF programs execute in the networking stack. On older kernels (< 6.6), this is managed through netlink-based TC with numeric priorities.
On newer kernels (>= 6.6), TCX mode uses explicit ordering.

### Check What Priority Mermin is Using

```bash
# Get a Mermin pod name
MERMIN_POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')

# Check TC filters on an interface (replace gke0 with your interface name)
kubectl exec -it ${MERMIN_POD} -- tc filter show dev gke0 ingress
```

You should see output like this:

```text
filter protocol all pref 1 bpf chain 0
filter protocol all pref 1 bpf chain 0 handle 0x1 mermin_ingress direct-action not_in_hw id 123 tag abc123def456
```

### How Priority Works

Think of priority as a queue - lower numbers cut to the front of the line:

- **Lower number = Higher priority = Runs earlier** in the TC chain
- **Higher number = Lower priority = Runs later** in the TC chain

**Mermin's default: Priority 1** - Mermin runs first to capture an unfiltered, unprocessed view of network packets.

**The Priority Conflict**:

Most CNI programs (Cilium, Calico) also default to priority 1 for early packet processing. This creates a conflict - only one program can use each priority value.

**Resolving the Conflict**:

Since Mermin uses `TC_ACT_UNSPEC` (pass-through), it observes packets without modifying or blocking them. Running Mermin at priority 1 provides the most accurate observability data.

**If your CNI also uses priority 1**, you need to choose:

1. **Recommended**: Keep Mermin at priority 1, adjust your CNI to priority 2+ (e.g., Cilium priority 2)
2. **Alternative**: Move Mermin to a higher priority if you prefer CNI to run first (loses unfiltered view)

{% hint style="warning" %}
**Test any priority changes thoroughly!** Adjusting either Mermin's or your CNI's priority can affect network behavior differently depending on your CNI plugin.
Validate in a non-production environment that flows are captured correctly and network connectivity works as expected.
{% endhint %}

**Why priority 1 matters for Mermin**:

- Prevents flow gaps from orphaned programs after restarts
- Provides the most complete and accurate network observability

### Troubleshooting Priority Conflicts

Priority conflicts are rare, but they can happen. You'll typically notice network connectivity issues if Mermin interferes with your CNI.

**Common causes:**

1. Mermin running before critical CNI programs that need to see traffic first
2. Multiple programs using the same priority value
3. Non-standard CNI priority configurations

**Debug it step by step:**

First, check what priorities are in use:

```bash
# List all TC filters with priorities
kubectl exec -it ${MERMIN_POD} -- sh -c 'for iface in $(ip -o link show | awk -F: "{print \$2}" | tr -d " "); do echo "=== $iface ==="; tc filter show dev $iface ingress 2>/dev/null; done'
```

Then adjust based on your kernel version:

**For older kernels (< 6.6) - netlink mode:**

```hcl
discovery "instrument" {
  tc_priority = 100 # Run after most CNI programs
}
```

**For newer kernels (>= 6.6) - TCX mode:**

```hcl
discovery "instrument" {
  tcx_order = "last" # Run after all other programs
}
```

{% hint style="warning" %}
**Important**: Changing from the default priority/order settings can cause issues with some CNI plugins, including missing flows or network connectivity problems.
Test thoroughly in a non-production environment first and verify that flows are being captured correctly for your specific CNI.
{% endhint %}

Not sure which kernel you're running?

```bash
kubectl exec -it ${MERMIN_POD} -- uname -r
```

If it's >= 6.6.0, you're using TCX mode (you'll also see this in the logs). In TCX mode, `tc_priority` is ignored in favor of `tcx_order`.

**Quick reference:**

- **TCX mode** (kernel >= 6.6): Programs are ordered explicitly using `tcx_order` (first/last)
- **Netlink mode** (kernel < 6.6): Programs are ordered by numeric priority (lower = earlier)
- Priority only affects execution order, not performance
- Running first helps prevent flow gaps after restarts

## Configuration Syntax Errors

HCL syntax errors can be tricky to debug. If Mermin won't start and you see something like:

```text
ERROR Failed to parse configuration: unexpected token at line 10
```

Your configuration file has a syntax error.

### Validate Your Configuration

Use Terraform's formatter to check for syntax errors:

```bash
terraform fmt -check config.hcl
```

### Common Mistakes to Watch For

- **Missing closing braces** - Every `{` needs a matching `}`
- **Mismatched quotes** - Use `"quotes"` consistently
- **Invalid key names** - Use underscores (`tcp_priority`), not hyphens (`tcp-priority`)

## Next Steps

{% tabs %}
{% tab title="Resolved? Configure Mermin" %}
1. [**Configure Network Interfaces**](../configuration/reference/network-interface-discovery.md): Optimize for your CNI
2. [**Set Up OTLP Export**](../configuration/reference/opentelemetry-otlp-exporter.md): Send flows to your backend
{% endtab %}

{% tab title="Still Troubleshooting?" %}
1. [**Diagnose eBPF Verifier Errors**](common-ebpf-errors.md): Detailed solutions for verifier failures
2. [**Understand Interface Visibility**](interface-visibility-and-traffic-decapsulation.md): Why traffic might not appear
{% endtab %}

{% tab title="Get Help" %}
- [**Search Existing Issues**](https://github.com/elastiflow/mermin/issues): Check if someone else had the same problem
- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask for community help
{% endtab %}
{% endtabs %}

### Related Documentation

- [**Configuration Reference**](../configuration/overview.md): Complete configuration options
- [**Security Considerations**](../concepts/security-considerations.md): Understand required privileges
