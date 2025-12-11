# Security Considerations

## Host Mounts Required

For **orphan cleanup support** on pod restarts (highly recommended for production), mount `/sys/fs/bpf` as a hostPath volume is required.
When a Mermin pod crashes unexpectedly (OOM, node failure, etc.), its TC programs remain attached to interfaces. On restart, Mermin can clean up these "orphaned" programs by loading pinned links from `/sys/fs/bpf`.

**TCX Mode and BPF Filesystem (Kernel >= 6.6):**

{% hint style="info" %}
**Linux Kernel 6.6+** introduced TCX (TC eXpress), an improved TC attachment mechanism that supports multiple programs per hook. Mermin automatically uses TCX when available.
{% endhint %}

**Verifying TCX mode:**

Check Mermin logs on startup:

```bash
kubectl logs <mermin-pod> | grep tcx_mode
# Should show: kernel.tcx_mode=true (kernel >= 6.6)
```

**For older kernels (< 6.6):** Mermin uses netlink-based TC attachment, which includes automatic orphan cleanup without requiring `/sys/fs/bpf`.

## Privileges Required

Mermin requires elevated privileges to operate:

* **Host PID Namespace**: Required to access `/proc/1/ns/net` for namespace switching
* **Linux Capabilities**: Requires specific capabilities instead of full privileged mode:
  * `CAP_NET_ADMIN` - Attach TC (traffic control) programs to network interfaces
  * `CAP_BPF` - Load eBPF programs (kernel 5.8+)
  * `CAP_PERFMON` - Access eBPF ring buffers (kernel 5.8+)
  * `CAP_SYS_ADMIN` - Switch network namespaces and access BPF filesystem
  * `CAP_SYS_PTRACE` - Access other processes' namespace files (`/proc/1/ns/net`)
  * `CAP_SYS_RESOURCE` - Increase memlock limits for eBPF maps

## Network Namespace Switching

Mermin uses a sophisticated approach to monitor host network interfaces without requiring `hostNetwork: true`:

1. **Startup**: Mermin starts in its own pod network namespace
2. **Attachment**: Temporarily switches to host network namespace to attach eBPF programs
3. **Operation**: Switches back to pod namespace for all other operations

This approach provides:

* **Network isolation**: Pod has its own network namespace
* **Kubernetes DNS**: Can resolve service names for OTLP endpoints
* **Host monitoring**: eBPF programs remain attached to host interfaces

The eBPF programs execute in kernel space and remain attached regardless of the userspace process's namespace.

## Data Privacy

* **No Payload Capture**: Mermin only captures packet headers, not application data
* **Metadata Only**: Flow records contain IPs, ports, protocols – not packet contents
* **Configurable Filtering**: Filter out sensitive or noisy traffic before export
* **TLS Transport**: All OTLP exports can be encrypted with TLS

## RBAC

Mermin needs Kubernetes RBAC permissions to:

* Read pods, services, deployments, and other resources (for metadata enrichment)
* List and watch resources across all namespaces
* Access the Kubernetes API server

See the Helm chart's [ClusterRole](https://github.com/elastiflow/mermin/blob/beta/charts/mermin/templates/clusterrole.yaml) for the minimal required permissions.
