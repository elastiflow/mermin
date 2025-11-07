---
hidden: true
---

# Network Interface Discovery

This page explains how Mermin discovers and monitors network interfaces on the host. Interface selection is critical for determining what network traffic Mermin captures.

## Overview

Mermin attaches eBPF programs to network interfaces to capture packets. The `discovery.instrument.interfaces` configuration specifies which interfaces to monitor using patterns that are resolved against available host interfaces.

## Configuration

<!-- Source: charts/mermin/config/examples/config.hcl -->
```hcl
discovery "instrument" {
  # Network interfaces to monitor
  #
  # Supports literal names, glob patterns (*, ?), and regex (/pattern/)
  #
  # Default strategy (if not specified): Complete visibility without duplication
  # - veth* for same-node pod-to-pod traffic
  # - CNI-specific tunnel/overlay interfaces for inter-node traffic
  # - Does NOT monitor physical interfaces (eth*, ens*) to avoid duplication
  #
  # Visibility strategies:
  #
  # 1. Complete visibility (DEFAULT - recommended for most deployments):
  #    interfaces = ["veth*", "tunl*", "ip6tnl*", "vxlan*", "flannel*", "cali*", "cilium_*", "lxc*"]
  #    ✅ Captures all traffic (same-node + inter-node, IPv4 + IPv6)
  #    ✅ No flow duplication (avoids bridges and physical interfaces)
  #    ⚠️  Higher overhead (many veth interfaces in large clusters)
  #
  # 2. Inter-node only (lower overhead, incomplete visibility):
  #    interfaces = ["eth*", "ens*"]
  #    ✅ Low overhead (few interfaces)
  #    ❌ Misses same-node pod-to-pod traffic
  #
  # 3. Custom CNI-specific patterns:
  #    - Flannel: ["veth*", "flannel*", "cni*"]
  #    - Calico:  ["veth*", "cali*", "tunl*", "ip6tnl*"]
  #    - Cilium:  ["lxc*", "cilium_*"]
  #    - GKE:     ["veth*", "gke*"]
  #    - Dual-stack: Add "ip6tnl*" to any of the above
  #
  # Leave empty or comment out to use defaults
  # interfaces = [
  #   "veth*",      # Same-node pod-to-pod traffic
  #   "tunl*",      # Calico IPIP tunnels (IPv4)
  #   "ip6tnl*",    # IPv6 tunnels (Calico, dual-stack)
  #   "vxlan*",     # VXLAN overlays
  #   "flannel*",   # Flannel interfaces
  #   "cali*",      # Calico interfaces
  #   "cilium_*",   # Cilium overlays
  #   "lxc*",       # Cilium pod interfaces
  #   "gke*",       # GKE interfaces
  #   "eni*",       # AWS VPC CNI
  #   "azure*",     # Azure CNI
  #   "ovn-k8s*",   # OVN-Kubernetes
  # ]

  # Automatically discover and attach to new interfaces matching patterns
  # Recommended for ephemeral interfaces like veth* (created/destroyed with pods)
  # Default: true
  # auto_discover_interfaces = true
}
```

## Dynamic Interface Discovery

Mermin includes an **Interface Controller** that automatically discovers and manages network interfaces. The controller continuously watches for interface changes and synchronizes the configured patterns with active interfaces, attaching/detaching eBPF programs as interfaces are created and destroyed. This is particularly useful for ephemeral interfaces like veth pairs that come and go with pods.

Configuration:

```hcl
discovery "instrument" {
  interfaces = ["veth*", "tunl*", "flannel*"]

  # Enable the interface controller for dynamic interface attachment (default: true)
  auto_discover_interfaces = true
}
```

### How It Works

**Continuous Synchronization:**

* Maintains desired state (configured interface patterns)
* Tracks actual state (active interfaces, attached eBPF programs)
* Synchronizes state by attaching/detaching programs when changes are detected

**Real-Time Netlink Events:**

* Watches for Linux netlink RTM\_NEWLINK/RTM\_DELLINK events
* Detects interface state changes (UP/DOWN)
* Automatically syncs when interfaces are created or destroyed

**Interface Lifecycle (with Controller):**

1. **Pod created** → veth pair created → Controller detects RTM\_NEWLINK → Attaches eBPF programs
2. **Pod deleted** → veth pair removed → Controller detects RTM\_DELLINK → Detaches eBPF programs

**State Management:**

* Controller owns all interface-related state
* TC link IDs tracked for clean detachment
* Pattern matching happens once during discovery, not per-packet

### Static vs. Dynamic Interfaces examples

**Static interfaces** (attached at startup only):

* Physical interfaces: `eth0`, `ens32`, `eno1`
* Tunnel interfaces: `tunl0`, `flannel.1`
* Bridge interfaces: `cni0`, `docker0`

**Dynamic interfaces** (continuously monitored):

* Veth pairs: `vethXXXXXXXX` (created/destroyed with pods)
* Temporary interfaces created by CNI plugins

### Performance Considerations

**Overhead:**

* Controller has zero CPU overhead when no changes occur
* Sync operations (attach/detach) are fast (<10ms per interface)
* No impact on packet processing performance
* State management happens off the data path

**Memory:**

* Each monitored interface adds ~1KB to memory usage
* Controller state: patterns, active interfaces, TC links (\~100KB baseline)
* In clusters with 1000 pods (2000 veth interfaces), total is \~2.1MB
* Netlink socket overhead is negligible (<100KB)

**Scaling:**
- Controller syncing happens asynchronously, doesn't block packets
- Event-driven architecture scales efficiently with high pod churn
- O(1) lookups for interface state and TC link management

### Disabling the Interface Controller

For specialized scenarios where you only want static interface monitoring you may set `auto_discover_interfaces = false`

This disables the controller's synchronization and watches only interfaces present at startup. Note: With the interface controller enabled, there's no performance reason to disable this feature - the overhead is negligible.

## Troubleshooting

### No Interfaces Matched

**Symptom:** No flow are showing for expected interfaces

**Solutions:**

1. **List available interfaces:**
    Using kubectl debug command
    ```bash
    kubectl debug node/${NODE_NAME} -it --image=busybox --profile=sysadmin
    ip link show
    # or
    ls -1 /sys/class/net/
    ```

2. **Test pattern matching:**
    ```bash
    # Check if pattern matches
    ls -1 /sys/class/net/ | grep '${INTERFACE_PATTERN}'
    # For example
    ls -1 /sys/class/net/ | grep 'gke*'
    ```

### Flow Duplication

**Symptom:** Same flow appears multiple times

**Causes:**

* Monitoring both physical and virtual interfaces
* Same packet traverses multiple monitored interfaces

**Solution:**
  Tweak the monitored interfaces, you may need to experiment with interface match patterns, for example:
  ```hcl
  discovery "instrument" {
    interfaces = ["veth*"]  # include only veth interfaces
  }
  ```

### Monitoring Interface Resolution

You can see which interfaces were resolved by Mermin in logs:

```bash
kubectl logs <pod> | grep -E '(discovered|resolved).+ interface'
```

Example log output:
```text
... discovered interface from host namespace ... [ INTERFACE_LIST ]
... resolved interface from patterns ... [ INTERFACE_LIST ]
```

## Best Practices

1. **Start with defaults**: Use default patterns for initial deployment
2. **Monitor metrics**: Watch packet/flow counts per interface
3. **Test patterns**: Validate interface resolution in non-production first
4. **Document choices**: Comment why specific interfaces are monitored
5. **Review periodically**: Interface naming may change with OS/CNI/K8s upgrades

## Next Steps

* [**Parser Configuration**](parser.md): Configure tunnel protocol detection
* [**Flow Filtering**](filtering.md): Filter flows by interface name
* [**Troubleshooting No Flows**](../troubleshooting/no-flows.md): Diagnose interface issues
* [**Advanced Scenarios**](../deployment/advanced-scenarios.md): CNI-specific configurations
