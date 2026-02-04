# Configure Network Interface Discovery

This page explains how Mermin discovers and monitors network interfaces on the host. Interface selection is critical for determining what network traffic Mermin captures.

## Overview

Mermin attaches eBPF programs to network interfaces to capture packets. The `discovery.instrument.interfaces` configuration specifies which interfaces to monitor using patterns that are resolved against available host interfaces.

## Configuration

You specify which interfaces to monitor with the `interfaces` option. Example (physical interfaces only; the [default](#default-configuration) uses veth and tunnel patterns):

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "en*"]
}
```

## Interface Patterns

Mermin supports three pattern types for interface matching:

### 1. Literal Names

Exact interface name matching:

```hcl
discovery "instrument" {
  interfaces = ["eth0", "ens32"]
}
```

* Matches exactly `eth0` and `ens32`
* No wildcards or patterns
* Most explicit, least flexible

### 2. Glob Patterns

Shell-style wildcard matching:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens?3"]
}
```

**Wildcard Characters:**

* `*`: Matches zero or more characters
  * `eth*` matches `eth0`, `eth1`, `eth10`, etc.
* `?`: Matches exactly one character
  * `ens?3` matches `ens03`, `ens13`, but not `ens3` or `ens123`

**Examples:**

```hcl
discovery "instrument" {
  interfaces = [
    "eth*",      # Matches eth0, eth1, eth10, etc.
    "ens*",      # Matches ens32, ens33, ens160, etc.
    "en?",       # Matches en0, en1, but not en10
    "cni*",      # Matches cni0, cni1, cniXXXXXXXX
    "cilium_*",  # Matches cilium_host, cilium_net, etc.
  ]
}
```

### 3. Regex Patterns

Full regular expression matching (enclosed in `/`):

```hcl
discovery "instrument" {
  interfaces = ["/^eth[0-9]+$/", "/^ens[0-9]{1,3}$/"]
}
```

**Regex syntax:**

* Pattern must be enclosed in forward slashes: `/pattern/`
* Supports full regex syntax
* Maximum pattern length: 256 characters (security limit)

**Examples:**

```hcl
discovery "instrument" {
  interfaces = [
    "/^eth\\d+$/",              # Matches eth0, eth1, eth123
    "/^(en|eth)[0-9]+$/",       # Matches en0, en1, eth0, eth1
    "/^ens[0-9]{1,3}$/",        # Matches ens0-ens999
    "/^(cni|gke|cilium_).*/",   # Matches CNI interfaces
  ]
}
```

{% hint style="warning" %}
Regex patterns must escape special characters. Use `\\d` for digits, `\\w` for word characters, etc.
{% endhint %}

## Pattern Resolution

Mermin resolves patterns at startup and configuration reload:

1. **List available interfaces**: Queries the host's network interfaces
2. **Apply patterns**: Matches each pattern against available interfaces
3. **Deduplicate**: Removes duplicate interfaces if matched by multiple patterns
4. **Attach eBPF programs**: Attaches to all resolved interfaces

### Resolution Example

**Host interfaces:**

```text
eth0, eth1, ens32, ens33, lo, docker0, cni0, cni123abc
```

**Configuration:**

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "cni*"]
}
```

**Resolved interfaces:**

```text
eth0, eth1, ens32, ens33, cni0, cni123abc
```

**Not included:** `lo` (loopback), `docker0` (not matched). Loopback is typically excluded because it carries only localhost traffic and is rarely needed for flow observability.

## Default Configuration

If `interfaces` is empty or not specified, Mermin uses these defaults. Both an empty list (`interfaces = []`) and omitting the option yield the same default set.

```hcl
discovery "instrument" {
  interfaces = [
    "veth*",      # Same-node pod-to-pod traffic
    "tunl*",      # Calico IPIP tunnels (IPv4)
    "ip6tnl*",    # IPv6 tunnels (Calico, dual-stack)
    "vxlan*",     # VXLAN overlays
    "flannel*",   # Flannel interfaces
    "cali*",      # Calico interfaces
    "cilium_*",   # Cilium overlays
    "lxc*",       # Cilium pod interfaces
    "gke*",       # GKE interfaces
    "eni*",       # AWS VPC CNI
    "azure*",     # Azure CNI
    "ovn-k8s*",   # OVN-Kubernetes
  ]
}
```

**Strategy**: Complete visibility without flow duplication

* **`veth*`** captures all same-node pod-to-pod traffic (works with all bridge-based CNIs)
* **Tunnel/overlay interfaces** (`tunl*`, `ip6tnl*`, `vxlan*`, `flannel*`) capture inter-node traffic for both IPv4 and IPv6
* **CNI-specific interfaces** (`cali*`, `cilium_*`, `lxc*`, `gke*`, `eni*`, `azure*`, `ovn-k8s*`) for various network plugins
* **No physical interfaces** (`eth*`, `ens*`) or bridge interfaces (`cni0`, `docker0`) to avoid duplication or missing same-node traffic

This works for most CNI configurations including Flannel, Calico, Cilium, kindnetd, and cloud providers. Supports dual-stack (IPv4+IPv6) clusters.

## Traffic Visibility Strategies

The interfaces you monitor determine what traffic Mermin captures:

### Complete Visibility (Default)

Monitor veth pairs and tunnel/overlay interfaces:

```hcl
discovery "instrument" {
  interfaces = [
    "veth*",      # Same-node traffic
    "tunl*",      # Inter-node tunnels (Calico)
    "flannel*",   # Inter-node (Flannel)
    # ... other CNI-specific patterns
  ]
}
```

**Captures:**

* ✅ Same-node pod-to-pod traffic (via veth)
* ✅ Inter-node traffic (via tunnel/overlay interfaces)
* ✅ No flow duplication (separate packet paths)

**Trade-offs:**

* ⚠️ Higher overhead (monitors many veth interfaces in large clusters)
* ⚠️ Veth interfaces churn (created/destroyed with pods)

**Use cases:**

* Complete network observability
* Debugging same-node communication
* Most production deployments

### Inter-Node Only (Lower Overhead)

Monitor only physical interfaces:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*"]
}
```

**Captures:**

* ✅ Traffic between nodes
* ✅ Traffic to/from external networks
* ❌ **Misses same-node pod-to-pod traffic**

**Trade-offs:**

* ✅ Low overhead (few interfaces)
* ✅ No flow duplication (only physical interfaces monitored)
* ❌ Incomplete visibility (misses same-node pod traffic)

**Use cases:**

* Clusters with minimal same-node communication
* Cost-sensitive deployments
* External traffic focus

### Physical + CNI (Full Visibility with Duplication Risk)

Monitor both physical and CNI interfaces:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "cni*", "gke*", "cilium_*"]
}
```

**Captures:**

* ✅ All inter-node traffic
* ✅ All intra-node pod-to-pod traffic
* ⚠️ **May see duplicate flows** (same traffic captured on multiple interfaces)

**Use cases:**

* Complete visibility requirements
* Debugging pod-to-pod communication
* Compliance or security auditing

{% hint style="info" %}
For most use cases, the default configuration (complete visibility with veth + tunnel interfaces) provides comprehensive observability without duplication.
{% endhint %}

## Dynamic Interface Discovery

Mermin includes an **Interface Controller** that automatically discovers and manages network interfaces.
The controller continuously watches for interface changes and synchronizes the configured patterns with active interfaces, attaching/detaching eBPF programs as interfaces are created and destroyed.
This is particularly useful for ephemeral interfaces like veth pairs that come and go with pods.

### Discovery Configuration

```hcl
discovery "instrument" {
  interfaces = ["veth*", "tunl*", "flannel*"]

  # Enable the interface controller for automatic monitoring (default: true)
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

### Static vs. Dynamic Interfaces

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

* Each monitored interface adds \~1KB to memory usage
* Controller state: patterns, active interfaces, TC links (\~100KB baseline)
* In clusters with 1000 pods (2000 veth interfaces), total is \~2.1MB
* Netlink socket overhead is negligible (<100KB)

**Scaling:**

* Tested with 10,000+ veth interfaces without performance degradation
* Controller syncing happens asynchronously, doesn't block packets
* Event-driven architecture scales efficiently with high pod churn
* O(1) lookups for interface state and TC link management

### Disabling the Interface Controller

For specialized scenarios where you only want static interface monitoring:

```hcl
discovery "instrument" {
  interfaces = ["tunl*", "flannel*"]  # Exclude veth*
  auto_discover_interfaces = false
}
```

This disables the controller's synchronization and watches only interfaces present at startup. Note: With the interface controller enabled, there's no performance reason to disable this feature - the overhead is negligible.

{% hint style="warning" %}
When `auto_discover_interfaces` is disabled, the Interface Controller does not run. Mermin only attaches to interfaces present at startup. New interfaces created after startup will not be monitored until Mermin is restarted.
{% endhint %}

### TC Attachment Order

When attaching eBPF programs to interfaces, Mermin supports two options that affect where its programs run in the TC chain relative to other programs (e.g., CNI or Cilium):

* **`tc_priority`** (netlink only, kernel &lt; 6.6): TC priority for program attachment. Higher values = lower priority = runs later. Default: `1`. Range: 1–32767. Values below 30 may run before some CNI programs.
* **`tcx_order`** (TCX only, kernel ≥ 6.6): Order in the TCX program chain. Options: `"last"` (default; runs after other programs, recommended for observability) or `"first"` (runs before).

Most deployments can leave these at their defaults. Tune them only if you need Mermin to see traffic before or after specific CNI or security programs.

```hcl
discovery "instrument" {
  interfaces = ["veth*", "tunl*"]
  tc_priority = 1      # optional; default 1
  tcx_order  = "last"  # optional; default "last"
}
```

## CNI-Specific Patterns

Different Container Network Interfaces create different interface patterns:

### Flannel

```hcl
discovery "instrument" {
  # Physical for inter-node, cni for intra-node
  interfaces = ["eth*", "ens*", "cni*"]
}
```

Flannel typically creates `cni0` bridge interface.

### Calico

```hcl
discovery "instrument" {
  # Physical for inter-node, cali for intra-node
  interfaces = ["eth*", "ens*", "cali*"]
}
```

Calico creates `caliXXXXXXXX` interfaces for each pod.

### Cilium

```hcl
discovery "instrument" {
  # Physical for inter-node, cilium_ for intra-node
  interfaces = ["eth*", "ens*", "cilium_*"]
}
```

Cilium uses `cilium_host` and `cilium_net` interfaces.

### GKE

```hcl
discovery "instrument" {
  # GKE-specific patterns
  interfaces = ["eth*", "gke*"]
}
```

GKE creates `gkeXXXXXXXX` interfaces for pods.

### Weave Net

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "weave"]
}
```

Weave Net uses a `weave` interface.

## Cloud Provider Patterns

### AWS (EKS)

```hcl
discovery "instrument" {
  # Primary ENI and secondary ENIs
  interfaces = ["eth*", "eni*"]
}
```

### GCP (GKE)

```hcl
discovery "instrument" {
  interfaces = ["eth*", "gke*"]
}
```

### Azure (AKS)

```hcl
discovery "instrument" {
  interfaces = ["eth*"]
}
```

### Bare Metal / On-Premises

```hcl
discovery "instrument" {
  # Traditional or predictable naming
  interfaces = ["eth*", "ens*", "eno*", "enp*"]
}
```

## Advanced Patterns

### Exclude Specific Interfaces

While Mermin doesn't support exclusion patterns directly, use specific patterns to include only desired interfaces:

```hcl
discovery "instrument" {
  # Use regex to limit to specific interface names
  interfaces = [
    "/^eth[0-9]$/",      # Only eth0-eth9 (single digit)
    "/^ens3[0-9]$/"      # Only ens30-ens39
  ]
}
```

### Broad Patterns for Varying Hosts

Use broad patterns that adapt to host configuration:

```hcl
discovery "instrument" {
  interfaces = [
    "eth*",   # Traditional
    "ens*",   # Predictable (systemd)
    "en*",    # macOS/BSD style
    "eno*",   # Onboard devices
    "enp*",   # PCI devices
  ]
}
```

## Troubleshooting

### No Interfaces Matched

**Symptom:** Log message "no interfaces matched the configured patterns"

**Solutions:**

1. **List available interfaces:**

   ```bash
   kubectl exec <pod> -- ip link show
   # or on host
   ip link show
   ```

2. **Test pattern matching:**

   ```bash
   # Check if pattern matches
   ip link show | grep -E "^[0-9]+: eth"
   ```

3. **Update configuration:**

   ```hcl
   discovery "instrument" {
     interfaces = ["eth0"]  # Use exact name from ip link show
   }
   ```

### Interface Not Found

**Symptom:** Warning log that an interface was not found (e.g. "interface '…' not found in datalink::interfaces()")

**Causes:**

* Interface doesn't exist
* Interface name changed
* Node has different interface naming

**Solutions:**

1. Verify interface exists: `ip link show`
2. Use glob patterns instead of exact names
3. Check if interface is created after Mermin starts

### Capturing Too Much Traffic

**Symptom:** High CPU/memory usage, too many flows

**Solutions:**

1. **Reduce monitored interfaces:**

   ```hcl
   discovery "instrument" {
     interfaces = ["eth0"]  # Monitor only primary interface
   }
   ```

2. **Remove CNI interfaces:**

   ```hcl
   discovery "instrument" {
     interfaces = ["eth*", "ens*"]  # Remove cni*, cali*, etc.
   }
   ```

3. **Add flow filters** (see [Filtering](filtering.md))

### Flow Duplication

**Symptom:** Same flow appears multiple times

**Causes:**

* Monitoring both physical and virtual interfaces
* Same packet traverses multiple monitored interfaces

**Solutions:**

1. **Monitor only physical interfaces:**

   ```hcl
   discovery "instrument" {
     interfaces = ["eth*", "ens*"]  # Don't include CNI interfaces
   }
   ```

2. **Deduplicate in backend:**
   * Use flow fingerprinting (Community ID)
   * Deduplicate based on 5-tuple + timestamps

## Monitoring Interface Resolution

Check logs to see which interfaces Mermin resolved:

```bash
kubectl logs <pod> | grep -i interface
```

Example log output:

```text
INFO Resolved interfaces interfaces=["eth0","eth1","ens32"]
INFO eBPF programs attached interfaces=["eth0","eth1","ens32"]
```

## Best Practices

1. **Start with defaults**: Use default patterns for initial deployment
2. **Monitor metrics**: Watch packet/flow counts per interface
3. **Test patterns**: Validate interface resolution in non-production first
4. **Use the narrowest patterns that meet your needs**: Prefer specific patterns when limiting scope (e.g., a single physical interface)
5. **Document choices**: Comment why specific interfaces are monitored
6. **Review periodically**: Interface naming may change with OS upgrades

## Complete Configuration Examples

### Minimal (Physical Interfaces Only)

```hcl
discovery "instrument" {
  interfaces = ["eth0"]
}
```

### Physical Interfaces Only (Alternative)

```hcl
discovery "instrument" {
  # Not the default: use when you want inter-node/external traffic only.
  # The actual default is the complete-visibility set (veth*, tunl*, etc.) above.
  interfaces = ["eth*", "ens*", "en*"]
}
```

### Complete Visibility (With CNI)

```hcl
discovery "instrument" {
  interfaces = [
    "eth*",      # Physical interfaces
    "ens*",      # Predictable naming
    "cni*",      # Flannel/generic CNI
    "cali*",     # Calico
    "cilium_*",  # Cilium
    "gke*",      # GKE
  ]
}
```

### Regex-Based Selection

```hcl
discovery "instrument" {
  interfaces = [
    "/^eth[0-9]+$/",         # eth0, eth1, eth10, ... (one or more digits)
    "/^ens[0-9]{1,3}$/",     # ens0-ens999
    "/^(cni|cali|cilium).*/", # Any CNI interface
  ]
}
```

## Next Steps

* [**Parser Configuration**](references/network-packet-parser.md): Configure tunnel protocol detection
* [**Flow Filtering**](filtering.md): Filter flows by interface name
* [**Troubleshooting**](../troubleshooting/troubleshooting.md): Diagnose interface issues
* [**Advanced Scenarios**](../deployment/advanced-scenarios.md): CNI-specific configurations
