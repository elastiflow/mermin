---
hidden: true
---

# Interface Visibility and Traffic Decapsulation

## Overview

Understanding what traffic is visible at different network interface levels is critical for configuring Mermin correctly. This guide explains the difference between monitoring veth interfaces (pod-level) versus physical interfaces (node-level), and how tunnel encapsulation affects traffic visibility.

## Key Concept: Decapsulation Happens in the Kernel

When using overlay networking (VXLAN, Geneve, WireGuard, etc.), the Linux kernel performs encapsulation and decapsulation **between** the physical interface and the pod network namespace. This means:

- **Physical interfaces** (`eth*`, `ens*`) see **encapsulated** traffic (tunnel headers, node IPs)
- **Veth interfaces** (`veth*`) see **decapsulated** traffic (pod IPs, actual application protocols)
- **Tunnel interfaces** (`tunl*`, `flannel*`) see **both** (tunnel metadata + inner headers)

## Traffic Flow Through the Network Stack

### Inter-Node Traffic (Pod A on Node 1 → Pod B on Node 2)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Node 1                                                                       │
│                                                                              │
│  Pod A namespace                                                             │
│    └─> vethXXX (pod side)                                                   │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]                          │
│          │ ✅ Pod IPs visible                                                │
│          │ ✅ Application protocol visible                                   │
│          │ ❌ No tunnel headers                                              │
│          ▼                                                                   │
│    vethXXX (host side) ──> bridge ──> Kernel routing                       │
│          │                                                                   │
│          │ CNI encapsulation happens here                                   │
│          ▼                                                                   │
│    eth0 (physical interface)                                                │
│          │ Packet: [Eth | IP: Node1→Node2 | UDP 4789                       │
│          │          | VXLAN VNI=1000                                        │
│          │          | Eth | IP: PodA→PodB | TCP 80]                         │
│          │ ✅ Node IPs visible                                               │
│          │ ✅ Tunnel headers visible (VXLAN/Geneve/WireGuard)                │
│          │ ✅ Pod IPs buried inside tunnel                                   │
│          ▼                                                                   │
│    ─────[Network]─────────────────────────────────────────────────────>     │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Node 2                                                                       │
│                                                                              │
│    eth0 (physical interface)                                                │
│          │ Packet: [Eth | IP: Node1→Node2 | UDP 4789                       │
│          │          | VXLAN VNI=1000                                        │
│          │          | Eth | IP: PodA→PodB | TCP 80]                         │
│          │ ✅ Encapsulated tunnel traffic visible                            │
│          ▼                                                                   │
│    Kernel decapsulation (VXLAN driver)                                      │
│          │                                                                   │
│          │ Tunnel headers stripped                                          │
│          ▼                                                                   │
│    bridge ──> vethYYY (host side)                                           │
│          ▼                                                                   │
│    vethYYY (pod side)                                                       │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]                          │
│          │ ✅ Pod IPs visible                                                │
│          │ ✅ Application protocol visible                                   │
│          │ ❌ No tunnel headers (removed by kernel)                          │
│          ▼                                                                   │
│  Pod B namespace                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Same-Node Traffic (Pod A → Pod B, both on same node)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Node 1                                                                       │
│                                                                              │
│  Pod A namespace                                                             │
│    └─> vethXXX (pod side)                                                   │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]                          │
│          ▼                                                                   │
│    vethXXX (host side) ──> bridge ──> vethYYY (host side)                  │
│          │                              │                                    │
│          │ ✅ Never encapsulated        │                                    │
│          │ ✅ Never leaves host         │                                    │
│          │ ✅ Never touches eth0        │                                    │
│          ▼                              ▼                                    │
│    vethYYY (pod side)                                                        │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]                          │
│          ▼                                                                   │
│  Pod B namespace                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key insight**: Same-node traffic **never gets encapsulated** because it doesn't need to traverse the physical network.

## What You See at Each Interface Type

### Monitoring veth* Interfaces

**Visibility:**
```
✅ Pod IP addresses (10.244.x.x, etc.)
✅ Application layer protocols (HTTP, gRPC, database)
✅ Actual application ports (80, 443, 3306, etc.)
✅ Unencrypted traffic (post-decryption)
✅ Same-node pod-to-pod traffic
✅ Inter-node traffic (after kernel decapsulation)

❌ WireGuard encryption headers
❌ VXLAN/Geneve encapsulation
❌ GRE tunnels
❌ IPsec ESP/AH headers
❌ Node IP addresses (outer headers)
❌ Tunnel UDP ports (4789, 6081, 51820)
❌ Tunnel VNI/IDs
❌ Network path/routing information
```

**Example packet on veth:**
```
Ethernet Header:
  Src MAC: aa:bb:cc:dd:ee:01
  Dst MAC: aa:bb:cc:dd:ee:02

IPv4 Header:
  Src IP: 10.244.1.5 (Pod A)
  Dst IP: 10.244.2.8 (Pod B)
  Protocol: TCP

TCP Header:
  Src Port: 45678
  Dst Port: 80
  Flags: ACK PSH

Payload: HTTP GET / HTTP/1.1...
```

### Monitoring Physical Interfaces (eth*, ens*)

**Visibility:**
```
✅ Node IP addresses (actual routing infrastructure)
✅ Tunnel protocols (VXLAN, Geneve, WireGuard)
✅ Tunnel UDP ports (4789, 6081, 51820)
✅ Tunnel VNI/IDs
✅ Encrypted payloads (WireGuard, IPsec)
✅ Network routing and path information
✅ Inter-node traffic only

❌ Pod IP addresses (buried in tunnel payload)
❌ Application protocols (encrypted/encapsulated)
❌ Same-node pod-to-pod traffic (never hits physical interface)
❌ Decrypted traffic content
```

**Example packet on eth0:**
```
Ethernet Header:
  Src MAC: 00:0c:29:xx:xx:01
  Dst MAC: 00:0c:29:xx:xx:02

IPv4 Header:
  Src IP: 192.168.1.10 (Node 1)
  Dst IP: 192.168.1.11 (Node 2)
  Protocol: UDP

UDP Header:
  Src Port: 54321
  Dst Port: 4789 (VXLAN)

VXLAN Header:
  VNI: 1000
  Flags: 0x08

Inner Ethernet Header:
  Src MAC: aa:bb:cc:dd:ee:01
  Dst MAC: aa:bb:cc:dd:ee:02

Inner IPv4 Header:
  Src IP: 10.244.1.5 (Pod A)
  Dst IP: 10.244.2.8 (Pod B)
  Protocol: TCP

Inner TCP Header:
  Src Port: 45678
  Dst Port: 80

Payload: HTTP GET / HTTP/1.1...
```

### Monitoring Tunnel Interfaces (tunl*, flannel*)

**Visibility:**
```
✅ Both outer (node) and inner (pod) IP addresses
✅ Tunnel metadata (VNI, tunnel type)
✅ Inner application protocols
✅ Inter-node traffic at tunnel level

❌ Same-node traffic (doesn't use tunnels)
```

These interfaces provide the best of both worlds for inter-node traffic visibility.

## Protocols You Won't See on veth*

### WireGuard

WireGuard encryption/decryption happens at the WireGuard interface (`wg0`) or physical interface level, **before** traffic reaches veth pairs.

**At eth0:**
```
[Eth | IP: Node1→Node2 | UDP 51820 | WireGuard encrypted payload]
```

**At veth:**
```
[Eth | IP: PodA→PodB | TCP 80 | HTTP data]  ← Decrypted
```

### VXLAN/Geneve

Encapsulation is added by the kernel VXLAN/Geneve driver **after** traffic leaves the veth interface.

**At veth (outbound):**
```
[Eth | IP: PodA→PodB | TCP 80]
```

**At eth0 (outbound):**
```
[Eth | IP: Node1→Node2 | UDP 4789 | VXLAN | Eth | IP: PodA→PodB | TCP 80]
```

### IPsec ESP/AH

If using IPsec encryption, the ESP/AH headers are applied at the IPsec subsystem level, not visible on veth.

**At eth0:**
```
[Eth | IP: Node1→Node2 | ESP SPI=12345 | Encrypted payload]
```

**At veth:**
```
[Eth | IP: PodA→PodB | TCP 80 | Unencrypted data]
```

### GRE Tunnels

GRE encapsulation happens at the GRE interface (`gre0`, `gretap0`), not at veth level.

## Configuration Implications

### For veth*-Primary Monitoring

If you're monitoring **primarily veth*** interfaces, your configuration can be simplified:

```hcl
parser {
  # Tunnel port detection not needed for veth
  # These settings don't hurt, but won't be used
  geneve_port = 6081      # Not visible on veth
  vxlan_port = 4789       # Not visible on veth
  wireguard_port = 51820  # Not visible on veth

  # Can use lower header depth (no tunnels to parse)
  max_header_depth = 4  # Adequate for most cases

  # IPv6 extension headers might still be relevant
  # (if pods themselves use IPv6 with extensions)
  parse_ipv6_fragment = false
  parse_ipv6_routing = false
  parse_ipv6_hopopt = false
  parse_ipv6_dest_opts = false
}

discovery "instrument" {
  interfaces = [
    "veth*"      # Decapsulated pod traffic only
  ]
}
```

**Advantages:**
- ✅ Lower eBPF complexity (no tunnel parsing)
- ✅ Accurate pod-to-pod visibility
- ✅ Application-layer protocols visible
- ✅ Captures same-node traffic

**Limitations:**
- ❌ No tunnel type information
- ❌ No VNI/tunnel IDs
- ❌ No node IP visibility
- ❌ Can't detect tunnel overhead or MTU issues

### For Complete Visibility (Recommended)

Monitor both veth and tunnel interfaces for comprehensive visibility:

```hcl
discovery "instrument" {
  interfaces = [
    "veth*",      # Same-node traffic (decapsulated)
    "tunl*",      # Calico IPIP tunnels
    "ip6tnl*",    # IPv6 tunnels
    "flannel*",   # Flannel VXLAN/overlay
    "vxlan*",     # Generic VXLAN
    # Do NOT add eth* to avoid duplication
  ]
}

parser {
  # Keep tunnel parsing enabled
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820

  max_header_depth = 6  # Needed for tunnel parsing
}
```

**Why this works:**
- `veth*` captures same-node traffic (never tunneled)
- Tunnel interfaces capture inter-node traffic (with tunnel metadata)
- No duplication (separate packet paths)
- Complete visibility of both application and infrastructure layers

### Why NOT to Monitor eth* with veth*

Adding `eth*` alongside `veth*` causes **flow duplication**:

```
Pod A → Pod B (inter-node):
  1. Seen on vethXXX (outbound from Pod A) → Flow 1: PodA→PodB
  2. Seen on eth0 (encapsulated)           → Flow 2: Node1→Node2 UDP 4789
  3. Seen on vethYYY (inbound to Pod B)    → Flow 3: PodA→PodB (duplicate!)
```

You'll see the **same logical flow twice** (once at sender veth, once at receiver veth), plus the tunnel flow in between.

## Use Cases

| Use Case | Recommended Interfaces | Rationale |
|----------|----------------------|-----------|
| **Pod application monitoring** | `veth*` only | See actual application traffic without tunnel noise |
| **Network infrastructure monitoring** | `eth*`, `ens*` only | See node-level routing, tunnels, bandwidth usage |
| **Complete Kubernetes observability** | `veth*` + tunnel interfaces | See both pod traffic and tunnel metadata |
| **Debugging same-node traffic** | `veth*` only | Inter-node tunnels won't help here |
| **Debugging inter-node routing** | `eth*` or tunnel interfaces | Need to see node IPs and routing |
| **CNI/overlay troubleshooting** | Tunnel interfaces | Need VNI, tunnel IDs, encapsulation metadata |

## Examples by CNI

### Flannel VXLAN

**Traffic Flow:**
```
vethXXX → bridge → flannel.1 → VXLAN encap → eth0 ──[network]──> eth0 → VXLAN decap → flannel.1 → bridge → vethYYY
```

**What to monitor:**
```hcl
interfaces = ["veth*", "flannel*"]  # Captures both decapsulated and tunnel traffic
```

### Calico IPIP

**Traffic Flow:**
```
vethXXX → caliXXX → tunl0 → IPIP encap → eth0 ──[network]──> eth0 → IPIP decap → tunl0 → caliYYY → vethYYY
```

**What to monitor:**
```hcl
interfaces = ["veth*", "cali*", "tunl*"]
```

### Cilium (native routing)

**Traffic Flow:**
```
vethXXX → cilium_host → routing → eth0 ──[network]──> eth0 → routing → cilium_host → vethYYY
```

**What to monitor:**
```hcl
interfaces = ["veth*", "cilium_*"]  # No tunnels in native routing mode
```

### Calico with WireGuard Encryption

**Traffic Flow:**
```
vethXXX → caliXXX → wg0 → WireGuard encrypt → eth0 ──[network]──> eth0 → WireGuard decrypt → wg0 → caliYYY → vethYYY
```

**At veth:** Decrypted pod traffic
**At eth0:** Encrypted WireGuard packets (UDP 51820)
**At wg0:** Can see WireGuard tunnel metadata

**What to monitor:**
```hcl
interfaces = ["veth*", "cali*"]  # Don't monitor wg0 (encrypted, not useful)
```

## Summary

| Aspect | veth* Interfaces | Physical Interfaces (eth*) | Tunnel Interfaces |
|--------|-----------------|---------------------------|-------------------|
| **Pod IPs** | ✅ Always visible | ❌ Hidden in tunnel | ✅ Visible (inner) |
| **Node IPs** | ❌ Not visible | ✅ Visible | ✅ Visible (outer) |
| **Tunnels/Encryption** | ❌ Decapsulated | ✅ Visible | ✅ Visible |
| **Same-node traffic** | ✅ Captured | ❌ Never reaches physical | ❌ Not tunneled |
| **Inter-node traffic** | ✅ Decapsulated | ✅ Encapsulated | ✅ Both |
| **Application protocols** | ✅ Clear | ❌ Buried/encrypted | ✅ Clear (inner) |
| **eBPF complexity** | Low | High | Medium |
| **Flow duplication risk** | Low (with tunnel ifaces) | High (with veth) | Low |

## Key Takeaway

**When monitoring veth* interfaces, you are observing traffic at the "pod network" layer, not the "node network" layer. The kernel has already performed decapsulation, decryption, and routing before packets reach veth pairs. You will see clean, decapsulated pod-to-pod traffic with actual application protocols and pod IP addresses, but you will not see tunnel headers, encryption layers, or node-level routing information.**

For most Kubernetes observability use cases, this is exactly what you want: visibility into actual workload communication without the complexity of infrastructure tunneling protocols.
