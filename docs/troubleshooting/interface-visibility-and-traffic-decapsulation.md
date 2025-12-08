---
hidden: true
---

# Interface Visibility and Traffic Decapsulation

Not seeing the traffic you expect from Mermin? The issue is often related to *which* network interfaces you're monitoring. Different interface types show you completely different views of the same traffic, and understanding these differences is crucial for getting Mermin configured correctly.

## The Big Picture: What Am I Actually Seeing?

Here's the key insight that explains everything: the Linux kernel automatically encapsulates and decapsulates network traffic as it moves between physical interfaces and pod namespaces. This means the same packet looks completely different depending on where you observe it.

Think of it like watching a package move through the postal system:

- **At the sender's house** (veth): You see the gift box with "To: Mom" written on it
- **On the delivery truck** (eth0): You see the gift box inside a shipping container labeled "Truck A → Warehouse B"
- **At the sorting facility** (tunnel interface): You can see both the shipping container AND the gift box inside

Here's what traffic looks like at each layer:

- **Physical interfaces** (`eth*`, `ens*`): Encapsulated traffic with tunnel headers and node IPs
- **Veth interfaces** (`veth*`): Decapsulated traffic showing pod IPs and application protocols
- **Tunnel interfaces** (`tunl*`, `flannel*`): Both layers visible - tunnel metadata plus inner packet headers

## How Traffic Actually Flows Through the Network Stack

Let's follow a packet's journey through the network stack to see how encapsulation and decapsulation work in practice.

### Inter-Node Traffic: When Pods Talk Across Nodes

Imagine Pod A on Node 1 wants to send an HTTP request to Pod B on Node 2. Here's the fascinating journey that packet takes:

```text
┌───────────────────────────────────────────────────────────────┐
│ Node 1                                                        │
│                                                               │
│  Pod A namespace                                              │
│    └─> vethXXX (pod side)                                     │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]             │
│          │ ✅ Pod IPs visible                                 │
│          │ ✅ Application protocol visible                    │
│          │ ❌ No tunnel headers                               │
│          ▼                                                    │
│    vethXXX (host side) ──> bridge ──> Kernel routing          │
│          │                                                    │
│          │ CNI encapsulation happens here                     │
│          ▼                                                    │
│    eth0 (physical interface)                                  │
│          │ Packet: [Eth | IP: Node1→Node2 | UDP 4789          │
│          │          | VXLAN VNI=1000                          │
│          │          | Eth | IP: PodA→PodB | TCP 80]           │
│          │ ✅ Node IPs visible                                │
│          │ ✅ Tunnel headers visible (VXLAN/Geneve/WireGuard) │
│          │ ✅ Pod IPs buried inside tunnel                    │
│          ▼                                                    │
│    ─────[Network]───────────────────────────────────────────> │
└───────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│ Node 2                                                        │
│                                                               │
│    eth0 (physical interface)                                  │
│          │ Packet: [Eth | IP: Node1→Node2 | UDP 4789          │
│          │          | VXLAN VNI=1000                          │
│          │          | Eth | IP: PodA→PodB | TCP 80]           │
│          │ ✅ Encapsulated tunnel traffic visible             │
│          ▼                                                    │
│    Kernel decapsulation (VXLAN driver)                        │
│          │                                                    │
│          │ Tunnel headers stripped                            │
│          ▼                                                    │
│    bridge ──> vethYYY (host side)                             │
│          ▼                                                    │
│    vethYYY (pod side)                                         │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]             │
│          │ ✅ Pod IPs visible                                 │
│          │ ✅ Application protocol visible                    │
│          │ ❌ No tunnel headers (removed by kernel)           │
│          ▼                                                    │
│  Pod B namespace                                              │
└───────────────────────────────────────────────────────────────┘
```

### Same-Node Traffic (Pod A → Pod B, both on same node)

```text
┌───────────────────────────────────────────────────────────────┐
│ Node 1                                                        │
│                                                               │
│  Pod A namespace                                              │
│    └─> vethXXX (pod side)                                     │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]             │
│          ▼                                                    │
│    vethXXX (host side) ──> bridge ──> vethYYY (host side)     │
│          │                              │                     │
│          │ ✅ Never encapsulated        │                     │
│          │ ✅ Never leaves host         │                     │
│          │ ✅ Never touches eth0        │                     │
│          ▼                              ▼                     │
│    vethYYY (pod side)                                         │
│          │ Packet: [Eth | IP: PodA→PodB | TCP 80]             │
│          ▼                                                    │
│  Pod B namespace                                              │
└───────────────────────────────────────────────────────────────┘
```

**The key insight**: Same-node traffic never gets encapsulated because it never needs to leave the host. It's like two people in the same building passing notes directly—no need for the postal system!

## What You See on Different Interface Types

Now that you understand how traffic flows, let's look at what you'll actually see when monitoring different interface types.

### veth* Interfaces: The Application View

This is where you see "clean" pod-to-pod traffic, exactly as the applications see it. All the tunnel complexity has been stripped away by the kernel.

**What you can see:**

- Pod IPs (10.244.x.x)
- Application protocols (HTTP, gRPC, databases)
- Application ports (80, 443, 3306)
- Unencrypted traffic (after the kernel decrypts it)
- Both same-node and inter-node traffic (after decapsulation)

**What's invisible:**

- Tunnel headers (VXLAN/Geneve/WireGuard/GRE/IPsec) - the kernel removed them
- Node IPs (outer headers) - only pod IPs remain
- Tunnel ports (4789, 6081, 51820) - you see application ports instead
- Tunnel VNIs - no tunnel metadata at all
- Network routing information - you see the logical connection

**Example of what monitoring veth shows:**

```text
Ethernet: aa:bb:cc:dd:ee:01 → aa:bb:cc:dd:ee:02
IPv4: 10.244.1.5 (Pod A) → 10.244.2.8 (Pod B)
TCP: 45678 → 80 [ACK PSH]
Payload: HTTP GET / HTTP/1.1...
```

### Physical Interfaces (eth*, ens*): The Infrastructure View

This is where you see the "real" network traffic at the node level - all the tunnel and routing infrastructure that CNIs use to make pod networking work.

**What you can see:**

- Node IPs - the actual machines communicating
- Tunnel protocols (VXLAN, Geneve, WireGuard)
- Tunnel ports (4789, 6081, 51820)
- Tunnel VNIs - which overlay network the traffic belongs to
- Encrypted payloads - before decryption
- Network routing information - how packets move between nodes
- Inter-node traffic only - same-node traffic never hits the physical NIC

**What's invisible:**

- Pod IPs - buried deep inside the tunnel encapsulation
- Application protocols - hidden behind encryption/encapsulation
- Same-node traffic - it shortcuts through the bridge, never touches eth0
- Decrypted content - you only see encrypted payloads

**Example of what monitoring eth0 shows:**

```text
Outer Ethernet: 00:0c:29:xx:xx:01 → 00:0c:29:xx:xx:02
Outer IPv4: 192.168.1.10 (Node 1) → 192.168.1.11 (Node 2)
Outer UDP: 54321 → 4789 (VXLAN)
VXLAN: VNI=1000, Flags=0x08
Inner Ethernet: aa:bb:cc:dd:ee:01 → aa:bb:cc:dd:ee:02
Inner IPv4: 10.244.1.5 (Pod A) → 10.244.2.8 (Pod B)
Inner TCP: 45678 → 80
Payload: HTTP GET / HTTP/1.1...
```

### Tunnel Interfaces (tunl*, flannel*): The Best of Both Worlds

Tunnel interfaces give you a hybrid view - they sit at the point where the kernel does encapsulation/decapsulation, so you can see both layers!

**What you can see:**

- Outer (node) IPs AND inner (pod) IPs - both at once!
- Tunnel metadata (VNI, tunnel type)
- Inner application protocols - the actual HTTP, gRPC, etc.
- Inter-node traffic with full context

**What's invisible:**

- Same-node traffic - it never gets tunneled in the first place

This is the sweet spot for troubleshooting inter-node communication issues, because you get the complete picture.

## Why Some Protocols Never Show Up on veth*

Understanding when encryption and encapsulation happen is key to knowing where you'll see different protocol headers.

### WireGuard

WireGuard encrypts at the `wg0` interface (or sometimes `eth0`), which happens *before* traffic reaches the veth interfaces.

What this means in practice:

- **eth0**: You see encrypted blobs: `[Eth | IP: Node1→Node2 | UDP 51820 | WireGuard encrypted data]`
- **veth**: You see decrypted application traffic: `[Eth | IP: PodA→PodB | TCP 80 | HTTP]`

By the time packets reach veth, the kernel has already decrypted them.

### VXLAN/Geneve

VXLAN and Geneve encapsulation is added *after* packets leave the veth interfaces, as they head toward the physical network.

The progression:

- **veth**: Clean pod traffic: `[Eth | IP: PodA→PodB | TCP 80]`
- **eth0**: Wrapped in tunnel: `[Eth | IP: Node1→Node2 | UDP 4789 | VXLAN | Eth | IP: PodA→PodB | TCP 80]`

The tunnel wrapper is added after veth, so veth never sees it.

### IPsec ESP/AH

IPsec encryption happens in the IPsec subsystem, not at the veth level.

What you'll see:

- **eth0**: Encrypted ESP packets: `[Eth | IP: Node1→Node2 | ESP SPI=12345 | Encrypted payload]`
- **veth**: Unencrypted traffic: `[Eth | IP: PodA→PodB | TCP 80 | Clear text]`

### GRE Tunnels

GRE encapsulation happens at the GRE interface (`gre0`, `gretap0`), not at veth.

Same pattern - veth sees clean traffic, GRE interface sees encapsulated traffic.

## How to Configure Mermin for Different Scenarios

Now that you understand what each interface type shows, let's look at how to configure Mermin based on what you need to observe.

### Simple Setup: veth-Only Monitoring

If you just want to see what your applications are doing (pod-to-pod communication), this is the simplest approach:

```hcl
discovery "instrument" {
  interfaces = ["veth*"]
}
```

**Why this works well:**

- Lower eBPF complexity (less resource usage)
- Clean pod-to-pod visibility without tunnel noise
- Application protocols are clearly visible
- Captures both same-node and inter-node traffic (after decapsulation)

**What you'll miss:**

- Tunnel information - you won't see VXLAN, Geneve, etc.
- VNIs - no visibility into which overlay network traffic uses
- Node IPs - only pod IPs are visible
- Can't troubleshoot tunnel overhead or MTU issues

**Best for**: Application performance monitoring, service mesh visibility, debugging application-level issues

### Comprehensive Setup: veth + Tunnel Interfaces (Recommended)

For complete visibility into both application traffic AND infrastructure, monitor veth along with tunnel interfaces:

```hcl
discovery "instrument" {
  interfaces = [
    "veth*",      # Same-node traffic + pod IPs
    "tunl*",      # Calico IPIP tunnels
    "ip6tnl*",    # IPv6 tunnels
    "flannel*",   # Flannel VXLAN interfaces
    "vxlan*",     # Generic VXLAN interfaces
    # Do NOT add eth* (causes duplication - see below!)
  ]
}

parser {
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
}
```

**Why this is the sweet spot:**

- Veth captures same-node traffic cleanly
- Tunnel interfaces capture inter-node traffic with both pod IPs AND tunnel metadata
- No flow duplication because they're on separate paths
- Complete visibility: you see application behavior AND infrastructure details

**Best for**: Complete Kubernetes observability, troubleshooting CNI issues, capacity planning

### Why You Shouldn't Monitor eth\* with veth\*

It's tempting to monitor everything, but adding `eth*` alongside `veth*` creates a mess: flow duplication.

Here's what happens when Pod A talks to Pod B across nodes:

```text
Pod A → Pod B (inter-node):
  1. vethXXX (outbound) → Flow recorded: PodA→PodB
  2. eth0 (encapsulated) → Flow recorded: Node1→Node2 UDP 4789
  3. vethYYY (inbound) → Flow recorded: PodA→PodB (duplicate!)
```

You end up with the same logical flow appearing three times in your data:

- Once at the sender's veth
- Once at the receiver's veth (duplicate!)
- Once as encapsulated node traffic on eth0

This inflates your metrics and makes analysis confusing. Stick with either veth + tunnel interfaces OR just eth*, but not both.

## Choosing the Right Configuration for Your Use Case

Not sure which interfaces to monitor? Here's a guide based on what you're trying to accomplish:

| Use Case                              | Recommended Interfaces      | Rationale                                           |
|---------------------------------------|-----------------------------|-----------------------------------------------------|
| **Pod application monitoring**        | `veth*` only                | See actual application traffic without tunnel noise |
| **Network infrastructure monitoring** | `eth*`, `ens*` only         | See node-level routing, tunnels, bandwidth usage    |
| **Complete Kubernetes observability** | `veth*` + tunnel interfaces | See both pod traffic and tunnel metadata            |
| **Debugging same-node traffic**       | `veth*` only                | Inter-node tunnels won't help here                  |
| **Debugging inter-node routing**      | `eth*` or tunnel interfaces | Need to see node IPs and routing                    |
| **CNI/overlay troubleshooting**       | Tunnel interfaces           | Need VNI, tunnel IDs, encapsulation metadata        |

## CNI-Specific Configuration Examples

Different CNI plugins create different interface types and use different encapsulation methods. Here's how to configure Mermin for popular CNIs:

### Flannel VXLAN

**How traffic flows:**

`vethXXX → bridge → flannel.1 → VXLAN encap → eth0 ──[network]──> eth0 → VXLAN decap → flannel.1 → bridge → vethYYY`

**What to monitor:** `interfaces = ["veth*", "flannel*"]`

This gives you clean pod traffic on veth and VXLAN tunnel details on flannel.1.

### Calico IPIP

**How traffic flows:**

`vethXXX → caliXXX → tunl0 → IPIP encap → eth0 ──[network]──> eth0 → IPIP decap → tunl0 → caliYYY → vethYYY`

**What to monitor:** `interfaces = ["veth*", "cali*", "tunl*"]`

Calico uses its own cali* interfaces plus the tunl0 interface for IPIP tunneling.

### Cilium (Native Routing)

**How traffic flows:**

`vethXXX → cilium_host → routing → eth0 ──[network]──> eth0 → routing → cilium_host → vethYYY`

**What to monitor:** `interfaces = ["veth*", "cilium_*"]`

Cilium in native routing mode doesn't use tunnels, just direct routing through cilium_host.

### Calico with WireGuard Encryption

**How traffic flows:**

`vethXXX → caliXXX → wg0 → encrypt → eth0 ──[network]──> eth0 → decrypt → wg0 → caliYYY → vethYYY`

**What you see at each layer:**

- **veth**: Decrypted pod traffic (clear HTTP, gRPC, etc.)
- **eth0**: Encrypted WireGuard packets (UDP 51820, encrypted blobs)
- **wg0**: Tunnel metadata (before encryption/after decryption)

**What to monitor:** `interfaces = ["veth*", "cali*"]` (skip wg0)

You'll see clean application traffic on veth - by the time it reaches veth, WireGuard has already decrypted it.

## Summary

| Aspect                    | veth* Interfaces         | Physical Interfaces (eth*) | Tunnel Interfaces |
|---------------------------|--------------------------|----------------------------|-------------------|
| **Pod IPs**               | ✅ Always visible         | ❌ Hidden in tunnel         | ✅ Visible (inner) |
| **Node IPs**              | ❌ Not visible            | ✅ Visible                  | ✅ Visible (outer) |
| **Tunnels/Encryption**    | ❌ Decapsulated           | ✅ Visible                  | ✅ Visible         |
| **Same-node traffic**     | ✅ Captured               | ❌ Never reaches physical   | ❌ Not tunneled    |
| **Inter-node traffic**    | ✅ Decapsulated           | ✅ Encapsulated             | ✅ Both            |
| **Application protocols** | ✅ Clear                  | ❌ Buried/encrypted         | ✅ Clear (inner)   |
| **eBPF complexity**       | Low                      | High                       | Medium            |
| **Flow duplication risk** | Low (with tunnel ifaces) | High (with veth)           | Low               |

## The Bottom Line

Here's what you need to remember: **Monitoring veth* interfaces gives you "pod network" visibility, not "node network" visibility.**

The Linux kernel does all the heavy lifting - decapsulation, decryption, and routing - before packets reach the veth interfaces. This means:

**What you see on veth:**

- Clean pod-to-pod traffic
- Application protocols (HTTP, gRPC, SQL)
- Pod IPs (10.244.x.x)
- The traffic as your applications actually see it

**What you don't see on veth:**

- Tunnel headers (VXLAN, Geneve, IPsec)
- Encryption layers (WireGuard, IPsec)
- Node routing information
- Node IPs

For most Kubernetes observability use cases, this is exactly what you want: insight into actual workload communication without getting lost in infrastructure tunneling complexity. Your applications don't know about VXLAN or WireGuard, and for monitoring application behavior, you usually don't need to either.

**When you do need infrastructure visibility** (troubleshooting CNI issues, debugging tunnel problems, capacity planning), add tunnel interfaces to your configuration to see both layers.
