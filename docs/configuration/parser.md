---
hidden: true
---

# Parser Configuration

The parser configuration controls how Mermin's eBPF programs parse network packets, including tunnel detection, protocol parsing depth, and IPv6 extension header handling.

## Overview

Mermin's parser configuration allows you to:

- Specify ports for tunnel protocol detection (VXLAN, Geneve, WireGuard)
- Control the maximum depth of nested protocol headers to parse
- Enable/disable parsing of advanced IPv6 extension headers

These settings directly affect eBPF verifier complexity and can be tuned to balance visibility needs against deployment constraints.

## Configuration

```hcl
parser {
  # Tunnel port detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820

  # Protocol parsing controls
  max_header_depth = 6

  # IPv6 extension header parsing (disabled by default for Kubernetes)
  parse_ipv6_hopopt = false
  parse_ipv6_fragment = false
  parse_ipv6_routing = false
  parse_ipv6_dest_opts = false
}
```

## Configuration Options

### Protocol Parsing Controls

#### `max_header_depth`

**Type:** Integer (1-8) **Default:** `6`

Maximum number of nested protocol headers to parse per packet.

**Description:**

Limits how deep the eBPF program will parse through nested encapsulation layers. Lower values reduce eBPF verifier complexity, which is critical for deployment in constrained kernel environments.

**Example header stack** (depth = 7):

```text
Ethernet → IPv6 → UDP → VXLAN → Ethernet → IPv4 → TCP
```

**When to customize:**

- **Reduce to 4-5**: If experiencing eBPF verifier failures ("BPF program is too large")
- **Reduce to 4-5**: In K3s or older kernel environments
- **Keep at 6**: Standard Kubernetes deployments (default)
- **Increase to 7-8**: Complex multi-layer tunneling scenarios (rare)

**Verifier Impact:**

Lower values significantly reduce eBPF instruction count:

- Depth 8: ~1M+ verifier instructions (may fail verification)
- Depth 6: ~300-500K verifier instructions (recommended)
- Depth 4: ~100-200K verifier instructions (minimal)

**Example:**

```hcl
parser {
  max_header_depth = 6  # Standard Kubernetes (default)
}
```

**For constrained environments:**

```hcl
parser {
  max_header_depth = 4  # Reduce for K3s or older kernels
}
```

#### `parse_ipv6_hopopt`

**Type:** Boolean **Default:** `false`

Enable parsing of IPv6 Hop-by-Hop Options header.

**Description:**

Controls whether the parser processes IPv6 Hop-by-Hop Options headers. These headers are rarely used in standard Kubernetes networking and are disabled by default to reduce verifier complexity.

**Use cases:**

- Router Alert for multicast protocols (RSVP, MLD)
- Jumbo Payloads (>65KB packets)
- Custom IPv6 options in specialized networks

**When to enable:**

- Your network uses IPv6 multicast with Router Alert
- Large MTU environments with Jumbo Payload option
- Specialized telco/carrier networks

**Verifier Impact:** Minimal (~5K instructions when enabled)

**Example:**

```hcl
parser {
  parse_ipv6_hopopt = false  # Default - disabled for Kubernetes
}
```

**Enable for multicast:**

```hcl
parser {
  parse_ipv6_hopopt = true  # Enable if using multicast
}
```

#### `parse_ipv6_fragment`

**Type:** Boolean **Default:** `false`

Enable parsing of IPv6 Fragment Header.

**Description:**

Controls whether the parser processes IPv6 fragmentation headers. Most Kubernetes CNIs perform path MTU discovery to avoid fragmentation, making this header rare in practice.

**When to enable:**

- Environments with MTU mismatches causing fragmentation
- Networks without proper PMTU discovery
- Troubleshooting fragmentation-related issues

**Verifier Impact:** Minimal (~5K instructions when enabled)

**Example:**

```hcl
parser {
  parse_ipv6_fragment = false  # Default - disabled for Kubernetes
}
```

#### `parse_ipv6_routing`

**Type:** Boolean **Default:** `false`

Enable parsing of IPv6 Routing Header.

**Description:**

Controls whether the parser processes IPv6 Routing headers (Type 2, RPL Source Route, Segment Routing, etc.). These are rarely used in Kubernetes environments.

**Use cases:**

- IPv6 Segment Routing (SRv6)
- Mobile IPv6 (uncommon in K8s)
- Specialized routing scenarios

**When to enable:**

- Service meshes using SRv6
- Mobile IPv6 deployments
- Networks with custom routing requirements

**Verifier Impact:** Minimal (~5K instructions when enabled)

**Example:**

```hcl
parser {
  parse_ipv6_routing = false  # Default - disabled for Kubernetes
}
```

#### `parse_ipv6_dest_opts`

**Type:** Boolean **Default:** `false`

Enable parsing of IPv6 Destination Options header.

**Description:**

Controls whether the parser processes IPv6 Destination Options headers. These are rarely seen in standard Kubernetes networking.

**When to enable:**

- Networks using custom IPv6 options
- Specialized security or telemetry scenarios
- Troubleshooting specific IPv6 option-related issues

**Verifier Impact:** Minimal (~5K instructions when enabled)

**Example:**

```hcl
parser {
  parse_ipv6_dest_opts = false  # Default - disabled for Kubernetes
}
```

### Tunnel Port Detection

### `geneve_port`

**Type:** Integer (port number) **Default:** `6081`

UDP port number for Geneve tunnel detection.

**Description:**

- [Geneve](https://datatracker.ietf.org/doc/html/rfc8926) (Generic Network Virtualization Encapsulation) is a tunneling protocol
- IANA assigned port: 6081
- Used by various cloud networking solutions and SDN controllers

**When to customize:**

- Your environment uses non-standard Geneve port
- Network policy requires specific port assignment
- Conflict with other services on standard port

**Example:**

```hcl
parser {
  geneve_port = 6081  # IANA standard (default)
}
```

**Custom port example:**

```hcl
parser {
  geneve_port = 7081  # Custom port
}
```

### `vxlan_port`

**Type:** Integer (port number) **Default:** `4789`

UDP port number for VXLAN tunnel detection.

**Description:**

- [VXLAN](https://datatracker.ietf.org/doc/html/rfc7348) (Virtual Extensible LAN) is a network virtualization technology
- IANA assigned port: 4789
- Commonly used in Kubernetes networking (Flannel, Calico, NSX-T)

**When to customize:**

- Your CNI or network plugin uses non-standard VXLAN port
- Legacy VXLAN deployments using older port assignments
- Custom overlay network configuration

**Example:**

```hcl
parser {
  vxlan_port = 4789  # IANA standard (default)
}
```

**Custom port example:**

```hcl
parser {
  vxlan_port = 8472  # Flannel's default in older versions
}
```

### `wireguard_port`

**Type:** Integer (port number) **Default:** `51820`

UDP port number for WireGuard tunnel detection.

**Description:**

- [WireGuard](https://www.wireguard.com/) is a modern VPN protocol
- Default port: 51820 (not IANA assigned, but widely adopted)
- Used for secure site-to-site or pod-to-pod encrypted connections

**When to customize:**

- WireGuard configured with custom listen port
- Multiple WireGuard tunnels with different ports
- Security requirements for non-default ports

**Example:**

```hcl
parser {
  wireguard_port = 51820  # Default WireGuard port
}
```

**Custom port example:**

```hcl
parser {
  wireguard_port = 51821  # Custom WireGuard port
}
```

## How Tunnel Parsing Works

### Packet Processing Flow

1. **Outer Header Parsing**:
   - Mermin's eBPF program examines the outer IP header
   - Checks UDP destination port against configured tunnel ports
2. **Tunnel Type Detection**:
   - If port matches `vxlan_port` → Parse as VXLAN
   - If port matches `geneve_port` → Parse as Geneve
   - If port matches `wireguard_port` → Parse as WireGuard
3. **Inner Header Parsing**:
   - Extract encapsulated packet
   - Parse inner IP, TCP/UDP headers
   - Generate flow records using inner headers
4. **Flow Attributes**:
   - Flow records contain both outer and inner header information
   - Tunnel type is recorded in flow metadata
   - Enables tracking of overlay network traffic

### Tunnel Detection Benefits

**Without tunnel parsing:**

- Flows show only tunnel endpoints (node IPs)
- Cannot see actual source/destination of encapsulated traffic
- Limited visibility into overlay network communication

**With tunnel parsing:**

- Flows show inner source/destination (pod IPs)
- Complete visibility into overlay traffic
- Accurate flow accounting for containerized workloads

## CNI-Specific Configurations

### Flannel with VXLAN

Flannel typically uses VXLAN on port 8472 (older) or 4789 (newer):

```hcl
parser {
  vxlan_port = 4789  # Modern Flannel
  # vxlan_port = 8472  # Legacy Flannel
}
```

### Calico with VXLAN

Calico uses standard VXLAN port when VXLAN mode is enabled:

```hcl
parser {
  vxlan_port = 4789  # Calico VXLAN
}
```

### Cilium with Geneve

Cilium can use Geneve for overlay networking:

```hcl
parser {
  geneve_port = 6081  # Cilium Geneve overlay
}
```

### WireGuard Encryption

If using WireGuard for pod-to-pod encryption:

```hcl
parser {
  wireguard_port = 51820  # Default WireGuard
}
```

### NSX-T

VMware NSX-T uses Geneve:

```hcl
parser {
  geneve_port = 6081  # NSX-T overlay
}
```

## Determining Your Configuration

### Identifying VXLAN Port

**Flannel:**

```bash
# Check Flannel configuration
kubectl -n kube-system get configmap kube-flannel-cfg -o yaml | grep -i port

# Or check pod arguments
kubectl -n kube-system get pod -l app=flannel -o yaml | grep -i port
```

**Calico:**

```bash
# Check Calico configuration
kubectl get felixconfiguration default -o yaml | grep -i vxlan
```

### Identifying Geneve Port

**Cilium:**

```bash
# Check Cilium config
kubectl -n kube-system get configmap cilium-config -o yaml | grep -i geneve
```

**NSX-T:**

```bash
# Typically uses default Geneve port 6081
# Check NSX-T configuration documentation
```

### Identifying WireGuard Port

```bash
# Check WireGuard configuration
kubectl get configmap -n kube-system -o yaml | grep -i wireguard

# Or check node configuration
ssh node "sudo wg show"
```

## Multiple Tunnel Types

Some environments use multiple tunnel types simultaneously. Configure all relevant ports:

```hcl
parser {
  # VXLAN for main overlay network (Flannel)
  vxlan_port = 4789

  # Geneve for service mesh (NSX-T)
  geneve_port = 6081

  # WireGuard for encryption
  wireguard_port = 51820
}
```

## Performance Considerations

### Impact of Tunnel Parsing

- **CPU Usage**: Minimal overhead for tunnel header parsing
- **Memory**: No additional memory required
- **Accuracy**: Significantly improves flow accuracy in overlay networks

### When to Disable

Tunnel parsing cannot be disabled, but misconfigured ports may cause:

- Incorrect tunnel detection
- Flows attributed to wrong source/destination
- Missing inner packet information

## Validation

Verify tunnel parsing is working:

### Check Flow Records

```bash
# View flow logs
kubectl logs -l app.kubernetes.io/name=mermin --tail=20

# Look for tunnel information in flow records
# Should see inner IP addresses (pod IPs) not just node IPs
```

### Compare With/Without Tunnel Parsing

**Without proper configuration:**

- Flows show: Node IP A → Node IP B (outer headers only)
- Protocol: UDP (tunnel protocol)
- Ports: tunnel ports (4789, 6081, etc.)

**With proper configuration:**

- Flows show: Pod IP X → Pod IP Y (inner headers)
- Protocol: TCP/UDP/ICMP (actual application protocol)
- Ports: application ports (80, 443, etc.)

## eBPF Verifier Considerations

### Understanding Verifier Complexity

The Linux eBPF verifier analyzes all possible execution paths in the program to ensure safety. Parser configuration directly impacts verifier complexity:

**Primary factors:**

- `max_header_depth`: Major impact - each additional depth level exponentially increases paths
- IPv6 extension headers: Minor impact - each enabled header adds ~5K instructions
- Tunnel types: Fixed impact - already optimized

**Symptoms of verifier failure:**

```text
BPF program is too large. Processed 1000001 insn
verification time 3775231 usec
```

**Resolution steps:**

1. **Reduce max_header_depth** (most effective):

   ```hcl
   parser {
     max_header_depth = 5  # Or even 4 for K3s
   }
   ```

2. **Disable unused IPv6 options** (already default):

   ```hcl
   parser {
     parse_ipv6_hopopt = false
     parse_ipv6_fragment = false
     parse_ipv6_routing = false
     parse_ipv6_dest_opts = false
   }
   ```

3. **Update kernel** (if possible): Newer kernels (5.10+) have improved verifier efficiency

### Recommended Configurations by Environment

**Standard Kubernetes (Kind, K3s, Cloud providers):**

```hcl
parser {
  # Tunnel detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820

  # Parsing limits
  max_header_depth = 6  # Handles most scenarios

  # IPv6 extensions (disabled for typical K8s)
  parse_ipv6_hopopt = false
  parse_ipv6_fragment = false
  parse_ipv6_routing = false
  parse_ipv6_dest_opts = false
}
```

**Constrained environments (older kernels, K3s on edge):**

```hcl
parser {
  # Tunnel detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820

  # Reduced parsing depth
  max_header_depth = 4  # Lower for verifier compatibility

  # IPv6 extensions disabled
  parse_ipv6_hopopt = false
  parse_ipv6_fragment = false
  parse_ipv6_routing = false
  parse_ipv6_dest_opts = false
}
```

**Advanced networks (SRv6, multicast, specialized):**

```hcl
parser {
  # Tunnel detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820

  # Standard depth
  max_header_depth = 6

  # Enable specific IPv6 extensions as needed
  parse_ipv6_hopopt = true      # For multicast Router Alert
  parse_ipv6_fragment = false
  parse_ipv6_routing = true     # For SRv6
  parse_ipv6_dest_opts = false
}
```

## Complete Configuration Example

```hcl
# Parser configuration - complete example
parser {
  # Tunnel protocol detection ports
  geneve_port = 6081      # Cilium, NSX-T (IANA standard)
  vxlan_port = 4789       # Flannel, Calico (IANA standard)
  wireguard_port = 51820  # WireGuard VPN (default port)

  # Protocol parsing depth (affects eBPF verifier complexity)
  max_header_depth = 6    # Standard for Kubernetes (range: 1-8)

  # IPv6 extension header parsing (disabled by default)
  # Only enable if your network specifically requires these headers
  parse_ipv6_hopopt = false    # Hop-by-Hop Options (multicast, jumbo frames)
  parse_ipv6_fragment = false  # Fragment Header (typically avoided via PMTU)
  parse_ipv6_routing = false   # Routing Header (SRv6, Mobile IPv6)
  parse_ipv6_dest_opts = false # Destination Options (custom options)
}
```

## Troubleshooting

### Seeing Only Tunnel Endpoints in Flows

**Symptoms:** Flows show node IPs instead of pod IPs

**Solutions:**

1. Verify tunnel port configuration matches your CNI
2. Check CNI documentation for port settings
3. Inspect actual tunnel traffic: `tcpdump -i any -n udp port 4789`

### Incorrect Tunnel Detection

**Symptoms:** Flows misattributed or missing

**Solutions:**

1. Confirm tunnel ports with CNI configuration
2. Check for port conflicts with other services
3. Review eBPF program logs for parsing errors

### Multiple Ports for Same Protocol

If your environment uses multiple ports for the same tunnel protocol (e.g., multiple VXLAN configurations), Mermin currently supports only one port per protocol type. Choose the most commonly used port or consult support for multi-port scenarios.

## Best Practices

1. **Use IANA defaults**: Unless you have a specific reason, use the default ports
2. **Document customizations**: If using custom ports, document why in comments
3. **Validate after changes**: Test flow accuracy after modifying parser configuration
4. **Match CNI configuration**: Ensure parser ports match your CNI's tunnel ports
5. **Monitor metrics**: Watch for anomalies after configuration changes

## Next Steps

- [**Network Interface Discovery**](discovery-interfaces.md): Configure which interfaces to monitor
- [**Flow Filtering**](filtering.md): Filter flows based on protocols and ports
- [**Deployment Issues**](../troubleshooting/deployment-issues.md): Troubleshoot eBPF verifier failures
- [**Troubleshooting No Flow Data**](../troubleshooting/no-flows.md): Diagnose flow capture issues
- [**Advanced Scenarios**](../deployment/advanced-scenarios.md): CNI-specific deployment guides
