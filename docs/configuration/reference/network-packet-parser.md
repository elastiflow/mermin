# Configure Parsing of Network Packet

The parser configuration controls how Mermin's eBPF programs detect and parse tunneled traffic by specifying UDP ports for VXLAN, Geneve, and WireGuard.

## Overview

Mermin's parser configuration allows you to:

- Specify UDP ports for tunnel protocol detection (VXLAN, Geneve, WireGuard)
- Match your CNI or overlay network's tunnel port settings so inner (pod) traffic is visible

Correct port configuration ensures flows show inner source/destination (e.g., pod IPs) instead of only tunnel endpoints (node IPs). These settings do not add configurable parsing depth or IPv6 extension options; only tunnel ports are configurable.

## Configuration

```hcl
parser {
  # Tunnel port detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
}
```

## Configuration Options

### Tunnel Port Detection

#### `geneve_port`

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

#### `vxlan_port`

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

#### `wireguard_port`

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

**Symptoms of verifier failure:**

```text
BPF program is too large. Processed 1000001 insn
verification time 3775231 usec
```

**Resolution steps:**

1. **Update kernel** (if possible): Newer kernels (5.14+) have improved verifier efficiency

### Recommended Configurations by Environment

**Standard Kubernetes (Kind, K3s, Cloud providers):**

```hcl
parser {
  # Tunnel detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
}
```

**Constrained environments (older kernels, K3s on edge):**

```hcl
parser {
  # Tunnel detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
}
```

**Advanced networks (SRv6, multicast, specialized):**

```hcl
parser {
  # Tunnel detection
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
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

- [**Configuration Overview**](../overview.md): Config file format and structure
- [**Network Interface Discovery**](network-interface-discovery.md): Configure which interfaces to monitor
- [**Flow Filtering**](flow-span-filters.md): Filter flows based on protocols and ports
- [**Deployment Issues**](../../troubleshooting/deployment-issues.md): Troubleshoot eBPF verifier failures
- [**Troubleshooting**](../../troubleshooting/troubleshooting.md): Diagnose flow capture issues
- [**Advanced Scenarios**](../../deployment/advanced-scenarios.md): CNI-specific deployment guides
