# TCP Flags Implementation Summary

## Overview

This document summarizes the implementation of TCP flags extraction for the Mermin eBPF project as per Linear issue ENG-170.

## Requirements Met

✅ **Extract TCP flags out of TCP header and add to packet meta**
✅ **Support tunneled packets by extracting innermost and outermost TCP flags**
✅ **Value is a byte where each bit represents the flag**
✅ **Log the TCP flags within the userspace program**

## Changes Made

### 1. PacketMeta Structure Updates (`mermin-common/src/lib.rs`)

Added two new fields to the `PacketMeta` structure:
- `outer_tcp_flags: u8` - TCP flags from the outermost TCP header (0 if not TCP or no outer TCP)
- `inner_tcp_flags: u8` - TCP flags from the innermost TCP header (0 if not TCP)

Added helper methods:
- `has_tcp_flags()` - Returns true if packet has TCP flags
- `is_tunneled_tcp()` - Returns true if packet has different outer/inner TCP flags
- `format_tcp_flags(flags: u8)` - Formats flags as human-readable string (e.g., "SYN,ACK")

### 2. TCP Header Enhancements (`network-types/src/tcp.rs`)

Added new method to `TcpHdr`:
- `flags() -> u8` - Returns the raw TCP flags byte directly from the header

The flags byte contains all TCP control flags:
- Bit 0: FIN
- Bit 1: SYN  
- Bit 2: RST
- Bit 3: PSH
- Bit 4: ACK
- Bit 5: URG
- Bit 6: ECE
- Bit 7: CWR

### 3. eBPF Parser Updates (`mermin-ebpf/src/main.rs`)

Enhanced the `Parser` struct:
- Added `tunnel_depth: u8` field to track tunneling level
- Updated `parse_tcp_header()` to extract TCP flags using the new `flags()` method
- Implemented logic to distinguish between outer and inner TCP headers:
  - For non-tunneled packets: both outer and inner flags are set to the same value
  - For tunneled packets: outer flags are from the first TCP header, inner flags from the innermost TCP header
- Updated `parse_geneve_header()` and `parse_vxlan_header()` to increment `tunnel_depth`

### 4. Userspace Logging (`mermin/src/main.rs`)

Updated packet logging to include TCP flags:
- Both IPv4 and IPv6 packet logs now include: `TCP Flags: outer=0x{:02x}, inner=0x{:02x}`
- Flags are displayed in hexadecimal format for easy bit-level inspection

## Technical Details

### TCP Flag Bit Layout

The TCP flags byte follows the standard RFC 793 layout:
```
7 6 5 4 3 2 1 0
C E U A P R S F
W C R C S S Y I
R E G K H T N N
```

### Tunneling Support

The implementation handles multiple levels of encapsulation:
1. **VXLAN tunnels** - Increments tunnel depth when parsing VXLAN headers
2. **Geneve tunnels** - Increments tunnel depth when parsing Geneve headers
3. **Multiple TCP layers** - Correctly identifies outer vs inner TCP headers based on tunnel depth

### Example Output

For a non-tunneled TCP SYN packet:
```
Received TCP packet: Community ID: abc123, Src IPv4: 10.0.0.1, Dst IPv4: 10.0.0.2, L3 Octet Count: 60, Src Port: 12345, Dst Port: 80, TCP Flags: outer=0x02, inner=0x02
```

For a VXLAN-tunneled TCP SYN-ACK packet:
```
Received TCP packet: Community ID: def456, Src IPv4: 192.168.1.1, Dst IPv4: 192.168.1.2, L3 Octet Count: 110, Src Port: 80, Dst Port: 12345, TCP Flags: outer=0x02, inner=0x12
```

## Testing

- Added comprehensive unit tests for TCP flag methods
- Added tests for the new `flags()` method in `TcpHdr`
- Updated PacketMeta size calculations to account for new fields
- No linting errors detected

## Compliance with eBPF Constraints

The implementation follows eBPF best practices:
- Uses bounded operations (no dynamic allocation)
- Maintains proper memory alignment
- Uses simple bit operations for flag extraction
- Preserves existing parsing logic and performance characteristics

## Usage

The TCP flags can now be accessed in userspace code:
```rust
let packet_meta: PacketMeta = /* received from eBPF */;

// Check if packet has TCP flags
if packet_meta.has_tcp_flags() {
    println!("Outer TCP flags: 0x{:02x}", packet_meta.outer_tcp_flags);
    println!("Inner TCP flags: 0x{:02x}", packet_meta.inner_tcp_flags);
    
    // Check if tunneled
    if packet_meta.is_tunneled_tcp() {
        println!("This is a tunneled TCP packet with different inner/outer flags");
    }
    
    // Format flags as human-readable string
    let outer_flags_str = PacketMeta::format_tcp_flags(packet_meta.outer_tcp_flags);
    let inner_flags_str = PacketMeta::format_tcp_flags(packet_meta.inner_tcp_flags);
}
```

This implementation fully satisfies the requirements of Linear issue ENG-170.