# Interface Monitoring Module

This module provides pure Rust implementations for monitoring network interface events using the Linux netlink protocol.

## Pure Rust Netlink Implementation

The `netlink_monitor` module replaces raw `libc` syscalls with the `netlink-sys` crate, providing:

- **Type-safe** netlink message handling
- **Pure Rust** implementation (no unsafe socket operations)
- **Better error handling** with idiomatic Rust patterns
- **Compatibility** with namespace switching

## Components

### NetlinkMonitor

The main struct for monitoring network interface events:

```rust
use crate::iface::NetlinkMonitor;
use std::time::Duration;

// Create a monitor
let mut monitor = NetlinkMonitor::new()?;

// Receive events with timeout
match monitor.recv_event(Duration::from_secs(1)) {
    Ok(Some(event)) => {
        // Handle event
        println!("Event: {:?}", event);
    }
    Ok(None) => {
        // Timeout
    }
    Err(e) => {
        // Handle error
    }
}
```

### LinkEvent

Represents different types of network interface events:

- `LinkEvent::NewLink` - New interface added
- `LinkEvent::DelLink` - Interface deleted  
- `LinkEvent::Other` - Other link events

## Key Implementation Details

### Multicast Subscription

The implementation uses `RTMGRP_LINK` bitmask (not group ID) for multicast subscription:

```rust
const RTMGRP_LINK: u32 = 0x00000001;
let addr = SocketAddr::new(0, RTMGRP_LINK);
socket.bind(&addr)?;
```

This is equivalent to the old libc approach but in pure Rust.

### Message Parsing

Uses `netlink-packet-route` for type-safe message parsing:

```rust
let header = NetlinkHeader::deserialize(header_bytes)?;
let route_msg = RouteNetlinkMessage::deserialize(&header, payload_bytes)?;
```

## Comparison to Old Implementation

| Aspect | Old (libc) | New (netlink-sys) |
|--------|-----------|-------------------|
| Safety | `unsafe` blocks | Safe Rust |
| Types | Raw C types | Rust types |
| Errors | Error codes | `Result<T, Error>` |
| Parsing | Manual | Type-safe |
| Documentation | Limited | Comprehensive |

## Dependencies

Required dependencies in `Cargo.toml`:

```toml
netlink-sys = "0.8"
netlink-packet-core = "0.7"
netlink-packet-route = "0.21"
```

## Future Integration

When the interface controller is created, use this module instead of raw libc netlink code:

1. Replace `libc::socket(AF_NETLINK, ...)` with `NetlinkMonitor::new()`
2. Replace `libc::recv()` with `monitor.recv_event()`
3. Remove unsafe socket-related code
4. Keep `setns()` for namespace switching (separate concern)

## See Also

- `/workspace/NETLINK_IMPLEMENTATION.md` - Full implementation documentation
- `/tmp/netlink_evaluation.md` - Evaluation of different approaches
- `/tmp/netlink_tests/` - Standalone test programs
