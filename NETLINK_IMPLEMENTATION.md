# Pure Rust Netlink Implementation

## Overview

This document describes the pure Rust netlink implementation that replaces raw `libc` syscalls with the `netlink-sys` crate. This implementation provides a safer, more idiomatic Rust interface for monitoring network interface events.

## Implementation Files

- **`mermin/src/iface/mod.rs`** - Module definition
- **`mermin/src/iface/netlink_monitor.rs`** - Pure Rust netlink monitor implementation
- **`mermin/tests/netlink_test_sys.rs`** - Standalone test for netlink-sys approach
- **`mermin/tests/netlink_test_neli.rs`** - Standalone test for neli approach (alternative)
- **`mermin/tests/netlink_test_rtnetlink.rs`** - Test demonstrating rtnetlink limitations

## Evaluation Results

Three approaches were tested:

### 1. netlink-sys (WINNER ✅)

**Status**: Fully validated and implemented

**Pros**:
- Low-level, full control over netlink protocol
- Works with RTMGRP_LINK bitmask subscription
- Synchronous API - simpler for blocking operations
- Direct socket access for advanced operations
- Pure Rust replacement for libc syscalls
- Compatible with netlink-packet-route for parsing

**Cons**:
- Requires separate parsing library
- More verbose than higher-level libraries
- Manual error handling

**Verdict**: ✅ **SELECTED** - Best fit for replacing raw libc netlink code

### 2. rtnetlink

**Status**: Not suitable

**Pros**:
- High-level async API
- Good for get/set operations
- Type-safe operations

**Cons**:
- NOT designed for multicast event monitoring
- No API to subscribe to multicast groups
- Adds unnecessary async complexity
- Would require forking/patching

**Verdict**: ❌ Not suitable for event monitoring

### 3. neli

**Status**: Not evaluated (API compatibility issues)

**Issues**:
- Version 0.7.x requires edition2024
- Version 0.6.x has different API
- API incompatibilities prevented full evaluation

## Implementation Details

### Key Components

#### NetlinkMonitor struct

```rust
pub struct NetlinkMonitor {
    socket: Socket,           // Pure Rust netlink socket
    buffer: Vec<u8>,          // Receive buffer
}
```

#### Socket Creation and Binding

The old libc approach:
```c
let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
let addr = sockaddr_nl { nl_family: AF_NETLINK, nl_groups: RTMGRP_LINK, ... };
libc::bind(fd, &addr, ...);
```

New pure Rust approach:
```rust
let mut socket = Socket::new(NETLINK_ROUTE)?;
socket.bind(&SocketAddr::new(0, RTMGRP_LINK))?;
```

**Key Insight**: `SocketAddr` expects a **BITMASK** in the groups field, not a group ID. Use `RTMGRP_LINK = 0x00000001` directly, not group ID `1`.

#### Receiving Events

The old libc approach:
```c
let n = libc::recv(fd, buf, len, MSG_DONTWAIT);
```

New pure Rust approach:
```rust
let n = socket.recv(&mut buf, libc::MSG_DONTWAIT as i32)?;
```

#### Message Parsing

Uses `netlink-packet-route` for type-safe parsing:

```rust
let header = NetlinkHeader::deserialize(header_bytes)?;
let route_msg = RouteNetlinkMessage::deserialize(&header, payload_bytes)?;

match route_msg {
    RouteNetlinkMessage::NewLink(link_msg) => { /* handle new link */ }
    RouteNetlinkMessage::DelLink(link_msg) => { /* handle delete link */ }
    _ => { /* other */ }
}
```

## Usage Example

```rust
use mermin::iface::NetlinkMonitor;
use std::time::Duration;

// Create monitor
let mut monitor = NetlinkMonitor::new()?;

// Poll for events with timeout
match monitor.recv_event(Duration::from_secs(1)) {
    Ok(Some(event)) => {
        println!("Received event: {:?}", event);
        // Handle event...
    }
    Ok(None) => {
        // Timeout, no events
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}

// Or block until event received
let event = monitor.recv_event_blocking()?;
```

## Dependencies

Added to `mermin/Cargo.toml`:

```toml
[dependencies]
netlink-sys = "0.8"
netlink-packet-core = "0.7"
netlink-packet-route = "0.21"
```

## Namespace Switching Compatibility

The implementation maintains compatibility with namespace switching via `setns()`. The `NetlinkMonitor` provides access to the underlying socket:

```rust
let monitor = NetlinkMonitor::new()?;
let socket = monitor.socket();

// Can still use libc setns() with the socket fd if needed
// (setns is not a socket operation, so libc is still appropriate)
```

## Testing

### Standalone Tests

Three standalone test programs were created in `/tmp/netlink_tests/`:

1. **test_sys** - Validates netlink-sys approach
2. **test_rtnetlink** - Demonstrates rtnetlink capabilities and limitations
3. **test_neli** - (Not completed due to API issues)

Run tests:
```bash
cd /tmp/netlink_tests
cargo build --release
./target/release/test_sys
./target/release/test_rtnetlink
```

### Unit Tests

The `netlink_monitor.rs` includes unit tests:

```bash
cargo test --package mermin iface::netlink_monitor
```

## Integration Notes

### What Was Changed

1. Created `mermin/src/iface/` module structure
2. Implemented `NetlinkMonitor` using pure Rust netlink-sys
3. Added netlink dependencies to Cargo.toml
4. Registered iface module in main.rs

### What Stays the Same

- Namespace switching (`setns`) still uses libc (not a socket operation)
- Overall architecture and threading model unchanged
- Event handling patterns remain the same

### Future Work

When interface controller is created/recreated:

1. Replace raw libc socket code with `NetlinkMonitor::new()`
2. Replace `recv()` loops with `recv_event()` or `recv_event_blocking()`
3. Remove raw `unsafe` blocks for socket operations
4. Keep `setns()` for namespace switching (separate concern)

## Benefits of This Implementation

1. **Type Safety**: Compile-time guarantees for netlink message handling
2. **Error Handling**: Idiomatic Rust error handling with `Result<T, Error>`
3. **Documentation**: Self-documenting types and functions
4. **Maintainability**: Easier to understand and modify than raw C syscalls
5. **Safety**: Fewer unsafe blocks, reduced risk of memory safety issues
6. **Pure Rust**: No dependency on C socket API (except for `setns`)

## References

- **netlink-sys**: https://docs.rs/netlink-sys/
- **netlink-packet-route**: https://docs.rs/netlink-packet-route/
- **Linux netlink protocol**: https://man7.org/linux/man-pages/man7/netlink.7.html
- **Evaluation results**: `/tmp/netlink_evaluation.md`
