# Testing the Pure Rust Netlink Implementation

This document describes how to test the pure Rust netlink implementation with Docker.

## Prerequisites

- Docker installed and running
- Access to the project root directory

## Build and Test Steps

### 1. Build the Docker Container

```bash
cd /workspace
docker build -t mermin-builder:latest --target builder .
```

### 2. Run Basic Compilation Test

Verify that the new netlink module compiles:

```bash
docker run -it --privileged \
  --mount type=bind,source=.,target=/app \
  mermin-builder:latest \
  /bin/bash -c "cargo check --package mermin"
```

Expected: Should compile without errors (once eBPF toolchain is available).

### 3. Run Unit Tests

Test the netlink monitor implementation:

```bash
docker run -it --privileged \
  --mount type=bind,source=.,target=/app \
  mermin-builder:latest \
  /bin/bash -c "cargo test --package mermin iface::netlink_monitor"
```

Expected: Tests should pass, demonstrating that:
- NetlinkMonitor can be created
- Socket binding succeeds
- Receive with timeout works correctly

### 4. Run Integration Tests

The standalone test programs in `/tmp/netlink_tests/` can be built and run inside Docker:

```bash
# Build standalone tests
docker run -it --privileged \
  --mount type=bind,source=/tmp/netlink_tests,target=/tests \
  mermin-builder:latest \
  /bin/bash -c "cd /tests && cargo build --release"

# Run netlink-sys test
docker run -it --privileged \
  --mount type=bind,source=/tmp/netlink_tests,target=/tests \
  mermin-builder:latest \
  /bin/bash -c "/tests/target/release/test_sys"

# Run rtnetlink test
docker run -it --privileged \
  --mount type=bind,source=/tmp/netlink_tests,target=/tests \
  mermin-builder:latest \
  /bin/bash -c "/tests/target/release/test_rtnetlink"
```

### 5. Test with Real Network Events

Create a test that triggers actual network interface events:

```bash
docker run -it --privileged \
  --mount type=bind,source=/tmp/netlink_tests,target=/tests \
  mermin-builder:latest \
  /bin/bash -c "
    # Start the monitor in background
    /tests/target/release/test_sys &
    MONITOR_PID=\$!
    
    # Wait for monitor to start
    sleep 1
    
    # Trigger network events
    ip link add dummy0 type dummy
    sleep 1
    ip link del dummy0
    
    # Wait for monitor to process
    wait \$MONITOR_PID
  "
```

Expected: Should see output indicating events were received.

### 6. Build Full Mermin Binary

```bash
docker run -it --privileged \
  --mount type=bind,source=.,target=/app \
  mermin-builder:latest \
  /bin/bash -c "cargo build --release"
```

Expected: Full binary builds successfully with netlink module included.

### 7. Run Full Integration Test

If there's an interface controller that uses NetlinkMonitor:

```bash
# Run mermin with test configuration
docker run -it --privileged \
  --mount type=bind,source=.,target=/app \
  mermin-builder:latest \
  /bin/bash -c "cargo test --test integration"
```

## Verification Checklist

- [ ] Docker container builds successfully
- [ ] `cargo check` passes without compilation errors
- [ ] Unit tests pass (`test_create_monitor`, `test_recv_with_timeout`)
- [ ] Standalone test programs compile
- [ ] test_sys successfully creates and binds socket
- [ ] test_rtnetlink correctly identifies limitations
- [ ] Network events are received when triggered
- [ ] Full mermin binary builds with netlink module
- [ ] Integration tests pass (if controller exists)

## Troubleshooting

### Compilation Errors

If you see netlink-related compilation errors:

1. Check that dependencies are correct:
   ```toml
   netlink-sys = "0.8"
   netlink-packet-core = "0.7"
   netlink-packet-route = "0.21"
   ```

2. Clear cargo cache and rebuild:
   ```bash
   docker run -it --privileged \
     --mount type=bind,source=.,target=/app \
     mermin-builder:latest \
     /bin/bash -c "cargo clean && cargo build"
   ```

### Runtime Errors

If netlink socket creation fails:

1. Ensure Docker is run with `--privileged` flag
2. Check that container has `CAP_NET_ADMIN` capability
3. Verify kernel supports netlink (should be available on all Linux systems)

### No Events Received

If events aren't received during tests:

1. Verify socket is bound with correct multicast group (RTMGRP_LINK = 0x00000001)
2. Check that events are actually being generated (create/delete interfaces)
3. Ensure proper timing (events might arrive quickly)

## Manual Testing

For manual testing and experimentation:

```bash
# Start interactive shell in container
docker run -it --privileged \
  --mount type=bind,source=.,target=/app \
  mermin-builder:latest \
  /bin/bash

# Inside container, build and test
cd /app
cargo build
cargo test

# Or run standalone tests
cd /tests
cargo build --release
./target/release/test_sys

# Trigger events manually
ip link add test0 type dummy
ip link set test0 up
ip link del test0
```

## Success Criteria

The implementation is considered successful if:

1. ✅ Code compiles without errors
2. ✅ Unit tests pass
3. ✅ NetlinkMonitor can create and bind socket
4. ✅ Events can be received (demonstrated in test)
5. ✅ Type-safe message parsing works
6. ✅ No regression in existing functionality

## Notes

- The netlink implementation is standalone and doesn't affect existing code
- It can be integrated into an interface controller when needed
- The pure Rust approach eliminates unsafe socket operations
- Namespace switching (setns) remains separate and can still use libc
