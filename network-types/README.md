# Network Types

A lightweight, `no_std` compatible library that defines network protocol data structures for parsing and generating network packets. This crate is designed to work in both userspace and eBPF environments.

## Overview

The `network-types` crate provides memory-compatible structures for common network protocol headers. These structures are designed to be binary-compatible with their network protocol specifications, making them suitable for direct parsing of network packets.

## Features

- `#![no_std]` compatible for use in environments without the standard library
- Memory-compatible structures with `#[repr(C, packed)]` for binary compatibility
- Comprehensive enums for protocol types (e.g., EtherType)
- Helper methods for parsing and constructing headers
- Thoroughly tested with both unit tests and integration tests

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
network-types = { path = "path/to/network-types" }
```

Example usage for parsing an Ethernet header:

```
use network_types::eth::{EthHdr, EtherType};

// Parse an Ethernet header from raw bytes
let eth_header: EthHdr = unsafe { *(raw_bytes.as_ptr() as *const EthHdr) };

// Access header fields
let dst_mac = eth_header.dst_addr;
let src_mac = eth_header.src_addr;

// Parse the EtherType
match eth_header.ether_type() {
    Ok(EtherType::Ipv4) => {
        // Handle IPv4 packet
    },
    Ok(EtherType::Ipv6) => {
        // Handle IPv6 packet
    },
    Ok(other_type) => {
        // Handle other known protocol
    },
    Err(unknown_value) => {
        // Handle unknown protocol
    }
}
```

## Integration Tests

The `network-types` crate includes comprehensive integration tests that verify the structures work correctly in both userspace and eBPF environments.

### Test Structure

The integration tests are organized into three main components:

1. **integration**: Userspace tests that send test packets and verify the results
2. **integration-ebpf**: eBPF program that parses packets and sends the results back to userspace
3. **integration-common**: Common types used by both the userspace and eBPF components

### Prerequisites

To run the integration tests, you need:

- Rust toolchain with the nightly channel (for eBPF support)
- `bpf-linker` installed (`cargo install bpf-linker`)
- Root privileges (for loading eBPF programs)
- Linux kernel with eBPF support (4.9+)

#### Easy Button Environment for Running Tests

Launch the project as a dev container within VSCode or RustRover. You can find the dev container Dockerfile and configuration in the workspace's root under the `.devcontainer` directory.

### Running the Tests

The integration tests are managed through a Makefile with several targets:

1. **setup**: Sets up the environment variables
2. **build**: Builds the eBPF program
3. **test**: Runs the integration tests
4. **clean**: Cleans up build artifacts

To run the tests:
```
cd tests
make test
```

The tests will:
1. Load and attach an eBPF program to the loopback interface
2. Send test packets with known header values
3. The eBPF program will parse these headers and send the parsed values back to userspace
4. The tests will verify that the parsed values match the expected values

### Adding New Tests

To add a new test for a different header type:

1. Create helper functions for constructing test packets and verifying results
2. Use the `define_header_test!` macro to generate the test function

Example:

```
define_header_test!(
    test_parses_new_header,
    NewHdr,
    PacketType::New,
    create_new_test_packet,
    verify_new_header
);
```

## License

This project is licensed under the terms specified in the workspace configuration.
