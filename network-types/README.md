# Network Types ⚙️

A lightweight, no_std compatible Rust crate that provides network protocol data structures for parsing, manipulating,
and generating network packets. This crate is designed for high-performance, low-level networking in both userspace and
eBPF environments.

### 🎯 Core Purpose

The primary goal of network-types is to provide a set of pure Rust, no_std-compatible data structures for working with
network packets.

By offering structs with a guaranteed memory layout (#[repr(C, packed)]), this crate enables safe, efficient, and direct
interaction with raw network data. It removes the need for manual byte manipulation and provides type-safe abstractions,
which are essential in performance-critical applications and restrictive environments like eBPF.

## ✨ Key Features

#![no_std] Compatible: Use it in any environment, from bare-metal to kernel space, without the standard library.

- Guaranteed Binary Compatibility: Structures are defined with #[repr(C, packed)] to ensure their memory layout is
  identical to the on-the-wire network protocol specifications.
- Ergonomic Helpers: Provides safe and convenient methods for parsing and accessing header fields, like ether_type()
  which safely handles endianness.
- Comprehensive Protocol Enums: Includes thorough enums for common protocol identifiers (e.g., EtherType), making your
  code more readable and robust.
- Rigorously Tested: Validated by a comprehensive integration test suite that simulates a real-world eBPF scenario to
  guarantee correctness.

## 🚀 Usage

First, add the crate to your `Cargo.toml`:

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
network-types = { path = "path/to/network-types" }
```

Here's a basic example of parsing an Ethernet header from a raw byte slice:

```rust
use network_types::eth::{EthHdr, EtherType};

fn parse_ethernet_frame(raw_bytes: &[u8]) {
    // This is safe as long as raw_bytes contains at least sizeof(EthHdr).
    // Direct memory casting is common for performance-critical packet parsing.
    let eth_header: &EthHdr = unsafe { &*(raw_bytes.as_ptr() as *const EthHdr) };

    // Access header fields directly
    let dst_mac = eth_header.dst_addr;
    let src_mac = eth_header.src_addr;
    println!("Source MAC: {}, Destination MAC: {}", src_mac, dst_mac);

    // Use helper methods to safely parse protocol types
    match eth_header.ether_type() {
        Ok(EtherType::Ipv4) => {
            println!("Payload is an IPv4 packet.");
            // Handle IPv4 packet
        }
        Ok(EtherType::Ipv6) => {
            println!("Payload is an IPv6 packet.");
            // Handle IPv6 packet
        }
        // ... and so on
        _ => println!("Payload is another protocol."),
    }
}
```

-----

## 🧪 Rigorous Integration Testing

### Why a Complex Test Suite?

While the crate's purpose is simple, proving its correctness—especially for eBPF—is not. A primary challenge in eBPF
development is ensuring that data structures are memory-compatible across different compilation targets (userspace vs.
kernel). We previously encountered subtle bugs where:

1. Code passing local tests would fail to compile for the eBPF target.
2. Code that successfully compiled would later cause a runtime panic when loaded into the kernel.

To prevent this, we built an extensive integration test suite that validates our structures in a real-world eBPF
workflow, guaranteeing they are correct and reliable.

### Test Workflow

The tests follow a full-circle workflow:

1. The userspace test constructs a network packet and sends it.
2. An eBPF program, using these same network-types structs, is attached to a network interface to capture the packet.
3. The eBPF program parses the packet headers and sends the parsed data back to userspace via an eBPF map.
4. The userspace test verifies that the data received from the eBPF program matches the original values sent.

#### Running the Tests

The test suite is located in the network-types/tests/ directory and is managed via a Makefile.

#### Prerequisites

- A Linux environment with eBPF capabilities.
- A correctly configured Rust toolchain (the workspace toolchain file will be respected).
- sudo privileges for loading the eBPF program into the kernel.

#### The Easy Way: Dev Container

The simplest way to get a working test environment is to launch this project in a Dev Container using `docker run`. All
dependencies are pre-installed in the container defined in the builder image within the `Dockerfile`.

See the [workspace README](https://github.com/elastiflow/mermin?tab=readme-ov-file#using-a-dockerized-build-environment)
for more information.

### Running the Tests

All commands should be run from the network-types/tests/ directory.

```shell
# Navigate to the tests directory first
cd network-types/tests
```

1. `make build`: Compiles the eBPF program (integration-ebpf) required by the test suite. You must run this before make
   test.
2. `make test`: Runs the userspace integration tests. This will fail if the eBPF program hasn't been built first.
3. `make test-ci`: (Recommended) This is the command our CI uses. It conveniently runs build and then test in the
   correct
   order, avoiding common test failures.
4. `make clean`: Cleans up all build artifacts.

> Important: The Makefile commands use sudo because loading eBPF programs requires elevated privileges. The script
> correctly preserves your user's environment variables (PATH, CARGO_HOME, etc.) to ensure the right Rust toolchain is
> used.

The tests will:

1. Load and attach an eBPF program to the loopback interface
2. Send test packets with known header values
3. The eBPF program will parse these headers and send the parsed values back to userspace
4. The tests will verify that the parsed values match the expected values

### Extending the Test Suite 🧑‍💻

Adding a new test for another header type is a streamlined process, thanks to a helper macro. The workflow involves two
main steps:

1. **Create helper functions**: You'll need one function that constructs the test packet with known values and another
   that verifies the data returned from the eBPF program.
2. **Use the macro**: Call the define_header_test! macro to generate the full, end-to-end test case boilerplate for you.

Here is an example of how to use the macro. The comments explain each parameter:

```rust
define_header_test!(
    // 1. The name for your new test function.
    test_parses_new_header,
    // 2. The header struct from `network-types` that you are testing.
    NewHdr,
    // 3. A unique enum variant from `PacketType` to identify this test.
    PacketType::New,
    // 4. The name of your function that builds the test packet.
    create_new_test_packet,
    // 5. The name of your function that verifies the results.
    verify_new_header
);
```

## 📜 License

This project is licensed under the terms specified in the Cargo.toml file at the root of the workspace.
