#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Build the eBPF object
################################################################################
echo "=== Building eBPF object (nightly toolchain) ==="
rustup run nightly \
  cargo -Z build-std=core \
        build -p eth-ebpf-test-ebpf \
        --release --target bpfel-unknown-none

# The veth setup and cleanup logic has been removed from this script.
# The Rust test code will now manage the environment exclusively.

################################################################################
# Run all integration tests
################################################################################
echo "=== Running integration tests with eBPF logs ==="

CARGO_BIN="$(command -v cargo)"
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

## Run QUIC tests
#echo "=== Running QUIC header tests ==="
#sudo --preserve-env=PATH \
#     env CARGO_HOME="$CARGO_HOME" \
#         RUSTUP_HOME="$RUSTUP_HOME" \
#         RUSTUP_TOOLCHAIN=nightly \
#         RUST_LOG=info,eth_ebpf_test=debug \
#         "$CARGO_BIN" test -p eth-ebpf-test \
#         --test quic_hdr_kernel_integration \
#         -- --test-threads=1 --nocapture

# Run GRE tests
echo "=== Running GRE header tests ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         RUSTUP_TOOLCHAIN=nightly \
         RUST_LOG=info,eth_ebpf_test=debug \
         "$CARGO_BIN" test -p eth-ebpf-test \
         --test gre_hdr_kernel_integration \
         -- --test-threads=1 --nocapture

# Run OSPF tests
echo "=== Running OSPF header tests ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         RUSTUP_TOOLCHAIN=nightly \
         RUST_LOG=info,eth_ebpf_test=debug \
         "$CARGO_BIN" test -p eth-ebpf-test \
         --test ospf_hdr_kernel_integration \
         -- --test-threads=1 --nocapture
         
# Run BGP tests
echo "=== Running BGP header tests ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         RUSTUP_TOOLCHAIN=nightly \
         RUST_LOG=info,eth_ebpf_test=debug \
         "$CARGO_BIN" test -p eth-ebpf-test \
         --test bgp_hdr_kernel_integration \
         -- --test-threads=1 --nocapture

# Run GENEVE tests
echo "=== Running GENEVE header tests ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         RUSTUP_TOOLCHAIN=nightly \
         RUST_LOG=info,eth_ebpf_test=debug \
         "$CARGO_BIN" test -p eth-ebpf-test \
         --test geneve_hdr_kernel_integration \
         -- --test-threads=1 --nocapture