#!/usr/bin/env bash

source run_setup.sh

# Build the eBPF object file
echo "=== Building eBPF object file ==="
rustup run nightly \
  "$CARGO_BIN" -Z build-std=core \
        build -p integration-ebpf \
        --release --target bpfel-unknown-none
