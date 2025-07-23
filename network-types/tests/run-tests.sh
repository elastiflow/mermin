
#!/usr/bin/env bash
set -euo pipefail

# This script automates the build and test process for the integration tests,
# handling the specific requirements of the eBPF development environment.


# Find the full, absolute path to the 'cargo' executable.
CARGO_BIN="$(command -v cargo)"
if [ -z "$CARGO_BIN" ]; then
    echo "Error: 'cargo' command not found. Make sure the Rust toolchain is installed and in your PATH."
    exit 1
fi

# Define other necessary environment variables.
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

################################################################################
# 1. Clean previous build artifacts
################################################################################
echo "=== Cleaning project (with sudo) ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         "$CARGO_BIN" clean

################################################################################
# 2. Build the eBPF object file
################################################################################
echo "=== Building eBPF object file ==="
rustup run nightly \
  "$CARGO_BIN" -Z build-std=core \
        build -p integration-ebpf \
        --release --target bpfel-unknown-none

################################################################################
# 3. Run the integration tests
################################################################################
echo "=== Running integration tests ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         RUST_LOG=info,integration=debug \
         "$CARGO_BIN" test -p integration \
         -- --test-threads=1 --nocapture