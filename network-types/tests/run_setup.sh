#!/usr/bin/env bash

# Find the full, absolute path to the 'cargo' executable.
CARGO_BIN="$(command -v cargo)"
if [ -z "$CARGO_BIN" ]; then
   echo "Error: 'cargo' command not found. Make sure the Rust toolchain is installed and in your PATH."
   exit 1
fi

# Define other necessary environment variables.
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
