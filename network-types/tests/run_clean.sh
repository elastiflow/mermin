#!/usr/bin/env bash

source run_setup.sh

# Clean previous build artifacts
echo "=== Cleaning project (with sudo) ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         "$CARGO_BIN" clean