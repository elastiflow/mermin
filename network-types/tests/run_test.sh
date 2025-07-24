#!/usr/bin/env bash

source run_setup.sh

# Run the integration tests
echo "=== Running integration tests ==="
sudo --preserve-env=PATH \
     env CARGO_HOME="$CARGO_HOME" \
         RUSTUP_HOME="$RUSTUP_HOME" \
         RUST_LOG=info,integration=debug \
         "$CARGO_BIN" test -p integration \
         -- --test-threads=1 --nocapture
