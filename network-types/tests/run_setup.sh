#!/usr/bin/env bash

# Check if we are running under sudo. If so, the SUDO_USER variable will be set.
if [ -n "$SUDO_USER" ]; then
    # We are running as root. We need to find the home directory of the user
    # who *called* sudo. `getent` is a standard and robust way to do this.
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    # We are not running under sudo, so the current user's HOME is correct.
    USER_HOME="$HOME"
fi

# Define other necessary environment variables using the correct home directory.
CARGO_HOME="${CARGO_HOME:-$USER_HOME/.cargo}"
RUSTUP_HOME="${RUSTUP_HOME:-$USER_HOME/.rustup}"

# Find the full, absolute path to the 'cargo' executable.
CARGO_BIN="$(command -v cargo)"
if [ -z "$CARGO_BIN" ]; then
   echo "Error: 'cargo' command not found. Make sure the Rust toolchain is installed and in your PATH."
   exit 1
fi

# Define toolchain
TOOLCHAIN_VERSION="nightly-2025-06-23"
