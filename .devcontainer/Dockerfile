# Start from the official Rust dev container image
FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# Switch to root to install system dependencies
USER root

# Install LLVM 20 and the essential eBPF dependencies in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsb-release wget software-properties-common gnupg \
    && wget -q https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh \
    && chmod +x /tmp/llvm.sh \
    # Execute the script to install LLVM, Clang, and related tools version 20
    && /tmp/llvm.sh 20 all \
    # Install development headers and tools required for building and running Aya
    && apt-get install -y --no-install-recommends \
        iputils-ping \
        libclang-20-dev \
        llvm-20-dev \
        libelf-dev \
        zlib1g-dev \
        libzstd-dev \
        libbpf-tools \
    # Clean up downloaded packages and lists to keep the image size down
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/llvm.sh

# Set environment variables to help Rust's build scripts find LLVM 20.
# The `llvm-sys` crate specifically looks for the `LLVM_SYS_..._PREFIX` variable format.
ENV LLVM_SYS_201_PREFIX=/usr/lib/llvm-20
# Also add LLVM's tools (like llvm-config) to the PATH
ENV PATH="/usr/lib/llvm-20/bin:${PATH}"

# Switch back to the non-root vscode user, which is the default user in the base image.
USER vscode

# Install and set the nightly toolchain as the default.
# This is required for eBPF development with Aya.
RUN rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly && \
    rustup component add rustfmt && \
    rustup component add clippy --toolchain nightly && \
    rustup default nightly

# Install the latest PUBLISHED versions of the core Aya tools.
# We chain the commands with '&&' to ensure they run sequentially.
RUN cargo install bpf-linker --no-default-features && \
    cargo install bindgen-cli && \
    cargo install --git https://github.com/aya-rs/aya --locked aya-tool
