FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# Switch to root to install system dependencies
USER root

# Install LLVM 20 and the essential eBPF dependencies in a single layer
# Install the essential eBPF dependencies in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends lsb-release wget software-properties-common gnupg
# Install LLVM 20
RUN wget -q https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && chmod +x /tmp/llvm.sh
# Execute the script to install LLVM, Clang, and related tools version 20
RUN /tmp/llvm.sh 20 all
# Install development headers and tools required for building and running Aya
RUN apt-get install -y --no-install-recommends \
    libclang-20-dev \
    llvm-20-dev \
    libelf-dev \
    zlib1g-dev \
    libzstd-dev \
    libbpf-tools
# Clean up downloaded packages and lists to keep the image size down
RUN apt-get autoremove -y && apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/llvm.sh

# Set environment variables to help Rust's build scripts find LLVM 20.
# The `llvm-sys` crate specifically looks for the `LLVM_SYS_..._PREFIX` variable format.
# Also add LLVM's tools (like llvm-config) to the PATH
ENV LLVM_SYS_200_PREFIX=/usr/lib/llvm-20
ENV PATH="/usr/lib/llvm-20/bin:${PATH}"

# Switch back to the non-root vscode user, which is the default user in the base image.
USER vscode

# Install and set the nightly toolchain as the default.
# This is required for eBPF development with Aya.
RUN rustup toolchain install nightly
RUN rustup component add rust-src --toolchain nightly
RUN rustup component add rustfmt --toolchain nightly
RUN rustup component add clippy --toolchain nightly
RUN rustup default nightly

# Install the latest PUBLISHED versions of the core Aya tools.
RUN cargo install bpf-linker
RUN cargo install bindgen-cli
RUN cargo install --git https://github.com/aya-rs/aya --locked aya-tool
