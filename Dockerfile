# ---- Builder Stage ----
# Use a Rust base image with build tools.
FROM rust:1.88.0-bookworm AS builder

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
    libzstd-dev
# Clean up downloaded packages and lists to keep the image size down
RUN apt-get autoremove -y && apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/llvm.sh

# Set environment variables to help Rust's build scripts find LLVM 20.
# The `llvm-sys` crate specifically looks for the `LLVM_SYS_..._PREFIX` variable format.
# Also add LLVM's tools (like llvm-config) to the PATH
ENV LLVM_SYS_200_PREFIX=/usr/lib/llvm-20
ENV PATH="/usr/lib/llvm-20/bin:${PATH}"

WORKDIR /usr/src

# Set the nightly toolchain as the default for eBPF development
RUN rustup toolchain install nightly
RUN rustup component add rust-src --toolchain nightly
RUN rustup default nightly

# Install the core Aya build tools
RUN cargo install bpf-linker
RUN cargo install bindgen-cli

# Copy source code
COPY . .

# Build the final application, leveraging the cached dependencies
RUN cargo build --release

# ---- Runtime Stage ----
# Use a slim base image for the final container with shell support
FROM alpine:3.22.1 AS runner

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/target/release/mermin /usr/local/bin/

# Set the binary as the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/mermin"]

# Use a slim base image for the final container without shell support
FROM gcr.io/distroless/static-debian12 AS runner-slim

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/target/release/mermin /usr/local/bin/

# Set the binary as the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/mermin"]
