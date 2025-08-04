ARG APP_ROOT=/app
ARG APP=mermin

# ---- Builder Stage ----
# Use a Rust base image with build tools.
FROM mcr.microsoft.com/devcontainers/rust:1-bookworm AS base

# Switch to root to install system dependencies
USER root

# Install LLVM 20 and the essential eBPF dependencies in a single layer
# Install the essential eBPF dependencies in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends lsb-release wget software-properties-common gnupg
# Install LLVM 20, Clang, and related tools version 20
RUN wget -q https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && chmod +x /tmp/llvm.sh \
  && /tmp/llvm.sh 20 all
# Install development headers and tools required for building and running Aya
RUN apt-get install -y --no-install-recommends \
    libclang-20-dev \
    llvm-20-dev \
    libelf-dev \
    zlib1g-dev \
    libzstd-dev \
    libbpf-tools

# Set environment variables to help Rust's build scripts find LLVM 20.
# The `llvm-sys` crate specifically looks for the `LLVM_SYS_..._PREFIX` variable format.
# Also add LLVM's tools (like llvm-config) to the PATH
ENV LLVM_SYS_200_PREFIX=/usr/lib/llvm-20
ENV PATH="/usr/lib/llvm-20/bin:${PATH}"

# Switch back to the non-root vscode user, which is the default user in the base image.
USER vscode

# Set the nightly toolchain as the default for eBPF development
RUN rustup toolchain install nightly
RUN rustup component add rust-src --toolchain nightly
RUN rustup component add rustfmt --toolchain nightly
RUN rustup component add clippy --toolchain nightly
RUN rustup default nightly

# Install the core Aya build tools
RUN cargo install bpf-linker
RUN cargo install bindgen-cli
RUN cargo install --git https://github.com/aya-rs/aya --locked aya-tool

# ---- Builder Stage ----
# Use a slim base image for the final container with shell support
FROM base AS builder
ARG APP_ROOT APP

USER root
WORKDIR ${APP_ROOT}
# Copy source code
COPY . .

# Build the final application, leveraging the cached dependencies
RUN cargo build --release

# Use a slim base image for the final container without shell support
FROM scratch AS runner
ARG APP_ROOT APP

# Copy the compiled binary from the builder stage
COPY --from=builder ${APP_ROOT}/target/release/${APP} /usr/bin/${APP}
ENTRYPOINT ["/usr/bin/${APP}"]

# ---- Runtime Stage ----
# Use a slim base image for the final container with shell support
FROM alpine:3.22.1 AS runner-alpine
ARG APP_ROOT APP

# Copy the compiled binary from the builder stage
COPY --from=builder ${APP_ROOT}/target/release/${APP} /usr/bin/${APP}
ENTRYPOINT ["/usr/bin/${APP}"]
