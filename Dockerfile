# syntax=docker/dockerfile:1.7-labs
# Using "labs" due to "COPY --parents", https://docs.docker.com/reference/dockerfile/#copy---parents
ARG APP_ROOT=/app
ARG APP=mermin


# ---- Build Stage ----
FROM rust:1.88.0-trixie AS base

# Since Mermin needs root to be ran, switching to non-root in in the base/builder stages does not improve the security.
# hadolint ignore=DL3002 # root is needed due to eBPF
USER root

# Install Dev Container essentials
# hadolint ignore=DL3059,DL3008 # multi-stage build, more RUN -> better caching, not pinning versions for now
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    git \
    ca-certificates \
    lsb-release \
    wget \
    gnupg \
    # Jetbrains specific dependencies: https://www.jetbrains.com/help/idea/prerequisites-for-dev-containers.html#remote_container
    default-jdk \
    curl \
    unzip \
    libxext6 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    libfreetype6 \
    procps \
    bpftool \
    iproute2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure passwordless sudo for the poseidon user
# Create a non-root user 'poseidon' and grant sudo privileges
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN useradd --create-home --shell /bin/bash poseidon \
    && echo "poseidon ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/poseidon

# Install LLVM
# Workaround she LLVM signing issue, https://github.com/llvm/llvm-project/issues/153385#issuecomment-3239875987
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN sed -i 's/sha1.second_preimage_resistance = 2026-02-01/sha1.second_preimage_resistance = 2026-03-01/' /usr/share/apt/default-sequoia.config
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN wget -q https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && chmod +x /tmp/llvm.sh \
    && /tmp/llvm.sh 20 all

# Install eBPF Dependencies
# hadolint ignore=DL3059,DL3008 # multi-stage build, more RUN -> better caching, not pinning versions for now
RUN apt-get install -y --no-install-recommends \
    iputils-ping \
    libclang-20-dev \
    llvm-20-dev \
    libelf-dev \
    zlib1g-dev \
    libzstd-dev \
    libbpf-tools

# Download bpftool and make it available system-wide
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN wget -c --progress=dot:giga -O /tmp/bpftool.tar.gz https://github.com/libbpf/bpftool/releases/download/v7.6.0/bpftool-v7.6.0-"$(dpkg --print-architecture)".tar.gz && \
  tar xfvpz /tmp/bpftool.tar.gz -C /usr/bin/ bpftool && \
  chmod 0755 /usr/bin/bpftool

# Verify bpftool is working
RUN bpftool --version

# Set environment variables to help Rust's build scripts find LLVM 20.
# The `llvm-sys` crate specifically looks for the `LLVM_SYS_..._PREFIX` variable format.
# Also add LLVM's tools (like llvm-config) to the PATH
ENV LLVM_SYS_200_PREFIX=/usr/lib/llvm-20
ENV PATH="/usr/lib/llvm-20/bin:${PATH}"

# Install the core Aya build tools
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN cargo install bpf-linker
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN cargo install bindgen-cli
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN cargo install --git https://github.com/aya-rs/aya --locked aya-tool

# ---- Builder Stage ----
FROM base AS builder
ARG APP_ROOT APP
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3002 # root is needed due to eBPF
USER root

WORKDIR ${APP_ROOT}

# Build dependencies (hack, https://github.com/rust-lang/cargo/issues/2644#issuecomment-2335499312)
# Cleanup everything related Mermin code in "./target" afterwards
COPY --parents **/Cargo.lock **/Cargo.toml ./
COPY --parents **/rust-toolchain.toml **/rustfmt.toml ./
RUN find . -type d | while read -r i; do mkdir -p "$i/src"; echo 'fn main() {}' > "$i/src/main.rs"; echo '// dummy line' > "$i/src/lib.rs"; done \
  && cargo build --release \
  && find . -type d -name 'src' -not -path './target/*' -prune -exec rm -rf {} \; \
  && find . -mindepth 1 -maxdepth 1 -type d | while read -r i; do find ./target/ -type d -name "${i#./}-*" -prune -exec rm -rf {} \;; done

# Copy source code (heavily relies on .dockerignore)
COPY . .
# Build the final application, leveraging the cached dependencies
RUN cargo build --release

# ---- Runtime Stage ----
# Use a distroless base image for the final container without shell support
# hadolint ignore=DL3006 # gcr.io/distroless/cc-debian12 don't have tags
FROM gcr.io/distroless/cc-debian13 AS runner
ARG APP_ROOT APP

COPY --from=builder ${APP_ROOT}/target/release/${APP} /usr/bin/${APP}
ENTRYPOINT ["/usr/bin/mermin"]

# ---- Runtime Stage ----
# Use a distroless base image for the final container with shell support
FROM debian:13.2-slim AS runner-debug
ARG APP_ROOT APP

COPY --from=builder ${APP_ROOT}/target/release/${APP} /usr/bin/${APP}
# Ignoring package versions warning, debug image not intended for production usage but for debug purposes
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
  bpftool \
  iproute2 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/bin/mermin"]
