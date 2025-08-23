ARG APP_ROOT=/app
ARG APP=mermin

# ---- Bpftool Build Stage ----
FROM debian:bookworm-slim AS bpftool-build

ARG SOURCE_REPO=https://github.com/libbpf/bpftool.git
ARG SOURCE_REF=main

# Install build dependencies and build bpftool in a single layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gpg gpg-agent libelf-dev libmnl-dev libc-dev libgcc-12-dev libcap-dev \
        bash-completion binutils binutils-dev ca-certificates make git \
        xz-utils gcc pkg-config bison flex build-essential clang llvm llvm-dev && \
    git clone --recurse-submodules --depth 1 -b $SOURCE_REF $SOURCE_REPO /tmp/bpftool && \
    cd /tmp/bpftool && \
    EXTRA_CFLAGS=--static OUTPUT=/usr/bin/ make -C src -j "$(nproc)" && \
    strip /usr/bin/bpftool && \
    ldd /usr/bin/bpftool 2>&1 | grep -q -e "Not a valid dynamic program" \
        -e "not a dynamic executable" || \
	    ( echo "Error: bpftool is not statically linked"; false ) && \
    apt-get purge -y gpg gpg-agent libelf-dev libmnl-dev libc-dev libgcc-12-dev libcap-dev \
        bash-completion binutils binutils-dev ca-certificates make git \
        xz-utils gcc pkg-config bison flex build-essential clang llvm llvm-dev && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /tmp/bpftool /var/lib/apt/lists/*

# ---- Build Stage ----
FROM rust:1.88.0-bookworm AS base

# Switch to root to install system dependencies
USER root

# Install Dev Container essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    git \
    ca-certificates \
    lsb-release \
    wget \
    software-properties-common \
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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure passwordless sudo for the poseidon user
# Create a non-root user 'poseidon' and grant sudo privileges
RUN useradd --create-home --shell /bin/bash poseidon \
    && echo "poseidon ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/poseidon

# Install LLVM
RUN wget -q https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh && chmod +x /tmp/llvm.sh \
    && /tmp/llvm.sh 20 all

# Install eBPF Dependencies
RUN apt-get install -y --no-install-recommends \
    iputils-ping \
    libclang-20-dev \
    llvm-20-dev \
    libelf-dev \
    zlib1g-dev \
    libzstd-dev \
    libbpf-tools

# Copy bpftool from the build stage and make it available system-wide
COPY --from=bpftool-build /usr/bin/bpftool /usr/bin/bpftool

# Verify bpftool is working
RUN bpftool --version

# Set environment variables to help Rust's build scripts find LLVM 20.
# The `llvm-sys` crate specifically looks for the `LLVM_SYS_..._PREFIX` variable format.
# Also add LLVM's tools (like llvm-config) to the PATH
ENV LLVM_SYS_200_PREFIX=/usr/lib/llvm-20
ENV PATH="/usr/lib/llvm-20/bin:${PATH}"

# Switch back to the non-root poseidon user, which is the default user in the base image.
USER poseidon

# Install the core Aya build tools
RUN cargo install bpf-linker
RUN cargo install bindgen-cli
RUN cargo install --git https://github.com/aya-rs/aya --locked aya-tool

# ---- Builder Stage ----
FROM base AS builder
ARG APP_ROOT APP

USER root

WORKDIR ${APP_ROOT}
# Copy source code
COPY . .

# Build the final application, leveraging the cached dependencies
RUN cargo build --release

# ---- Runtime Stage ----
# Use a distroless base image for the final container without shell support
FROM gcr.io/distroless/cc-debian12 AS runner
ARG APP_ROOT APP

ENV RUST_LOG=info

COPY --from=builder ${APP_ROOT}/target/release/${APP} /usr/bin/${APP}
ENTRYPOINT ["/usr/bin/mermin"]

# ---- Runtime Stage ----
# Use a distroless base image for the final container with shell support
FROM gcr.io/distroless/cc-debian12:debug AS runner-debug
ARG APP_ROOT APP

ENV RUST_LOG=info

COPY --from=builder ${APP_ROOT}/target/release/${APP} /usr/bin/${APP}
ENTRYPOINT ["/usr/bin/mermin"]
