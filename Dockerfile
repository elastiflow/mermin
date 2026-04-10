# syntax=docker/dockerfile:1.23-labs@sha256:7eca9451d94f9b8ad22e44988b92d595d3e4d65163794237949a8c3413fbed5d
# nosemgrep: dockerfile.security.last-user-is-root.last-user-is-root
# Using "labs" due to "COPY --parents", https://docs.docker.com/reference/dockerfile/#copy---parents
ARG APP_ROOT=/app
ARG APP=mermin


# ---- Build Stage ----
FROM debian:13.4-slim@sha256:4ffb3a1511099754cddc70eb1b12e50ffdb67619aa0ab6c13fcd800a78ef7c7a AS dependency-hack
ARG APP_ROOT

WORKDIR ${APP_ROOT}
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY --parents **/Cargo.lock **/Cargo.toml ./

# Changes mermin version in both mermin/Cargo.toml and Cargo.lock to 0.0.1 to prevent dependency cache invalidation
RUN cp mermin/Cargo.toml mermin/Cargo.toml.orig \
  && cp Cargo.lock Cargo.lock.orig \
  && sed -i 's/^version = ".*"/version = "0.0.1"/' mermin/Cargo.toml \
  && cat Cargo.lock.orig | tr '\n' '\r' \
    | sed 's/name = "mermin"\rversion = "[0-9]\{,999\}\.[0-9]\{,999\}\.[0-9]\{,999\}"\r/name = "mermin"\rversion = "0.0.1"\r/' \
    | tr '\r' '\n' > Cargo.lock

# ---- Build Stage ----
FROM rust:1.88.0-trixie@sha256:9a7159329166b45f453351a077367f501aa3e98378f7e327530e7966a139d05f AS base

# Since Mermin needs root to be ran, switching to non-root in in the base/builder stages does not improve the security.
# nosemgrep: dockerfile.security.last-user-is-root.last-user-is-root # root is needed due to eBPF
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
    pkg-config \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure passwordless sudo for the poseidon user
# Create a non-root user 'poseidon' and grant sudo privileges
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN useradd --create-home --shell /bin/bash poseidon \
    && echo "poseidon ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/poseidon

# Install LLVM
# Workaround for LLVM signing issue, https://github.com/llvm/llvm-project/issues/153385#issuecomment-3239875987
# hadolint ignore=DL3059 # multi-stage build, more RUN -> better caching
RUN sed -i 's/sha1.second_preimage_resistance = 2026-02-01/sha1.second_preimage_resistance = 2026-04-01/' /usr/share/apt/default-sequoia.config
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
COPY --parents **/rust-toolchain.toml **/rustfmt.toml ./
## Download cargo components
RUN cargo --version
COPY --from=dependency-hack --parents ${APP_ROOT}/**/Cargo.lock ${APP_ROOT}/**/Cargo.toml ./
# --parents copies everything to the ${APP_ROOT}${APP_ROOT} ("/app/app") subdir
RUN mv ${APP_ROOT}${APP_ROOT}/* ./ && rm -rf ${APP_ROOT}${APP_ROOT}
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
FROM gcr.io/distroless/cc-debian13@sha256:56aaf20ab2523a346a67c8e8f8e8dabe447447d0788b82284d14ad79cd5f93cc AS runner
ARG APP_ROOT APP

COPY --from=builder ${APP_ROOT}/target/release/${APP} /usr/bin/${APP}
ENTRYPOINT ["/usr/bin/mermin"]

# ---- Runtime Stage ----
# Use a distroless base image for the final container with shell support
FROM debian:13.4-slim@sha256:4ffb3a1511099754cddc70eb1b12e50ffdb67619aa0ab6c13fcd800a78ef7c7a AS runner-debug
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
