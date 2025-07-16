FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# Install llvm
RUN apt-get update \
  && apt install -y lsb-release wget software-properties-common gnupg \
  && wget https://apt.llvm.org/llvm.sh \
  && chmod a+x llvm.sh \
  && ./llvm.sh 19 all \
  && apt install -y libclang-19-dev libpolly-19-dev libzstd-dev bpftool \
  && apt autoremove -y

# Install Rust with nightly sources
ENV RUST_VERSION=stable
USER vscode
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain=$RUST_VERSION
RUN rustup toolchain install nightly --component rust-src
RUN export LLVM_SYS_191_PREFIX=/usr/include/llvm-19
ENV PATH "$PATH:/usr/local/cargo/bin"

# BPF and aya tools
RUN cargo install --no-default-features bpf-linker
RUN cargo install bindgen-cli cargo-generate
RUN cargo install --git https://github.com/aya-rs/aya -- aya-tool