# eth-ebpf-test

This module is used for testing `network-types` in a live eBPF environment. These tests offer full coverage for Kernel-Space to User-Space 

## Prerequisites (Mac)

1.  Install Lima and setup VM
    ```shell
    brew install lima qemu
    
    limactl create --name aya --arch aarch64 --cpus 4 --memory 6 --disk 60 - <<'EOF'
    images:
      - location: https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img
        arch: aarch64
    mounts:
      - location: "~"
        writable: true
    containerd:
      system: false
      user: false
    provision:
      - mode: system
        script: |
          apt-get update -y
          apt-get upgrade -y
          apt-get install -y \
            build-essential clang llvm lld libelf-dev zlib1g-dev \
            pkg-config git curl ca-certificates
    EOF
    
    # Boot it
    limactl start aya
    
    # Log in
    limactl shell aya
    ```
2.  Configure VM:
    ```shell
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    rustup toolchain install nightly
    rustup +nightly component add rust-src llvm-tools-preview
    # make sure the usual build deps are around
    sudo apt update \
    && sudo apt install -y build-essential clang llvm \
    libelf-dev pkg-config zlib1g-dev
    sudo apt install -y libssl-dev pkg-config
    # optional but nice: speed up git2 / libssh2 builds
    sudo apt install -y libssh2-1-dev libgit2-dev
    # then compile Aya's main branch and install only the binary target
    cargo install --git https://github.com/aya-rs/aya --locked --bins aya-tool
    cargo install bpf-linker
    cargo install cargo-generate
    
    # Mount the debugfs and tracefs filesystems, which are often not mounted
    # by default in cloud/VM images. This is essential for many tracing tools.
    sudo mount -t debugfs debugfs /sys/kernel/debug
    sudo mount -t tracefs tracefs /sys/kernel/tracing
    
    # Set kernel.perf_event_paranoid to -1. This is a critical step that
    # allows processes with sufficient capabilities (like those run with sudo)
    # to use the perf event subsystem for monitoring and logging.
    sudo sysctl -w kernel.perf_event_paranoid=-1
    ```

## Build & Run

```shell
limactl shell aya ./run_tests.sh
```