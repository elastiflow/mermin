<h1 align="center"><a href="https://www.elastiflow.com" target="_blank"><img src="https://github-production-user-asset-6210df.s3.amazonaws.com/8366524/440061409-ab56b8c6-d92f-47d2-8361-b149dad35330.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20250502%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250502T213450Z&X-Amz-Expires=300&X-Amz-Signature=327615e59b6233132263063689059906822a0a4c284e8194c7be61f1032e1eb5&X-Amz-SignedHeaders=host" width="400" alt="Mermin Logo"></a></p>

## About Mermin

Mermin is a suite of Kubernetes native network traffic observability tools. It includes mergent, an eBPF agent for generating flows, and mercoll, an Open Telemetry collector.

## mergent

### Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

### Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

### Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package mergent --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/mergent` can be
copied to a Linux server or VM and run there.

### License

With the exception of eBPF code, mergent is distributed under the terms
of the [Apache License] (version 2.0).

#### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

[Apache license]: LICENSE-APACHE
[GNU General Public License, Version 2]: LICENSE-GPL2

## mercoll

Placeholder
