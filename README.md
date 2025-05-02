<h1 align="center"><a href="https://www.elastiflow.com" target="_blank"><img src="https://private-user-images.githubusercontent.com/8366524/440065134-13ba8509-8fc5-42ca-84c1-5ecc73b0b8be.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NDYyMjMxMjksIm5iZiI6MTc0NjIyMjgyOSwicGF0aCI6Ii84MzY2NTI0LzQ0MDA2NTEzNC0xM2JhODUwOS04ZmM1LTQyY2EtODRjMS01ZWNjNzNiMGI4YmUucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9QUtJQVZDT0RZTFNBNTNQUUs0WkElMkYyMDI1MDUwMiUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNTA1MDJUMjE1MzQ5WiZYLUFtei1FeHBpcmVzPTMwMCZYLUFtei1TaWduYXR1cmU9OGY1MmM0YjIwMmQ0ZmFmZDYxNjhkOTgxYzJlMzI4YzgwODBkM2ZkMGE2NDBjNDE5ZWYzOTNjODg0Y2QyYTMwMiZYLUFtei1TaWduZWRIZWFkZXJzPWhvc3QifQ.9mm7FFLkGhtajXZa2Bnyip_Qk_NYxbvrHrsyGF_v7JY" width="400" alt="Mermin Logo"></a></p>

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
