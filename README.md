<h1 align="center"><a href="https://www.elastiflow.com" target="_blank"><img src="https://res.cloudinary.com/elastiflow-cloudinary/image/upload/v1746227898/mermin-horizontal_kxhvzo.png" width="400" alt="Mermin Logo"></a></p>

## About Mermin

Mermin is a suite of Kubernetes native network traffic observability tools. It includes mermin, an eBPF agent for generating flows, and mercoll, an Open Telemetry collector.

## mermin

### Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

### Build & Run

It is recommended to run `cargo clean` previous to any build.

Use `cargo build` from the root of the project to build mermin. Then run:

```shell
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Once the program is running, open a secondary terminal to run a ping command such as `ping -c 5 localhost` to start seeing logs.

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

### Test & Format

Unit tests in the repo can be run with `cargo test`.

For formatting ensure you have run `cargo fmt`. You can also run `cargo clippy --package mermin-ebpf -- -D warnings` for linting the mermin-ebpf folder and `cargo clippy --all-features -- -D warnings` for all other features.

### Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package mermin --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/mermin` can be
copied to a Linux server or VM and run there.

### License

With the exception of eBPF code, mermin is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

#### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

## mercoll

Placeholder
