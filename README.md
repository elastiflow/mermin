<h1 align="center"><a href="https://www.elastiflow.com" target="_blank"><img src="https://res.cloudinary.com/elastiflow-cloudinary/image/upload/v1746227898/mermin-horizontal_kxhvzo.png" width="400" alt="Mermin Logo"></a></h1>

Mermin is a powerful, Kubernetes-native network traffic observability tool. 🔭 It uses an **eBPF** agent to efficiently
capture network flow data and sends it via the **OpenTelemetry** Collector protocol for easy integration with modern
observability platforms.

-----

## 🚀 Quick Start: Deploying to Kubernetes with `kind`

This guide will get you running Mermin on a local **Kubernetes** cluster using [kind](https://kind.sigs.k8s.io/).

### Prerequisites

You'll need the following tools installed on your machine:

* [Docker](https://docs.docker.com/get-docker/)
* [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
* [Helm](https://helm.sh/docs/intro/install/)

### Installation

Once the prerequisites are met, you can create a local cluster, build the Mermin image, and deploy it with a single
command sequence:

```shell
# 1. Create the kind cluster
kind create cluster --config local/kind-config.yaml

# 2. Build the mermin image and load it into the cluster
docker build -t mermin:latest --target runner-slim .
kind load docker-image mermin:latest

# 3. Deploy mermin using Helm
helm upgrade -i mermin charts/mermin --values local/values.yaml
```

> **Note**: The repository includes a `Makefile` with convenience targets (`make k8s-get`, `make k8s-diff`) for some of
> these commands.

### Verifying the Deployment

1. **Check that the `mermin` pods are running** on each node. You should see one pod per worker node.

   ```shell
   kubectl get pods -l app.kubernetes.io/name=mermin
   ```

2. **View the logs** from any of the Mermin pods to see network flow data.

   ```shell
   kubectl logs -l app.kubernetes.io/name=mermin -f
   ```

   To generate some network traffic, try pinging between pods in your cluster.

### Cleanup

To remove Mermin from your cluster, uninstall the Helm chart. To tear down the entire cluster, use `kind delete`.

```shell
# Uninstall the mermin Helm release
helm uninstall mermin

# Delete the kind cluster
kind delete cluster
```

-----

## 🧑‍💻 Local Development and Contribution

This section is for developers who want to contribute to Mermin or run the agent locally for testing.

### Prerequisites

Ensure you have the following installed:

1. **Stable Rust Toolchain**: `rustup toolchain install stable`
2. **Nightly Rust Toolchain**: `rustup toolchain install nightly --component rust-src`
3. **bpf-linker**: `cargo install bpf-linker` (use `--no-default-features` on macOS)
4. (if cross-compiling) **rustup target**: `rustup target add ${ARCH}-unknown-linux-musl`
5. (if cross-compiling) **LLVM**: (e.g.) `brew install llvm` (on macOS)
6. (if cross-compiling) **C toolchain**: (e.g.) [
   `brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)

### Build and Run Locally

#### 1. Build the `mermin` agent:

```shell
cargo build --release
```

The build script automatically compiles the eBPF program and embeds it into the final binary.

#### 2. Run the agent:

Running the eBPF agent requires elevated privileges.

```shell
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

> The `sudo -E` command runs the program as root while preserving the user's environment variables, which is
> necessary for `cargo` to find the correct binary.

#### 3. Generate Traffic:

Once the program is running, open a new terminal and generate some network activity to see the logs.

```shell
ping -c 5 localhost
```

> If you experience unexpected results, try to run `cargo clean` before each build to avoid stale artifacts.

### Testing and Linting

#### Run unit tests:

Run the following commands to run the unit tests for the main application.

```shell
cargo test
```

Run the following command to run the unit tests for the eBPF program only:

```shell
cargo test -p mermin-ebpf
```

#### Format your code:

```shell
cargo fmt
```

#### Run Clippy for lints:

```shell
# Lint the eBPF code
cargo clippy -p mermin-ebpf -- -D warnings

# Lint the main application code
cargo clippy --all-features -- -D warnings
```

### Using a Dockerized Build Environment

To ensure a consistent and reproducible build environment that matches the CI/CD pipeline, you can use Docker. This is
especially helpful on platforms like macOS.

#### 1. Build the containerized environment:

```shell
docker build -t mermin-builder:latest --target builder .
```

#### 2. Run commands inside the container:

This mounts your local repository into the container at `/app`.

```shell
docker run -it --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash
```

Inside the container's shell, you can now run any of the `cargo` build or test commands mentioned above.

### Cross-Compiling

To build a Linux binary from a different OS (like macOS), you can cross-compile. The following command builds for a
specified architecture (e.g., `aarch64` or `x86_64`).

```shell
# Replace ${ARCH} with your target architecture, e.g., aarch64
ARCH=aarch64
CC=${ARCH}-linux-musl-gcc cargo build -p mermin --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The final binary will be located at `target/${ARCH}-unknown-linux-musl/release/mermin` and can be copied to a Linux
server to be executed.

-----

## 📜 License

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