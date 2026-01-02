# Contributor Guide

- [Contributor Guide](#contributor-guide)
  - [Prerequisites](#prerequisites)
  - [Build and Run Locally](#build-and-run-locally)
    - [1. Build the `mermin` agent](#1-build-the-mermin-agent)
      - [Pull Pre-built Images](#pull-pre-built-images)
    - [2. Configuration Files](#2-configuration-files)
    - [3. Run the agent](#3-run-the-agent)
    - [4. Generate Traffic](#4-generate-traffic)
  - [Testing and Linting](#testing-and-linting)
    - [Run unit tests](#run-unit-tests)
    - [Format your code](#format-your-code)
    - [Run Clippy for lints](#run-clippy-for-lints)
    - ["hack" hints](#hack-hints)
  - [Using a Dockerized Build Environment](#using-a-dockerized-build-environment)
    - [1. Build the containerized environment](#1-build-the-containerized-environment)
    - [2. Run commands inside the container](#2-run-commands-inside-the-container)
  - [Testing on local Kind K8s cluster](#testing-on-local-kind-k8s-cluster)
    - [Iterating on Code Changes](#iterating-on-code-changes)
    - [Verifying the Deployment](#verifying-the-deployment)
    - [Cleanup](#cleanup)
  - [Cross-Compiling](#cross-compiling)
    - [Setting Up rust-analyzer on macOS](#setting-up-rust-analyzer-on-macos)
      - [Configure VS Code/Cursor settings](#configure-vs-codecursor-settings)
  - [Next Steps](#next-steps)
  - [Getting Help](#getting-help)

Welcome to the Mermin contributor guide! This document will help you set up your development environment, build the project, run tests, and contribute effectively to Mermin.

## Prerequisites

Ensure you have the following installed:

1. **Stable Rust Toolchain**: `rustup toolchain install stable`
2. **Nightly Rust Toolchain**: `rustup toolchain install nightly --component rust-src`
3. **bpf-linker**: `cargo install bpf-linker` (use `--no-default-features` on macOS — optionally specify your llvm version with `--features llvm-21`)
4. (if cross-compiling) **rustup target**: `rustup target add ${ARCH}-unknown-linux-musl`
5. (if cross-compiling) **LLVM**: (e.g.) `brew install llvm` (on macOS)
6. (if cross-compiling) **C toolchain**: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
7. Required software to run Mermin locally:
   - [**Docker**](https://docs.docker.com/get-docker/): Container runtime
   - [**kind**](https://kind.sigs.k8s.io/docs/user/quick-start/#installation): Kubernetes in Docker
   - [**kubectl**](https://kubernetes.io/docs/tasks/tools/): Kubernetes command-line tool
   - [**Helm**](https://helm.sh/docs/intro/install/): Kubernetes package manager (version 3.x)

## Build and Run Locally

Mermin supports multiple local development workflows depending on your needs:

| Workflow                | Setup Complexity | Iteration Speed  | Best For                                                                |
|-------------------------|------------------|------------------|-------------------------------------------------------------------------|
| **Bare Metal (Native)** | Low              | Fast (seconds)   | Rapid eBPF/userspace development, packet parsing logic                  |
| **Dockerized Build**    | Medium           | Medium (minutes) | Cross-platform development (macOS), CI/CD environment parity            |
| **Kubernetes (kind)**   | High             | Slow (minutes)   | Testing K8s metadata enrichment, Helm charts, full deployment scenarios |

**Choosing your workflow:**

1. **Bare Metal (Native)**: Requires Linux, but provides instant feedback. Run `cargo build` and execute the binary directly with `sudo`. Ideal for iterating on eBPF programs, packet parsing, and core flow logic. Cannot test Kubernetes metadata enrichment without a cluster.

2. **Dockerized Build**: Use a Docker container for building to match the CI/CD environment. Useful on macOS or when you need a consistent, reproducible build environment. Slightly slower than native builds but works anywhere Docker runs.

3. **Kubernetes (kind)**: Full integration testing environment. Deploy to a local Kubernetes cluster for testing Kubernetes metadata enrichment, Helm chart configurations, and complete deployment scenarios. Highest setup complexity and slowest iteration cycle, but essential for validating end-to-end functionality.

### 1. Build the `mermin` agent

```shell
cargo build --release
```

The build script automatically compiles the eBPF program and embeds it into the final binary.

#### Pull Pre-built Images

You may optionally pull the existing image for testing purposes instead of building locally. Check the [latest releases](https://github.com/elastiflow/mermin/pkgs/container/mermin) to find the most recent version tag.

```sh
# Pull the standard image
docker pull ghcr.io/elastiflow/mermin:v0.1.0-beta.40

# Pull the debug image (includes shell for troubleshooting)
docker pull ghcr.io/elastiflow/mermin:v0.1.0-beta.40-debug
```

### 2. Configuration Files

Mermin supports configuration in both **HCL** and **YAML** formats. A comprehensive example configuration file is provided at `charts/mermin/config/examples/config.hcl`, which includes:

- **Stdout exporter enabled**: Flow data printed to console for easy debugging
- **OTLP exporter configured**: With placeholders for authentication and TLS settings
- **Kubernetes metadata enrichment**: Default Pod, Service, Deployment associations and selectors
- **Interface discovery**: Defaults for automatic detection and attachment to network interfaces
- **Flow filtering**: Configurable filters for source, destination, network, and flow attributes
- **Parser options**: Tunnel protocol detection (VXLAN, Geneve, WireGuard) and protocol parsing flags
- **Logging**: Set to `info` level by default

For local development, create a minimal configuration in the `local/` directory. Here's a simple starter config that enables stdout output:

```hcl
# local/config.hcl - Minimal config for local development
log_level = "info"

export "traces" {
  stdout = {
    format = "text_indent"
  }
}
```

The comprehensive example at `charts/mermin/config/examples/config.hcl` can be used as a reference for more advanced configuration options.

**Converting between HCL and YAML:**

Mermin also supports YAML configuration. You can convert between formats using the [fmtconvert](https://github.com/genelet/determined/tree/main/cmd/fmtconvert) tool:

```sh
# Install fmtconvert
go install github.com/genelet/determined/cmd/fmtconvert@latest

# Convert HCL to YAML
fmtconvert -from hcl -to yaml charts/mermin/config/examples/config.hcl > local/config.yaml
```

### 3. Run the agent

Running the eBPF agent requires elevated privileges. Use the `--config` flag to specify your configuration file.

> **Note**: You can run without a configuration file, but the default settings disable stdout and OTLP exporting, so you won't see any flow trace output. For local development, it's recommended to use atleast a configuration file with stdout exporting enabled (see the minimal config example above).

**Using HCL:**

```shell
# Using your local config (recommended for getting started)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config local/config.hcl
```

**Using YAML:**

If you prefer YAML format, you can convert your HCL config on-the-fly:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config <(fmtconvert -from hcl -to yaml local/config.hcl)
```

> The `sudo -E` command runs the program as root while preserving the user's environment variables, which is
> necessary for `cargo` to find the correct binary.

### 4. Generate Traffic

Once the program is running, open a new terminal and generate some network activity to see the logs.

```shell
ping -c 4 localhost
```

> If you experience unexpected results, try to run `cargo clean` before each build to avoid stale artifacts.

## Testing and Linting

### Run unit tests

Run the following commands to run the unit tests for the main application.

```shell
cargo test
```

Run the following command to run the unit tests for the eBPF program only:

```shell
cargo test -p mermin-ebpf --features test
```

### Format your code

```shell
cargo fmt
```

### Run Clippy for lints

```shell
# Lint the eBPF code
cargo clippy -p mermin-ebpf -- -D warnings

# Lint the main application code
cargo clippy --all-features -- -D warnings
```

### "hack" hints

- Generate metrics description for the [app-metrics docs](../observability/app-metrics.md) with `jq`
  ```bash
  curl -s ${POD_IP}:10250/metrics:summary | jq --arg metric_prefix ${METRIC_PREFIX} -r -f hack/gen_metrics_doc.jq
  # Example
  curl -s localhost:10250/metrics:summary | jq --arg metric_prefix mermin_ebpf -r -f hack/gen_metrics_doc.jq
  ```

## Using a Dockerized Build Environment

To ensure a consistent and reproducible build environment that matches the CI/CD pipeline, you can use Docker. This is
especially helpful on platforms like macOS.

### 1. Build the containerized environment

```shell
docker build -t mermin-builder:latest --target builder .
```

### 2. Run commands inside the container

This mounts your local repository into the container at `/app`.

```shell
docker run -it --privileged -v `pwd`:/app mermin-builder:latest /bin/bash
```

Inside the container's shell, you can now run any of the `cargo` build or test commands mentioned above.

## Testing on local Kind K8s cluster

You can create a local cluster, build the Mermin image, and deploy it with a single command sequence:

```shell
# 1. Create the kind cluster
kind create cluster --config docs/deployment/examples/local/kind-config.yaml

# 2. Build the mermin image and load it into the cluster
docker build -t mermin:latest --target runner-debug .
kind load docker-image -n atlantis mermin:latest

# 3. Deploy mermin using Helm
helm upgrade -i --wait --timeout 15m -n default --create-namespace \
  -f docs/deployment/examples/local/values.yaml \
  --set-file config.content=docs/deployment/examples/local/config.example.hcl \
  --devel \
  mermin charts/mermin
```

**Alternative deployment options:**

```shell
# Using make targets
make helm-upgrade

# With custom local config
make helm-upgrade EXTRA_HELM_ARGS='--set-file config.content=local/config.hcl'
```

**Optionally install `metrics-server` to get metrics if it has not been installed yet**

```sh
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.0/components.yaml
# Patch to use insecure TLS, commonly needed on dev local clusters
kubectl -n kube-system patch deployment metrics-server --type='json' -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
```

**Optionally install [Prometheus/Grafana](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) to get Mermin metrics:**  
Not intended for a production usage, Grafana auth is disabled (insecure).

```sh
helm repo add prometheus https://prometheus-community.github.io/helm-charts
helm upgrade -i --wait --timeout 15m -n prometheus --create-namespace \
  -f docs/deployment/examples/local/values_prom_stack.yaml \
  prometheus prometheus/kube-prometheus-stack
kubectl -n prometheus patch sts prometheus-grafana \
  --type="json" -p='[{"op":"replace","path":"/spec/persistentVolumeClaimRetentionPolicy/whenDeleted", "value": "Delete"}]'

# Port-forward Grafana to open in the browser
kubectl -n prometheus port-forward svc/prometheus-grafana 3000:3000

# Port-forward Prometheus to open in the browser
kubectl -n prometheus port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090
```

### Iterating on Code Changes

When making changes to the Mermin code, you can quickly rebuild and reload the image into kind without redeploying the entire Helm chart:

```shell
# Rebuild the image, load it into kind, and restart the DaemonSet
docker build -t mermin:latest --target runner-debug . && \
kind load docker-image mermin:latest --name atlantis && \
kubectl rollout restart daemonset/mermin -n default && \
kubectl rollout status daemonset/mermin -n default
```

This workflow is much faster than a full `helm upgrade` when you're only changing the application code.

> **Note**: For this workflow to work, your `values.yaml` must configure the image to use the local build. The example at `docs/deployment/examples/local/values.yaml` already includes these settings.

Required image configuration:

```yaml
mermin:
  image:
    repository: mermin
    tag: latest
    pullPolicy: Never
```

> **Note**: The repository includes a `Makefile` with convenience targets (`make k8s-get`, `make k8s-diff`) for some of
> these commands.

### Verifying the Deployment

- Check that the `mermin` pods are running on each node. You should see one pod per worker node.

   ```shell
   kubectl get pods -l app.kubernetes.io/name=mermin
   ```

- View the logs from any of the Mermin pods to see network flow data.

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
kind delete cluster -n atlantis
```

## Cross-Compiling

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

### Setting Up rust-analyzer on macOS

Since Mermin is a Linux eBPF project, rust-analyzer needs to be configured to check code for the Linux target instead of macOS. Without this configuration, you'll encounter proc-macro errors and type mismatches in Cursor/VS Code.

#### Configure VS Code/Cursor settings

Create or update `.vscode/settings.json` in the project root with the following configuration (adjust `ARCH` to match your system):

```json
{
    "rust-analyzer.cargo.target": "aarch64-unknown-linux-musl",
    "rust-analyzer.cargo.extraEnv": {
        "CC": "aarch64-linux-musl-gcc",
        "ARCH": "aarch64"
    },
    "rust-analyzer.cargo.extraArgs": [
        "--config=target.aarch64-unknown-linux-musl.linker=\"aarch64-linux-musl-gcc\""
    ],
    "rust-analyzer.check.command": "check",
    "rust-analyzer.check.extraArgs": [
        "--target=aarch64-unknown-linux-musl",
        "--config=target.aarch64-unknown-linux-musl.linker=\"aarch64-linux-musl-gcc\""
    ],
    "rust-analyzer.check.extraEnv": {
        "CC": "aarch64-linux-musl-gcc",
        "ARCH": "aarch64"
    },
    "rust-analyzer.linkedProjects": [
        "./Cargo.toml"
    ],
    "rust-analyzer.diagnostics.enable": true,
    "rust-analyzer.diagnostics.experimental.enable": false
}
```

> **Note**: Replace `aarch64` with `x86_64` throughout the configuration if you're on an Intel Mac.

## Next Steps

Once you have your development environment set up, you may want to explore:

- [Debugging Network Traffic](debugging-network.md) - Learn how to use Wireshark for live packet capture
- [Debugging eBPF Programs](debugging-ebpf.md) - Deep dive into eBPF program inspection and optimization
- [Deployment Documentation](../deployment/deployment.md) - Understand production deployment scenarios

## Getting Help

If you encounter issues during development:

- Check the [Troubleshooting Guide](../troubleshooting/troubleshooting.md)
- Ask questions in [GitHub Discussions](https://github.com/elastiflow/mermin/discussions)
- Report bugs via [GitHub Issues](https://github.com/elastiflow/mermin/issues)
