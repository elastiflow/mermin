# Contributor Guide

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

1. **Bare Metal (Native)**: Requires Linux, but provides instant feedback. Run `cargo build` and execute the binary directly with `sudo`. Ideal for iterating on eBPF programs, packet parsing, and core flow logic.
   Cannot test Kubernetes metadata enrichment without a cluster.
2. **Dockerized Build**: Use a Docker container for building to match the CI/CD environment. Useful on macOS or when you need a consistent, reproducible build environment. Slightly slower than native builds but works anywhere Docker runs.
3. **Kubernetes (kind)**: Full integration testing environment. Deploy to a local Kubernetes cluster for testing Kubernetes metadata enrichment, Helm chart configurations, and complete deployment scenarios.
   Highest setup complexity and slowest iteration cycle, but essential for validating end-to-end functionality.

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

> **Note**: You can run without a configuration file, but the default settings disable stdout and OTLP exporting, so you won't see any flow trace output.
> For local development, it's recommended to use at least a configuration file with stdout exporting enabled (see the minimal config example above).

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

- Generate metrics description for the [internal metrics docs](../internal-monitoring/internal-metrics.md) with `jq`

  ```bash
  curl -s ${POD_IP}:10250/metrics:summary | jq --arg metric_prefix ${METRIC_PREFIX} -r -f hack/gen_metrics_doc.jq
  # Example
  curl -s localhost:10250/metrics:summary | jq --arg metric_prefix mermin_ebpf -r -f hack/gen_metrics_doc.jq
  ```

- Download Grafana dashboard JSON from a local Grafana instance

  ```bash
  # From a local Grafana
  curl -s "localhost:3000/api/dashboards/uid/mermin_app" | jq '.dashboard' | jq -f hack/sanitize_grafana_dashboard.jq > docs/internal-monitoring/grafana-mermin-app.json
  # Or from a copy/pasted file
  jq -f hack/sanitize_grafana_dashboard.jq docs/internal-monitoring/grafana-mermin-app.json > docs/internal-monitoring/grafana-mermin-app.json.tmp \
    && mv docs/internal-monitoring/grafana-mermin-app.json.tmp docs/internal-monitoring/grafana-mermin-app.json
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

> **Note**: Docker Desktop for Mac does not support BPF LSM (Linux Security Modules). If you need to develop or test
> LSM-based features (like process tracking via `lsm` hooks), use [Colima with QEMU](#using-colima-for-lsm-development) instead.

## Using Colima for LSM Development

[Colima](https://colima.run/) provides a Docker-compatible runtime on macOS with better kernel support than Docker Desktop.
This is **required** for developing BPF LSM features (e.g., `socket_post_create`, `tcp_v4_connect` hooks for process tracking).

### Why Colima with QEMU?

Docker Desktop for Mac uses a LinuxKit VM that lacks `CONFIG_SECURITY=y` and `CONFIG_BPF_LSM=y`. Colima with an Ubuntu
VM has these compiled in, but **BPF LSM must be enabled via kernel boot parameters**.

**Critical**: You must use `--vm-type=qemu`, not VZ. The VZ framework (Virtualization.Framework) loads the kernel directly
via the hypervisor and **bypasses GRUB entirely**, making kernel boot parameter changes impossible. QEMU boots through
GRUB, allowing BPF LSM to be enabled persistently.

### 1. Install Colima

```shell
brew install colima docker
```

### 2. Start Colima

{% hint style="warning" %}
Stop Docker Desktop if running, conflict with Colima
{% endhint %}

#### Configure Colima profile

One-time task (if you don't delete profile via `colima --profile atlantis delete`). Needed to configure LSM

```shell
# Delete any existing Colima instance to start fresh
colima --profile atlantis stop 2>/dev/null || true
colima --profile atlantis delete 2>/dev/null || true

# Enable BPF LSM in GRUB (you may lower the CPU/Mem if don't plan to run heavy services in Colima)
colima --profile atlantis start --vm-type=vz --cpu 8 --memory 16 --disk 60 --edit
```

Add GRUB overrides to enable BPF LSM, simply replace/add following to the `provision` block in the config.

```yaml
  - mode: system
    script: |
      echo "GRUB_CMDLINE_LINUX_DEFAULT=\"console=tty1 console=ttyAMA0 lsm=lockdown,capability,landlock,yama,apparmor,bpf\"" | tee /etc/default/grub.d/99-bpf-lsm.cfg && update-grub
```

Restart Colima VM for GRUB settings to take an effect

```shell
colima --profile atlantis restart

# Check if BPF LSM module is loaded
colima --profile atlantis ssh -- cat /sys/kernel/security/lsm; echo
# Expected output
# lockdown,capability,landlock,yama,apparmor,bpf
```

#### Start Colima

If you already have your [Colima profile configured](#configure-colima-profile), you may simply start/stop Colima VM when needed

```shell
colima --profile atlantis start
colima --profile atlantis stop
```

### 3. Build and Run Mermin

```shell
# Build Mermin using the Docker container
docker build -t mermin-builder:latest --target builder .
docker run --rm --privileged --mount type=bind,source=$(pwd),target=/app mermin-builder:latest \
  /bin/bash -c "cargo build --release"

# SSH into Colima and run Mermin
colima --profile atlantis ssh
cd /Users/$(whoami)/Documents/Code/mermin  # Adjust path as needed
sudo ./target/release/mermin --config local/config.hcl
```

### Troubleshooting Colima

**BPF LSM still not enabled after restart:**

This usually means you're using VZ instead of QEMU. Check with:

```shell
colima list
# Look for "VMTYPE" column - should show "qemu", not "vz"
```

If it shows "vz", delete and recreate with QEMU:

```shell
colima delete
colima start --vm-type=qemu --cpu 4 --memory 8 --disk 60
```

**Docker commands not working:**

```shell
# Ensure Colima is running
colima --profile atlantis status

# If Docker context isn't set
docker context use colima
```

## Testing on local Kind K8s cluster

You can create a local cluster, build the Mermin image, and deploy it with a single command sequence:

{% hint style="info" %}
It is recommended to use [colima](#why-colima-with-qemu) as a VM for docker on MacOS
{% endhint %}

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
  mermin charts/mermin
```

**Alternative deployment options:**

```shell
# Using make targets
make helm-upgrade

# With custom local config
make helm-upgrade HELM_EXTRA_ARGS='--set-file config.content=docs/deployment/examples/local/config.example.hcl'
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

{% tabs %}
{% tab title="Debug & Develop" %}
1. [**Capture Packets with Wireshark**](debugging-network.md): Live network traffic debugging
2. [**Inspect eBPF Programs with bpftool**](debugging-ebpf.md): Program inspection and optimization
{% endtab %}

{% tab title="Understand Production" %}
1. [**Review Deployment Options**](../deployment/overview.md): Production deployment scenarios
2. [**Explore the Architecture**](../concepts/agent-architecture.md): How Mermin processes flows
{% endtab %}

{% tab title="Contribute" %}
1. [**Read the Contribution Guidelines**](../CONTRIBUTING.md): PR process and commit conventions
2. [**Find an Issue to Work On**](https://github.com/elastiflow/mermin/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22): Good first issues for new contributors
{% endtab %}
{% endtabs %}

## Getting Help

If you encounter issues during development:

- Check the [Troubleshooting Guide](../troubleshooting/troubleshooting.md)
- Ask questions in [GitHub Discussions](https://github.com/elastiflow/mermin/discussions)
- Report bugs via [GitHub Issues](https://github.com/elastiflow/mermin/issues)
