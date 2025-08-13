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
docker build -t mermin:latest --target runner-debug .
kind load docker-image mermin:latest

# 3a. (optional) if you already have a Helm release, uninstall it first
helm uninstall mermin

# 3b. Deploy mermin using Helm
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
ping -c 4 localhost
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

### Debugging with Wireshark

This section outlines how to perform live network packet captures from a running pod in your Kubernetes cluster and
inspect the traffic using Wireshark. This is incredibly useful for debugging network policies, service connectivity, and
analyzing the behavior of your eBPF programs.

#### Prerequisites

Before you begin, ensure you have the following tools installed and configured on your local machine:

- kubectl: The Kubernetes command-line tool, configured to connect to your cluster.
- Wireshark: The network protocol analyzer.
- k9s (Optional): A terminal-based UI to manage Kubernetes clusters, which simplifies getting a shell into pods.

#### 1. Identify Your Target Pod

First, list the running pods to identify the one you want to inspect. Pay attention to the pod's name, its IP address,
and the node it's running on.

```shell
kubectl get pods -o wide
```

You'll see output similar to this:

| NAME         | READY | STATUS  | RESTARTS | AGE | IP          | NODE               | NOMINATED NODE | READINESS GATES |
|--------------|-------|---------|----------|-----|-------------|--------------------|----------------|-----------------| 
| mermin-vrxd2 | 1/1   | Running | 0        | 42s | 10.244.0.11 | kind-control-plane | <none>         | <none>          |
| mermin-8k9x7 | 1/1   | Running | 0        | 42s | 10.244.3.21 | kind-worker        | <none>         | <none>          |
| mermin-pdsn7 | 1/1   | Running | 0        | 42s | 10.244.1.7  | kind-worker2       | <none>         | <none>          |

For this example, we will capture traffic from mermin-vrxd2.

#### 2. Start the Live Capture

To start the capture, we will use kubectl debug to attach a temporary container with networking tools (netshoot) to
our target pod. We'll then pipe the output of tcpdump from that container directly into Wireshark on your local
machine.

Run the following command in your terminal. Replace <pod-name> with your target pod's name (e.g., mermin-vrxd2)
and <container-name> with the name of the container (e.g., mermin) inside the pod (if it's not the default one).

```shell
kubectl debug -i -q <pod-name> --image=nicolaka/netshoot --target=<container-name> --profile=sysadmin -- tcpdump -i eth0 -w - | wireshark -k -i -
```

Command Breakdown:

- kubectl debug -i -q <pod-name>: Attaches an interactive, ephemeral debug container to the specified pod.
- `--image=nicolaka/netshoot`: Uses the netshoot image, which is packed with useful networking utilities like tcpdump.
- `--target=<container-name>`: Specifies which container in the pod to target for debugging.
- `--profile=sysadmin`: Specifies the security context profile to use for the debug container. This is required to
  run tcpdump.
- `-- tcpdump -i eth0 -w -`: Executes tcpdump inside the debug container.
    - `-i eth0`: Listens on the primary network interface, eth0.
    - `-w -`: Writes the raw packet data to standard output (-) instead of a file.
- `| wireshark -k -i -`: Pipes the standard output from tcpdump into Wireshark.
- `-k`: Starts the capture session immediately.
- `-i -`: Reads packet data from standard input (-).

Example command:

```shell
kubectl debug -i -q mermin-vrxd2 --image=nicolaka/netshoot --target=mermin --profile=sysadmin -- tcpdump -i eth0 -w - | wireshark -k -i -
```

Wireshark will launch automatically and begin capturing packets from the pod's network interface.

#### 3. Generate Network Traffic

To see packets in Wireshark, you need to generate some network activity. Open a second terminal window and get a
shell into another pod. You can do this with kubectl exec or more easily with a tool like k9s.

From your pod list, pick a different pod to be the source of the traffic (e.g., mermin-8k9x7).

Get a shell into that pod.

Ping the IP address of your target pod (10.244.0.11 in our example).

Get a shell into the source pod

```shell
kubectl exec -it mermin-8k9x7 -- sh
```

From inside the pod's shell, ping the target pod

```shell
ping -c 4 10.244.0.11
```

#### 4. Inspect the Packets

Switch back to Wireshark. You will see the ICMP (ping) request and reply packets appearing in real-time. You can now
use Wireshark's powerful filtering and inspection tools to analyze the traffic in detail, verifying that your eBPF
programs are functioning as expected.

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