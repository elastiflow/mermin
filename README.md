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
kind load docker-image -n atlantis mermin:latest

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

#### 1. Build the `mermin` agent

```shell
cargo build --release
```

The build script automatically compiles the eBPF program and embeds it into the final binary.

#### 2. Configuration Files

Mermin supports configuration in both **YAML** and **HCL** formats. Default configuration files for local development are provided in the project root: `config.yaml` and `config.hcl`.

Both files contain sensible defaults for local development, including:

* **Stdout exporter enabled**: Flow data will be printed to the console for easy debugging.
* **OTLP exporter disabled**: External telemetry endpoints are disabled by default.
* **Default interfaces**: Monitors `eth0` by default.
* **Logging**: Set to `info` level.

You can customize the configuration by editing these files or creating your own.

#### 3. Run the agent

Running the eBPF agent requires elevated privileges. Use the `--config` flag to specify your chosen configuration file. Default configuration files `config.yaml` and `config.hcl` are provided in the project root with the stdout exporter enabled for local development.

**Using YAML:**
```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config config.yaml
```

**Using HCL:**
```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config config.hcl
```

> The `sudo -E` command runs the program as root while preserving the user's environment variables, which is
> necessary for `cargo` to find the correct binary.

#### 4. Generate Traffic

Once the program is running, open a new terminal and generate some network activity to see the logs.

```shell
ping -c 4 localhost
```

> If you experience unexpected results, try to run `cargo clean` before each build to avoid stale artifacts.

### Testing and Linting

#### Run unit tests

Run the following commands to run the unit tests for the main application.

```shell
cargo test
```

Run the following command to run the unit tests for the eBPF program only:

```shell
cargo test -p mermin-ebpf --features test
```

#### Format your code

```shell
cargo fmt
```

#### Run Clippy for lints

```shell
# Lint the eBPF code
cargo clippy -p mermin-ebpf -- -D warnings

# Lint the main application code
cargo clippy --all-features -- -D warnings
```

### Using a Dockerized Build Environment

To ensure a consistent and reproducible build environment that matches the CI/CD pipeline, you can use Docker. This is
especially helpful on platforms like macOS.

#### 1. Build the containerized environment

```shell
docker build -t mermin-builder:latest --target builder .
```

#### 2. Run commands inside the container

This mounts your local repository into the container at `/app`.

```shell
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash
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

* kubectl: The Kubernetes command-line tool, configured to connect to your cluster.
* Wireshark: The network protocol analyzer.
* k9s (Optional): A terminal-based UI to manage Kubernetes clusters, which simplifies getting a shell into pods.

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

* kubectl debug -i -q <pod-name>: Attaches an interactive, ephemeral debug container to the specified pod.
* `--image=nicolaka/netshoot`: Uses the netshoot image, which is packed with useful networking utilities like tcpdump.
* `--target=<container-name>`: Specifies which container in the pod to target for debugging.
* `--profile=sysadmin`: Specifies the security context profile to use for the debug container. This is required to
  run tcpdump.
* `-- tcpdump -i eth0 -w -`: Executes tcpdump inside the debug container.
    * `-i eth0`: Listens on the primary network interface, eth0.
    * `-w -`: Writes the raw packet data to standard output (-) instead of a file.
* `| wireshark -k -i -`: Pipes the standard output from tcpdump into Wireshark.
* `-k`: Starts the capture session immediately.
* `-i -`: Reads packet data from standard input (-).

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

## 🔍 Debugging eBPF Programs with bpftool

This section covers how to use `bpftool` to inspect and debug your eBPF programs running in the cluster. This is essential for understanding program behavior, performance characteristics, and troubleshooting issues.

### Prerequisites

To use bpftool for debugging, you'll need access to a container with bpftool installed. The mermin-builder image includes bpftool, so you can use it directly.

#### 1. Build the containerized environment (if not already built)

```shell
docker build -t mermin-builder:latest --target builder .
```

#### 2. Access the container with bpftool

```shell
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash
```

### Basic eBPF Program Inspection

#### List all loaded eBPF programs

```shell
bpftool prog list
```

This shows all eBPF programs currently loaded in the kernel, including their IDs, types, names, and tags.

#### Find specific programs by name

```shell
bpftool prog list | grep mermin
```

This filters the list to show only programs with "mermin" in the name.

#### Get detailed information about a specific program

```shell
# Replace 167 with the actual program ID from your system
bpftool prog show id 167
```

This provides comprehensive information including:

* Program type and name
* Load time and user ID
* Translated bytecode size (`xlated`)
* JIT-compiled size (`jited`)
* Memory lock size (`memlock`)
* Associated map IDs
* BTF (BPF Type Format) ID

### Analyzing Program Instructions

#### Count the number of instructions in an eBPF program

One of the most useful metrics for eBPF programs is the instruction count, which affects performance and complexity limits.

```shell
# Get the instruction count for a specific program
bpftool prog dump xlated id 167 | grep -E '^[0-9]+:' | wc -l
```

**What this command does:**

* `bpftool prog dump xlated id 167`: Dumps the translated bytecode for program ID 167
* `grep -E '^[0-9]+:'`: Filters to only show lines that start with numbers (the actual instructions)
* `wc -l`: Counts the total number of instruction lines

**Example output:**

```shell
root@container:/app# bpftool prog list | grep mermin
167: sched_cls  name mermin  tag 53ad10d9eaf0e6f8  gpl
168: sched_cls  name mermin  tag 53ad10d9eaf0e6f8  gpl
169: sched_cls  name mermin  tag 53ad10d9eaf0e6f8  gpl

root@container:/app# bpftool prog dump xlated id 169 | grep -E '^[0-9]+:' | wc -l
2584
```

This shows that your mermin eBPF program contains **2,584 instructions**.

#### Alternative methods for instruction counting

**Method 1: Raw line count (includes comments and headers)**

```shell
bpftool prog dump xlated id 167 | wc -l
```

**Method 2: Size-based estimation**

```shell
bpftool prog show id 167 | grep xlated | awk '{print "Estimated instructions: " $2/8}'
```

**Method 3: View actual instructions (first 20 lines)**

```shell
bpftool prog dump xlated id 167 | head -20
```

### Advanced eBPF Analysis

#### Inspect eBPF maps

```shell
# List all maps
bpftool map list

# Show details of a specific map
bpftool map show id 162

# Dump map contents (if readable)
bpftool map dump id 162
```

#### Check program verification details

```shell
# Get verification log if available
bpftool prog show id 167 | grep -A 10 "verification_log"
```

#### Monitor program performance

```shell
# Show program statistics
bpftool prog show id 167 | grep -A 5 "run_time"
```

### Troubleshooting Common Issues

#### Program loading failures

If your eBPF program fails to load, check the verification log:

```shell
# Look for verification errors in dmesg
dmesg | grep -i "bpf\|ebpf" | tail -20
```

#### Instruction limit exceeded

eBPF programs have instruction limits (typically 1 million for complex programs). If you hit this limit:

```shell
# Check current instruction count
bpftool prog dump xlated id 167 | grep -E '^[0-9]+:' | wc -l

# Look for optimization opportunities in the disassembly
bpftool prog dump xlated id 167 | grep -E '^[0-9]+:' | head -50
```

#### Memory issues

Check memory usage and limits:

```shell
# View memory lock size
bpftool prog show id 167 | grep memlock

# Check system limits
cat /proc/sys/kernel/bpf_jit_harden
```

### Integration with Development Workflow

You can integrate bpftool analysis into your development process:

```shell
# Quick instruction count check during development
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "bpftool prog list | grep mermin && echo 'Instruction counts:' && for id in \$(bpftool prog list | grep mermin | awk '{print \$1}' | tr -d ':'); do echo -n \"Program \$id: \"; bpftool prog dump xlated id \$id | grep -E '^[0-9]+:' | wc -l; done"
```

This command provides a comprehensive overview of all mermin programs and their instruction counts in a single execution.

-----

## 🔍 Inspecting eBPF Programs for Network-Types Integration Tests

This section covers how to inspect and analyze the eBPF programs used in the network-types integration test suite. These programs are TC classifiers that parse various network protocol headers and are essential for testing network packet parsing functionality.

### Prerequisites

The network-types integration tests require the mermin-builder container environment due to eBPF compilation requirements:

```shell
# Build the containerized environment
docker build -t mermin-builder:latest --target builder .
```

### Building the Integration Test eBPF Programs

First, build the eBPF programs for the integration tests:

```shell
cd network-types/tests
make build
```

This compiles the eBPF programs targeting the `bpfel-unknown-none` architecture.

### Inspecting eBPF Programs Using bpftool

#### Method 1: Direct Binary Analysis (Recommended)

Since the integration test eBPF programs may not load directly due to libbpf version compatibility, you can analyze the compiled binary directly:

```shell
# Get the total instruction count
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | grep -E '^[[:space:]]*[0-9a-f]+:' | wc -l"

# Get the last instruction to confirm the range
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | grep -E '^[[:space:]]*[0-9a-f]+:' | tail -1"
```

#### Method 2: Runtime Inspection (If Programs Load)

If the eBPF programs get loaded during test execution, you can inspect them with bpftool:

```shell
# Run the test and capture the eBPF program
cd network-types/tests
timeout 20s cargo test -p integration -- --test-threads=1 --nocapture & sleep 8

# List eBPF programs (excluding main mermin programs)
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "bpftool prog list | grep -v mermin | grep -E '(sched_cls|tc|integration|test)'"

# Get detailed information about a specific program
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "bpftool prog show id <PROGRAM_ID>"
```

### Understanding the Integration Test eBPF Programs

#### Program Structure

The integration test eBPF programs are TC classifiers that:

* **Function**: `integration_test` - Main entry point
* **Type**: `sched_cls` (TC classifier)
* **Purpose**: Parse network packet headers for various protocols
* **Protocols Supported**: Ethernet, IPv4/IPv6, TCP/UDP, AH, ESP, Hop-by-Hop options, Geneve

#### Key Components

1. **Main Function**: Starts at instruction 0, handles packet type detection
2. **Protocol Parsers**: Individual parsing logic for each supported protocol
3. **PerfEventArray Map**: `OUT_DATA` map for outputting parsed headers
4. **Error Handling**: Graceful fallbacks for unsupported packet types

#### Instruction Count Analysis

Based on the current implementation, the integration test eBPF program contains:

* **Total Instructions**: 1,367 (0-1366)
* **Main Function Range**: 0-1366
* **Architecture**: eBPF (bpfel-unknown-none)
* **Build Profile**: Release

### Advanced Analysis Techniques

#### Disassembly Analysis

```shell
# View the main function start
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | grep -A 10 -B 5 'integration_test'"

# View the end of the function
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | tail -20"
```

#### Protocol-Specific Analysis

```shell
# Find protocol parsing sections
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | grep -A 5 -B 5 'PacketType'"
```

### Performance and Optimization

#### Instruction Count Monitoring

Track instruction count changes during development:

```shell
# Before optimization
make build
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | grep -E '^[[:space:]]*[0-9a-f]+:' | wc -l"

# After optimization - compare the counts
```

#### Memory Usage Analysis

```shell
# Check binary size
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "ls -lh /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test"

# Analyze section sizes
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -h /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test"
```

### Troubleshooting Integration Test eBPF Programs

#### Common Issues

1. **libbpf Compatibility**: Modern libbpf versions may not support legacy map definitions
2. **Instruction Limits**: Ensure programs stay within eBPF instruction limits
3. **Map Access**: Verify PerfEventArray map configuration

#### Debugging Commands

```shell
# Check for compilation errors
make build 2>&1 | grep -i error

# Verify binary format
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "file /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test"

# Analyze program structure
docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | head -50"
```

### Integration with CI/CD

You can integrate eBPF program analysis into your CI/CD pipeline:

```yaml
# Example GitHub Actions step
- name: Analyze eBPF Programs
  run: |
    docker run -it --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "
      cd /app/network-types/tests
      make build
      echo '=== eBPF Program Analysis ==='
      llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | grep -E '^[[:space:]]*[0-9a-f]+:' | wc -l
      echo 'Instructions: $(llvm-objdump -d /app/target/debug/build/integration-*/out/integration-ebpf/bpfel-unknown-none/release/integration-ebpf-test | grep -E "^[[:space:]]*[0-9a-f]+:" | wc -l)'
    "
```

This comprehensive approach ensures you can monitor and optimize your integration test eBPF programs throughout the development lifecycle.

-----

## Artifacts

The image with the `-debug` prefix is built using the `gcr.io/distroless/cc-debian12:debug` base image and provides additional debugging tools compared to the standard image.

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
