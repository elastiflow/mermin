<h1 align="center"><a href="https://www.elastiflow.com" target="_blank"><img src="https://res.cloudinary.com/elastiflow-cloudinary/image/upload/v1746227898/mermin-horizontal_kxhvzo.png" width="400" alt="Mermin Logo"></a></h1>

Mermin is a powerful, Kubernetes-native network traffic observability tool. 🔭 It uses an **eBPF*- agent to efficiently
capture network flow data and sends it via the **OpenTelemetry** Collector protocol for easy integration with modern
observability platforms.

-----

- [🚀 Quick Start: Deploying to Kubernetes with `kind`](#-quick-start-deploying-to-kubernetes-with-kind)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Verifying the Deployment](#verifying-the-deployment)
  - [Cleanup](#cleanup)
- [🧑‍💻 Local Development and Contribution](#-local-development-and-contribution)
  - [Prerequisites](#prerequisites-1)
  - [Build and Run Locally](#build-and-run-locally)
    - [1. Build the `mermin` agent](#1-build-the-mermin-agent)
    - [2. Configuration Files](#2-configuration-files)
    - [3. Run the agent](#3-run-the-agent)
    - [4. Generate Traffic](#4-generate-traffic)
  - [Testing and Linting](#testing-and-linting)
    - [Run unit tests](#run-unit-tests)
    - [Format your code](#format-your-code)
    - [Run Clippy for lints](#run-clippy-for-lints)
  - [Using a Dockerized Build Environment](#using-a-dockerized-build-environment)
    - [1. Build the containerized environment](#1-build-the-containerized-environment)
    - [2. Run commands inside the container](#2-run-commands-inside-the-container)
  - [Cross-Compiling](#cross-compiling)
  - [Debugging with Wireshark](#debugging-with-wireshark)
    - [Prerequisites](#prerequisites-2)
    - [1. Identify Your Target Pod](#1-identify-your-target-pod)
    - [2. Start the Live Capture](#2-start-the-live-capture)
    - [3. Generate Network Traffic](#3-generate-network-traffic)
    - [4. Inspect the Packets](#4-inspect-the-packets)
- [🔍 Debugging eBPF Programs with bpftool](#-debugging-ebpf-programs-with-bpftool)
  - [Prerequisites](#prerequisites-3)
    - [1. Build the containerized environment (if not already built)](#1-build-the-containerized-environment-if-not-already-built)
    - [2. Access the container with bpftool](#2-access-the-container-with-bpftool)
  - [Basic eBPF Program Inspection](#basic-ebpf-program-inspection)
    - [List all loaded eBPF programs](#list-all-loaded-ebpf-programs)
    - [Find specific programs by name](#find-specific-programs-by-name)
    - [Get detailed information about a specific program](#get-detailed-information-about-a-specific-program)
  - [Analyzing Program Instructions](#analyzing-program-instructions)
    - [Count the number of instructions in an eBPF program](#count-the-number-of-instructions-in-an-ebpf-program)
    - [Alternative methods for instruction counting](#alternative-methods-for-instruction-counting)
  - [Advanced eBPF Analysis](#advanced-ebpf-analysis)
    - [Inspect eBPF maps](#inspect-ebpf-maps)
    - [Check program verification details](#check-program-verification-details)
    - [Monitor program performance](#monitor-program-performance)
  - [Troubleshooting Common Issues](#troubleshooting-common-issues)
    - [Program loading failures](#program-loading-failures)
    - [Instruction limit exceeded](#instruction-limit-exceeded)
    - [Memory issues](#memory-issues)
  - [Integration with Development Workflow](#integration-with-development-workflow)
- [🔍 Inspecting eBPF Programs for Network-Types Integration Tests](#-inspecting-ebpf-programs-for-network-types-integration-tests)
  - [Prerequisites](#prerequisites-4)
  - [Building the Integration Test eBPF Programs](#building-the-integration-test-ebpf-programs)
  - [Inspecting eBPF Programs Using bpftool](#inspecting-ebpf-programs-using-bpftool)
    - [Method 1: Direct Binary Analysis (Recommended)](#method-1-direct-binary-analysis-recommended)
    - [Method 2: Runtime Inspection (If Programs Load)](#method-2-runtime-inspection-if-programs-load)
  - [Understanding the Integration Test eBPF Programs](#understanding-the-integration-test-ebpf-programs)
    - [Program Structure](#program-structure)
    - [Key Components](#key-components)
    - [Instruction Count Analysis](#instruction-count-analysis)
  - [Advanced Analysis Techniques](#advanced-analysis-techniques)
    - [Disassembly Analysis](#disassembly-analysis)
    - [Protocol-Specific Analysis](#protocol-specific-analysis)
  - [Performance and Optimization](#performance-and-optimization)
    - [Instruction Count Monitoring](#instruction-count-monitoring)
    - [Memory Usage Analysis](#memory-usage-analysis)
  - [Troubleshooting Integration Test eBPF Programs](#troubleshooting-integration-test-ebpf-programs)
    - [Common Issues](#common-issues)
    - [Debugging Commands](#debugging-commands)
  - [Integration with CI/CD](#integration-with-cicd)
- [📊 Measuring eBPF Stack Usage](#-measuring-ebpf-stack-usage)
  - [🚨 Critical Concept: Individual vs. Cumulative Stack Usage](#-critical-concept-individual-vs-cumulative-stack-usage)
  - [📋 Quick Analysis](#-quick-analysis)
    - [1. Prerequisites](#1-prerequisites)
    - [2. Stack Analysis Scripts](#2-stack-analysis-scripts)
    - [3. Running the Analysis](#3-running-the-analysis)
  - [🔧 Interpreting Results](#-interpreting-results)
    - [Understanding `check_stack_usage.sh` Output](#understanding-check_stack_usagesh-output)
    - [Understanding `analyze_call_chain.sh` Output](#understanding-analyze_call_chainsh-output)
    - [Understanding Verifier Error Messages](#understanding-verifier-error-messages)
    - [Critical Thresholds (64-byte aligned)](#critical-thresholds-64-byte-aligned)
  - [🎯 Quick Fixes](#-quick-fixes)
  - [🔍 Advanced Analysis Commands](#-advanced-analysis-commands)
  - [🚀 CI/CD Integration](#-cicd-integration)
- [Artifacts](#artifacts)
- [📜 License](#-license)
  - [eBPF](#ebpf)


## 🚀 Quick Start: Deploying to Kubernetes with `kind`

Mermin is distributed using Helm charts, examples for various deployments may be found in the `examples/` directory.
This guide will get you running Mermin on a local **Kubernetes*- cluster using [kind](https://kind.sigs.k8s.io/).

### Prerequisites

You'll need the following tools installed on your machine:

- [Docker](https://docs.docker.com/get-docker/)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [Helm](https://helm.sh/docs/intro/install/)

### Installation

Once the prerequisites are met, you can create a local cluster, build the Mermin image, and deploy it with a single
command sequence:

```shell
# 1. Create the kind cluster
kind create cluster --config examples/local/kind-config.yaml

# 2. Build the mermin image and load it into the cluster
docker build -t mermin:latest --target runner-debug .
kind load docker-image -n atlantis mermin:latest

# 3. (optional) if you already have a Helm release, uninstall it first
helm uninstall mermin

# 4b. Deploy mermin using Helm
make helm-upgrade
# 4c. Or deploy mermin using Helm with a non-default config (create config first)
make helm-upgrade EXTRA_HELM_ARGS='--set-file config.content=examples/local/config.hcl'
# 4d. Or deploy using raw Helm cli
helm upgrade -i mermin charts/mermin --values examples/local/values.yaml --wait --timeout 10m
```

> **Note**: The repository includes a `Makefile` with convenience targets (`make k8s-get`, `make k8s-diff`) for some of
> these commands.

### Verifying the Deployment

1. **Check that the `mermin` pods are running*- on each node. You should see one pod per worker node.

   ```shell
   kubectl get pods -l app.kubernetes.io/name=mermin
   ```

2. **View the logs*- from any of the Mermin pods to see network flow data.

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
6. (if cross-compiling) **C toolchain**: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)

### Build and Run Locally

#### 1. Build the `mermin` agent

```shell
cargo build --release
```

The build script automatically compiles the eBPF program and embeds it into the final binary.

#### 2. Configuration Files

Mermin supports configuration in both **YAML*- and **HCL*- formats. Default configuration file for local development is provided in the project root: `config.hcl`.

File contain sensible defaults for local development, including:

- **Stdout exporter enabled**: Flow data will be printed to the console for easy debugging.
- **OTLP exporter disabled**: External telemetry endpoints are disabled by default.
- **Default interfaces**: Monitors `eth0` by default.
- **Logging**: Set to `info` level.

You can customize the configuration by editing these files or creating your own.

Mermin also supports YAML configuration which can be generated by using [fmtconvert](https://github.com/genelet/determined/tree/main/cmd/fmtconvert) tool (`go install github.com/genelet/determined/cmd/fmtconvert@latest`)

```sh
fmtconvert -from hcl -to yaml examples/local/config.hcl > examples/local/config.yaml
```

#### 3. Run the agent

Running the eBPF agent requires elevated privileges. Use the `--config` flag to specify your chosen configuration file. Default configuration file `config.hcl` is provided in the project root with the stdout exporter enabled for local development.

**Using HCL:**

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config examples/local/config.hcl
```

**Using YAML:**

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config <(fmtconvert -from hcl -to yaml examples/local/config.hcl)
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

Run the following command in your terminal. Replace `<pod-name>` with your target pod's name (e.g., mermin-vrxd2)
and `<container-name>` with the name of the container (e.g., mermin) inside the pod (if it's not the default one).

```shell
kubectl debug -i -q <pod-name> --image=nicolaka/netshoot --target=<container-name> --profile=sysadmin -- tcpdump -i eth0 -w - | wireshark -k -i -
```

Command Breakdown:

- kubectl debug -i -q `<pod-name>`: Attaches an interactive, ephemeral debug container to the specified pod.
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

- Program type and name
- Load time and user ID
- Translated bytecode size (`xlated`)
- JIT-compiled size (`jited`)
- Memory lock size (`memlock`)
- Associated map IDs
- BTF (BPF Type Format) ID

### Analyzing Program Instructions

#### Count the number of instructions in an eBPF program

One of the most useful metrics for eBPF programs is the instruction count, which affects performance and complexity limits.

```shell
# Get the instruction count for a specific program
bpftool prog dump xlated id 167 | grep -E '^[0-9]+:' | wc -l
```

**What this command does:**

- `bpftool prog dump xlated id 167`: Dumps the translated bytecode for program ID 167
- `grep -E '^[0-9]+:'`: Filters to only show lines that start with numbers (the actual instructions)
- `wc -l`: Counts the total number of instruction lines

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

**Method 1: Raw line count (includes comments and headers):**

```shell
bpftool prog dump xlated id 167 | wc -l
```

**Method 2: Size-based estimation:**

```shell
bpftool prog show id 167 | grep xlated | awk '{print "Estimated instructions: " $2/8}'
```

**Method 3: View actual instructions (first 20 lines):**

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

- **Function**: `integration_test` - Main entry point
- **Type**: `sched_cls` (TC classifier)
- **Purpose**: Parse network packet headers for various protocols
- **Protocols Supported**: Ethernet, IPv4/IPv6, TCP/UDP, AH, ESP, Hop-by-Hop options, Geneve

#### Key Components

1. **Main Function**: Starts at instruction 0, handles packet type detection
2. **Protocol Parsers**: Individual parsing logic for each supported protocol
3. **PerfEventArray Map**: `OUT_DATA` map for outputting parsed headers
4. **Error Handling**: Graceful fallbacks for unsupported packet types

#### Instruction Count Analysis

Based on the current implementation, the integration test eBPF program contains:

- **Total Instructions**: 1,367 (0-1366)
- **Main Function Range**: 0-1366
- **Architecture**: eBPF (bpfel-unknown-none)
- **Build Profile**: Release

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

## 📊 Measuring eBPF Stack Usage

eBPF programs have a strict **512-byte stack limit**. When exceeded, you'll see errors like:

```shell
Error: the BPF_PROG_LOAD syscall failed. Verifier output: combined stack size of 3 calls is 544. Too large
```

### 🚨 Critical Concept: Individual vs. Cumulative Stack Usage

**Individual Function Stack**: Maximum stack used by any single function
**Cumulative Call Chain Stack**: Total stack across all functions in a call chain

**The verifier failure above shows CUMULATIVE usage**: `144 + 328 + 0 = 544 bytes`

### 📋 Quick Analysis

#### 1. Prerequisites

```shell
docker build -t mermin-builder:latest --target builder .
```

#### 2. Stack Analysis Scripts

The project includes three analysis scripts in the `scripts/` directory:

**`scripts/check_stack_usage.sh`*- - Quick health check (30 seconds)

- **Purpose**: Fast individual function stack analysis for daily development and CI/CD
- **Thresholds**: Critical >320 bytes, Warning >192 bytes (64-byte aligned)
- **Output**: Simple pass/fail with color-coded status
- **Features**: ✅ Forces fresh builds, detects build failures, prevents stale results

**`scripts/analyze_call_chain.sh`*- - Call chain overview (45 seconds)

- **Purpose**: Shows function calls and stack usage levels for initial investigation
- **Output**: Function call instructions and sorted stack usage levels
- **Use When**: Investigating verifier failures or understanding call patterns
- **Features**: ✅ Forces fresh builds, shows binary timestamps, handles no-call scenarios

**`scripts/cumulative_stack_calculator.sh`*- - Educational deep dive (2 minutes)

- **Purpose**: Step-by-step educational breakdown of cumulative stack calculation
- **Output**: Detailed hex-to-decimal conversions, scenarios, and insights
- **Use When**: Learning how verifier calculates stack, training new developers
- **Features**: ✅ Forces fresh builds, comprehensive error handling

#### 3. Running the Analysis

```shell
# Quick health check (30 seconds)
./scripts/check_stack_usage.sh

# Call chain overview (45 seconds)
./scripts/analyze_call_chain.sh

# Detailed educational analysis (2 minutes)
./scripts/cumulative_stack_calculator.sh
```

### 🔧 Interpreting Results

#### Understanding `check_stack_usage.sh` Output

```bash
📊 Individual function max stack: 136 bytes (0x88)
✅ GOOD: Individual stack usage within safe limits
```

- **Below 192 bytes**: ✅ Safe for most call chains
- **192-320 bytes**: ⚠️ Monitor call depth - might exceed 512 in deep chains
- **Above 320 bytes**: 🔥 High risk - will likely cause verifier failures

#### Understanding `analyze_call_chain.sh` Output

```bash
📞 Function Calls Found:
call    0x1         # Function call to address 0x1
call    0x1a        # Function call to address 0x1a

📊 Stack Usage Levels:
• 328 bytes (0x148)  # Largest stack usage
• 144 bytes (0x90)   # Second largest
• 136 bytes (0x88)   # Third largest
```

**How to interpret:**

- **Multiple calls**: Shows potential call chain depth
- **High stack values**: Look for values >192 bytes
- **Combined risk**: Add largest values to estimate cumulative usage

#### Understanding Verifier Error Messages

```shell
Error: combined stack size of 3 calls is 544. Too large
stack depth 144+328+0
```

**Translation:**

- **3 calls**: Call chain is Function A → Function B → Function C
- **544 bytes**: Total cumulative stack (144 + 328 + 0 = 472 + ~72 bytes overhead)
- **144, 328, 0**: Individual stack usage per function in the chain

#### Critical Thresholds (64-byte aligned)

- **192 bytes**: Warning threshold - monitor for deep call chains
- **320 bytes**: Critical threshold - high probability of overflow
- **512 bytes**: Hard eBPF limit - verifier will reject

### 🎯 Quick Fixes

When you see high stack usage:

1. **Split Large Functions**: Break functions >192 bytes into smaller ones
2. **Eliminate Large Variables**: Avoid big structs on the stack
3. **Use `#[inline(always)]`**: For small helper functions
4. **Check Call Depth**: Minimize function call chains

### 🔍 Advanced Analysis Commands

For deeper investigation:

```shell
# Find specific stack offset (e.g., 328 bytes = 0x148)
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep 'r10.*-.*0x148'"

# Show function calls with context
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -A 3 -B 3 'call.*0x'"

# Count total function calls
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -c 'call.*0x'"
```

### 🚀 CI/CD Integration

**For CI/CD pipelines, use the quick health check:**

```yaml
- name: Check eBPF Stack Usage
  run: |
    docker build -t mermin-builder:latest --target builder .
    ./scripts/check_stack_usage.sh
    # Exit with error if stack usage is too high
    MAX_STACK=$(./scripts/check_stack_usage.sh | grep -oE '[0-9]+ bytes' | grep -oE '[0-9]+' | head -1)
    if [ "$MAX_STACK" -gt 320 ]; then exit 1; fi
```

**For debugging failed CI builds, run locally:**

```bash
# Get detailed analysis when CI fails
./scripts/analyze_call_chain.sh
./scripts/cumulative_stack_calculator.sh
```

This approach gives you both quick diagnostics and deep analysis capabilities for eBPF stack issues.

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

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE

[MIT license]: LICENSE-MIT

[GNU General Public License, Version 2]: LICENSE-GPL2
