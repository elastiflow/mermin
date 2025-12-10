# Debugging eBPF Programs

This guide covers how to inspect, debug, and optimize eBPF programs in Mermin. It includes tools and techniques for understanding program behavior, performance characteristics, and troubleshooting issues.

## Table of Contents

- [Debugging eBPF Programs with bpftool](#debugging-ebpf-programs-with-bpftool)
- [Measuring eBPF Stack Usage](#measuring-ebpf-stack-usage)

---

## Debugging eBPF Programs with bpftool

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

---

## Measuring eBPF Stack Usage

eBPF programs have a strict **512-byte stack limit**. When exceeded, you'll see errors like:

```shell
Error: the BPF_PROG_LOAD syscall failed. Verifier output: combined stack size of 3 calls is 544. Too large
```

### Critical Concept: Individual vs. Cumulative Stack Usage

**Individual Function Stack**: Maximum stack used by any single function
**Cumulative Call Chain Stack**: Total stack across all functions in a call chain

**The verifier failure above shows CUMULATIVE usage**: `144 + 328 + 0 = 544 bytes`

### Quick Analysis

#### 1. Prerequisites

```shell
docker build -t mermin-builder:latest --target builder .
```

#### 2. Stack Analysis Scripts

The project includes three analysis scripts in the `scripts/` directory:

**`scripts/check_stack_usage.sh`** - Quick health check (30 seconds)

- **Purpose**: Fast individual function stack analysis for daily development and CI/CD
- **Thresholds**: Critical >320 bytes, Warning >192 bytes (64-byte aligned)
- **Output**: Simple pass/fail with color-coded status
- **Features**: Forces fresh builds, detects build failures, prevents stale results

**`scripts/analyze_call_chain.sh`** - Call chain overview (45 seconds)

- **Purpose**: Shows function calls and stack usage levels for initial investigation
- **Output**: Function call instructions and sorted stack usage levels
- **Use When**: Investigating verifier failures or understanding call patterns
- **Features**: Forces fresh builds, shows binary timestamps, handles no-call scenarios

**`scripts/cumulative_stack_calculator.sh`** - Educational deep dive (2 minutes)

- **Purpose**: Step-by-step educational breakdown of cumulative stack calculation
- **Output**: Detailed hex-to-decimal conversions, scenarios, and insights
- **Use When**: Learning how verifier calculates stack, training new developers
- **Features**: Forces fresh builds, comprehensive error handling

#### 3. Running the Analysis

```shell
# Quick health check (30 seconds)
./mermin/tests/e2e/common/check_stack_usage.sh

# Call chain overview (45 seconds)
./scripts/analyze_call_chain.sh

# Detailed educational analysis (2 minutes)
./scripts/cumulative_stack_calculator.sh
```

### Interpreting Results

#### Understanding `check_stack_usage.sh` Output

```bash
📊 Individual function max stack: 136 bytes (0x88)
✅ GOOD: Individual stack usage within safe limits
```

- **Below 192 bytes**: Safe for most call chains
- **192-320 bytes**: Monitor call depth - might exceed 512 in deep chains
- **Above 320 bytes**: High risk - will likely cause verifier failures

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

### Quick Fixes

When you see high stack usage:

1. **Split Large Functions**: Break functions >192 bytes into smaller ones
2. **Eliminate Large Variables**: Avoid big structs on the stack
3. **Use `#[inline(always)]`**: For small helper functions
4. **Check Call Depth**: Minimize function call chains

### Advanced Analysis Commands

For deeper investigation:

```shell
# Find specific stack offset (e.g., 328 bytes = 0x148)
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep 'r10.*-.*0x148'"

# Show function calls with context
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -A 3 -B 3 'call.*0x'"

# Count total function calls
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -c 'call.*0x'"
```

### CI/CD Integration

**For CI/CD pipelines, use the quick health check:**

```yaml
- name: Check eBPF Stack Usage
  run: |
    docker build -t mermin-builder:latest --target builder .
    ./mermin/tests/e2e/common/check_stack_usage.sh
    # Exit with error if stack usage is too high
    MAX_STACK=$(./mermin/tests/e2e/common/check_stack_usage.sh | grep -oE '[0-9]+ bytes' | grep -oE '[0-9]+' | head -1)
    if [ "$MAX_STACK" -gt 320 ]; then exit 1; fi
```

**For debugging failed CI builds, run locally:**

```bash
# Get detailed analysis when CI fails
./scripts/analyze_call_chain.sh
./scripts/cumulative_stack_calculator.sh
```

This approach gives you both quick diagnostics and deep analysis capabilities for eBPF stack issues.

---

## Next Steps

- [Contributor Guide](contributor-guide.md) - Return to the main contributor guide
- [Debugging Network Traffic](debugging-network.md) - Learn about Wireshark packet capture
- [Troubleshooting Guide](../troubleshooting/troubleshooting.md) - Common issues and solutions
