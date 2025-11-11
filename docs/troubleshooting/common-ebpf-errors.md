---
description: >-
  This guide helps diagnose and resolve eBPF verifier errors that may occur when
  deploying Mermin on different kernel versions.
---

# Common eBPF Errors

### Overview

The eBPF verifier is a kernel component that validates eBPF programs before loading them. It ensures programs are safe, terminate, and don't access invalid memory. Verifier behavior and strictness varies across kernel versions, which can cause programs that work on newer kernels to fail on older ones.

**Key points:**

* eBPF verifier strictness varies by kernel version
* Older kernels have stricter or less sophisticated verifiers
* Mermin has been optimized for compatibility but some edge cases may still occur
* Most verifier errors are resolved in beta.21 and later

{% hint style="info" %}
If you encounter eBPF verifier issues or program loading failures not covered by the solutions in this guide, please reach out to the Mermin team. We continuously improve kernel compatibility and your feedback helps us identify and resolve edge cases.
{% endhint %}

### Symptoms

Mermin pods fail to start with errors in logs like:

```
ERROR Failed to load eBPF program
verification time XXXXX usec
processed XXXX insns (limit 1000000)
```

The pod may be in `CrashLoopBackOff` or `Error` state.

### Common eBPF Verifier Error Patterns

#### Invalid Zero-Sized Read

**Error Pattern:**

```
R4 invalid zero-sized read: u64=[0,191]
verification time 38379 usec
stack depth 208+56+0+0+16+0+0
processed 8264 insns (limit 1000000)
```

**What it means:**

The verifier detected an attempt to read zero bytes from memory, which it considers invalid. This typically happens when:

* Length calculation results in zero
* Bounds checking doesn't prove non-zero length to the verifier

**Example:**

```
979: (2d) if r1 > r4 goto pc+1 981
981: (07) r9 += 42
982: (bf) r1 = r8
983: (79) r2 = *(u64 *)(r10 -80)
984: (bf) r3 = r9
985: (85) call bpf_skb_load_bytes#26
R4 invalid zero-sized read: u64=[0,191]
```

#### Invalid Map Access / Out of Range

**Error Pattern:**

```
invalid access to map value, value_size=234 off=42 size=0
R3 min value is outside of the allowed memory range
verification time 27928 usec
processed 8264 insns (limit 1000000)
```

**What it means:**

The verifier cannot prove that a map access is within bounds. This occurs when:

* Offset + size exceeds map value size
* The verifier's range tracking shows potential out-of-bounds access
* Zero-size reads/writes to maps

**Example**

```
2484: (bf) r4 = r1
2485: (0f) r4 += r3              ; R3_w=1 R4_w=map_value(off=0,ks=4,vs=234,imm=0)
2486: (bf) r5 = r2
2487: (0f) r5 += r3              ; R3_w=1 R5_w=fp-56
2488: (71) r5 = *(u8 *)(r5 +0)
2489: (73) *(u8 *)(r4 +0) = r5
...
985: (85) call bpf_skb_load_bytes#26
invalid access to map value, value_size=234 off=42 size=0
```

#### Instruction Limit Exceeded

**Error Pattern:**

```
BPF program is too large. processed 1000001 insns
processed 1000001 insns (limit 1000000) max_states_per_insn 10 total_states 25000
```

**What it means:**

The eBPF program contains too many instructions. The kernel enforces a limit (typically 1 million instructions) to ensure programs terminate.

#### Unbounded Loop Detection

**Error Pattern:**

```
back-edge from insn X to Y
infinite loop detected at insn X
processed XXXX insns (limit 1000000)
```

**What it means:**

The verifier detected a loop without a provable upper bound. eBPF requires all loops to have bounded iterations.

#### Stack Size Exceeded

**Error Pattern:**

```
combined stack size of N calls is XXXX. Too large
max stack depth exceeded
```

#### Why Verifier Errors Vary by Kernel

The eBPF verifier has evolved significantly across kernel versions:

* **Kernel 5.4-5.10**: Basic verifier, stricter bounds checking
* **Kernel 5.11-5.15**: Improved range tracking, better loop handling
* **Kernel 5.16+**: Enhanced verifier with better state pruning
* **Kernel 6.0+**: Most sophisticated verifier, relaxed some restrictions

Older kernels may reject programs that newer kernels accept because:

* Less sophisticated range tracking
* Stricter bounds checking requirements
* Different handling of helper function return values
* More conservative loop analysis

