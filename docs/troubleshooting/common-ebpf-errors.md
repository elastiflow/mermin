# Common eBPF Errors

eBPF programs must pass the kernel's verifier before they can run. The verifier is like a strict security guard—it checks that your program is safe, won't crash the kernel, and will eventually terminate. Understanding verifier errors can be tricky, especially since verifier behavior changes significantly between kernel versions.

## What You Need to Know About the Verifier

**Good news**: Verifier errors are rare, especially on modern kernels. Most Mermin deployments work out of the box without any issues.

**When problems do occur**, they're typically on older kernel versions (< 5.16) that can't perform the sophisticated complexity analysis that newer kernels can. Older kernels are more conservative and may reject programs that newer kernels accept without issue.

The eBPF verifier has evolved considerably over time. A program that loads perfectly on a newer kernel might fail on an older one:

- **Kernel 5.4-5.10**: The early days - stricter bounds checking, more conservative validation
- **Kernel 5.11-5.15**: Getting smarter - improved range tracking and better loop handling
- **Kernel 5.16+**: Even better - enhanced state pruning for more complex programs
- **Kernel 6.0+**: Most sophisticated - relaxed restrictions and the most permissive verifier

**Recommended**: Use kernel 5.14+ (preferably 6.6+) for the best experience and fewest compatibility issues.

{% hint style="info" %}
Hit a verifier error we haven't covered? Reach out to the Mermin team! We're constantly improving kernel compatibility based on real-world feedback.
{% endhint %}

## How to Recognize Verifier Errors

When the verifier rejects a program, your pods won't start. You'll see errors like this in the logs:

```shell
ERROR Failed to load eBPF program
verification time XXXXX usec
processed XXXX insns (limit 1000000)
```

Your pods will be stuck in `CrashLoopBackOff` or `Error` state.

## Common Verifier Errors (And What They Mean)

Let's break down the most common verifier errors you might encounter and what's actually going wrong.

### Invalid Zero-Sized Read

This one shows up when the verifier thinks you're trying to read zero bytes of memory.

**What you'll see:**

```shell
R4 invalid zero-sized read: u64=[0,191]
verification time 38379 usec
processed 8264 insns (limit 1000000)
```

**What's happening**: The verifier detected a potential zero-byte memory read. This typically happens when your length calculations might result in zero, or when the verifier can't prove that the length is definitely non-zero.

**Real-world example:**

```shell
979: (2d) if r1 > r4 goto pc+1 981
985: (85) call bpf_skb_load_bytes#26
R4 invalid zero-sized read: u64=[0,191]
```

The verifier sees that R4 (the length parameter) could be anywhere from 0 to 191, including zero. Since reading zero bytes doesn't make sense, it rejects the program.

### Invalid Map Access

This error means you're trying to access a map in a way the verifier can't verify is safe.

**What you'll see:**

```shell
invalid access to map value, value_size=234 off=42 size=0
R3 min value is outside of the allowed memory range
verification time 27928 usec
```

**What's happening**: The verifier can't prove your map access stays within bounds. Maybe your offset + size exceeds the map's value size, or the verifier's range tracking shows you could potentially access memory outside the allowed range.

Think of it like this: if you have a 234-byte map value and try to access byte 235, that's out of bounds. The verifier catches these potential violations before they can crash anything.

**Real-world example:**

```shell
2485: (0f) r4 += r3              ; R3_w=1 R4_w=map_value(off=0,ks=4,vs=234,imm=0)
2489: (73) *(u8 *)(r4 +0) = r5
invalid access to map value, value_size=234 off=42 size=0
```

The verifier is concerned that after adding R3 to R4, the resulting offset (42) might be too close to the end of the 234-byte value.

### Instruction Limit Exceeded

Your program is doing too much! The kernel has a limit on how complex an eBPF program can be.

**What you'll see:**

```shell
BPF program is too large. processed 1000001 insns
processed 1000001 insns (limit 1000000)
```

**What's happening**: Your program exceeds the kernel's instruction limit (typically 1 million instructions). This usually happens when parsing deeply nested network headers or processing complex protocols.

**What to do**: See the [Deployment Issues guide](deployment-issues.md#5-ebpf-verifier-rejection-program-too-large) for solutions, including reducing parser complexity or limiting the number of protocol layers processed.

### Unbounded Loop Detection

eBPF programs must always terminate—no infinite loops allowed!

**What you'll see:**

```shell
back-edge from insn X to Y
infinite loop detected at insn X
```

**What's happening**: The verifier found a loop without a provable upper bound. In eBPF, every loop must have a maximum number of iterations that the verifier can determine at verification time. If the verifier can't prove your loop will eventually exit, it rejects the program.

This is a fundamental eBPF safety requirement—infinite loops could freeze the kernel.

### Stack Size Exceeded

You've used too much stack space across your function calls.

**What you'll see:**

```shell
combined stack size of N calls is XXXX. Too large
max stack depth exceeded
```

**What's happening**: The combined stack usage across all your function calls exceeds the kernel's limit (typically 512 bytes). Each function call adds to the stack, and nested calls add up quickly.

## Runtime eBPF Errors

While verifier errors prevent programs from loading, runtime errors occur after your eBPF program is loaded and running. These are less common but important to understand.

### Ring Buffer Full - Dropping Flow Events

The eBPF ring buffer temporarily holds new flow events before userspace processes them. When this buffer fills up, new flow events are dropped to prevent the eBPF program from blocking.

**What you'll see:**

```shell
ERROR mermin: ebpf - ring buffer full - dropping flow event for new flow
```

**What's happening**: Your network is creating new flows faster than the ring buffer can drain them. This typically occurs during:

- **Traffic bursts**: Sudden spike in new connections (e.g., load balancer scaling, DDoS)
- **High connection rate**: Sustained high rate of new flow creation (>1,000 FPS)
- **Worker backpressure**: Downstream processing can't keep up (check worker channel metrics)

**Important**: Flow tracking continues! The flow is still tracked in the FLOW_STATS map, but userspace won't receive the initial packet data for deep packet inspection on that specific flow.

**How to fix it:**

1. **Increase ring buffer size** in your configuration:

   ```hcl
   pipeline {
     flow_capture {
       flow_events_capacity = 2048  # Double the default 1024 entries
       # Or use: 4096, 8192 for higher traffic
     }
   }
   ```

   **Sizing guide** (based on flows per second):
   - Default 1024 entries (~240 KB) handles 50-500 FPS
   - 2048 entries (~480 KB) for 500-2K FPS
   - 4096 entries (~960 KB) for 2K-5K FPS
   - 8192+ entries (~1.9 MB+) for >5K FPS

2. **Scale worker threads** if backpressure is the issue:

   ```hcl
   pipeline {
     flow_producer {
       workers = 8  # Default is 4
     }
   }
   ```

3. **Monitor metrics** to understand the issue:
   - `mermin_flow_events_total{result="dropped_backpressure"}` - Worker channel full
   - `mermin_ringbuf_packets_total{type="received"}` - Ring buffer throughput

**Performance impact**: Ring buffer memory is allocated per-node (not per-CPU), so increasing from 256 KB to 1 MB adds only ~750 KB of memory per node. The performance benefit far outweighs the minimal memory cost.

**When NOT to increase**: If drops are rare (< 1% of flows) during brief bursts, the default size is adequate. The ring buffer is designed to smooth out temporary spikes.

## Understanding TC Priority and TCX Order

Beyond verifier errors, there's another important aspect of eBPF program loading: execution order. When multiple eBPF programs are attached to the same network interface, the order they run in matters—a lot.

TC (Traffic Control) priority and TCX ordering control when your eBPF program runs relative to other programs (like your CNI). This affects which packets Mermin sees and in what state (before or after CNI modifications like NAT or encapsulation).

### Want to Learn More?

For the complete guide on TC priority, including troubleshooting conflicts with your CNI, see the [Understanding TC Priority](deployment-issues.md#understanding-tc-priority) section in the Deployment Issues guide. It covers:

- How priority values work and why they matter
- Troubleshooting priority conflicts between Mermin and your CNI
- CNI-specific recommendations and gotchas
- How to verify and test your configuration

### Quick Reference

**Mermin's defaults:**

- `tc_priority = 1` and `tcx_order = "first"` - Mermin runs first to capture unfiltered packets
- **Kernel < 6.6**: Uses netlink-based TC with numeric priority values (1-32767, lower = earlier)
- **Kernel >= 6.6**: Uses TCX mode with explicit ordering ("first" or "last")

**Why this matters**: Mermin operates passively (observes without modifying packets), so running first is usually safe and provides the most accurate observability data.
