# Troubleshoot Common eBPF Errors

eBPF programs must pass the kernel's verifier before running. The verifier checks that programs are safe, will not crash the kernel, and will terminate. Verifier behavior changes significantly between kernel versions, making error diagnosis challenging.

## Quick Reference

Use this table to quickly diagnose common eBPF errors:

| Error Pattern                                      | Likely Cause                                | Quick Fix                                                   |
|----------------------------------------------------|---------------------------------------------|-------------------------------------------------------------|
| `R4 invalid zero-sized read`                       | Kernel < 5.16 with stricter bounds checking | Upgrade kernel to 5.16+                                     |
| `invalid access to map value`                      | Map bounds check failure                    | Upgrade kernel to 5.16+                                     |
| `program is too large` / `processed 1000001 insns` | eBPF instruction limit exceeded             | Reduce parser complexity or protocol layers                 |
| `back-edge from insn` / `infinite loop detected`   | Unbounded loop in eBPF code                 | Ensure loops have provable bounds                           |
| `combined stack size...Too large`                  | Stack overflow (>512 bytes)                 | Reduce nested function calls                                |
| `ring buffer full - dropping flow event`           | High traffic burst overwhelming buffer      | Increase `flow_events_capacity` to 2048+                    |
| `Operation not permitted`                          | Missing Linux capabilities                  | Verify `privileged: true` or add `CAP_BPF`, `CAP_NET_ADMIN` |
| `BTF is not supported`                             | Kernel lacks BTF support                    | Use kernel with BTF enabled or upgrade                      |

For detailed explanations and solutions, see the sections below.

---

## What You Need to Know About the Verifier

Verifier errors are rare on modern kernels. Most Mermin deployments work without issues. 

Problems typically occur on older kernel versions (< 5.16) that lack sophisticated complexity analysis, and are more conservative.

The eBPF verifier has evolved considerably over time. What newer kernels accept, older kernels may reject:

- **Kernel 5.4-5.10**: The early days - stricter bounds checking, more conservative validation
- **Kernel 5.11-5.15**: Getting smarter - improved range tracking and better loop handling
- **Kernel 5.16+**: Even better - enhanced state pruning for more complex programs
- **Kernel 6.0+**: Most sophisticated - relaxed restrictions and the most permissive verifier

**Recommended**: Use kernel 5.14+ (preferably 6.6+) for the best experience and fewest compatibility issues.

{% hint style="info" %}
Hit a verifier error we haven't covered? Reach out to the Mermin team! We're constantly improving kernel compatibility based on real-world feedback.
{% endhint %}

## How to Recognize Verifier Errors

When the verifier rejects a program, pods fail to start. The logs show errors like:

```shell
ERROR Failed to load eBPF program
verification time XXXXX usec
processed XXXX insns (limit 1000000)
```

Pods remain stuck in `CrashLoopBackOff` or `Error` state.

## Common Verifier Errors (And What They Mean)

The following sections explain the most common verifier errors and their causes.

### Invalid Zero-Sized Read

This error occurs when the verifier detects a potential zero-byte memory read.

**What you'll see:**

```shell
R4 invalid zero-sized read: u64=[0,191]
verification time 38379 usec
processed 8264 insns (limit 1000000)
```

**Cause**: The verifier detected a potential zero-byte memory read. This typically occurs when length calculations might result in zero, or when the verifier cannot prove the length is non-zero.

**Real-world example:**

```shell
979: (2d) if r1 > r4 goto pc+1 981
985: (85) call bpf_skb_load_bytes#26
R4 invalid zero-sized read: u64=[0,191]
```

The verifier sees that R4 (the length parameter) could be anywhere from 0 to 191, including zero. Since reading zero bytes doesn't make sense, it rejects the program.

### Invalid Map Access

This error indicates a map access the verifier cannot verify as safe.

**What you'll see:**

```shell
invalid access to map value, value_size=234 off=42 size=0
R3 min value is outside of the allowed memory range
verification time 27928 usec
```

**Cause**: The verifier cannot prove the map access stays within bounds. The offset + size may exceed the map's value size, or range tracking indicates potential access outside the allowed memory range. For example, accessing byte 235 in a 234-byte map value triggers this error.

**Real-world example:**

```shell
2485: (0f) r4 += r3              ; R3_w=1 R4_w=map_value(off=0,ks=4,vs=234,imm=0)
2489: (73) *(u8 *)(r4 +0) = r5
invalid access to map value, value_size=234 off=42 size=0
```

The verifier is concerned that after adding R3 to R4, the resulting offset (42) might be too close to the end of the 234-byte value.

### Instruction Limit Exceeded

The kernel limits eBPF program complexity.

**What you'll see:**

```shell
BPF program is too large. processed 1000001 insns
processed 1000001 insns (limit 1000000)
```

**Cause**: The program exceeds the kernel's instruction limit (typically 1 million instructions). This commonly occurs when parsing deeply nested network headers or processing complex protocols.

**What to do**: See the [Deployment Issues guide](deployment-issues.md#5-ebpf-verifier-rejection-program-too-large) for solutions, including reducing parser complexity or limiting the number of protocol layers processed.

### Unbounded Loop Detection

eBPF programs must always terminate. Infinite loops are prohibited.

**What you'll see:**

```shell
back-edge from insn X to Y
infinite loop detected at insn X
```

**Cause**: The verifier found a loop without a provable upper bound. Every eBPF loop must have a maximum iteration count determinable at verification time. The verifier rejects programs with loops that cannot be proven to exit – a fundamental safety requirement to prevent kernel freezes.

### Stack Size Exceeded

Combined stack usage across function calls exceeds the limit.

**What you'll see:**

```shell
combined stack size of N calls is XXXX. Too large
max stack depth exceeded
```

**Cause**: Combined stack usage across function calls exceeds the kernel's limit (typically 512 bytes). Each function call consumes stack space, and nested calls accumulate rapidly.

## Runtime eBPF Errors

While verifier errors prevent programs from loading, runtime errors occur after your eBPF program is loaded and running. These are less common but important to understand.

### Ring Buffer Full - Dropping Flow Events

The eBPF ring buffer temporarily holds new flow events before userspace processes them. When the buffer fills, new flow events are dropped to prevent the eBPF program from blocking.

**What you'll see:**

```shell
ERROR mermin: ebpf - ring buffer full - dropping flow event for new flow
```

**Cause**: The network creates new flows faster than the ring buffer can drain. This typically occurs during:

- **Traffic bursts**: Sudden spike in new connections (e.g., load balancer scaling, DDoS)
- **High connection rate**: Sustained high rate of new flow creation (>1,000 FPS)
- **Worker backpressure**: Downstream processing can't keep up (check worker channel metrics)

**Note**: Flow tracking continues. The flow remains tracked in the FLOW_STATS map, but userspace does not receive the initial packet data for deep packet inspection on that specific flow.

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

Beyond verifier errors, there's another important aspect of eBPF program loading: execution order. When multiple eBPF programs are attached to the same network interface, the order they run in matters — a lot.

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

---

## Next Steps

{% tabs %}
{% tab title="Still Stuck?" %}
1. [**Review Full Deployment Troubleshooting**](deployment-issues.md): Complete guide to pod startup and permission issues
2. [**Test eBPF Attach/Detach**](deployment-issues.md#test-ebpf-attachdetach-operations): Validate your kernel capabilities
{% endtab %}

{% tab title="Get Help" %}
1. [**Search Existing Issues**](https://github.com/elastiflow/mermin/issues): Check if someone else encountered the same error
2. [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask for help with your specific error
{% endtab %}
{% endtabs %}

### Related Guides

- [**Understand Interface Visibility**](interface-visibility-and-traffic-decapsulation.md): Why you might not see expected traffic
- [**Configure Network Interfaces**](../configuration/reference/network-interface-discovery.md): Set up the correct patterns for your CNI
