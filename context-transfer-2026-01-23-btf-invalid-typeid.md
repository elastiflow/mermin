# Context Transfer Summary

**Generated**: 2026-01-23
**Purpose**: BTF Invalid type_id=0 error investigation for SkStorage eBPF map

## Problem Statement

When running mermin in Docker, the eBPF program fails to load with a BTF error showing `Invalid type_id` (type_id=0). This started after adding LSM eBPF process attribution using `SkStorage` maps in commit `fb8502f`. The error prevents the eBPF program from loading entirely.

## Code References

### Key Files & Locations
- `Cargo.toml:L19-L23`: Workspace aya dependency versions
- `mermin-ebpf/src/main.rs:L88-L99`: aya-ebpf imports including `btf_maps::SkStorage`
- `mermin-ebpf/src/main.rs:L183-L185`: `SOCKET_IDENTITY` SkStorage map definition
- `mermin-ebpf/src/main.rs:L266-L317`: `socket_post_create` LSM hook using SkStorage
- `mermin-ebpf/src/main.rs:L379-L583`: `try_flow_stats` TC program retrieving from SkStorage
- `mermin-ebpf/src/main.rs:L593-L715`: `parse_flow_key` function (returns `Result<EtherType, Error>`)
- `mermin-ebpf/src/main.rs:L796-L839`: `parse_metadata` function (returns `Result<usize, Error>`)
- `mermin-common/src/lib.rs:L166-L178`: `SocketIdentity` struct definition (32 bytes)
- `mermin/build.rs:L1-L25`: aya-build usage for eBPF compilation

### Critical Types Causing BTF Issues
- `SkStorage<SocketIdentity>` (`main.rs:L185`): BTF map type for socket-local storage
- `Result<EtherType, Error>` (`main.rs:L594`): Return type causing invalid type_id
- `Option<()>` (after inline fix): Also caused invalid type_id

## Error Details

### BTF Verifier Output (Key Lines)
```
[45] STRUCT Result_3C_network_types...EtherType...mermin_3A__3A_Error_3E_ size=4 vlen=1
        (anon) type_id=0 bits_offset=0 Invalid type_id
```

After changing to `#[inline(always)]`, error shifted to:
```
[36] STRUCT Option_3C__28__29__3E_ size=1 vlen=1
        (anon) type_id=0 bits_offset=0 Invalid type_id
```

### Root Cause Hypothesis
The BTF (BPF Type Format) encoding for Rust enums (`Result`, `Option`) is generating invalid type references. The `type_id=0` is invalid in BTF (valid IDs start at 1). This appears to be a bug in how LLVM/bpf-linker generates BTF for Rust enum discriminants.

## Completed Work

### Changes Made (still in place)
- `Cargo.toml:L20`: Synchronized `aya-build` revision to match `aya-ebpf` revision (`de42b80c74883f512542875e7cfa96b8634a8991`)

### Changes Made and Reverted
- `main.rs:L593,L796`: Changed `#[inline(never)]` to `#[inline(always)]` - **REVERTED** (shifted error to `Option` type instead of fixing)

### Decisions & Rationale
- Used git revision `de42b80c74883f512542875e7cfa96b8634a8991` for aya-ebpf because it has SkStorage support (not available in crates.io 0.1.1)
- Version synchronization was necessary but not sufficient to fix the BTF issue

## What Was Tried

### Attempt 1: Copy SkStorage Code Into Mermin Module
- **Hypothesis**: Could vendor the SkStorage implementation locally to avoid dependency on unreleased aya-ebpf git revision
- **Action**: Copied the SkStorage BTF map implementation from aya-ebpf into a local module within mermin
- **Result**: Experienced the same BTF `Invalid type_id=0` error - the issue is not specific to the aya crate source but rather how BTF is generated for the types involved
- **Decision**: Switched to using aya-ebpf directly from the GitHub commit that has SkStorage support

### Attempt 2: Synchronize aya Versions
- **Hypothesis**: Mismatch between `aya-build` (rev `a7e3e6d4...`) and `aya-ebpf` (rev `de42b80c...`) causing BTF incompatibility
- **Action**: Changed `aya-build` to use same revision as `aya-ebpf`
- **Result**: Build succeeded, but BTF error persisted at runtime

### Attempt 3: Change Inline Attributes
- **Hypothesis**: `#[inline(never)]` on `parse_flow_key` exposed `Result` type to BTF encoding
- **Action**: Changed to `#[inline(always)]`
- **Result**: Error shifted from `Result` type to `Option` type - did not fix root cause

## Remaining Tasks

### Investigation Needed
- [ ] Investigate if this is a known aya/bpf-linker bug with Rust enum BTF encoding
- [ ] Check if newer aya revisions fix this BTF issue
- [ ] Explore alternative: avoid `Option`/`Result` in eBPF code paths that get BTF-encoded
- [ ] Check if removing SkStorage map eliminates BTF errors (to isolate cause)
- [ ] Investigate bpf-linker version and potential fixes

### Potential Solutions to Try
- [ ] Try a newer aya revision (check aya-rs/aya main branch for BTF fixes)
- [ ] Refactor code to avoid Rust enums in non-inlined functions
- [ ] Check if `#[repr(C)]` on Error/custom types helps
- [ ] Try removing SkStorage temporarily to see if error persists (isolate cause)

## Important Context

### Dependencies (from Cargo.toml)
```toml
aya = { version = "0.13.1" }  # crates.io - userspace
aya-build = { git = "...", rev = "de42b80c74883f512542875e7cfa96b8634a8991" }
aya-ebpf = { git = "...", rev = "de42b80c74883f512542875e7cfa96b8634a8991" }
aya-log = { version = "0.2.1" }  # crates.io
aya-log-ebpf = { git = "...", rev = "de42b80c74883f512542875e7cfa96b8634a8991" }
```

### Why SkStorage is Needed
- Socket-PID-Comm association for flow attribution
- LSM hook stamps `SocketIdentity` at socket creation
- TC programs retrieve identity for process attribution on flows
- Storage auto-cleans when socket is destroyed

### Build/Test Commands
```bash
# Build container
docker build -t mermin-builder:latest --target builder .

# Clean build
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "cargo clean && cargo build --release"

# Run
docker run -it --privileged -v `pwd`:/app mermin-builder:latest /bin/bash
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config docs/deployment/examples/local/config.hcl
```

### Key Observations
1. Error always shows `type_id=0` which is invalid in BTF
2. Error affects Rust enum types (`Result`, `Option`) specifically
3. Inlining functions shifts which enum type fails, but doesn't fix the issue
4. The SkStorage map definition itself references types that may be triggering the issue
5. This may be a bpf-linker or LLVM BTF generation bug

## Hypotheses for Next Chat

### Most Likely: bpf-linker BTF Generation Bug
The bpf-linker generates BTF metadata from LLVM debug info. Rust enums have complex internal representations (discriminant + variants), and the BTF encoder may be generating invalid type references for enum discriminants.

### Possible Fix Paths
1. **Upgrade bpf-linker**: Check if newer versions fix BTF enum encoding
2. **Try aya main branch**: Latest aya may have workarounds or fixes
3. **Avoid enums in BTF-visible code**: Refactor to use raw integers instead of Result/Option in certain contexts
4. **File upstream issue**: This may need a fix in bpf-linker or aya

### Questions for Next Session
1. What version of bpf-linker is in the Docker container?
2. Are there any open issues in aya-rs/aya about BTF and Rust enums?
3. Would removing the SkStorage map isolate whether it's the cause?
