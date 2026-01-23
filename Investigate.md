# Investigation: Late Start Architecture for Process Attribution

# Architecture

This architecture solves the “Late Start” problem, ensures the highest possible efficiency, and provides full coverage for both TCP and UDP.
1. The Core: Socket Local Storage (sk_storage)
Instead of using a standard BPF Hash Map (which suffers from hash collisions and lookup overhead), we use Socket Local Storage.
• Mechanism: Metadata is attached directly to the struct sock object inside the kernel.
• Performance: Faster than a hash map because the TC program accesses the data via a direct pointer after the socket lookup.
• Lifecycle: The kernel automatically deletes the storage when the socket is destroyed, eliminating the need for complex “cleanup” code.1
2. The Three-Pillar Population Strategy
To ensure the sk_storage is always populated with the correct PID/Comm, the agent uses three different mechanisms:
Pillar A: The “Catch-Up” (BPF Iterators)
Trigger: Executed once at agent startup.
Hook: iter/tcp and iter/udp.
Purpose: Walks the kernel’s internal socket tables to find connections that were already established before the agent started. It populates the sk_storage for these “historical” sockets.
Pillar B: The “Real-Time TCP” (LSM Hooks)
Trigger: On connection lifecycle events.
Hooks: socket_connect (outbound) and socket_post_accept (inbound).
Purpose: Captures the PID/Comm the moment a new TCP connection is born and stores it in sk_storage.
Pillar C: The “Real-Time UDP” (Data Flow Hooks)
• Trigger: On data transmission/reception.
• Hooks: udp_sendmsg and udp_recvmsg (LSM hooks).
• Purpose: Since UDP is connectionless, these hooks ensure that even if a socket is reused for different flows, the PID context is refreshed as soon as data is handled.
3. The Data Plane: Traffic Control (TC)
The TC program remains incredibly lean and efficient:
Parse Header: Extract the 5-tuple from the packet.
Socket Lookup: Call bpf_skc_lookup_tcp or bpf_sk_lookup_udp to find the active kernel socket.
Storage Retrieval: Call bpf_sk_storage_get to retrieve the PID/Comm directly from the socket object.
Extract: Get relevant process metadata.
Release: Call bpf_sk_release to maintain kernel memory safety.
4. Why does this work? (Challenge -> Solution)
Late Agent Start -> BPF Iterators sync existing connections.
High Traffic Volume -> sk_storage provides O(1) direct access speed.
UDP Connectionless -> recvmsg/sendmsg hooks capture the process behind the flow.
Memory Management -> Auto-Cleanup via sk_storage avoids map leaks.
TCP SYN Discovery -> socket_connect catches the PID before the first packet is sent.

## Implementation Approach: Using Raw BPF Helpers

### Library Support Verification

**Status Check Results:**
- ❌ **aya-ebpf 0.1.1**: Does NOT have `SkStorage` type in the `maps` module
- ❌ **aya 0.13.1 (userspace)**: Does NOT have `SkStorage` type in the `maps` module  
- ✅ **Kernel**: Supports `BPF_MAP_TYPE_SK_STORAGE` (requires kernel 5.2+)
- ✅ **Kernel**: Provides `bpf_sk_storage_get()` and `bpf_sk_storage_delete()` helpers

**Available Socket Map Types:**
- `SockMap` / `SockHash`: Available in both aya-ebpf and aya, but these are for packet redirection (`BPF_MAP_TYPE_SOCKMAP` / `BPF_MAP_TYPE_SOCKHASH`), NOT socket-local storage
- `SkStorage`: Not available in either crate - requires using raw BPF helpers

### Solution: Raw BPF Helper Implementation

Since `SkStorage` is not available in aya-ebpf 0.1.1 or aya 0.13.1, we will implement socket storage using raw BPF helpers directly.

#### Step 1: Define Raw BPF Helpers in eBPF Code

Since aya-ebpf 0.1.1 may not expose these helpers, define them manually:

```rust
// In mermin-ebpf/src/main.rs
#[cfg(not(feature = "test"))]
extern "C" {
    /// Retrieve or store data in socket-local storage
    /// 
    /// Parameters:
    /// - `map`: Pointer to BPF_MAP_TYPE_SK_STORAGE map
    /// - `sk`: Pointer to socket (struct sock *)
    /// - `value`: Pointer to value to store (when creating/updating), or NULL for retrieval
    /// - `flags`: BPF_NOEXIST (1), BPF_EXIST (2), or BPF_ANY (0)
    /// 
    /// Returns: pointer to stored value on success, NULL on failure
    fn bpf_sk_storage_get(
        map: *mut core::ffi::c_void,
        sk: *mut core::ffi::c_void,
        value: *mut core::ffi::c_void,
        flags: u64,
    ) -> *mut core::ffi::c_void;
    
    /// Delete data from socket-local storage
    /// 
    /// Parameters:
    /// - `map`: Pointer to BPF_MAP_TYPE_SK_STORAGE map
    /// - `sk`: Pointer to socket (struct sock *)
    /// 
    /// Returns: 0 on success, negative error code on failure
    /// Note: Kernel auto-deletes storage on socket destroy, so this is rarely needed
    fn bpf_sk_storage_delete(
        map: *mut core::ffi::c_void,
        sk: *mut core::ffi::c_void,
    ) -> i64;
}
```

**Alternative**: First check if helpers are available in `aya_ebpf::helpers` or `aya_ebpf_bindings::helpers` before defining manually.

#### Step 2: Map Definition in eBPF Code

The `BPF_MAP_TYPE_SK_STORAGE` map must be defined in eBPF code. Since the type doesn't exist, we'll define it as a placeholder that the kernel will recognize:

```rust
// In mermin-ebpf/src/main.rs
/// Socket-local storage map for process attribution.
/// Maps socket pointer -> SocketIdentity (PID, executable name, cgroup ID, UID).
/// Populated by LSM hooks at socket creation time, queried by TC programs for flow attribution.
/// Storage is automatically freed when socket is destroyed by the kernel.
/// 
/// Note: This uses BPF_MAP_TYPE_SK_STORAGE which is not available as a type in aya-ebpf 0.1.1.
/// The map will be created by the kernel when the eBPF program is loaded.
/// We use raw BPF helpers (bpf_sk_storage_get) to interact with this map.
#[cfg(not(feature = "test"))]
#[map(name = "SOCKET_IDENTITY")]
static mut SOCKET_IDENTITY: [u8; 0] = []; // Placeholder - actual type determined by kernel
```

**Map Requirements:**
- Key size: Must be 4 bytes (32-bit unsigned integer) - handled by kernel
- Value size: `SocketIdentity` struct (32 bytes) - must implement `Pod` trait
- Max entries: Must be 0 (entries determined by number of sockets on system)
- Flags: Requires `BPF_F_NO_PREALLOC` flag (set automatically by kernel for SK_STORAGE)

#### Step 3: Map Creation from Userspace

The map will be created automatically when the eBPF program is loaded. In `mermin/src/main.rs`:

```rust
// After loading eBPF program
let mut ebpf = EbpfLoader::new()
    .set_max_entries("SOCKET_IDENTITY", 0) // SK_STORAGE requires max_entries = 0
    .load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mermin"
    )))?;

// The map is automatically created by the loader
// Access it as a generic Map (SkStorage type doesn't exist in aya 0.13.1)
let socket_identity_map = ebpf.take_map("SOCKET_IDENTITY")
    .ok_or_else(|| MerminError::internal("SOCKET_IDENTITY not found"))?;

// Note: If aya adds SkStorage support in future versions, we can convert it:
// let socket_storage: aya::maps::SkStorage<SocketIdentity> = 
//     aya::maps::SkStorage::try_from(socket_identity_map)?;
```

#### Step 4: Using Helpers in LSM Hook (Storing Data)

```rust
fn try_socket_post_create(ctx: LsmContext) -> Result<(), ()> {
    // Get socket pointer from LSM context
    let sock = unsafe { ctx.arg::<*const core::ffi::c_void>(0) };
    if sock.is_null() {
        return Err(());
    }

    // Capture process context
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let comm = unsafe { 
        bpf_get_current_comm().unwrap_or([0u8; 16])
    };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };

    let identity = SocketIdentity {
        pid: (pid_tgid >> 32) as u32,
        tgid: pid_tgid as u32,
        comm,
        cgroup_id,
        uid: uid_gid as u32,
    };

    // Store using bpf_sk_storage_get with BPF_ANY flag (0 = create or update)
    unsafe {
        let map_ptr = &SOCKET_IDENTITY as *const _ as *mut core::ffi::c_void;
        let value_ptr = &identity as *const _ as *mut core::ffi::c_void;
        
        let result = bpf_sk_storage_get(
            map_ptr,
            sock as *mut core::ffi::c_void,
            value_ptr,
            0u64, // BPF_ANY = create or update
        );
        
        if result.is_null() {
            // Failed to store - non-fatal, allow socket creation to proceed
            return Err(());
        }
    }

    Ok(())
}
```

#### Step 5: Using Helpers in TC Program (Retrieving Data)

```rust
// In try_flow_stats function, after parsing flow key
let sk = unsafe { (*ctx.skb.skb).__bindgen_anon_2.sk };
if !sk.is_null() {
    unsafe {
        let map_ptr = &SOCKET_IDENTITY as *const _ as *mut core::ffi::c_void;
        
        // Retrieve: pass NULL for value, 0 for flags (read-only)
        let identity_ptr = bpf_sk_storage_get(
            map_ptr,
            sk as *mut core::ffi::c_void,
            core::ptr::null_mut(), // NULL = retrieve only, don't create
            0u64, // No flags = just read
        );
        
        if !identity_ptr.is_null() {
            let identity = &*(identity_ptr as *const SocketIdentity);
            stats.process_pid = identity.pid;
            stats.process_tgid = identity.tgid;
            stats.process_comm = identity.comm;
            stats.process_cgroup_id = identity.cgroup_id;
            stats.process_uid = identity.uid;
        } else {
            // No storage found (e.g., pre-existing connection before agent started)
            // PID of 0 indicates attribution unavailable
            stats.process_pid = 0;
            stats.process_tgid = 0;
            stats.process_comm = [0; 16];
            stats.process_cgroup_id = 0;
            stats.process_uid = 0;
        }
    }
} else {
    // No socket associated with skb
    stats.process_pid = 0;
    stats.process_tgid = 0;
    stats.process_comm = [0; 16];
    stats.process_cgroup_id = 0;
    stats.process_uid = 0;
}
```

### Implementation Notes

1. **Helper Function Flags**:
   - `BPF_NOEXIST` (1): Create new entry only, fail if exists
   - `BPF_EXIST` (2): Update existing entry only, fail if doesn't exist
   - `BPF_ANY` (0): Create or update (most flexible, recommended for LSM hooks)

2. **Lifecycle Management**: 
   - The kernel automatically deletes storage when the socket is destroyed
   - No manual cleanup needed - eliminates map leaks
   - `bpf_sk_storage_delete()` is rarely needed (only for explicit cleanup)

3. **Error Handling**: 
   - All operations are non-fatal
   - Socket creation/usage proceeds even if storage operations fail
   - Missing storage in TC programs indicates pre-existing connections (handled gracefully)

4. **Performance**:
   - O(1) direct access via socket pointer (faster than hash map lookup)
   - No hash collisions (data attached directly to socket object)
   - Minimal overhead for storage operations

5. **Future Compatibility**:
   - If aya-ebpf adds `SkStorage` type in future versions, migration path:
     - Replace raw helper calls with type-safe `SkStorage::get()` / `SkStorage::set()` methods
     - Replace manual map definition with `SkStorage::with_max_entries()`
     - Keep same underlying kernel mechanism

## Open Questions to Investigate

### 1. Socket Post-Create Compatibility with bpf_sk_lookup
**Question**: Is the `struct sock` from `socket_post_create` compatible with `bpf_sk_lookup` for packet attribution?

**Context**: Based on further reading, the problem with `socket_post_create` is that the `struct sock` for it and `socket_post_accept` are different, and if you use `bpf_sk_lookup` with the `struct sock` from `socket_post_create` against a network packet, then it will return nothing. @James needs to verify that this is true.

**Action Required**: 
- Verify if `bpf_sk_lookup_tcp`/`bpf_sk_lookup_udp` can successfully match packets to sockets created via `socket_post_create`
- Test with actual socket creation scenarios (both client and server side)
- Determine if `socket_post_accept` is required for server-side TCP connections

### 2. TCP Ephemeral Port Availability in security_socket_connect
**Question**: Does `security_socket_connect` have the ephemeral client port available, or do we need `security_inet_conn_established`?

**Context**: For TCP, on `security_socket_connect` hook the client port (ephemeral) may not be assigned just yet. Gemini suggested using `security_inet_conn_established`, which actually makes sense. Or it may be both: `security_socket_connect` if port is 0, try to use `security_inet_conn_established`.

**Action Required**:
- Test when ephemeral ports are assigned in the TCP connection lifecycle
- Determine if `security_socket_connect` has port information available
- Evaluate whether `security_inet_conn_established` is needed as a fallback or primary hook
- Consider hybrid approach: use `security_socket_connect` if port is available, otherwise use `security_inet_conn_established`

### 3. UDP Hook Strategy and Performance
**Question**: Should we process all `security_socket_sendmsg`/`security_socket_recvmsg` hooks (with UDP filtering) or only the first one per socket?

**Context**: 
- `udp_sendmsg`/`udp_recvmsg` don't exist as LSM hooks, only as kprobe/kretprobe
- `security_socket_sendmsg`/`security_socket_recvmsg` are protocol-agnostic LSM hooks
- We can check the `sk` struct for IP protocol to filter UDP traffic
- Processing every `sendmsg` hook may have performance implications

**Action Required**:
- Benchmark performance impact of processing all `sendmsg`/`recvmsg` hooks with protocol filtering
- Determine if we can optimize by only processing the first message per socket
- Verify that protocol filtering via `sk` struct is reliable and efficient
- Consider if we need both `sendmsg` and `recvmsg` or if one is sufficient

### 4. Socket Post-Create vs Socket Post-Accept for Server Sockets
**Question**: What's the relationship between `socket_post_create` and `socket_post_accept` for server-side TCP sockets?

**Context**: 
- `socket_post_create` is dispatched for both server and client sockets
- `socket_post_accept` is dispatched when a server accepts a new connection
- The `struct sock` objects may be different between these hooks
- Need to understand which one provides the correct socket for packet attribution

**Action Required**:
- Document the lifecycle of server sockets: creation vs accept
- Test which hook provides the socket that `bpf_sk_lookup` can match to packets
- Determine if we need both hooks or if one is sufficient

## Current Implementation Gaps

### Pillar A: BPF Iterators (Catch-Up at Startup)
**Status**: Not implemented

**Required Components**:
- `iter/tcp` iterator program to walk existing TCP connections
- `iter/udp` iterator program to walk existing UDP sockets
- Logic to populate `sk_storage` with PID/comm for pre-existing sockets using `bpf_sk_storage_get()` with `BPF_ANY` flag
- Integration point in agent startup sequence

**Challenges**:
- Need to ensure iterators can access socket identity information
- Must handle cases where process may have exited but socket still exists
- Performance considerations for systems with many existing connections

### Pillar B: Real-Time TCP Hooks
**Status**: Partially implemented (only `socket_post_create` exists, needs raw helper integration)

**Missing Components**:
- Integration of `bpf_sk_storage_get()` helper in `socket_post_create` (currently uses non-existent `SkStorage` type)
- `socket_connect` LSM hook for outbound TCP connections
- `socket_post_accept` LSM hook for inbound TCP connections (if needed)
- `security_inet_conn_established` hook (if ephemeral ports aren't available in `socket_connect`)
- Logic to handle port availability edge cases

**Current State**:
- ⚠️ `socket_post_create` implemented but uses non-existent `SkStorage` type - needs raw helper migration
- ❌ `socket_connect` not implemented
- ❌ `socket_post_accept` not implemented
- ❌ `security_inet_conn_established` not implemented

### Pillar C: Real-Time UDP Hooks
**Status**: Not implemented

**Required Components**:
- `security_socket_sendmsg` LSM hook with UDP protocol filtering
- `security_socket_recvmsg` LSM hook with UDP protocol filtering
- Logic to check `sk` struct for IP protocol to filter UDP-only
- Use `bpf_sk_storage_get()` with `BPF_ANY` flag to refresh PID context
- Performance optimization strategy (process all vs first message)

**Challenges**:
- Protocol filtering overhead
- UDP connectionless nature means sockets may be reused for different flows
- Need to refresh PID context on each message (or determine if first is sufficient)

## Architecture Requirements

### Three-Pillar Population Strategy
1. **Pillar A (Catch-Up)**: BPF Iterators at agent startup
   - Walk kernel socket tables for existing connections
   - Populate `sk_storage` for historical sockets
   - Addresses "Late Agent Start" problem

2. **Pillar B (Real-Time TCP)**: LSM lifecycle hooks
   - `socket_connect` for outbound connections
   - `socket_post_accept` for inbound connections (or `socket_post_create` if compatible)
   - Capture PID/comm at connection birth

3. **Pillar C (Real-Time UDP)**: Data flow hooks
   - `security_socket_sendmsg`/`security_socket_recvmsg` with UDP filtering
   - Refresh PID context as data is handled
   - Handle connectionless nature of UDP

### Data Plane (TC Programs)
**Status**: ⚠️ Partially implemented - needs raw helper migration

**Current Implementation**:
- TC programs attempt to retrieve PID/comm from `sk_storage` but use non-existent `SkStorage` type
- Code references `SOCKET_IDENTITY.get()` which doesn't compile
- Uses `bpf_skc_lookup_tcp`/`bpf_sk_lookup_udp` to find active kernel socket (✅ working)

**Migration Required**:
- Replace `SOCKET_IDENTITY.get()` calls with raw `bpf_sk_storage_get()` helper
- Update socket field access from `(*ctx.skb.skb).sk` to `(*ctx.skb.skb).__bindgen_anon_2.sk`
- Handle NULL return values from helper (indicates no storage found)

## Testing Requirements

### Test Scenarios Needed
1. **Socket Creation Scenarios**:
   - Client-side TCP socket creation
   - Server-side TCP socket creation and accept
   - UDP socket creation (client and server)
   - Socket forking (parent creates socket, child uses it)

2. **Late Start Scenarios**:
   - Agent starts after connections are established
   - Verify iterators catch existing connections
   - Verify new connections are captured via hooks

3. **Edge Cases**:
   - Ephemeral port assignment timing
   - UDP socket reuse across different flows
   - Process exit while socket still active
   - High traffic volume performance

### Test Infrastructure
- Consider standalone test binaries for various socket scenarios (as suggested by Mack)
- Integration tests requiring Linux platform
- Performance benchmarks for hook processing overhead
