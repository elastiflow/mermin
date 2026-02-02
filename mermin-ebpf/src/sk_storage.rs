//! Socket-local storage (SK_STORAGE) for process information tracking.
//!
//! This module provides a BPF_MAP_TYPE_SK_STORAGE implementation that stores
//! process information directly on sockets, eliminating race conditions between
//! LSM/fexit hooks and TC hooks when tracking PID/comm for TCP connections.
//!
//! ## Background
//!
//! The previous approach had a race condition:
//! - LSM/fexit hooks tried to store PID/comm in FLOW_STATS by FlowKey
//! - If TC hadn't created the entry yet, process info was lost
//!
//! SK_STORAGE solves this by attaching data directly to the socket:
//! 1. LSM/fexit hooks store ProcessInfo on socket when connection established
//! 2. TC hooks read from socket storage when processing packets
//! 3. No dependency on map entry timing

use aya_ebpf::{
    bindings::bpf_sock,
    cty::c_void,
    helpers::{bpf_sk_storage_delete, bpf_sk_storage_get},
};
use core::marker::PhantomData;

/// Flags for bpf_sk_storage_get helper.
pub const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

/// Process information stored in socket-local storage.
/// Captures the PID and command name of the process that created/connected the socket.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessInfo {
    /// Process ID (from bpf_get_current_pid_tgid >> 32)
    pub pid: u32,
    /// Thread Group ID (from bpf_get_current_pid_tgid & 0xFFFFFFFF)
    pub tgid: u32,
    /// Process command name (TASK_COMM_LEN = 16 bytes)
    pub comm: [u8; 16],
}

/// A BPF socket-local storage map.
///
/// SK_STORAGE maps allow attaching data directly to sockets. The key is the socket
/// itself (not a user-defined key), and the value is stored per-socket.
///
/// This implementation is adapted from aya-ebpf upstream to support raw `*mut bpf_sock`
/// pointers, which is needed for TC hooks that access `skb->sk`.
#[repr(transparent)]
pub struct SkStorage<V> {
    def: UnsafeCell<SkStorageDef>,
    _v: PhantomData<V>,
}

use core::cell::UnsafeCell;

/// BTF-compatible map definition for BPF_MAP_TYPE_SK_STORAGE.
#[repr(C)]
pub struct SkStorageDef {
    /// Map type (BPF_MAP_TYPE_SK_STORAGE = 24)
    pub type_: u32,
    /// Flags for the map
    pub map_flags: u32,
    /// Size of the key (must be 0 for sk_storage)
    pub key_size: u32,
    /// Size of the value
    pub value_size: u32,
    /// Maximum entries (must be 0 for sk_storage, kernel manages lifecycle)
    pub max_entries: u32,
}

// SAFETY: SkStorage is a BPF map definition that is only accessed from eBPF context
// where the kernel provides thread-safety guarantees for map operations.
unsafe impl<V: Sync> Sync for SkStorage<V> {}

impl<V> SkStorage<V> {
    /// BPF_MAP_TYPE_SK_STORAGE constant
    const BPF_MAP_TYPE_SK_STORAGE: u32 = 24;
    /// BPF_F_NO_PREALLOC flag - required for SK_STORAGE
    const BPF_F_NO_PREALLOC: u32 = 1;

    /// Creates a new SK_STORAGE map with default settings.
    ///
    /// The map is automatically created when the eBPF program is loaded.
    /// Each socket can store one value, and the storage is automatically
    /// cleaned up when the socket is destroyed.
    pub const fn new() -> Self {
        Self {
            def: UnsafeCell::new(SkStorageDef {
                type_: Self::BPF_MAP_TYPE_SK_STORAGE,
                map_flags: Self::BPF_F_NO_PREALLOC,
                key_size: 0, // Must be 0 for sk_storage
                value_size: core::mem::size_of::<V>() as u32,
                max_entries: 0, // Managed by kernel
            }),
            _v: PhantomData,
        }
    }

    /// Gets a reference to the value stored for the given socket.
    ///
    /// # Safety
    ///
    /// The socket pointer must be valid and point to a kernel socket structure.
    ///
    /// # Arguments
    ///
    /// * `sk` - Raw pointer to a `bpf_sock` structure (typically from `skb->sk`)
    ///
    /// # Returns
    ///
    /// Returns `Some(&V)` if storage exists for this socket, `None` otherwise.
    #[inline(always)]
    pub unsafe fn get(&self, sk: *mut bpf_sock) -> Option<&V> {
        // SAFETY: Caller guarantees sk is valid. bpf_sk_storage_get is a kernel helper
        // that safely handles the socket storage lookup.
        let ptr = unsafe {
            bpf_sk_storage_get(
                &self.def as *const _ as *mut c_void,
                sk as *mut _,
                core::ptr::null_mut(),
                0,
            )
        };
        if ptr.is_null() {
            None
        } else {
            // SAFETY: ptr is non-null and points to valid storage of type V
            Some(unsafe { &*(ptr as *const V) })
        }
    }

    /// Gets a mutable reference to the value stored for the given socket,
    /// optionally creating it if it doesn't exist.
    ///
    /// # Safety
    ///
    /// The socket pointer must be valid and point to a kernel socket structure.
    ///
    /// # Arguments
    ///
    /// * `sk` - Raw pointer to a `bpf_sock` structure
    /// * `flags` - Storage flags (use `BPF_SK_STORAGE_GET_F_CREATE` to create if missing)
    ///
    /// # Returns
    ///
    /// Returns `Some(&mut V)` if storage exists or was created, `None` on failure.
    #[inline(always)]
    pub unsafe fn get_or_create(&self, sk: *mut bpf_sock, flags: u64) -> Option<&mut V> {
        // When creating, we need to provide an initial value
        // The kernel will copy this value if creating new storage
        let mut init = core::mem::MaybeUninit::<V>::zeroed();
        // SAFETY: Caller guarantees sk is valid. bpf_sk_storage_get is a kernel helper
        // that safely handles the socket storage lookup/creation.
        let ptr = unsafe {
            bpf_sk_storage_get(
                &self.def as *const _ as *mut c_void,
                sk as *mut _,
                init.as_mut_ptr() as *mut c_void,
                flags,
            )
        };
        if ptr.is_null() {
            None
        } else {
            // SAFETY: ptr is non-null and points to valid storage of type V
            Some(unsafe { &mut *(ptr as *mut V) })
        }
    }

    /// Deletes the storage associated with the given socket.
    ///
    /// # Safety
    ///
    /// The socket pointer must be valid.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, `Err(errno)` on failure.
    #[inline(always)]
    #[allow(dead_code)]
    pub unsafe fn delete(&self, sk: *mut bpf_sock) -> Result<(), i64> {
        // SAFETY: Caller guarantees sk is valid. bpf_sk_storage_delete is a kernel helper
        // that safely handles the socket storage deletion.
        let ret =
            unsafe { bpf_sk_storage_delete(&self.def as *const _ as *mut c_void, sk as *mut _) };
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }
}
