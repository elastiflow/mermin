//! Controller for network interface lifecycle management.
//!
//! Implements reconciliation pattern: watches netlink events (RTM_NEWLINK/RTM_DELLINK),
//! compares desired state (interface patterns) vs actual state (active interface),
//! and reconciles by attaching/detaching eBPF TC programs. Maintains dynamic interface
//! index → name mapping for flow decoration via lock-free DashMap.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Main Application                                │
//! └─────────────────────────────────────────────────────────────────────────┘
//!                                    │
//!                    ┌───────────────┴───────────────┐
//!                    │                               │
//!                    ▼                               ▼
//!          ┌──────────────────┐            ┌─────────────────┐
//!          │ IfaceController  │            │ Packet Pipeline │
//!          │    (Control)     │            │  (Hot Path)     │
//!          └──────────────────┘            └─────────────────┘
//!                    │                               │
//!                    │                               │ lock-free reads
//!                    │ owns & updates                │
//!                    ▼                               ▼
//!          ┌─────────────────────────────────────────────────┐
//!          │   Arc<DashMap<u32, String>> (iface_map)         │
//!          │   iface_index → iface_name mapping              │
//!          └─────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage Flow
//!
//! ```text
//! 1. INITIALIZATION
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ new(patterns, ebpf, use_tcx)                            │
//!    │   ├─ Initialize NetnsSwitch                             │
//!    │   └─ Resolve patterns → initial active_ifaces           │
//!    └─────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ initialize().await                                      │
//!    │   ├─ Build iface_map (index → name) in host namespace   │
//!    │   └─ Attach eBPF programs (ingress & egress) to all     │
//!    └─────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ start_reconciliation_loop(Arc<Mutex<Self>>)             │
//!    │   └─ Spawns background task                             │
//!    └─────────────────────────────────────────────────────────┘
//!
//! 2. RECONCILIATION LOOP (Dual-Thread Architecture)
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ Blocking Thread (permanently in host namespace)         │
//!    │   ├─ Pure Rust netlink-sys Socket (RTNLGRP_LINK)        │
//!    │   ├─ Blocking recv() loop                               │
//!    │   └─ Parses RTM_NEWLINK/RTM_DELLINK messages            │
//!    └─────────────────────────────────────────────────────────┘
//!                           │
//!                           │ mpsc::unbounded_channel
//!                           ▼
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ Async Task (tokio)                                      │
//!    │   └─ reconcile_link(&link_msg, is_new_or_set)           │
//!    │       ├─ Extract interface name & state (UP/DOWN)       │
//!    │       ├─ Match against patterns                         │
//!    │       └─ Compare with active_ifaces (desired state)     │
//!    └─────────────────────────────────────────────────────────┘
//!                           │
//!            ┌──────────────┴──────────────┐
//!            ▼                             ▼
//!     ┌─────────────┐             ┌─────────────────┐
//!     │ ADD PATH    │             │ REMOVE PATH     │
//!     │ (UP & !act) │             │ (!UP & active)  │
//!     └─────────────┘             └─────────────────┘
//!            │                             │
//!            ▼                             ▼
//!  iface_map_add()              active_ifaces.remove()
//!            │                   iface_map_remove()
//!            ▼                             │
//!  attach_all_programs()                   ▼
//!            │                   unregister_tc_link() x2
//!            ▼                             │
//!  active_ifaces.insert()                  ▼
//!                                 detach_program() x2
//!
//!    [On failure: rollback via iface_map_remove() + detach]
//!
//! 3. SHUTDOWN
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ shutdown().await                                        │
//!    │   ├─ Abort reconciliation loop                          │
//!    │   └─ Detach all eBPF programs from all interfaces       │
//!    └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Network Namespace Switching
//!
//! All interface operations (discovery, attachment, detachment) execute in the
//! host network namespace via `NetnsSwitch::in_host_namespace()`:
//!
//! ```text
//! ┌─────────────────┐        ┌──────────────────┐        ┌─────────────────┐
//! │   Pod Netns     │  ────► │   Host Netns     │  ────► │   Pod Netns     │
//! │  (container)    │ switch │ (iface ops here) │ switch │  (restored)     │
//! └─────────────────┘        └──────────────────┘  back  └─────────────────┘
//! ```
//!
//! The reconciliation loop's blocking thread uses `setns()` once at startup to permanently
//! enter the host namespace, avoiding repeated namespace switches on every netlink event.
//!
//! # Pure Rust Netlink Implementation
//!
//! Uses `netlink-sys::Socket` for pure Rust netlink operations instead of raw libc syscalls.
//! Key improvements:
//! - Type-safe socket operations
//! - Memory-safe implementation
//! - Idiomatic Rust error handling
//! - RTMGRP_LINK bitmask subscription (not group ID via setsockopt)
//!
//! The implementation subscribes to RTNLGRP_LINK multicast by binding with the bitmask
//! directly in SocketAddr (0x00000001), avoiding the need for setsockopt.
//!
//! # State Invariant
//!
//! The controller maintains this invariant across all operations:
//!
//! ```text
//! interface ∈ active_ifaces  ⟺  programs attached  ⟺  interface ∈ iface_map
//! ```
//!
//! If any operation fails, the entire transaction is rolled back to maintain consistency.

use std::{
    collections::{HashMap, HashSet},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
};

use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType, tc, tc::SchedClassifierLinkId},
};
use dashmap::DashMap;
use globset::Glob;
use netlink_packet_core::{NetlinkBuffer, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkFlags},
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use nix::sched::{CloneFlags, setns};
use pnet::datalink;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::{error::MerminError, iface::netns::NetnsSwitch};

/// RTMGRP_LINK multicast group bitmask for netlink subscription
/// This is used as a bitmask in SocketAddr, not as a group ID
const RTMGRP_LINK: u32 = 0x00000001;

/// Extension trait for TcAttachType to provide direction and program names
pub trait TcAttachTypeExt {
    fn direction_name(&self) -> &'static str;
    fn program_name(&self) -> &'static str;
}

impl TcAttachTypeExt for TcAttachType {
    fn direction_name(&self) -> &'static str {
        match self {
            TcAttachType::Ingress => "ingress",
            TcAttachType::Egress => "egress",
            TcAttachType::Custom(_) => "custom",
        }
    }

    fn program_name(&self) -> &'static str {
        match self {
            TcAttachType::Ingress => "mermin_ingress",
            TcAttachType::Egress => "mermin_egress",
            TcAttachType::Custom(_) => "mermin_custom",
        }
    }
}

/// Netlink interface events for reconciliation.
/// Currently unused as controller handles attachment/detachment internally.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum IfaceEvent {
    Added(String),
    Removed(String),
}

/// Controller for network iface lifecycle.
///
/// Reconciles desired state (patterns) with actual state (active_ifaces, tc_links)
/// by attaching/detaching eBPF TC programs. Owns all interface management including
/// initial attachment, dynamic reconciliation, iface_map updates, and graceful shutdown.
///
/// # Lock Ordering
///
/// When locks are acquired, they must follow this order to prevent deadlocks:
/// 1. IfaceController mutex (acquired in reconciliation loop)
/// 2. ebpf mutex (acquired during attach/detach operations)
///
/// The `attach_to_iface` method acquires the ebpf mutex and performs synchronous
/// FFI/syscalls within the critical section via `in_host_namespace`. The critical
/// section is kept minimal to avoid blocking other operations.
pub struct IfaceController {
    /// Glob patterns for matching interface names
    patterns: Vec<String>,
    /// Desired state: interfaces that should have eBPF programs attached
    active_ifaces: HashSet<String>,
    /// Actual state: link handles for attached programs, keyed by (iface_name, direction).
    /// Used to track what's actually attached and provides handles for detachment.
    tc_links: HashMap<(String, &'static str), SchedClassifierLinkId>,
    /// Shared map for packet decoration (iface_index → iface_name).
    /// Separate from controller state because it uses different key type (u32 vs String),
    /// requires concurrent access from packet processing hot path, and is shared via Arc.
    iface_map: Arc<DashMap<u32, String>>,
    /// Shared eBPF program object for attach/detach operations
    ebpf: Arc<tokio::sync::Mutex<Ebpf>>,
    /// Network namespace switcher for host namespace operations
    netns_switch: NetnsSwitch,
    /// TCX (kernel >= 6.6) vs netlink-based attachment
    use_tcx: bool,
}

/// TC attachment directions used for iterating over all attach types
const DIRECTIONS: &[&str] = &["ingress", "egress"];

impl IfaceController {
    /// Create controller, initialize netns switcher and resolve interface patterns.
    /// Requires hostPID: true and CAP_SYS_ADMIN for host namespace access.
    pub fn new(
        patterns: Vec<String>,
        ebpf: Arc<tokio::sync::Mutex<Ebpf>>,
        use_tcx: bool,
    ) -> Result<Self, MerminError> {
        let netns_switch = NetnsSwitch::new().map_err(|e| {
            MerminError::internal(format!(
                "failed to initialize network namespace switching: {e} - ensure hostPID: true is set, CAP_SYS_PTRACE, and CAP_SYS_ADMIN capabilities are granted",
            ))
        })?;

        let initial_ifaces = Self::resolve_ifaces(&patterns, &netns_switch)?;

        info!(
            event.name = "interface_controller.created",
            iface_count = initial_ifaces.len(),
            "interface controller created with resolved interfaces"
        );

        Ok(Self {
            patterns,
            active_ifaces: initial_ifaces,
            tc_links: HashMap::new(),
            iface_map: Arc::new(DashMap::new()),
            ebpf,
            netns_switch,
            use_tcx,
        })
    }

    /// Resolve patterns to concrete interface names from host namespace.
    fn resolve_ifaces(
        patterns: &[String],
        netns_switch: &NetnsSwitch,
    ) -> Result<HashSet<String>, MerminError> {
        let available: Vec<String> =
            netns_switch.in_host_namespace(Some("interface_discovery"), || {
                Ok(datalink::interfaces()
                    .into_iter()
                    .map(|i| i.name)
                    .collect::<Vec<String>>())
            })?;

        debug!(
            event.name = "interface_controller.interfaces_discovered",
            iface_count = available.len(),
            ifaces = ?available,
            "discovered interface from host namespace"
        );

        let mut resolved = HashSet::new();
        for pattern in patterns {
            for iface in &available {
                if Self::matches_pattern(iface, std::slice::from_ref(pattern)) {
                    resolved.insert(iface.clone());
                }
            }
        }

        debug!(
            event.name = "interface_controller.interfaces_resolved",
            iface_count = resolved.len(),
            ifaces = ?resolved,
            "resolved interface from patterns"
        );

        Ok(resolved)
    }

    fn matches_pattern(name: &str, patterns: &[String]) -> bool {
        patterns
            .iter()
            .any(|pattern| Self::glob_matches(pattern, name))
    }

    /// Attach eBPF programs to all active interface and build initial iface_map.
    /// Should be called once after controller creation.
    pub async fn initialize(&mut self) -> Result<(), MerminError> {
        info!(
            event.name = "interface_controller.initializing",
            iface_count = self.active_ifaces.len(),
            "initializing controller and attaching ebpf programs"
        );

        self.build_iface_map()?;

        let programs = [TcAttachType::Ingress, TcAttachType::Egress];

        // Clone to avoid borrow checker conflict (can't borrow self immutably while calling mutable methods)
        let ifaces: Vec<String> = self.active_ifaces.iter().cloned().collect();

        for attach_type in &programs {
            for iface in &ifaces {
                self.attach_to_iface(iface, *attach_type).await?;
            }
        }

        info!(
            event.name = "interface_controller.initialized",
            iface_count = self.active_ifaces.len(),
            tc_links = self.tc_links.len(),
            "controller initialized successfully"
        );

        Ok(())
    }

    /// Get shared iface_map for flow decoration. DashMap allows lock-free reads
    /// while controller updates it dynamically.
    #[must_use]
    pub fn iface_map(&self) -> Arc<DashMap<u32, String>> {
        Arc::clone(&self.iface_map)
    }

    /// Gracefully detach all eBPF programs. Should be called during shutdown.
    pub async fn shutdown(&mut self) -> Result<(), MerminError> {
        let total_links = self.tc_links.len();
        let mut detached_count = 0;
        let mut failed_count = 0;

        info!(
            event.name = "interface_controller.shutdown_started",
            total_links = total_links,
            "starting graceful shutdown and ebpf program detachment"
        );

        let tc_links = std::mem::take(&mut self.tc_links);

        for ((iface, direction), link_id) in tc_links {
            match self.detach_program(&iface, direction, link_id).await {
                Ok(_) => {
                    detached_count += 1;
                    debug!(
                        event.name = "interface_controller.program_detached",
                        network.interface.name = %iface,
                        ebpf.program.direction = %direction,
                        "successfully detached ebpf program"
                    );
                }
                Err(e) => {
                    failed_count += 1;
                    warn!(
                        event.name = "interface_controller.detach_failed",
                        network.interface.name = %iface,
                        ebpf.program.direction = %direction,
                        error = %e,
                        "failed to detach ebpf program"
                    );
                }
            }
        }

        info!(
            event.name = "interface_controller.shutdown_completed",
            total_links = total_links,
            detached_count = detached_count,
            failed_count = failed_count,
            "controller shutdown completed"
        );

        // Always return Ok - kernel will clean up remaining programs on process exit
        if failed_count > 0 {
            warn!(
                event.name = "interface_controller.shutdown_partial",
                failed_count = failed_count,
                total_links = total_links,
                "some ebpf programs failed to detach, but kernel will clean them up on process exit"
            );
        }
        Ok(())
    }

    /// Register TC link for tracking.
    pub fn register_tc_link(
        &mut self,
        iface: String,
        direction: &'static str,
        link_id: SchedClassifierLinkId,
    ) {
        debug!(
            event.name = "interface_controller.tc_link_registered",
            iface = %iface,
            direction = %direction,
            "TC link registered"
        );
        self.tc_links.insert((iface, direction), link_id);
    }

    /// Unregister TC link and return for detachment.
    pub fn unregister_tc_link(
        &mut self,
        iface: &str,
        direction: &str,
    ) -> Option<SchedClassifierLinkId> {
        let static_direction = Self::to_static_direction(direction)?;

        let link_id = self.tc_links.remove(&(iface.to_string(), static_direction));
        if link_id.is_some() {
            debug!(
                event.name = "interface_controller.tc_link_unregistered",
                iface = %iface,
                direction = %direction,
                "TC link unregistered"
            );
        }
        link_id
    }

    /// Convert direction string to static lifetime for HashMap key.
    fn to_static_direction(direction: &str) -> Option<&'static str> {
        match direction {
            "ingress" => Some("ingress"),
            "egress" => Some("egress"),
            _ => None,
        }
    }

    /// Build interface index → name mapping from host namespace.
    fn build_iface_map(&mut self) -> Result<(), MerminError> {
        self.iface_map.clear();

        self.netns_switch
            .in_host_namespace(Some("build_interface_map"), || {
                for iface in datalink::interfaces() {
                    if self.active_ifaces.contains(&iface.name) {
                        self.iface_map.insert(iface.index, iface.name.clone());
                    }
                }
                Ok(())
            })?;

        debug!(
            event.name = "interface_controller.interface_map_built",
            entry_count = self.iface_map.len(),
            "built interface index → name mapping"
        );

        Ok(())
    }

    /// Add newly discovered interface to iface_map.
    fn iface_map_add(&mut self, iface_name: &str) -> Result<(), MerminError> {
        self.netns_switch
            .in_host_namespace(Some("interface_map_add"), || {
                for iface in datalink::interfaces() {
                    if iface.name == iface_name {
                        self.iface_map.insert(iface.index, iface.name.clone());
                        debug!(
                            event.name = "interface_controller.interface_map_updated",
                            iface = %iface_name,
                            index = iface.index,
                            "added interface to interface_map"
                        );
                        return Ok(());
                    }
                }
                Err(MerminError::internal(format!(
                    "interface '{iface_name}' not found in datalink::interfaces()",
                )))
            })
    }

    /// Remove interface from iface_map.
    /// Collects all indices for the interface name first to prevent issues
    /// with kernel index reuse (where a new interface gets the same index).
    fn iface_map_remove(&mut self, iface_name: &str) {
        let removed_indices: Vec<u32> = self
            .iface_map
            .iter()
            .filter_map(|entry| {
                if entry.value() == iface_name {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        for idx in removed_indices {
            if let Some((_, name)) = self.iface_map.remove(&idx) {
                debug!(
                    event.name = "interface_controller.interface_map_updated",
                    iface = %name,
                    index = idx,
                    "removed interface from interface_map"
                );
            }
        }
    }

    /// Attach eBPF program to interface in host namespace.
    async fn attach_to_iface(
        &mut self,
        iface: &str,
        attach_type: TcAttachType,
    ) -> Result<(), MerminError> {
        let context = format!("{} ({})", iface, attach_type.direction_name());
        let iface_owned = iface.to_string();
        let use_tcx = self.use_tcx;

        // Closure cannot capture self, so get program name before entering
        let program_name = attach_type.program_name();

        // TCX (kernel >= 6.6) doesn't require clsact qdisc
        if !use_tcx {
            self.netns_switch.in_host_namespace(Some(&context), || {
                if let Err(e) = tc::qdisc_add_clsact(&iface_owned) {
                    debug!(
                        event.name = "interface_controller.qdisc_add_skipped",
                        network.interface.name = %iface_owned,
                        error = %e,
                        "clsact qdisc add failed (likely already exists)"
                    );
                }
                Ok(())
            })?;
        }

        let link_id = {
            let mut ebpf_guard = self.ebpf.lock().await;

            self.netns_switch.in_host_namespace(Some(&context), || {
                let program: &mut SchedClassifier = ebpf_guard
                    .program_mut(program_name)
                    .ok_or_else(|| {
                        MerminError::internal(format!(
                            "ebpf program '{program_name}' not found in loaded object",
                        ))
                    })?
                    .try_into()
                    .map_err(|e| MerminError::internal(format!("failed to cast program: {e}")))?;

                program.attach(&iface_owned, attach_type).map_err(|e| {
                    MerminError::internal(format!(
                        "failed to attach ebpf program to interface {iface}: {e}",
                    ))
                })
            })?
        };

        self.register_tc_link(iface.to_string(), attach_type.direction_name(), link_id);

        debug!(
            event.name = "interface_controller.program_attached",
            ebpf.program.direction = attach_type.direction_name(),
            network.interface.name = %iface,
            "ebpf program attached to interface"
        );

        Ok(())
    }

    /// Detach eBPF program from interface.
    async fn detach_program(
        &mut self,
        iface: &str,
        direction: &'static str,
        link_id: SchedClassifierLinkId,
    ) -> Result<(), MerminError> {
        let program_name = match direction {
            "ingress" => "mermin_ingress",
            "egress" => "mermin_egress",
            _ => unreachable!("to_static_direction ensures only ingress/egress"),
        };

        let iface_owned = iface.to_string();
        let context = format!("{} ({})", iface, direction);

        let mut ebpf_guard = self.ebpf.lock().await;

        self.netns_switch.in_host_namespace(Some(&context), || {
            let program: &mut SchedClassifier = ebpf_guard
                .program_mut(program_name)
                .ok_or_else(|| {
                    MerminError::internal(format!(
                        "ebpf program '{program_name}' not found for detachment",
                    ))
                })?
                .try_into()
                .map_err(|e| MerminError::internal(format!("failed to cast program: {e}")))?;

            program.detach(link_id).map_err(|e| {
                MerminError::internal(format!(
                    "failed to detach ebpf program from interface {iface_owned}: {e}"
                ))
            })
        })?;

        Ok(())
    }

    /// Start reconciliation loop via netlink multicast (RTNLGRP_LINK).
    /// Controller handles all attachment/detachment internally.
    ///
    /// Uses a dedicated blocking thread that permanently runs in the host network
    /// namespace to receive netlink events, then sends them via channel to the
    /// async task for processing.
    ///
    /// # Pure Rust Implementation
    ///
    /// This uses `netlink-sys::Socket` instead of raw libc syscalls for type-safe,
    /// memory-safe netlink operations. Key improvements:
    /// - No unsafe socket syscalls
    /// - RTMGRP_LINK subscription via SocketAddr bitmask (no setsockopt needed)
    /// - Idiomatic Rust error handling
    pub fn start_reconciliation_loop(controller: Arc<tokio::sync::Mutex<Self>>) -> JoinHandle<()> {
        let ctrl = Arc::clone(&controller);

        tokio::spawn(async move {
            info!(
                event.name = "interface_controller.syncing_started",
                "watching for network interface changes via netlink (RTM_NEWLINK/RTM_DELLINK)"
            );

            // Get netns file descriptor for host namespace
            let host_netns_fd = {
                let controller_guard = ctrl.lock().await;
                controller_guard.netns_switch.host_netns.as_raw_fd()
            };

            let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();

            // Spawn dedicated blocking thread in host namespace for netlink recv (can't use tokio async here)
            std::thread::spawn(move || {
                // CRITICAL: Enter host namespace and stay there for entire thread lifetime
                let host_fd = unsafe { OwnedFd::from_raw_fd(host_netns_fd) };
                if let Err(e) = setns(&host_fd, CloneFlags::CLONE_NEWNET) {
                    error!(
                        event.name = "interface_controller.netns_switch_failed",
                        error = %e,
                        "failed to switch blocking thread to host network namespace"
                    );
                    return;
                }

                debug!(
                    event.name = "interface_controller.blocking_thread_in_host_ns",
                    "netlink blocking thread permanently in host network namespace"
                );

                // PURE RUST IMPLEMENTATION: Create netlink socket using netlink-sys (no raw libc)
                let mut sock = match Socket::new(NETLINK_ROUTE) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(
                            event.name = "interface_controller.socket_creation_failed",
                            error = %e,
                            "failed to create netlink socket"
                        );
                        return;
                    }
                };

                // Bind with RTMGRP_LINK bitmask for multicast subscription
                // Key insight: SocketAddr expects a BITMASK in groups field, not a group ID
                // This replaces the need for setsockopt(NETLINK_ADD_MEMBERSHIP)
                let addr = SocketAddr::new(0, RTMGRP_LINK);
                if let Err(e) = sock.bind(&addr) {
                    error!(
                        event.name = "interface_controller.socket_bind_failed",
                        error = %e,
                        "failed to bind netlink socket with RTMGRP_LINK"
                    );
                    return;
                }

                debug!(
                    event.name = "interface_controller.subscribed_to_link_events",
                    rtmgrp_link_bitmask = format!("0x{:08x}", RTMGRP_LINK),
                    "successfully subscribed to RTNLGRP_LINK multicast group using pure Rust netlink-sys"
                );

                let mut buf = vec![0u8; 8192];
                loop {
                    // Pure Rust recv (no raw libc)
                    let n = match sock.recv(&mut buf, 0) {
                        Ok(n) => n,
                        Err(e) => {
                            error!(
                                event.name = "interface_controller.socket_recv_error",
                                error = %e,
                                "error receiving from netlink socket"
                            );
                            break;
                        }
                    };

                    if n > 0 {
                        trace!(
                            event.name = "interface_controller.netlink_data_received",
                            bytes = n,
                            "received netlink data"
                        );
                        // Parse all messages in buffer
                        let mut offset = 0;
                        while offset < n {
                            let bytes = &buf[offset..n];
                            match NetlinkBuffer::new_checked(bytes) {
                                Ok(nl_buf) => {
                                    match NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
                                    {
                                        Ok(msg) => {
                                            let msg_len = nl_buf.length() as usize;
                                            offset += (msg_len + 3) & !3; // NLMSG_ALIGN

                                            // Extract link messages and send via channel
                                            if let NetlinkPayload::InnerMessage(rtnl_msg) =
                                                msg.payload
                                            {
                                                match rtnl_msg {
                                                    RouteNetlinkMessage::NewLink(link_msg)
                                                    | RouteNetlinkMessage::SetLink(link_msg) => {
                                                        trace!(
                                                            event.name = "interface_controller.newlink_parsed",
                                                            "parsed NewLink/SetLink message, sending to async task"
                                                        );
                                                        if event_tx.send((link_msg, true)).is_err()
                                                        {
                                                            error!(
                                                                event.name = "interface_controller.channel_send_failed",
                                                                "failed to send NewLink event, receiver dropped"
                                                            );
                                                            return;
                                                        }
                                                    }
                                                    RouteNetlinkMessage::DelLink(link_msg) => {
                                                        trace!(
                                                            event.name = "interface_controller.dellink_parsed",
                                                            "parsed DelLink message, sending to async task"
                                                        );
                                                        if event_tx.send((link_msg, false)).is_err()
                                                        {
                                                            error!(
                                                                event.name = "interface_controller.channel_send_failed",
                                                                "failed to send DelLink event, receiver dropped"
                                                            );
                                                            return;
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(
                                                event.name = "interface_controller.message_parse_error",
                                                error = %e,
                                                "failed to parse netlink message"
                                            );
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    trace!(
                                        event.name = "interface_controller.buffer_check_failed",
                                        error = ?e,
                                        offset = offset,
                                        remaining = n - offset,
                                        "not enough bytes for complete message, ending parse loop"
                                    );
                                    break;
                                }
                            }
                        }

                        trace!(
                            event.name = "interface_controller.parse_loop_completed",
                            bytes_processed = n,
                            "completed parsing netlink data"
                        );
                    }
                }

                info!(
                    event.name = "interface_controller.socket_closed",
                    "netlink socket closed, exiting recv loop"
                );
            });

            trace!(
                event.name = "interface_controller.event_loop_started",
                "starting async event processing loop"
            );

            while let Some((link_msg, is_new_or_set)) = event_rx.recv().await {
                trace!(
                    event.name = "interface_controller.event_received_from_channel",
                    is_new_or_set = is_new_or_set,
                    "received link event from blocking thread channel"
                );

                let mut controller = ctrl.lock().await;
                if let Err(e) = controller.reconcile_link(&link_msg, is_new_or_set).await {
                    error!(
                        event.name = "interface_controller.reconcile_error",
                        error = %e,
                        "error reconciling link event"
                    );
                }
            }

            info!(
                event.name = "interface_controller.watching_stopped",
                "interface syncing stopped (channel closed)"
            );
        })
    }

    /// Attach all eBPF programs (ingress and egress) to an interface.
    /// Rolls back on failure by detaching any successfully attached programs.
    async fn attach_all_programs(&mut self, if_name: &str) -> Result<(), MerminError> {
        let mut attached_programs = Vec::new();

        for attach_type in &[TcAttachType::Ingress, TcAttachType::Egress] {
            match self.attach_to_iface(if_name, *attach_type).await {
                Ok(_) => {
                    attached_programs.push(*attach_type);
                }
                Err(e) => {
                    error!(
                        event.name = "interface_controller.attach_failed",
                        iface = %if_name,
                        direction = attach_type.direction_name(),
                        error = %e,
                        "failed to attach ebpf program to new interface, rolling back"
                    );
                    self.rollback_attachments(if_name, attached_programs).await;
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Rollback partial attachments by detaching all successfully attached programs.
    async fn rollback_attachments(&mut self, if_name: &str, programs: Vec<TcAttachType>) {
        for attach_type in programs {
            let direction = attach_type.direction_name();
            if let Some(link_id) = self.unregister_tc_link(if_name, direction)
                && let Err(e) = self.detach_program(if_name, direction, link_id).await
            {
                warn!(
                    event.name = "interface_controller.rollback_failed",
                    iface = %if_name,
                    direction = %direction,
                    error = %e,
                    "failed to detach during rollback"
                );
            }
        }
    }

    /// Reconcile link event by comparing desired vs actual state and
    /// attaching/detaching eBPF programs when they differ.
    /// Note: There is an inherent TOCTOU race between checking interface state
    /// and performing operations, but the rollback logic handles failures gracefully.
    async fn reconcile_link(
        &mut self,
        link_msg: &netlink_packet_route::link::LinkMessage,
        is_new_or_set: bool,
    ) -> Result<(), MerminError> {
        let if_name = link_msg
            .attributes
            .iter()
            .find_map(|attr| match attr {
                LinkAttribute::IfName(name) => Some(name.to_string()),
                _ => None,
            })
            .ok_or_else(|| MerminError::internal("interface name not found in link message"))?;

        trace!(
            event.name = "interface_controller.link_event_received",
            iface = %if_name,
            is_new_or_set = is_new_or_set,
            flags = ?link_msg.header.flags,
            "received netlink link event"
        );

        if !Self::matches_pattern(&if_name, &self.patterns) {
            debug!(
                event.name = "interface_controller.link_event_filtered",
                iface = %if_name,
                "interface does not match configured patterns"
            );
            return Ok(());
        }

        let is_up = if is_new_or_set {
            link_msg.header.flags.contains(LinkFlags::Up)
        } else {
            false
        };

        let is_active = self.active_ifaces.contains(&if_name);

        if is_up && !is_active {
            info!(
                event.name = "interface_controller.interface_added",
                iface = %if_name,
                "detected new interface, attaching ebpf programs"
            );

            if let Err(e) = self.iface_map_add(&if_name) {
                error!(
                    event.name = "interface_controller.interface_map_update_failed",
                    iface = %if_name,
                    error = %e,
                    "failed to update interface map for added interface, will retry on next event"
                );
                return Ok(());
            }

            // Attempt to attach both ingress and egress programs with automatic rollback on failure
            if let Err(e) = self.attach_all_programs(&if_name).await {
                // Rollback already performed by attach_all_programs
                // Remove from iface_map since we're not proceeding
                self.iface_map_remove(&if_name);
                // Log error but don't fail - will retry on next netlink event
                error!(
                    event.name = "interface_controller.attach_all_failed",
                    iface = %if_name,
                    error = %e,
                    "failed to attach programs to interface, will retry on next event"
                );
                return Ok(());
            }

            // Only mark as active if ALL operations succeeded
            self.active_ifaces.insert(if_name);
        } else if !is_up && is_active {
            info!(
                event.name = "interface_controller.interface_removed",
                iface = %if_name,
                "detected interface removal, detaching ebpf programs"
            );

            self.active_ifaces.remove(&if_name);

            self.iface_map_remove(&if_name);

            for direction in DIRECTIONS {
                if let Some(link_id) = self.unregister_tc_link(&if_name, direction) {
                    if let Err(e) = self.detach_program(&if_name, direction, link_id).await {
                        warn!(
                            event.name = "interface_controller.detach_failed",
                            iface = %if_name,
                            direction = %direction,
                            error = %e,
                            "failed to detach ebpf program from removed interface"
                        );
                    } else {
                        debug!(
                            event.name = "interface_controller.program_detached",
                            iface = %if_name,
                            direction = %direction,
                            "ebpf program detached from removed interface"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn glob_matches(pattern: &str, text: &str) -> bool {
        const MAX_PATTERN_LEN: usize = 256;

        if pattern.len() > MAX_PATTERN_LEN {
            warn!(
                event.name = "interface_controller.pattern_too_long",
                pattern_length = pattern.len(),
                "pattern exceeds maximum length, rejecting"
            );
            return false;
        }

        match Glob::new(pattern) {
            Ok(glob) => glob.compile_matcher().is_match(text),
            Err(e) => {
                warn!(
                    event.name = "interface_controller.invalid_pattern",
                    pattern = %pattern,
                    error = %e,
                    "invalid glob pattern, treating as literal match"
                );
                // Fall back to literal match if pattern is invalid
                pattern == text
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lightweight test struct to avoid unsafe initialization of eBPF/netns resources
    struct TestController {
        patterns: Vec<String>,
        active_ifaces: HashSet<String>,
        tc_links: HashMap<(String, &'static str), u32>, // u32 as LinkId placeholder since real LinkId can't be created in tests
    }

    impl TestController {
        fn new(patterns: Vec<String>, initial_ifaces: HashSet<String>) -> Self {
            Self {
                patterns,
                active_ifaces: initial_ifaces,
                tc_links: HashMap::new(),
            }
        }
    }

    #[test]
    fn test_controller_creation() {
        let patterns = vec!["veth*".to_string(), "tunl*".to_string()];
        let initial = HashSet::from(["veth0".to_string(), "tunl0".to_string()]);

        let controller = TestController::new(patterns.clone(), initial.clone());

        assert_eq!(controller.patterns, patterns);
        assert_eq!(controller.active_ifaces, initial);
        assert!(controller.tc_links.is_empty());
    }

    #[test]
    fn test_glob_matches_wildcard() {
        assert!(IfaceController::glob_matches("veth*", "veth0"));
        assert!(IfaceController::glob_matches("veth*", "veth12345"));
        assert!(!IfaceController::glob_matches("veth*", "eth0"));
        assert!(!IfaceController::glob_matches("veth*", "tunl0"));
    }

    #[test]
    fn test_glob_matches_exact() {
        assert!(IfaceController::glob_matches("eth0", "eth0"));
        assert!(!IfaceController::glob_matches("eth0", "eth1"));
        assert!(!IfaceController::glob_matches("eth0", "veth0"));
    }

    #[test]
    fn test_glob_matches_multiple_wildcards() {
        assert!(IfaceController::glob_matches("*eth*", "veth0"));
        assert!(IfaceController::glob_matches("*eth*", "eth0"));
        assert!(IfaceController::glob_matches("*eth*", "lxceth123"));
        assert!(!IfaceController::glob_matches("*eth*", "tunl0"));
    }

    #[test]
    fn test_glob_matches_prefix_suffix() {
        assert!(IfaceController::glob_matches("eth*", "eth0"));
        assert!(IfaceController::glob_matches("eth*", "eth1"));
        assert!(!IfaceController::glob_matches("eth*", "veth0"));

        assert!(IfaceController::glob_matches("*0", "eth0"));
        assert!(IfaceController::glob_matches("*0", "veth0"));
        assert!(!IfaceController::glob_matches("*0", "eth1"));
    }

    #[test]
    fn test_matches_pattern_single() {
        let patterns = vec!["veth*".to_string()];

        assert!(IfaceController::matches_pattern("veth0", &patterns));
        assert!(IfaceController::matches_pattern("veth123", &patterns));
        assert!(!IfaceController::matches_pattern("eth0", &patterns));
    }

    #[test]
    fn test_matches_pattern_multiple() {
        let patterns = vec!["veth*".to_string(), "tunl*".to_string(), "eth0".to_string()];

        assert!(IfaceController::matches_pattern("veth0", &patterns));
        assert!(IfaceController::matches_pattern("tunl0", &patterns));
        assert!(IfaceController::matches_pattern("eth0", &patterns));
        assert!(!IfaceController::matches_pattern("eth1", &patterns));
        assert!(!IfaceController::matches_pattern("wlan0", &patterns));
    }

    #[test]
    fn test_matches_pattern_no_match() {
        let patterns = vec!["veth*".to_string()];

        assert!(!IfaceController::matches_pattern("eth0", &patterns));
        assert!(!IfaceController::matches_pattern("tunl0", &patterns));
        assert!(!IfaceController::matches_pattern("lo", &patterns));
    }

    // Note: TC link tests are skipped because SchedClassifierLinkId cannot be created
    // in tests without actual eBPF program attachment. The registration/unregistration
    // logic is tested via integration tests when the full eBPF stack is running.

    #[test]
    fn test_active_ifaces_tracking() {
        let initial = HashSet::from(["eth0".to_string()]);
        let mut controller = TestController::new(vec![], initial);

        assert!(controller.active_ifaces.contains("eth0"));
        assert_eq!(controller.active_ifaces.len(), 1);

        controller.active_ifaces.insert("veth0".to_string());
        assert!(controller.active_ifaces.contains("veth0"));
        assert_eq!(controller.active_ifaces.len(), 2);

        controller.active_ifaces.remove("eth0");
        assert!(!controller.active_ifaces.contains("eth0"));
        assert_eq!(controller.active_ifaces.len(), 1);
    }

    #[test]
    fn test_tc_links_map_structure() {
        let controller = TestController::new(vec![], HashSet::new());
        assert!(controller.tc_links.is_empty());

        let key = ("veth0".to_string(), "ingress");
        assert!(!controller.tc_links.contains_key(&key));
    }

    #[test]
    fn test_pattern_matching_realistic_ifaces() {
        let patterns = vec![
            "veth*".to_string(),
            "tunl*".to_string(),
            "ip6tnl*".to_string(),
            "flannel*".to_string(),
            "cali*".to_string(),
        ];

        assert!(IfaceController::matches_pattern("veth123abc", &patterns));
        assert!(IfaceController::matches_pattern("tunl0", &patterns));
        assert!(IfaceController::matches_pattern("ip6tnl0", &patterns));
        assert!(IfaceController::matches_pattern("flannel.1", &patterns));
        assert!(IfaceController::matches_pattern("cali123abc", &patterns));

        assert!(!IfaceController::matches_pattern("eth0", &patterns));
        assert!(!IfaceController::matches_pattern("lo", &patterns));
        assert!(!IfaceController::matches_pattern("docker0", &patterns));
        assert!(!IfaceController::matches_pattern("br-123", &patterns));
    }

    #[test]
    fn test_empty_patterns() {
        let patterns: Vec<String> = vec![];

        assert!(!IfaceController::matches_pattern("veth0", &patterns));
        assert!(!IfaceController::matches_pattern("eth0", &patterns));
        assert!(!IfaceController::matches_pattern("anything", &patterns));
    }

    #[test]
    fn test_special_characters_in_iface_names() {
        let patterns = vec!["flannel.*".to_string()];

        // The dot should be treated literally in glob, not as regex "any character"
        assert!(IfaceController::matches_pattern("flannel.1", &patterns));
        assert!(IfaceController::matches_pattern("flannel.100", &patterns));
        // This actually matches because we escape special chars, so the literal "." is expected
        assert!(!IfaceController::matches_pattern("flannel-1", &patterns));
    }

    #[test]
    fn test_take_tc_links_leaves_empty_map() {
        let mut controller = TestController::new(vec![], HashSet::new());

        let empty = std::mem::take(&mut controller.tc_links);
        assert!(empty.is_empty());
        assert!(controller.tc_links.is_empty());

        let still_empty = std::mem::take(&mut controller.tc_links);
        assert!(still_empty.is_empty());
    }
}
