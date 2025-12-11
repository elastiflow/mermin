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
//! 1. INITIALIZATION (Main Thread)
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ main.rs: Load eBPF, extract maps                        │
//!    │   ├─ Ebpf loaded with programs                          │
//!    │   └─ Maps extracted: FLOW_STATS, FLOW_EVENTS            │
//!    └─────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ new(patterns, iface_map, ebpf, ...)                     │
//!    │   └─ Resolve patterns → initial active_ifaces           │
//!    │       (Thread not yet in host namespace)                │
//!    └─────────────────────────────────────────────────────────┘
//!                           │
//!                           │ Controller moved to thread
//!                           ▼
//! 2. CONTROLLER THREAD (Permanently in Host Namespace)
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ threads::spawn_controller_thread()                      │
//!    │   ├─ setns() to host namespace (once, permanent)        │
//!    │   └─ Event loop: process commands + netlink events      │
//!    └─────────────────────────────────────────────────────────┘
//!                           │
//!            ┌──────────────┴──────────────┐
//!            │                             │
//!            ▼                             ▼
//!    ┌──────────────┐           ┌──────────────────┐
//!    │ Initialize   │           │ NetlinkEvent     │
//!    │ Command      │           │ from netlink     │
//!    │              │           │ thread           │
//!    └──────────────┘           └──────────────────┘
//!            │                             │
//!            ▼                             ▼
//!    initialize()              handle_netlink_event()
//!       ├─ build_iface_map()      ├─ InterfaceUp
//!       └─ attach programs         │   └─ attach programs
//!                                  └─ InterfaceDown
//!                                      └─ detach programs
//!
//! 3. NETLINK THREAD (Permanently in Host Namespace)
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ threads::spawn_netlink_thread()                         │
//!    │   ├─ setns() to host namespace (once, permanent)        │
//!    │   ├─ Create netlink socket (RTNLGRP_LINK)               │
//!    │   ├─ Blocking recv() loop                               │
//!    │   └─ Send NetlinkEvent to controller thread             │
//!    └─────────────────────────────────────────────────────────┘
//!
//! 4. SHUTDOWN
//!    ┌─────────────────────────────────────────────────────────┐
//!    │ main.rs: Send Shutdown command                          │
//!    │   └─ Controller: shutdown()                             │
//!    │       └─ Detach all eBPF programs                       │
//!    └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Network Namespace Architecture
//!
//! All interface operations execute in the host network namespace.
//! The controller thread enters host namespace once at startup via `setns()`
//! and stays there permanently:
//!
//! ```text
//! ┌──────────────────┐                    ┌──────────────────────────────┐
//! │  Main Thread     │                    │  Controller Thread           │
//! │  (Pod Netns)     │                    │  (Host Netns - Permanent)    │
//! │                  │                    │                              │
//! │  - API Server    │                    │  - eBPF attach/detach        │
//! │  - Metrics       │   Commands via     │  - Interface discovery       │
//! │  - Flow Producer │   mpsc::channel    │  - Netlink event handling    │
//! │  - K8s Decorator │                    │  - State management          │
//! └──────────────────┘                    └──────────────────────────────┘
//! ```
//!
//! The controller thread uses `setns()` once at startup to permanently
//! enter the host namespace, eliminating namespace switching overhead and
//! preventing namespace restoration failures.
//!
//! # Netlink Socket Implementation
//!
//! Uses raw `libc` socket syscalls instead of `rtnetlink` or `netlink-sys` crates because:
//! - `rtnetlink::new_connection()` doesn't subscribe to multicast groups
//! - `netlink-sys::Socket::recv()` has buffering issues (returns positive byte count but doesn't fill buffer)
//! - Direct syscalls ensure correct multicast subscription via `setsockopt(NETLINK_ADD_MEMBERSHIP)`
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
    sync::Arc,
};

use aya::{
    Ebpf,
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        links::PinnedLink,
        tc::{self, NlOptions, SchedClassifierLinkId, TcAttachOptions, qdisc_detach_program},
    },
};
use crossbeam::channel::Sender;
use dashmap::DashMap;
use globset::Glob;
use pnet::datalink;
use tracing::{debug, error, info, trace, warn};

use crate::{
    error::MerminError,
    iface::types::{ControllerEvent, NetlinkEvent},
    metrics::{
        cleanup::MetricCleanupTracker,
        ebpf::{inc_tc_programs_attached, inc_tc_programs_detached},
    },
    runtime::conf::TcxOrderStrategy,
};

/// Extension trait for TcAttachType to provide direction and program names
pub trait TcAttachTypeExt {
    fn direction_name(&self) -> &'static str;
    fn program_name(&self) -> &'static str;
}

impl TcAttachTypeExt for TcAttachType {
    fn direction_name(&self) -> &'static str {
        match self {
            TcAttachType::Ingress => DIRECTION_INGRESS,
            TcAttachType::Egress => DIRECTION_EGRESS,
            TcAttachType::Custom(_) => "custom",
        }
    }

    fn program_name(&self) -> &'static str {
        match self {
            TcAttachType::Ingress => PROGRAM_NAME_INGRESS,
            TcAttachType::Egress => PROGRAM_NAME_EGRESS,
            TcAttachType::Custom(_) => "mermin_flow_custom",
        }
    }
}

/// Controller that runs in host network namespace.
///
/// Reconciles desired state (patterns) with actual state (active_ifaces, tc_links)
/// by attaching/detaching eBPF TC programs. Runs in a dedicated thread that permanently
/// stays in the host network namespace, eliminating repeated namespace switching.
///
/// ## Thread Architecture
///
/// This controller is designed to run in a dedicated blocking thread that:
/// - Enters host network namespace once at thread startup (via setns)
/// - Stays in host namespace permanently (no switching back)
/// - Handles netlink events and command messages in a single-threaded loop
/// - Performs all eBPF attach/detach operations synchronously
///
/// ## Ownership
///
/// - Direct ownership of `Ebpf` object (programs only, maps extracted beforehand)
/// - Shared ownership of `iface_map` (via Arc<DashMap>) for coordination with main thread
/// - All methods are synchronous/blocking (no async/await)
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
    /// eBPF program object (direct ownership, programs only - maps extracted beforehand)
    ebpf: Ebpf,
    /// TCX (kernel >= 6.6) vs netlink-based attachment
    use_tcx: bool,
    /// TC priority for netlink attachment (kernel < 6.6)
    /// Higher values = lower priority = runs later in chain
    tc_priority: u16,
    /// TCX ordering strategy (kernel >= 6.6)
    /// Controls where programs attach in TCX chain (first/last)
    tcx_order: TcxOrderStrategy,
    /// Whether /sys/fs/bpf is writable for TCX link pinning.
    /// Checked once during initialization to avoid repeated filesystem checks.
    bpf_fs_writable: bool,
    /// Optional channel for sending controller events to main thread for observability
    event_tx: Option<Sender<ControllerEvent>>,
    /// Optional cleanup tracker for removing stale metrics
    cleanup_tracker: Option<MetricCleanupTracker>,
}

/// Direction string constants
const DIRECTION_INGRESS: &str = "ingress";
const DIRECTION_EGRESS: &str = "egress";

/// Program name constants
const PROGRAM_NAME_INGRESS: &str = "mermin_flow_ingress";
const PROGRAM_NAME_EGRESS: &str = "mermin_flow_egress";

/// TC attachment directions used for iterating over all attach types
const DIRECTIONS: &[&str] = &[DIRECTION_INGRESS, DIRECTION_EGRESS];

impl IfaceController {
    /// Create blocking controller that runs in host network namespace.
    ///
    /// This constructor is called from the MAIN thread (before namespace switch).
    /// The controller is then moved to a dedicated thread which enters the host
    /// namespace via `setns()`. Interface discovery happens in `initialize()` after
    /// the namespace switch.
    ///
    /// ## Arguments
    ///
    /// - `patterns` - Glob patterns for matching interface names (e.g., "eth*", "ens*")
    /// - `iface_map` - Shared interface index → name map for packet decoration
    /// - `ebpf` - eBPF object with loaded programs (maps must be extracted beforehand)
    /// - `use_tcx` - Whether to use TCX (kernel >= 6.6) or netlink attachment
    /// - `bpf_fs_writable` - Whether /sys/fs/bpf is writable for TCX link pinning
    /// - `tc_priority` - TC priority for netlink mode (lower number = higher priority)
    /// - `tcx_order` - TCX ordering strategy (First or Last in chain)
    /// - `event_tx` - Optional channel for sending controller events for observability
    /// - `cleanup_tracker` - Optional cleanup tracker for removing stale metrics
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        patterns: Vec<String>,
        iface_map: Arc<DashMap<u32, String>>,
        ebpf: Ebpf,
        use_tcx: bool,
        bpf_fs_writable: bool,
        tc_priority: u16,
        tcx_order: TcxOrderStrategy,
        event_tx: Option<Sender<ControllerEvent>>,
        cleanup_tracker: Option<MetricCleanupTracker>,
    ) -> Result<Self, MerminError> {
        info!(
            event.name = "interface_controller.created",
            pattern_count = patterns.len(),
            use_tcx = use_tcx,
            bpf_fs_writable = bpf_fs_writable,
            "interface controller created, will discover interfaces after namespace switch"
        );

        Ok(Self {
            patterns,
            active_ifaces: HashSet::new(), // Will be populated by initialize() after namespace switch
            tc_links: HashMap::new(),
            iface_map,
            ebpf,
            use_tcx,
            tc_priority,
            tcx_order,
            bpf_fs_writable,
            event_tx,
            cleanup_tracker,
        })
    }

    /// Attach eBPF programs to all active interfaces and build initial iface_map.
    ///
    /// This is a blocking operation that should be called once after controller creation.
    /// Thread must already be in host network namespace.
    pub fn initialize(&mut self) -> Result<(), MerminError> {
        info!(
            event.name = "interface_controller.init_resolving_interfaces",
            pattern_count = self.patterns.len(),
            "resolving interface patterns to concrete interface names"
        );

        self.active_ifaces = Self::resolve_ifaces(&self.patterns)?;

        let sorted_ifaces: Vec<_> = {
            let mut v: Vec<_> = self.active_ifaces.iter().cloned().collect();
            v.sort();
            v
        };

        info!(
            event.name = "interface_controller.init_interfaces_resolved",
            iface_count = self.active_ifaces.len(),
            interfaces = ?sorted_ifaces,
            "resolved interfaces, beginning initialization"
        );

        self.build_iface_map()?;

        // Clean up any orphaned TC programs from previous instances before attaching new ones.
        // This prevents the issue where killed pods leave TC programs attached that intercept traffic.
        if let Err(e) = self.cleanup_orphaned_programs() {
            warn!(
                event.name = "interface_controller.cleanup_failed",
                error = %e,
                "failed to clean up orphaned TC programs, proceeding with attachment anyway"
            );
        }

        let programs = [TcAttachType::Ingress, TcAttachType::Egress];
        let ifaces: Vec<String> = self.active_ifaces.iter().cloned().collect();
        let mut failed_ifaces = HashSet::new();
        let mut success_per_iface: HashMap<String, u32> = HashMap::new();
        let mut success_count = 0u32;

        for attach_type in &programs {
            for iface in &ifaces {
                if let Err(e) = self.attach_to_iface(iface, *attach_type) {
                    warn!(
                        event.name = "interface_controller.init_attach_failed",
                        network.interface.name = %iface,
                        ebpf.program.direction = ?attach_type,
                        error = %e,
                        "failed to attach program during initialization, interface will be retried by reconciliation loop"
                    );
                    failed_ifaces.insert(iface.clone());
                } else {
                    *success_per_iface.entry(iface.clone()).or_insert(0) += 1;
                    success_count += 1;
                }
            }
        }

        // Send events for failed attachments
        for failed_iface in &failed_ifaces {
            if let Some(ref tx) = self.event_tx {
                let _ = tx.send(ControllerEvent::AttachmentFailed {
                    iface: failed_iface.clone(),
                    error: "attachment failed during initialization".to_string(),
                });
            }
        }

        // Only remove interfaces that had failures and didn't succeed completely
        // Cleanup partial attachments for these interfaces
        for failed_iface in &failed_ifaces {
            let successful_attachments = success_per_iface.get(failed_iface).copied().unwrap_or(0);
            if successful_attachments < programs.len() as u32 {
                for direction in DIRECTIONS {
                    if let Err(e) = self.detach_from_iface(failed_iface, direction) {
                        warn!(
                            event.name = "interface_controller.init_cleanup_failed",
                            network.interface.name = %failed_iface,
                            ebpf.program.direction = %direction,
                            error = %e,
                            "failed to cleanup partially attached program"
                        );
                    }
                }
                self.active_ifaces.remove(failed_iface);
                self.iface_map_remove(failed_iface);
            }
        }

        // Send events for successfully attached interfaces
        for iface in &ifaces {
            if !failed_ifaces.contains(iface)
                && let Some(ref tx) = self.event_tx
            {
                let _ = tx.send(ControllerEvent::InterfaceAttached {
                    iface: iface.clone(),
                });
            }
        }

        if !failed_ifaces.is_empty() {
            warn!(
                event.name = "interface_controller.init_partial_success",
                successful_attachments = success_count,
                failed_interfaces = ?failed_ifaces,
                "some interfaces failed during initialization, reconciliation loop will retry"
            );
        }

        info!(
            event.name = "interface_controller.initialized",
            iface_count = self.active_ifaces.len(),
            tc_links = self.tc_links.len(),
            successful_attachments = success_count,
            "controller initialized successfully"
        );

        Ok(())
    }

    /// Gracefully detach all eBPF programs. Should be called during shutdown.
    ///
    /// This is a blocking operation. Thread must be in host network namespace.
    pub fn shutdown(&mut self) -> Result<(), MerminError> {
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
            match self.detach_program(&iface, direction, link_id) {
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

    /// Get shared iface_map for flow decoration. DashMap allows lock-free reads
    /// while controller updates it dynamically.
    #[must_use]
    pub fn iface_map(&self) -> Arc<DashMap<u32, String>> {
        Arc::clone(&self.iface_map)
    }

    /// Build interface index → name mapping from host namespace.
    fn build_iface_map(&mut self) -> Result<(), MerminError> {
        self.iface_map.clear();

        for iface in datalink::interfaces() {
            if self.active_ifaces.contains(&iface.name) {
                self.iface_map.insert(iface.index, iface.name.clone());
            }
        }

        debug!(
            event.name = "interface_controller.interface_map_built",
            entry_count = self.iface_map.len(),
            "built interface index → name mapping"
        );

        Ok(())
    }

    /// Add newly discovered interface to iface_map.
    fn iface_map_add(&mut self, iface_name: &str) -> Result<(), MerminError> {
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

    /// Handle netlink event by reconciling interface state.
    ///
    /// This is the main event handler called by the controller thread in response
    /// to netlink events from the netlink monitoring thread.
    ///
    /// Blocking operation. Thread must be in host network namespace.
    pub fn handle_netlink_event(&mut self, event: NetlinkEvent) -> Result<(), MerminError> {
        match event {
            NetlinkEvent::InterfaceUp { name } => {
                if Self::matches_pattern(&name, &self.patterns)
                    && !self.active_ifaces.contains(&name)
                {
                    info!(
                        event.name = "interface_controller.interface_up",
                        network.interface.name = %name,
                        "interface came up, attaching eBPF programs"
                    );

                    self.iface_map_add(&name)?;

                    let mut attached_programs = Vec::new();

                    for attach_type in &[TcAttachType::Ingress, TcAttachType::Egress] {
                        match self.attach_to_iface(&name, *attach_type) {
                            Ok(()) => {
                                attached_programs.push(*attach_type);
                            }
                            Err(e) => {
                                warn!(
                                    event.name = "interface_controller.attach_failed",
                                    network.interface.name = %name,
                                    ebpf.program.direction = attach_type.direction_name(),
                                    error = %e,
                                    "failed to attach program to new interface, rolling back"
                                );

                                // Rollback: detach any successfully attached programs
                                for prev_attach_type in attached_programs {
                                    let direction = prev_attach_type.direction_name();
                                    if let Err(detach_err) =
                                        self.detach_from_iface(&name, direction)
                                    {
                                        warn!(
                                            event.name = "interface_controller.rollback_detach_failed",
                                            network.interface.name = %name,
                                            ebpf.program.direction = direction,
                                            error = %detach_err,
                                            "failed to detach program during rollback"
                                        );
                                    }
                                }

                                self.iface_map_remove(&name);

                                if let Some(ref tx) = self.event_tx {
                                    let _ = tx.send(ControllerEvent::AttachmentFailed {
                                        iface: name.clone(),
                                        error: format!("{e}"),
                                    });
                                }

                                return Err(e);
                            }
                        }
                    }

                    self.active_ifaces.insert(name.clone());

                    // Mark interface as active to prevent metric cleanup
                    if let Some(ref cleanup_tracker) = self.cleanup_tracker {
                        cleanup_tracker.mark_interface_active(&name);
                    }

                    if let Some(ref tx) = self.event_tx {
                        let _ = tx.send(ControllerEvent::InterfaceAttached { iface: name });
                    }
                }
            }
            NetlinkEvent::InterfaceDown { name } => {
                if self.active_ifaces.contains(&name) {
                    info!(
                        event.name = "interface_controller.interface_down",
                        network.interface.name = %name,
                        "interface went down, detaching eBPF programs"
                    );

                    self.active_ifaces.remove(&name);

                    self.iface_map_remove(&name);

                    for direction in DIRECTIONS {
                        if let Err(e) = self.detach_from_iface(&name, direction) {
                            warn!(
                                event.name = "interface_controller.detach_failed",
                                network.interface.name = %name,
                                ebpf.program.direction = %direction,
                                error = %e,
                                "failed to detach program from removed interface"
                            );
                        }
                    }

                    // Schedule cleanup of metrics for this interface
                    if let Some(ref cleanup_tracker) = self.cleanup_tracker {
                        cleanup_tracker.schedule_interface_cleanup(name.clone());
                    }

                    if let Some(ref tx) = self.event_tx {
                        let _ = tx.send(ControllerEvent::InterfaceDetached { iface: name });
                    }
                }
            }
        }
        Ok(())
    }

    /// Attach eBPF program to interface in host namespace.
    ///
    /// Orphan Handling:
    /// - Netlink mode: cleanup_orphaned_programs() removes old programs by name
    /// - TCX mode: Supports multiple programs on same hook. New program attaches successfully
    ///   even if orphaned programs exist from previous instances. Orphaned programs are
    ///   automatically cleaned up by the kernel when the old pod's file descriptors close.
    ///
    /// Note: True atomic replacement would require link pinning, which Aya doesn't currently
    /// support. See aya-link-pinning-enhancement.md for the GitHub issue.
    fn attach_to_iface(
        &mut self,
        iface: &str,
        attach_type: TcAttachType,
    ) -> Result<(), MerminError> {
        let iface_owned = iface.to_string();
        let direction_name = attach_type.direction_name();
        let use_tcx = self.use_tcx;
        let tc_priority = self.tc_priority;

        let program_name = attach_type.program_name();

        // TCX (kernel >= 6.6) doesn't require clsact qdisc
        // Netlink mode (kernel < 6.6) requires clsact qdisc
        if !use_tcx && let Err(e) = tc::qdisc_add_clsact(&iface_owned) {
            debug!(
                event.name = "interface_controller.qdisc_add_skipped",
                network.interface.name = %iface_owned,
                error = %e,
                "clsact qdisc add failed (likely already exists)"
            );
        }

        let program: &mut SchedClassifier = self
            .ebpf
            .program_mut(program_name)
            .ok_or_else(|| {
                MerminError::internal(format!(
                    "ebpf program '{program_name}' not found in loaded object",
                ))
            })?
            .try_into()
            .map_err(|e| MerminError::internal(format!("failed to cast program: {e}")))?;

        // TC Priority-Aware Attachment
        //
        // For TCX (kernel >= 6.6): use configured ordering strategy
        // For Netlink (kernel < 6.6): use priority-aware attachment
        //
        // Note: TCX provides better multi-program support without priority conflicts.
        // On older kernels, we explicitly use netlink with our configured priority.

        if use_tcx {
            // TCX mode: kernel >= 6.6, attach with configured ordering
            // TCX supports multiple programs on the same hook, so attachment
            // succeeds even if orphaned programs exist from crashed instances
            let link_order = match self.tcx_order {
                TcxOrderStrategy::Last => LinkOrder::last(),
                TcxOrderStrategy::First => LinkOrder::first(),
            };

            debug!(
                event.name = "interface_controller.attaching_tcx",
                network.interface.name = %iface_owned,
                ebpf.program.direction = direction_name,
                ebpf.tcx.order = %self.tcx_order,
                "attaching ebpf program with TCX ordering - \
                 will pin link for orphan cleanup on restart"
            );

            let options = TcAttachOptions::TcxOrder(link_order);
            let link_id = program
                .attach_with_options(&iface_owned, attach_type, options)
                .map_err(|e| {
                    MerminError::internal(format!(
                        "failed to attach ebpf program to interface {} (tcx mode, order={}): {}",
                        iface, self.tcx_order, e
                    ))
                })?;

            // CRITICAL: Check /sys/fs/bpf accessibility BEFORE taking the link.
            // If take_link() succeeds but pin() fails, the FdLink is consumed and
            // the program detaches immediately. By checking first, we avoid this.
            let pin_path = Self::pin_path(&iface_owned, direction_name);

            if self.bpf_fs_writable {
                match program.take_link(link_id) {
                    Ok(link) => match TryInto::<aya::programs::links::FdLink>::try_into(link) {
                        Ok(fd_link) => match fd_link.pin(&pin_path) {
                            Ok(pinned_fd_link) => {
                                debug!(
                                    event.name = "interface_controller.tcx_link_pinned",
                                    network.interface.name = %iface_owned,
                                    ebpf.program.direction = direction_name,
                                    pin_path = %pin_path,
                                    "tcx link pinned successfully - orphan cleanup enabled"
                                );
                                std::mem::forget(pinned_fd_link);
                            }
                            Err(e) => {
                                error!(
                                    event.name = "interface_controller.tcx_pin_failed_unexpected",
                                    network.interface.name = %iface_owned,
                                    ebpf.program.direction = direction_name,
                                    pin_path = %pin_path,
                                    error = %e,
                                    "pin() failed despite /sys/fs/bpf being writable - \
                                     fd link consumed, program may have detached"
                                );
                            }
                        },
                        Err(e) => {
                            warn!(
                                event.name = "interface_controller.tcx_link_conversion_failed",
                                network.interface.name = %iface_owned,
                                ebpf.program.direction = direction_name,
                                error = ?e,
                                "failed to convert link to fd link - program may be orphaned"
                            );
                        }
                    },
                    Err(e) => {
                        warn!(
                            event.name = "interface_controller.tcx_link_take_failed",
                            network.interface.name = %iface_owned,
                            ebpf.program.direction = direction_name,
                            error = %e,
                            "could not take link - will remain in program storage"
                        );
                    }
                }
            } else {
                warn!(
                    event.name = "interface_controller.tcx_link_not_pinned",
                    network.interface.name = %iface_owned,
                    ebpf.program.direction = direction_name,
                    "tcx link left in program storage (/sys/fs/bpf not writable) - \
                     program will stay attached, mount /sys/fs/bpf as hostPath for orphan cleanup"
                );
            }
        } else {
            // Netlink mode: kernel < 6.6, use priority
            debug!(
                event.name = "interface_controller.attaching_with_priority",
                network.interface.name = %iface_owned,
                ebpf.program.priority = tc_priority,
                ebpf.program.direction = direction_name,
                "attaching ebpf program with TC priority (netlink mode)"
            );

            let link_id =
                Self::attach_tc_with_priority(program, &iface_owned, attach_type, tc_priority)?;
            self.register_tc_link(iface.to_string(), direction_name, link_id);
        }

        inc_tc_programs_attached(iface, direction_name);

        debug!(
            event.name = "interface_controller.program_attached",
            ebpf.program.direction = direction_name,
            ebpf.program.priority = tc_priority,
            network.interface.name = %iface,
            "ebpf program attached to interface"
        );

        Ok(())
    }

    /// Attach eBPF TC program with specified priority (netlink-based).
    ///
    /// Uses aya's built-in `attach_with_options()` method with `NlOptions` to set priority.
    /// This allows mermin to coexist with other TC programs like Cilium by controlling
    /// execution order through priority values.
    ///
    /// ## Priority Semantics
    /// - Lower numeric values = higher priority = runs earlier in TC chain
    /// - Cilium typically uses priorities 1-20
    /// - mermin default is 50 (runs after Cilium)
    /// - Valid range: 1-65535 (we validate 30-32767 in config)
    ///
    /// ## Parameters
    /// - `program`: Mutable reference to the SchedClassifier program
    /// - `iface`: Interface name to attach to
    /// - `attach_type`: TC attach type (ingress/egress)
    /// - `priority`: TC priority value (higher = lower priority = runs later)
    ///
    /// ## Returns
    /// - `Ok(SchedClassifierLinkId)` on success
    /// - `Err(MerminError)` if attachment fails
    fn attach_tc_with_priority(
        program: &mut SchedClassifier,
        iface: &str,
        attach_type: TcAttachType,
        priority: u16,
    ) -> Result<SchedClassifierLinkId, MerminError> {
        let options = TcAttachOptions::Netlink(NlOptions {
            priority,
            handle: 0, // Let system choose handle
        });

        program
            .attach_with_options(iface, attach_type, options)
            .map_err(|e| {
                MerminError::internal(format!(
                    "failed to attach ebpf program to interface {iface} with priority {priority}: {e}",
                ))
            })
    }

    /// Detach eBPF program from interface.
    ///
    /// For TCX mode: Unpins the link before detaching to clean up the BPF filesystem.
    /// For Netlink mode: Standard detachment without pinning.
    ///
    /// Blocking operation. Thread must be in host network namespace.
    fn detach_program(
        &mut self,
        iface: &str,
        direction: &'static str,
        link_id: SchedClassifierLinkId,
    ) -> Result<(), MerminError> {
        let program_name = match direction {
            DIRECTION_INGRESS => PROGRAM_NAME_INGRESS,
            DIRECTION_EGRESS => PROGRAM_NAME_EGRESS,
            _ => unreachable!("to_static_direction ensures only ingress/egress"),
        };

        let iface_owned = iface.to_string();

        // In TCX mode, try to unpin the link before detaching
        if self.use_tcx {
            let pin_path = Self::pin_path(&iface_owned, direction);
            match PinnedLink::from_pin(&pin_path) {
                Ok(pinned_link) => match pinned_link.unpin() {
                    Ok(fd_link) => {
                        debug!(
                            event.name = "interface_controller.tcx_link_unpinned",
                            network.interface.name = %iface_owned,
                            ebpf.program.direction = %direction,
                            pin_path = %pin_path,
                            "unpinned TCX link during detachment"
                        );
                        inc_tc_programs_detached(iface, direction);
                        drop(fd_link);
                        return Ok(());
                    }
                    Err(e) => {
                        debug!(
                            event.name = "interface_controller.tcx_unpin_failed_fallback",
                            network.interface.name = %iface_owned,
                            ebpf.program.direction = %direction,
                            pin_path = %pin_path,
                            error = %e,
                            "failed to unpin TCX link, falling back to standard detach"
                        );
                    }
                },
                Err(e) => {
                    if Self::is_not_found_error(&e) {
                        debug!(
                            event.name = "interface_controller.tcx_pin_not_found",
                            network.interface.name = %iface_owned,
                            ebpf.program.direction = %direction,
                            pin_path = %pin_path,
                            "pinned link not found, using standard detach"
                        );
                    } else {
                        debug!(
                            event.name = "interface_controller.tcx_pin_load_failed_fallback",
                            network.interface.name = %iface_owned,
                            ebpf.program.direction = %direction,
                            pin_path = %pin_path,
                            error = %e,
                            "failed to load pinned link, falling back to standard detach"
                        );
                    }
                }
            }
        }

        let program: &mut SchedClassifier = self
            .ebpf
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
        })?;

        inc_tc_programs_detached(iface, direction);

        Ok(())
    }

    /// Detach eBPF program from interface (unified method for both TCX and Netlink modes).
    ///
    /// For TCX mode: First tries to unpin from BPF filesystem, then falls back to stored link_id.
    /// For Netlink mode: Uses stored link_id from tc_links HashMap.
    ///
    /// Blocking operation. Thread must be in host network namespace.
    fn detach_from_iface(
        &mut self,
        iface: &str,
        direction: &'static str,
    ) -> Result<(), MerminError> {
        if self.use_tcx {
            // Try pinned link first (if /sys/fs/bpf was available during attachment)
            let pin_path = Self::pin_path(iface, direction);
            match PinnedLink::from_pin(&pin_path) {
                Ok(pinned_link) => {
                    // Found pinned link, unpin and detach
                    match pinned_link.unpin() {
                        Ok(_fd_link) => {
                            debug!(
                                event.name = "interface_controller.tcx_pinned_link_detached",
                                network.interface.name = %iface,
                                ebpf.program.direction = %direction,
                                pin_path = %pin_path,
                                "detached TCX program via pinned link"
                            );
                            inc_tc_programs_detached(iface, direction);
                            return Ok(());
                        }
                        Err(e) => {
                            warn!(
                                event.name = "interface_controller.tcx_unpin_failed",
                                network.interface.name = %iface,
                                ebpf.program.direction = %direction,
                                pin_path = %pin_path,
                                error = %e,
                                "failed to unpin TCX link, trying standard detachment"
                            );
                        }
                    }
                }
                Err(_) => {
                    // No pinned link found, fall through to standard detachment
                    trace!(
                        event.name = "interface_controller.tcx_no_pinned_link",
                        network.interface.name = %iface,
                        ebpf.program.direction = %direction,
                        "no pinned link found, using standard detachment"
                    );
                }
            }
        }

        // Fall back to standard detachment (works for both TCX and Netlink)
        self.detach_netlink_program(iface, direction)
    }

    /// Detach program using stored link_id (works for both TCX and Netlink modes).
    ///
    /// Links are tracked in the tc_links HashMap with their link_id.
    ///
    /// Blocking operation. Thread must be in host network namespace.
    fn detach_netlink_program(
        &mut self,
        iface: &str,
        direction: &'static str,
    ) -> Result<(), MerminError> {
        if let Some(link_id) = self.unregister_tc_link(iface, direction) {
            self.detach_program(iface, direction, link_id)
        } else {
            debug!(
                event.name = "interface_controller.netlink_link_not_found",
                network.interface.name = %iface,
                ebpf.program.direction = %direction,
                "no netlink link found in tc_links HashMap (may have been already removed)"
            );
            Ok(())
        }
    }

    /// Clean up orphaned TC programs from all active interfaces before attachment.
    ///
    /// This prevents the issue where killed pods leave TC programs attached,
    /// which then intercept traffic and prevent new programs from functioning.
    ///
    /// For TCX mode (kernel >= 6.6): Attempts to load and detach pinned links.
    /// For Netlink mode (kernel < 6.6): Uses qdisc_detach_program to remove by program name.
    ///
    /// Blocking operation. Thread must be in host network namespace.
    fn cleanup_orphaned_programs(&mut self) -> Result<(), MerminError> {
        if self.use_tcx && self.bpf_fs_writable {
            // TCX mode: Try to clean up orphaned programs using pinned links
            info!(
                event.name = "interface_controller.tcx_cleanup_started",
                kernel.tcx_mode = true,
                iface_count = self.active_ifaces.len(),
                "attempting to clean up orphaned TCX programs via pinned links"
            );

            let mut total_removed = 0u32;
            let ifaces: Vec<String> = self.active_ifaces.iter().cloned().collect();

            for iface in &ifaces {
                for direction in DIRECTIONS {
                    let pin_path = Self::pin_path(iface, direction);
                    match PinnedLink::from_pin(&pin_path) {
                        Ok(pinned_link) => {
                            debug!(
                                event.name = "interface_controller.tcx_orphan_found",
                                network.interface.name = %iface,
                                ebpf.program.direction = %direction,
                                pin_path = %pin_path,
                                "found orphaned TCX link from previous instance"
                            );

                            match pinned_link.unpin() {
                                Ok(_fd_link) => {
                                    total_removed += 1;
                                    info!(
                                        event.name = "interface_controller.tcx_orphan_removed",
                                        network.interface.name = %iface,
                                        ebpf.program.direction = %direction,
                                        pin_path = %pin_path,
                                        "successfully removed orphaned TCX program"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        event.name = "interface_controller.tcx_orphan_unpin_failed",
                                        network.interface.name = %iface,
                                        ebpf.program.direction = %direction,
                                        pin_path = %pin_path,
                                        error = %e,
                                        "failed to unpin orphaned TCX link"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            if Self::is_not_found_error(&e) {
                                trace!(
                                    event.name = "interface_controller.tcx_no_orphan",
                                    network.interface.name = %iface,
                                    ebpf.program.direction = %direction,
                                    pin_path = %pin_path,
                                    "no orphaned TCX link found (expected on first run)"
                                );
                            } else {
                                debug!(
                                    event.name = "interface_controller.tcx_orphan_load_failed",
                                    network.interface.name = %iface,
                                    ebpf.program.direction = %direction,
                                    pin_path = %pin_path,
                                    error = %e,
                                    "could not load pinned link (may not exist or /sys/fs/bpf not mounted)"
                                );
                            }
                        }
                    }
                }
            }

            if total_removed > 0 {
                info!(
                    event.name = "interface_controller.tcx_cleanup_completed",
                    total_programs_removed = total_removed,
                    interfaces_cleaned = ifaces.len(),
                    "orphaned TCX program cleanup completed successfully"
                );
            } else {
                debug!(
                    event.name = "interface_controller.tcx_cleanup_none_found",
                    "no orphaned TCX programs found"
                );
            }

            return Ok(());
        }

        if self.use_tcx && !self.bpf_fs_writable {
            info!(
                event.name = "interface_controller.tcx_cleanup_skipped",
                kernel.tcx_mode = true,
                bpf_fs_writable = false,
                "skipping TCX orphan cleanup - /sys/fs/bpf not writable, no pinned links exist"
            );
            return Ok(());
        }

        // Netlink mode: kernel < 6.6, use qdisc_detach_program
        info!(
            event.name = "interface_controller.cleanup_started",
            iface_count = self.active_ifaces.len(),
            "cleaning up orphaned TC programs before attachment"
        );

        let mut total_removed = 0u32;
        let ifaces: Vec<String> = self.active_ifaces.iter().cloned().collect();

        for iface in &ifaces {
            let iface_owned = iface.clone();
            let removed = Self::cleanup_orphaned_programs_on_iface(&iface_owned, self.use_tcx)?;

            if removed > 0 {
                info!(
                    event.name = "interface_controller.cleanup_completed",
                    network.interface.name = %iface,
                    programs_removed = removed,
                    "cleaned up orphaned TC programs from interface"
                );
                total_removed += removed;
            }
        }

        if total_removed > 0 {
            info!(
                event.name = "interface_controller.cleanup_summary",
                total_programs_removed = total_removed,
                interfaces_cleaned = ifaces.len(),
                "orphaned TC program cleanup completed"
            );
        } else {
            debug!(
                event.name = "interface_controller.cleanup_none_found",
                "no orphaned TC programs found"
            );
        }

        Ok(())
    }

    /// Remove orphaned TC programs from an interface.
    ///
    /// Uses Aya's native netlink functions to find and detach TC programs by name.
    /// Returns the count of removed programs.
    ///
    /// This method must run in the host network namespace and is best-effort:
    /// if removal fails, it logs a warning but doesn't fail the entire operation.
    ///
    /// For TCX mode (kernel >= 6.6), orphaned programs cannot be removed without the original
    /// link_id. However, TCX supports multiple programs on the same hook, so new attachments
    /// should succeed. The kernel will clean up orphaned programs when the process exits.
    fn cleanup_orphaned_programs_on_iface(iface: &str, use_tcx: bool) -> Result<u32, MerminError> {
        let mut removed_count = 0u32;

        // Only netlink mode supports cleanup by program name
        // TCX requires link_id for detachment, which we don't have from previous instances
        if !use_tcx {
            let program_names = [
                (PROGRAM_NAME_INGRESS, TcAttachType::Ingress),
                (PROGRAM_NAME_EGRESS, TcAttachType::Egress),
            ];

            for (program_name, attach_type) in &program_names {
                match qdisc_detach_program(iface, *attach_type, program_name) {
                    Ok(()) => {
                        removed_count += 1;
                        debug!(
                            event.name = "interface_controller.orphaned_program_removed",
                            network.interface.name = %iface,
                            attach_type = ?attach_type,
                            program = %program_name,
                            "removed orphaned TC program (netlink mode)"
                        );
                    }
                    Err(e) => {
                        if Self::is_not_found_error(&e) {
                            trace!(
                                event.name = "interface_controller.no_orphaned_program",
                                network.interface.name = %iface,
                                attach_type = ?attach_type,
                                program = %program_name,
                                "no orphaned program found (expected)"
                            );
                        } else {
                            warn!(
                                event.name = "interface_controller.program_detach_failed",
                                network.interface.name = %iface,
                                attach_type = ?attach_type,
                                program = %program_name,
                                error = %e,
                                "failed to detach program (may have been removed already)"
                            );
                        }
                    }
                }
            }
        }

        Ok(removed_count)
    }

    /// Register TC link for tracking.
    fn register_tc_link(
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
    fn unregister_tc_link(
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

    /// Generate consistent BPF filesystem path for pinning TCX links.
    ///
    /// Path format: /sys/fs/bpf/mermin_tcx_{iface}_{direction}
    /// This ensures links can be reloaded on pod restart to cleanup orphaned programs.
    ///
    /// # Safety
    /// Interface names are kernel-controlled and should not contain path separators.
    /// We validate this with debug assertions to catch any unexpected behavior.
    fn pin_path(iface: &str, direction: &str) -> String {
        debug_assert!(
            !iface.contains('/') && !iface.contains('\0'),
            "interface name '{iface}' contains invalid path characters",
        );
        format!("/sys/fs/bpf/mermin_tcx_{iface}_{direction}")
    }

    /// Convert direction string to static lifetime for HashMap key.
    fn to_static_direction(direction: &str) -> Option<&'static str> {
        match direction {
            DIRECTION_INGRESS => Some(DIRECTION_INGRESS),
            DIRECTION_EGRESS => Some(DIRECTION_EGRESS),
            _ => None,
        }
    }

    /// Resolve patterns to concrete interface names.
    ///
    /// Discovers all network interfaces and matches them against configured patterns.
    /// Thread must already be in host network namespace.
    fn resolve_ifaces(patterns: &[String]) -> Result<HashSet<String>, MerminError> {
        let available: Vec<String> = datalink::interfaces().into_iter().map(|i| i.name).collect();
        let mut sorted_available = available.clone();
        sorted_available.sort();

        info!(
            event.name = "interface_controller.interfaces_discovered",
            iface_count = available.len(),
            interfaces = ?sorted_available,
            patterns = ?patterns,
            "discovered interfaces from host namespace"
        );

        let mut resolved = HashSet::new();
        let mut matches_per_pattern = HashMap::new();

        for pattern in patterns {
            let mut pattern_matches = Vec::new();
            for iface in &available {
                if Self::matches_pattern(iface, std::slice::from_ref(pattern)) {
                    resolved.insert(iface.clone());
                    pattern_matches.push(iface.clone());
                }
            }
            if !pattern_matches.is_empty() {
                pattern_matches.sort();
                matches_per_pattern.insert(pattern.clone(), pattern_matches);
            }
        }

        for (pattern, matches) in &matches_per_pattern {
            debug!(
                event.name = "interface_controller.pattern_matched",
                pattern = %pattern,
                match_count = matches.len(),
                matches = ?matches,
                "pattern matched interfaces"
            );
        }

        let mut resolved_list: Vec<_> = resolved.iter().collect();
        resolved_list.sort();
        info!(
            event.name = "interface_controller.interfaces_resolved",
            interfaces_count = resolved.len(),
            interfaces = ?resolved_list,
            "resolved interfaces from patterns"
        );

        if resolved.is_empty() {
            warn!(
                event.name = "interface_controller.no_interfaces_matched",
                pattern_count = patterns.len(),
                patterns = ?patterns,
                available_count = available.len(),
                available_interfaces = ?sorted_available,
                "no interfaces matched the configured patterns - controller will not attach to any interfaces"
            );
        }

        Ok(resolved)
    }

    /// Check if a name matches any of the given patterns.
    pub fn matches_pattern(name: &str, patterns: &[String]) -> bool {
        patterns
            .iter()
            .any(|pattern| Self::glob_matches(pattern, name))
    }

    /// Match a text against a glob pattern.
    pub fn glob_matches(pattern: &str, text: &str) -> bool {
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

    /// Check if an error indicates a "not found" condition.
    fn is_not_found_error(e: &impl std::fmt::Display) -> bool {
        let error_str = e.to_string();
        error_str.contains("No such file")
            || error_str.contains("not found")
            || error_str.contains("ENOENT")
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
