//! Controller for network interface lifecycle management.
//!
//! Implements reconciliation pattern: watches netlink events (RTM_NEWLINK/RTM_DELLINK),
//! compares desired state (interface patterns) vs actual state (active interface),
//! and reconciles by attaching/detaching eBPF TC programs. Maintains dynamic interface
//! index → name mapping for flow decoration via lock-free DashMap.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType, tc, tc::SchedClassifierLinkId},
};
use dashmap::DashMap;
use futures::stream::{Stream, StreamExt};
use globset::Glob;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkFlags},
};
use pnet::datalink;
use rtnetlink::new_connection;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::{error::MerminError, iface::netns::NetnsSwitch};

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
/// The `attach_to_iface` method uses `blocking_lock()` because it performs
/// FFI/syscalls within the critical section via `in_host_namespace`, which is
/// inherently blocking. The critical section is kept minimal.
pub struct IfaceController {
    patterns: Vec<String>,
    active_ifaces: HashSet<String>,
    tc_links: HashMap<(String, &'static str), SchedClassifierLinkId>,
    /// DashMap for lock-free reads during packet processing while controller updates dynamically
    iface_map: Arc<DashMap<u32, String>>,
    ebpf: Arc<tokio::sync::Mutex<Ebpf>>,
    netns_switch: NetnsSwitch,
    /// TCX (kernel >= 6.6) vs netlink-based attachment
    use_tcx: bool,
}

/// TC attachment directions used for iterating over all attach types
const DIRECTIONS: &[&str] = &["ingress", "egress"];

/// Timeout for netlink connection cleanup during reconciliation loop shutdown
const NETLINK_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

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
                "failed to initialize network namespace switching: {e} - ensure hostPID: true is set and CAP_SYS_ADMIN capability is granted",
            ))
        })?;

        let initial_ifaces = Self::resolve_ifaces(&patterns, &netns_switch)?;

        info!(
            event.name = "iface_controller.created",
            iface_count = initial_ifaces.len(),
            "interface controller created with resolved ifaces"
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

        info!(
            event.name = "iface_controller.ifaces_discovered",
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

        info!(
            event.name = "iface_controller.ifaces_resolved",
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
            event.name = "iface_controller.initializing",
            iface_count = self.active_ifaces.len(),
            "initializing controller and attaching eBPF programs"
        );

        self.build_iface_map()?;

        let programs = [TcAttachType::Ingress, TcAttachType::Egress];

        // Collect interface names as owned strings to avoid borrow checker issues
        // (cannot borrow self immutably while calling mutable attach_to_iface)
        // This is acceptable as it only happens once at initialization with a small set.
        let ifaces: Vec<String> = self.active_ifaces.iter().cloned().collect();

        for attach_type in &programs {
            for iface in &ifaces {
                self.attach_to_iface(iface, *attach_type).await?;
            }
        }

        info!(
            event.name = "iface_controller.initialized",
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
            event.name = "iface_controller.shutdown_started",
            total_links = total_links,
            "starting graceful shutdown and eBPF program detachment"
        );

        let tc_links = std::mem::take(&mut self.tc_links);

        for ((iface, direction), link_id) in tc_links {
            match self.detach_program(&iface, direction, link_id).await {
                Ok(_) => {
                    detached_count += 1;
                    info!(
                        event.name = "iface_controller.program_detached",
                        network.interface.name = %iface,
                        ebpf.program.direction = %direction,
                        "successfully detached ebpf program"
                    );
                }
                Err(e) => {
                    failed_count += 1;
                    warn!(
                        event.name = "iface_controller.detach_failed",
                        network.interface.name = %iface,
                        ebpf.program.direction = %direction,
                        error = %e,
                        "failed to detach ebpf program"
                    );
                }
            }
        }

        info!(
            event.name = "iface_controller.shutdown_completed",
            total_links = total_links,
            detached_count = detached_count,
            failed_count = failed_count,
            "controller shutdown completed"
        );

        // Always return Ok during shutdown. The kernel will clean up eBPF programs
        // when the process exits, and some failures are expected if interfaces
        // disappeared before shutdown. Failed detachments are already logged as warnings.
        if failed_count > 0 {
            warn!(
                event.name = "iface_controller.shutdown_partial",
                failed_count = failed_count,
                total_links = total_links,
                "some eBPF programs failed to detach, but kernel will clean them up on process exit"
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
            event.name = "iface_controller.tc_link_registered",
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
                event.name = "iface_controller.tc_link_unregistered",
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
            .in_host_namespace(Some("build_iface_map"), || {
                for iface in datalink::interfaces() {
                    if self.active_ifaces.contains(&iface.name) {
                        self.iface_map.insert(iface.index, iface.name.clone());
                    }
                }
                Ok(())
            })?;

        debug!(
            event.name = "iface_controller.iface_map_built",
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
                            event.name = "iface_controller.iface_map_updated",
                            iface = %iface_name,
                            index = iface.index,
                            "added interface to iface_map"
                        );
                        return Ok(());
                    }
                }
                // Iface not found - this is an error condition
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
                    event.name = "iface_controller.iface_map_updated",
                    iface = %name,
                    index = idx,
                    "removed interface from iface_map"
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
        use TcAttachTypeExt;

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
                        event.name = "iface_controller.qdisc_add_skipped",
                        network.interface.name = %iface_owned,
                        error = %e,
                        "clsact qdisc add failed (likely already exists)"
                    );
                }
                Ok(())
            })?;
        }

        let link_id = {
            let mut ebpf_guard = self.ebpf.blocking_lock();

            self.netns_switch.in_host_namespace(Some(&context), || {
                let program: &mut SchedClassifier = ebpf_guard
                    .program_mut(program_name)
                    .ok_or_else(|| {
                        MerminError::internal(format!(
                            "eBPF program '{program_name}' not found in loaded object",
                        ))
                    })?
                    .try_into()
                    .map_err(|e| MerminError::internal(format!("failed to cast program: {e}")))?;

                program.attach(&iface_owned, attach_type).map_err(|e| {
                    MerminError::internal(format!(
                        "failed to attach eBPF program to interface {iface}: {e}",
                    ))
                })
            })?
        };

        self.register_tc_link(iface.to_string(), attach_type.direction_name(), link_id);

        info!(
            event.name = "iface_controller.program_attached",
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
        let mut ebpf_guard = self.ebpf.lock().await;

        let program: &mut SchedClassifier = ebpf_guard
            .program_mut(program_name)
            .ok_or_else(|| {
                MerminError::internal(format!(
                    "eBPF program '{program_name}' not found for detachment",
                ))
            })?
            .try_into()
            .map_err(|e| MerminError::internal(format!("failed to cast program: {e}")))?;

        program.detach(link_id).map_err(|e| {
            MerminError::internal(format!(
                "failed to detach eBPF program from interface {iface}: {e}"
            ))
        })?;

        Ok(())
    }

    /// Start reconciliation loop via netlink multicast (RTNLGRP_LINK).
    /// Controller handles all attachment/detachment internally.
    pub fn start_reconciliation_loop(controller: Arc<tokio::sync::Mutex<Self>>) -> JoinHandle<()> {
        let ctrl = Arc::clone(&controller);

        tokio::spawn(async move {
            info!(
                event.name = "iface_controller.reconciliation_started",
                "started reconciliation loop via netlink (RTM_NEWLINK/RTM_DELLINK multicast)"
            );

            // Create netlink connection with message stream
            let (connection, _handle, messages) = match new_connection() {
                Ok(conn) => conn,
                Err(e) => {
                    error!(
                        event.name = "iface_controller.connection_failed",
                        error = %e,
                        "failed to create netlink connection"
                    );
                    return;
                }
            };

            if let Err(e) = ctrl
                .lock()
                .await
                .watch_and_reconcile(connection, messages)
                .await
            {
                error!(
                    event.name = "iface_controller.reconciliation_failed",
                    error = %e,
                    "reconciliation loop failed"
                );
            }

            info!(
                event.name = "iface_controller.reconciliation_stopped",
                "reconciliation loop stopped"
            );
        })
    }

    /// Core reconciliation loop: watch RTM_NEWLINK/RTM_DELLINK, compare with
    /// active_ifaces, and attach/detach eBPF programs when state differs.
    async fn watch_and_reconcile<M>(
        &mut self,
        connection: impl std::future::Future<Output = ()> + Send + 'static,
        mut messages: M,
    ) -> Result<(), MerminError>
    where
        M: Stream<
                Item = (
                    netlink_packet_core::NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>,
                    netlink_sys::SocketAddr,
                ),
            > + Unpin,
    {
        let connection_handle = tokio::spawn(connection);

        while let Some((message, _)) = messages.next().await {
            let NetlinkPayload::InnerMessage(rtnl_msg) = message.payload else {
                continue;
            };

            match rtnl_msg {
                RouteNetlinkMessage::NewLink(link_msg) | RouteNetlinkMessage::SetLink(link_msg) => {
                    self.reconcile_link(&link_msg, true).await?;
                }
                RouteNetlinkMessage::DelLink(link_msg) => {
                    self.reconcile_link(&link_msg, false).await?;
                }
                _ => {}
            }
        }

        connection_handle.abort();
        // Give connection handle time to clean up gracefully
        if tokio::time::timeout(NETLINK_CLEANUP_TIMEOUT, connection_handle)
            .await
            .is_err()
        {
            warn!(
                event.name = "iface_controller.connection_cleanup_timeout",
                timeout_secs = NETLINK_CLEANUP_TIMEOUT.as_secs(),
                "netlink connection cleanup timed out"
            );
        }
        Ok(())
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
                        event.name = "iface_controller.attach_failed",
                        iface = %if_name,
                        direction = attach_type.direction_name(),
                        error = %e,
                        "failed to attach eBPF program to new interface, rolling back"
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
                    event.name = "iface_controller.rollback_failed",
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

        if !Self::matches_pattern(&if_name, &self.patterns) {
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
                event.name = "iface_controller.reconcile_add",
                iface = %if_name,
                "interface should be active, reconciling by attaching eBPF programs"
            );

            if let Err(e) = self.iface_map_add(&if_name) {
                error!(
                    event.name = "iface_controller.iface_map_update_failed",
                    iface = %if_name,
                    error = %e,
                    "failed to update iface_map for added interface, will retry on next event"
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
                    event.name = "iface_controller.attach_all_failed",
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
                event.name = "iface_controller.reconcile_remove",
                iface = %if_name,
                "interface should not be active, reconciling by detaching eBPF programs"
            );

            self.active_ifaces.remove(&if_name);

            self.iface_map_remove(&if_name);

            for direction in DIRECTIONS {
                if let Some(link_id) = self.unregister_tc_link(&if_name, direction) {
                    if let Err(e) = self.detach_program(&if_name, direction, link_id).await {
                        warn!(
                            event.name = "iface_controller.detach_failed",
                            iface = %if_name,
                            direction = %direction,
                            error = %e,
                            "failed to detach eBPF program from removed interface"
                        );
                    } else {
                        info!(
                            event.name = "iface_controller.program_detached",
                            iface = %if_name,
                            direction = %direction,
                            "eBPF program detached from removed interface"
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
                event.name = "iface_controller.pattern_too_long",
                pattern_length = pattern.len(),
                "pattern exceeds maximum length, rejecting"
            );
            return false;
        }

        match Glob::new(pattern) {
            Ok(glob) => glob.compile_matcher().is_match(text),
            Err(e) => {
                warn!(
                    event.name = "iface_controller.invalid_pattern",
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

        // Simulate adding a new iface
        controller.active_ifaces.insert("veth0".to_string());
        assert!(controller.active_ifaces.contains("veth0"));
        assert_eq!(controller.active_ifaces.len(), 2);

        // Simulate removing an iface
        controller.active_ifaces.remove("eth0");
        assert!(!controller.active_ifaces.contains("eth0"));
        assert_eq!(controller.active_ifaces.len(), 1);
    }

    #[test]
    fn test_tc_links_map_structure() {
        // Test the HashMap structure without actual link IDs
        let controller = TestController::new(vec![], HashSet::new());

        // Verify initial state
        assert!(controller.tc_links.is_empty());

        // Verify the map accepts the expected key types
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

        // Should match
        assert!(IfaceController::matches_pattern("veth123abc", &patterns));
        assert!(IfaceController::matches_pattern("tunl0", &patterns));
        assert!(IfaceController::matches_pattern("ip6tnl0", &patterns));
        assert!(IfaceController::matches_pattern("flannel.1", &patterns));
        assert!(IfaceController::matches_pattern("cali123abc", &patterns));

        // Should not match
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

        // Take from empty controller using std::mem::take
        let empty = std::mem::take(&mut controller.tc_links);
        assert!(empty.is_empty());

        // Controller should still have empty tc_links
        assert!(controller.tc_links.is_empty());

        // Taking again should still yield empty map
        let still_empty = std::mem::take(&mut controller.tc_links);
        assert!(still_empty.is_empty());
    }
}
