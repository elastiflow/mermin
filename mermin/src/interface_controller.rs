//! Controller for network interface lifecycle management.
//!
//! Implements reconciliation pattern: watches netlink events (RTM_NEWLINK/RTM_DELLINK),
//! compares desired state (interface patterns) vs actual state (active interfaces),
//! and reconciles by attaching/detaching eBPF TC programs. Maintains dynamic interface
//! index → name mapping for flow decoration via lock-free DashMap.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType, tc, tc::SchedClassifierLinkId},
};
use dashmap::DashMap;
use futures::stream::{Stream, StreamExt};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkFlags},
};
use pnet::datalink;
use regex::{Regex, escape};
use rtnetlink::new_connection;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::{error::MerminError, netns::NetnsSwitch};

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
pub enum InterfaceEvent {
    Added(String),
    Removed(String),
}

/// Controller for network interface lifecycle.
///
/// Reconciles desired state (patterns) with actual state (active_interfaces, tc_links)
/// by attaching/detaching eBPF TC programs. Owns all interface management including
/// initial attachment, dynamic reconciliation, iface_map updates, and graceful shutdown.
pub struct InterfaceController {
    patterns: Vec<String>,
    active_interfaces: HashSet<String>,
    tc_links: HashMap<(String, &'static str), SchedClassifierLinkId>,
    /// DashMap for lock-free reads during packet processing while controller updates dynamically
    iface_map: Arc<DashMap<u32, String>>,
    ebpf: Arc<tokio::sync::Mutex<Ebpf>>,
    netns_switch: NetnsSwitch,
    /// TCX (kernel >= 6.6) vs netlink-based attachment
    use_tcx: bool,
}

/// TC attachment directions
const DIRECTIONS: &[&str] = &["ingress", "egress"];

impl InterfaceController {
    /// Create controller, initialize netns switcher, and resolve interface patterns.
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

        let initial_interfaces = Self::resolve_interfaces(&patterns, &netns_switch)?;

        info!(
            event.name = "interface_controller.created",
            interface_count = initial_interfaces.len(),
            "interface controller created with resolved interfaces"
        );

        Ok(Self {
            patterns,
            active_interfaces: initial_interfaces,
            tc_links: HashMap::new(),
            iface_map: Arc::new(DashMap::new()),
            ebpf,
            netns_switch,
            use_tcx,
        })
    }

    /// Resolve patterns to concrete interface names from host namespace.
    fn resolve_interfaces(
        patterns: &[String],
        netns_switch: &crate::netns::NetnsSwitch,
    ) -> Result<HashSet<String>, crate::error::MerminError> {
        let available: Vec<String> =
            netns_switch.in_host_namespace(Some("interface_discovery"), || {
                Ok(datalink::interfaces()
                    .into_iter()
                    .map(|i| i.name)
                    .collect::<Vec<String>>())
            })?;

        info!(
            event.name = "interface_controller.interfaces_discovered",
            interface_count = available.len(),
            interfaces = ?available,
            "discovered interfaces from host namespace"
        );

        let mut resolved = HashSet::new();
        for pattern in patterns {
            for iface in &available {
                if Self::matches_any_pattern(iface, std::slice::from_ref(pattern)) {
                    resolved.insert(iface.clone());
                }
            }
        }

        info!(
            event.name = "interface_controller.interfaces_resolved",
            interface_count = resolved.len(),
            interfaces = ?resolved,
            "resolved interfaces from patterns"
        );

        Ok(resolved)
    }

    fn matches_any_pattern(name: &str, patterns: &[String]) -> bool {
        patterns
            .iter()
            .any(|pattern| Self::glob_matches(pattern, name))
    }

    /// Attach eBPF programs to all active interfaces and build initial iface_map.
    /// Should be called once after controller creation.
    pub async fn initialize(&mut self) -> Result<(), MerminError> {
        info!(
            event.name = "interface_controller.initializing",
            interface_count = self.active_interfaces.len(),
            "initializing controller and attaching eBPF programs"
        );

        self.build_iface_map()?;

        let programs = [TcAttachType::Ingress, TcAttachType::Egress];

        // Clone to avoid borrowing self immutably and mutably in the same loop
        let interfaces: Vec<String> = self.active_interfaces.iter().cloned().collect();

        for attach_type in &programs {
            for iface in &interfaces {
                self.attach_to_interface(iface, *attach_type).await?;
            }
        }

        info!(
            event.name = "interface_controller.initialized",
            interface_count = self.active_interfaces.len(),
            tc_links = self.tc_links.len(),
            "controller initialized successfully"
        );

        Ok(())
    }

    /// Get shared iface_map for flow decoration. DashMap allows lock-free reads
    /// while controller updates it dynamically.
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
            "starting graceful shutdown and eBPF program detachment"
        );

        let tc_links = std::mem::take(&mut self.tc_links);

        for ((iface, direction), link_id) in tc_links {
            match self.detach_program(&iface, direction, link_id).await {
                Ok(_) => {
                    detached_count += 1;
                    info!(
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

        if failed_count > 0 {
            Err(MerminError::internal(format!(
                "failed to detach {failed_count} out of {total_links} eBPF programs",
            )))
        } else {
            Ok(())
        }
    }

    /// Register TC link for tracking.
    pub fn register_tc_link(
        &mut self,
        interface: String,
        direction: &'static str,
        link_id: SchedClassifierLinkId,
    ) {
        debug!(
            event.name = "interface_controller.tc_link_registered",
            interface = %interface,
            direction = %direction,
            "TC link registered"
        );
        self.tc_links.insert((interface, direction), link_id);
    }

    /// Unregister TC link and return for detachment.
    pub fn unregister_tc_link(
        &mut self,
        interface: &str,
        direction: &str,
    ) -> Option<SchedClassifierLinkId> {
        let static_direction = Self::direction_to_static(direction)?;

        let link_id = self
            .tc_links
            .remove(&(interface.to_string(), static_direction));
        if link_id.is_some() {
            debug!(
                event.name = "interface_controller.tc_link_unregistered",
                interface = %interface,
                direction = %direction,
                "TC link unregistered"
            );
        }
        link_id
    }

    /// Convert direction string to static lifetime for HashMap key.
    fn direction_to_static(direction: &str) -> Option<&'static str> {
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
                    if self.active_interfaces.contains(&iface.name) {
                        self.iface_map.insert(iface.index, iface.name.clone());
                    }
                }
                Ok(())
            })?;

        debug!(
            event.name = "interface_controller.iface_map_built",
            entry_count = self.iface_map.len(),
            "built interface index → name mapping"
        );

        Ok(())
    }

    /// Add newly discovered interface to iface_map.
    fn update_iface_map_for_added(&mut self, iface_name: &str) -> Result<(), MerminError> {
        self.netns_switch
            .in_host_namespace(Some("update_iface_map"), || {
                for iface in datalink::interfaces() {
                    if iface.name == iface_name {
                        self.iface_map.insert(iface.index, iface.name.clone());
                        debug!(
                            event.name = "interface_controller.iface_map_updated",
                            interface = %iface_name,
                            index = iface.index,
                            "added interface to iface_map"
                        );
                        break;
                    }
                }
                Ok(())
            })
    }

    /// Remove interface from iface_map.
    fn update_iface_map_for_removed(&mut self, iface_name: &str) {
        self.iface_map.retain(|_index, name| {
            if name == iface_name {
                debug!(
                    event.name = "interface_controller.iface_map_updated",
                    interface = %iface_name,
                    "removed interface from iface_map"
                );
                false
            } else {
                true
            }
        });
    }

    /// Attach eBPF program to interface in host namespace.
    async fn attach_to_interface(
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
        let program_name = format!("mermin_{direction}");
        let mut ebpf_guard = self.ebpf.lock().await;

        let program: &mut SchedClassifier = ebpf_guard
            .program_mut(&program_name)
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
                event.name = "interface_controller.reconciliation_started",
                "started reconciliation loop via netlink (RTM_NEWLINK/RTM_DELLINK multicast)"
            );

            // Create netlink connection with message stream
            let (connection, _handle, messages) = match new_connection() {
                Ok(conn) => conn,
                Err(e) => {
                    error!(
                        event.name = "interface_controller.connection_failed",
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
                    event.name = "interface_controller.reconciliation_failed",
                    error = %e,
                    "reconciliation loop failed"
                );
            }

            info!(
                event.name = "interface_controller.reconciliation_stopped",
                "reconciliation loop stopped"
            );
        })
    }

    /// Core reconciliation loop: watch RTM_NEWLINK/RTM_DELLINK, compare with
    /// active_interfaces, and attach/detach eBPF programs when state differs.
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
            let rtnl_msg = match message.payload {
                NetlinkPayload::InnerMessage(msg) => msg,
                _ => continue,
            };

            match rtnl_msg {
                RouteNetlinkMessage::NewLink(link_msg) | RouteNetlinkMessage::SetLink(link_msg) => {
                    self.reconcile_link_change(&link_msg, true).await?;
                }
                RouteNetlinkMessage::DelLink(link_msg) => {
                    self.reconcile_link_change(&link_msg, false).await?;
                }
                _ => {}
            }
        }

        connection_handle.abort();
        // Give connection handle time to clean up gracefully
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), connection_handle).await;
        Ok(())
    }

    /// Reconcile link change event by comparing desired vs actual state and
    /// attaching/detaching eBPF programs when they differ.
    async fn reconcile_link_change(
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

        if !Self::matches_any_pattern(&if_name, &self.patterns) {
            return Ok(());
        }

        let is_up = if is_new_or_set {
            link_msg.header.flags.contains(LinkFlags::Up)
        } else {
            false
        };

        let is_active = self.active_interfaces.contains(&if_name);

        if is_up && !is_active {
            info!(
                event.name = "interface_controller.reconcile_add",
                interface = %if_name,
                "interface should be active, reconciling by attaching eBPF programs"
            );

            if let Err(e) = self.update_iface_map_for_added(&if_name) {
                error!(
                    event.name = "interface_controller.iface_map_update_failed",
                    interface = %if_name,
                    error = %e,
                    "failed to update iface_map for added interface, will retry on next event"
                );
                return Ok(());
            }

            // Track successfully attached programs for rollback if needed
            let mut attached_programs = Vec::new();

            // Attempt to attach both ingress and egress programs
            for attach_type in &[TcAttachType::Ingress, TcAttachType::Egress] {
                match self.attach_to_interface(&if_name, *attach_type).await {
                    Ok(_) => {
                        attached_programs.push(*attach_type);
                    }
                    Err(e) => {
                        error!(
                            event.name = "interface_controller.attach_failed",
                            interface = %if_name,
                            direction = attach_type.direction_name(),
                            error = %e,
                            "failed to attach eBPF program to new interface, rolling back"
                        );

                        // Rollback: detach any programs that were successfully attached
                        for prev_attach_type in attached_programs {
                            let direction = prev_attach_type.direction_name();
                            if let Some(link_id) = self.unregister_tc_link(&if_name, direction)
                                && let Err(detach_err) =
                                    self.detach_program(&if_name, direction, link_id).await
                            {
                                warn!(
                                    event.name = "interface_controller.rollback_failed",
                                    interface = %if_name,
                                    direction = %direction,
                                    error = %detach_err,
                                    "failed to detach during rollback"
                                );
                            }
                        }

                        // Remove from iface_map since we're not proceeding
                        self.update_iface_map_for_removed(&if_name);

                        return Ok(());
                    }
                }
            }

            // Only mark as active if ALL operations succeeded
            self.active_interfaces.insert(if_name);
        } else if !is_up && is_active {
            info!(
                event.name = "interface_controller.reconcile_remove",
                interface = %if_name,
                "interface should not be active, reconciling by detaching eBPF programs"
            );

            self.active_interfaces.remove(&if_name);

            self.update_iface_map_for_removed(&if_name);

            for direction in DIRECTIONS {
                if let Some(link_id) = self.unregister_tc_link(&if_name, direction) {
                    if let Err(e) = self.detach_program(&if_name, direction, link_id).await {
                        warn!(
                            event.name = "interface_controller.detach_failed",
                            interface = %if_name,
                            direction = %direction,
                            error = %e,
                            "failed to detach eBPF program from removed interface"
                        );
                    } else {
                        info!(
                            event.name = "interface_controller.program_detached",
                            interface = %if_name,
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
        if let Some(regex_pattern) = Self::glob_to_regex(pattern) {
            regex_pattern.is_match(text)
        } else {
            pattern == text
        }
    }

    fn glob_to_regex(pattern: &str) -> Option<Regex> {
        const MAX_PATTERN_LEN: usize = 256;

        if pattern.len() > MAX_PATTERN_LEN {
            warn!(
                event.name = "interface_controller.pattern_too_long",
                pattern_length = pattern.len(),
                "pattern exceeds maximum length, ignoring"
            );
            return None;
        }

        let regex_pattern = pattern
            .split('*')
            .map(escape)
            .collect::<Vec<_>>()
            .join(".*");

        Regex::new(&format!("^{regex_pattern}$")).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lightweight test struct to avoid unsafe initialization of eBPF/netns resources
    struct TestController {
        patterns: Vec<String>,
        active_interfaces: HashSet<String>,
        tc_links: HashMap<(String, &'static str), u32>, // u32 as LinkId placeholder since real LinkId can't be created in tests
    }

    impl TestController {
        fn new(patterns: Vec<String>, initial_interfaces: HashSet<String>) -> Self {
            Self {
                patterns,
                active_interfaces: initial_interfaces,
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
        assert_eq!(controller.active_interfaces, initial);
        assert!(controller.tc_links.is_empty());
    }

    #[test]
    fn test_glob_matches_wildcard() {
        assert!(InterfaceController::glob_matches("veth*", "veth0"));
        assert!(InterfaceController::glob_matches("veth*", "veth12345"));
        assert!(!InterfaceController::glob_matches("veth*", "eth0"));
        assert!(!InterfaceController::glob_matches("veth*", "tunl0"));
    }

    #[test]
    fn test_glob_matches_exact() {
        assert!(InterfaceController::glob_matches("eth0", "eth0"));
        assert!(!InterfaceController::glob_matches("eth0", "eth1"));
        assert!(!InterfaceController::glob_matches("eth0", "veth0"));
    }

    #[test]
    fn test_glob_matches_multiple_wildcards() {
        assert!(InterfaceController::glob_matches("*eth*", "veth0"));
        assert!(InterfaceController::glob_matches("*eth*", "eth0"));
        assert!(InterfaceController::glob_matches("*eth*", "lxceth123"));
        assert!(!InterfaceController::glob_matches("*eth*", "tunl0"));
    }

    #[test]
    fn test_glob_matches_prefix_suffix() {
        assert!(InterfaceController::glob_matches("eth*", "eth0"));
        assert!(InterfaceController::glob_matches("eth*", "eth1"));
        assert!(!InterfaceController::glob_matches("eth*", "veth0"));

        assert!(InterfaceController::glob_matches("*0", "eth0"));
        assert!(InterfaceController::glob_matches("*0", "veth0"));
        assert!(!InterfaceController::glob_matches("*0", "eth1"));
    }

    #[test]
    fn test_matches_any_pattern_single() {
        let patterns = vec!["veth*".to_string()];

        assert!(InterfaceController::matches_any_pattern("veth0", &patterns));
        assert!(InterfaceController::matches_any_pattern(
            "veth123", &patterns
        ));
        assert!(!InterfaceController::matches_any_pattern("eth0", &patterns));
    }

    #[test]
    fn test_matches_any_pattern_multiple() {
        let patterns = vec!["veth*".to_string(), "tunl*".to_string(), "eth0".to_string()];

        assert!(InterfaceController::matches_any_pattern("veth0", &patterns));
        assert!(InterfaceController::matches_any_pattern("tunl0", &patterns));
        assert!(InterfaceController::matches_any_pattern("eth0", &patterns));
        assert!(!InterfaceController::matches_any_pattern("eth1", &patterns));
        assert!(!InterfaceController::matches_any_pattern(
            "wlan0", &patterns
        ));
    }

    #[test]
    fn test_matches_any_pattern_no_match() {
        let patterns = vec!["veth*".to_string()];

        assert!(!InterfaceController::matches_any_pattern("eth0", &patterns));
        assert!(!InterfaceController::matches_any_pattern(
            "tunl0", &patterns
        ));
        assert!(!InterfaceController::matches_any_pattern("lo", &patterns));
    }

    // Note: TC link tests are skipped because SchedClassifierLinkId cannot be created
    // in tests without actual eBPF program attachment. The registration/unregistration
    // logic is tested via integration tests when the full eBPF stack is running.

    #[test]
    fn test_active_interfaces_tracking() {
        let initial = HashSet::from(["eth0".to_string()]);
        let mut controller = TestController::new(vec![], initial);

        assert!(controller.active_interfaces.contains("eth0"));
        assert_eq!(controller.active_interfaces.len(), 1);

        // Simulate adding a new interface
        controller.active_interfaces.insert("veth0".to_string());
        assert!(controller.active_interfaces.contains("veth0"));
        assert_eq!(controller.active_interfaces.len(), 2);

        // Simulate removing an interface
        controller.active_interfaces.remove("eth0");
        assert!(!controller.active_interfaces.contains("eth0"));
        assert_eq!(controller.active_interfaces.len(), 1);
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
    fn test_glob_to_regex() {
        // Test simple wildcard
        let regex = InterfaceController::glob_to_regex("veth*").unwrap();
        assert!(regex.is_match("veth0"));
        assert!(regex.is_match("veth12345"));
        assert!(!regex.is_match("eth0"));

        // Test multiple wildcards
        let regex = InterfaceController::glob_to_regex("*eth*").unwrap();
        assert!(regex.is_match("veth0"));
        assert!(regex.is_match("eth0"));
        assert!(regex.is_match("something_eth_else"));
        assert!(!regex.is_match("tunl0"));

        // Test exact match (no wildcards)
        let regex = InterfaceController::glob_to_regex("eth0").unwrap();
        assert!(regex.is_match("eth0"));
        assert!(!regex.is_match("eth1"));
        assert!(!regex.is_match("eth0_suffix"));
    }

    #[test]
    fn test_pattern_matching_realistic_interfaces() {
        let patterns = vec![
            "veth*".to_string(),
            "tunl*".to_string(),
            "ip6tnl*".to_string(),
            "flannel*".to_string(),
            "cali*".to_string(),
        ];

        // Should match
        assert!(InterfaceController::matches_any_pattern(
            "veth123abc",
            &patterns
        ));
        assert!(InterfaceController::matches_any_pattern("tunl0", &patterns));
        assert!(InterfaceController::matches_any_pattern(
            "ip6tnl0", &patterns
        ));
        assert!(InterfaceController::matches_any_pattern(
            "flannel.1",
            &patterns
        ));
        assert!(InterfaceController::matches_any_pattern(
            "cali123abc",
            &patterns
        ));

        // Should not match
        assert!(!InterfaceController::matches_any_pattern("eth0", &patterns));
        assert!(!InterfaceController::matches_any_pattern("lo", &patterns));
        assert!(!InterfaceController::matches_any_pattern(
            "docker0", &patterns
        ));
        assert!(!InterfaceController::matches_any_pattern(
            "br-123", &patterns
        ));
    }

    #[test]
    fn test_empty_patterns() {
        let patterns: Vec<String> = vec![];

        assert!(!InterfaceController::matches_any_pattern(
            "veth0", &patterns
        ));
        assert!(!InterfaceController::matches_any_pattern("eth0", &patterns));
        assert!(!InterfaceController::matches_any_pattern(
            "anything", &patterns
        ));
    }

    #[test]
    fn test_special_characters_in_interface_names() {
        let patterns = vec!["flannel.*".to_string()];

        // The dot should be treated literally in glob, not as regex "any character"
        assert!(InterfaceController::matches_any_pattern(
            "flannel.1",
            &patterns
        ));
        assert!(InterfaceController::matches_any_pattern(
            "flannel.100",
            &patterns
        ));
        // This actually matches because we escape special chars, so the literal "." is expected
        assert!(!InterfaceController::matches_any_pattern(
            "flannel-1",
            &patterns
        ));
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
