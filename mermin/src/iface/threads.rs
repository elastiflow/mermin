//! Thread spawning functions for the dual-thread controller architecture.
//!
//! This module provides functions to spawn:
//! 1. Netlink monitoring thread - permanently in host namespace, blocking netlink socket
//! 2. Controller thread - permanently in host namespace, handles commands and netlink events

use std::{
    mem,
    os::fd::{FromRawFd, OwnedFd, RawFd},
    thread,
};

use crossbeam::channel::{Receiver, Sender};
use libc::{
    AF_NETLINK, NETLINK_ADD_MEMBERSHIP, SOCK_RAW, SOL_NETLINK, bind, c_void, recv, setsockopt,
    sockaddr_nl, socket,
};
use netlink_packet_core::{NetlinkBuffer, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkFlags},
};
use netlink_sys::protocols::NETLINK_ROUTE;
use nix::sched::{CloneFlags, setns};
use tracing::{debug, error, info, trace, warn};

use super::{
    controller::IfaceController,
    types::{ControllerCommand, ControllerEvent, NetlinkEvent},
};

/// RAII wrapper for netlink socket file descriptor to ensure proper cleanup.
/// Automatically closes the socket when dropped, preventing file descriptor leaks.
struct NetlinkSocket(RawFd);

impl NetlinkSocket {
    /// Get the raw file descriptor for syscalls
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid file descriptor that we own and are done using.
        unsafe {
            libc::close(self.0);
        }
        trace!(
            event.name = "interface_controller.netlink.socket_closed",
            socket_fd = self.0,
            "netlink socket closed via RAII cleanup"
        );
    }
}

/// Netlink multicast group for link events (interface up/down)
const RTNLGRP_LINK: i32 = 1;

/// Buffer size for netlink recv (must fit largest expected message)
const NETLINK_RECV_BUFFER_SIZE: usize = 8192;

/// Spawn controller thread that permanently stays in host network namespace.
///
/// This thread:
/// - Enters host namespace once at startup via `setns()`
/// - Stays in host namespace permanently (never switches back)
/// - Handles commands from main thread via `cmd_rx` channel
/// - Handles netlink events from netlink thread via `netlink_rx` channel
/// - Sends status events back to main thread via `event_tx` channel (if provided)
/// - Performs all eBPF attach/detach operations
///
/// ## Arguments
///
/// - `host_netns_fd` - File descriptor for `/proc/1/ns/net` (host namespace)
/// - `controller` - Initialized controller (will be moved to thread)
/// - `cmd_rx` - Receiver for commands from main thread
/// - `netlink_rx` - Receiver for netlink events from netlink thread
/// - `event_tx` - Optional sender for status events back to main thread
///
/// ## Errors
///
/// Returns an error if the thread cannot be spawned due to system resource limitations.
///
/// ## Panics
///
/// The spawned thread panics if unable to enter host network namespace (requires CAP_SYS_ADMIN).
pub fn spawn_controller_thread(
    host_netns_fd: RawFd,
    mut controller: IfaceController,
    cmd_rx: Receiver<ControllerCommand>,
    netlink_rx: Receiver<NetlinkEvent>,
    event_tx: Option<Sender<ControllerEvent>>,
) -> Result<thread::JoinHandle<()>, std::io::Error> {
    thread::Builder::new()
        .name("mermin-controller".to_string())
        .spawn(move || {
            // Enter host namespace permanently
            let host_fd = unsafe { OwnedFd::from_raw_fd(host_netns_fd) };
            if let Err(e) = setns(&host_fd, CloneFlags::CLONE_NEWNET) {
                error!(
                    event.name = "interface_controller.setns_failed",
                    error = %e,
                    "fatal: failed to enter host network namespace, thread cannot function"
                );
                panic!(
                    "controller thread failed to enter host namespace: {e}. \
                     requires hostPID: true and CAP_SYS_ADMIN capability.",
                );
            }
            info!(
                event.name = "interface_controller.started",
                "controller thread started and permanently in host network namespace"
            );

            loop {
                crossbeam::select! {
                    recv(cmd_rx) -> result => {
                        match result {
                            Ok(cmd) => {
                                debug!(
                                    event.name = "interface_controller.command_received",
                                    command = %cmd,
                                    "received command from main thread"
                                );

                                match cmd {
                                    ControllerCommand::Initialize => match controller.initialize() {
                                        Ok(_) => {
                                            if let Some(ref tx) = event_tx {
                                                let _ = tx.send(ControllerEvent::Initialized {
                                                    interface_count: controller.iface_map().len(),
                                                });
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                event.name = "interface_controller.init_failed",
                                                error = %e,
                                                "controller initialization failed"
                                            );
                                        }
                                    },
                                    ControllerCommand::Shutdown => {
                                        let _ = controller.shutdown();
                                        if let Some(ref tx) = event_tx {
                                            let _ = tx.send(ControllerEvent::ShutdownComplete);
                                        }
                                        info!(
                                            event.name = "interface_controller.exiting",
                                            "controller thread exiting"
                                        );
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                warn!(
                                    event.name = "interface_controller.command_channel_closed",
                                    "command channel closed, shutting down"
                                );
                                break;
                            }
                        }
                    }
                    recv(netlink_rx) -> result => {
                        match result {
                            Ok(event) => {
                                debug!(
                                    event.name = "interface_controller.netlink_event_received",
                                    netlink_event = %event,
                                    "received netlink event from monitoring thread"
                                );

                                if let Err(e) = controller.handle_netlink_event(event) {
                                    warn!(
                                        event.name = "interface_controller.netlink_event_failed",
                                        error = %e,
                                        "failed to handle netlink event"
                                    );
                                }
                            }
                            Err(_) => {
                                debug!(
                                    event.name = "interface_controller.netlink_channel_closed",
                                    "netlink channel closed, continuing to process commands"
                                );
                                // Continue processing commands even if netlink monitoring fails
                            }
                        }
                    }
                }
            }

            info!(
                event.name = "interface_controller.stopped",
                "controller thread stopped"
            );
        })
}

/// Spawn netlink monitoring thread that permanently stays in host network namespace.
///
/// This thread:
/// - Enters host namespace once at startup via `setns()`
/// - Stays in host namespace permanently (never switches back)
/// - Creates a raw netlink socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
/// - Subscribes to RTNLGRP_LINK multicast group for interface events
/// - Blocks on `recv()` waiting for kernel netlink messages
/// - Parses RTM_NEWLINK/RTM_SETLINK/RTM_DELLINK messages
/// - Extracts interface name and UP flag from link attributes
/// - Sends `NetlinkEvent::InterfaceUp` or `InterfaceDown` to controller thread
/// - Handles message boundaries correctly using NLMSG_ALIGN
/// - Exits gracefully on socket errors or channel closure
///
/// ## Arguments
///
/// - `host_netns_fd` - File descriptor for `/proc/1/ns/net` (host namespace)
/// - `event_tx` - Sender to send netlink events to controller thread
///
/// ## Errors
///
/// Returns an error if the thread cannot be spawned due to system resource limitations.
///
/// ## Panics
///
/// The spawned thread panics if unable to enter host network namespace (requires CAP_SYS_ADMIN).
/// Errors during netlink socket setup or recv are logged and cause thread to exit gracefully.
///
/// ## Implementation Notes
///
/// Uses raw libc socket APIs instead of netlink-sys crate due to buffering
/// issues with blocking recv(). All unsafe operations are documented with
/// SAFETY comments explaining invariants.
pub fn spawn_netlink_thread(
    host_netns_fd: RawFd,
    event_tx: Sender<NetlinkEvent>,
) -> Result<thread::JoinHandle<()>, std::io::Error> {
    thread::Builder::new()
        .name("mermin-netlink".to_string())
        .spawn(move || {
            // Enter host namespace permanently
            let host_fd = unsafe { OwnedFd::from_raw_fd(host_netns_fd) };
            if let Err(e) = setns(&host_fd, CloneFlags::CLONE_NEWNET) {
                error!(
                    event.name = "interface_controller.netlink.setns_failed",
                    error = %e,
                    "fatal: failed to enter host network namespace, thread cannot function"
                );
                panic!(
                    "netlink thread failed to enter host namespace: {e}. \
                     Requires hostPID: true and CAP_SYS_ADMIN capability.",
                );
            }

            info!(
                event.name = "interface_controller.netlink.started",
                "netlink monitoring thread started and permanently in host network namespace"
            );

            // Create netlink socket using raw libc (netlink-sys Socket has buffering issues)
            // SAFETY: socket() syscall is safe to call. We check the return value for errors.
            let sock_fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE as i32) };
            if sock_fd < 0 {
                let err = std::io::Error::last_os_error();
                error!(
                    event.name = "interface_controller.netlink.socket_creation_failed",
                    error = %err,
                    "failed to create netlink socket"
                );
                return;
            }

            // Wrap socket in RAII guard to ensure cleanup on all exit paths
            let sock = NetlinkSocket(sock_fd);

            info!(
                event.name = "interface_controller.netlink.socket_created",
                socket_fd = sock.as_raw_fd(),
                "netlink socket created successfully"
            );

            // Bind with kernel-assigned PID and no groups (will subscribe via setsockopt)
            // SAFETY: sockaddr_nl is a C-compatible struct that is safe to zero-initialize.
            let mut addr: sockaddr_nl = unsafe { mem::zeroed() };
            addr.nl_family = AF_NETLINK as u16;
            addr.nl_pid = 0; // Kernel assigns PID
            addr.nl_groups = 0; // No groups in bind, use setsockopt instead

            // SAFETY: sock is a valid socket descriptor, addr is properly initialized,
            // and we're passing the correct size. Return value is checked for errors.
            let ret = unsafe {
                bind(
                    sock.as_raw_fd(),
                    &addr as *const sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<sockaddr_nl>() as u32,
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                error!(
                    event.name = "interface_controller.netlink.socket_bind_failed",
                    error = %err,
                    "failed to bind netlink socket"
                );
                return;
            }

            debug!(
                event.name = "interface_controller.netlink.socket_bound",
                "netlink socket bound successfully"
            );

            // Add multicast group membership (RTNLGRP_LINK for interface events)
            // SAFETY: sock is a valid socket, RTNLGRP_LINK is a valid i32 constant,
            // and we're passing the correct size for the option value.
            let ret = unsafe {
                setsockopt(
                    sock.as_raw_fd(),
                    SOL_NETLINK,
                    NETLINK_ADD_MEMBERSHIP,
                    &RTNLGRP_LINK as *const i32 as *const c_void,
                    mem::size_of::<i32>() as u32,
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                error!(
                    event.name = "interface_controller.netlink.setsockopt_failed",
                    error = %err,
                    group_id = RTNLGRP_LINK,
                    "failed to add netlink multicast group membership"
                );
                return;
            }

            info!(
                event.name = "interface_controller.netlink.subscribed",
                group_id = RTNLGRP_LINK,
                "subscribed to RTNLGRP_LINK multicast group, monitoring interface events"
            );

            let mut buf = vec![0u8; NETLINK_RECV_BUFFER_SIZE];
            loop {
                // SAFETY: sock is valid, buf is properly sized and mutable,
                // and we pass the correct buffer length. Return value checked for errors.
                let n = unsafe { recv(sock.as_raw_fd(), buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };

                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    error!(
                        event.name = "interface_controller.netlink.socket_recv_error",
                        error = %err,
                        "error receiving from netlink socket, exiting"
                    );
                    break;
                }

                let n = n as usize;
                if n == 0 {
                    warn!(
                        event.name = "interface_controller.netlink.socket_closed",
                        "netlink socket closed by kernel, exiting"
                    );
                    break;
                }

                trace!(
                    event.name = "interface_controller.netlink.data_received",
                    bytes = n,
                    "received netlink data"
                );

                // Parse all messages in buffer (may contain multiple netlink messages)
                let mut offset = 0;
                while offset < n {
                    let bytes = &buf[offset..n];
                    match NetlinkBuffer::new_checked(bytes) {
                        Ok(nl_buf) => {
                            match NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes) {
                                Ok(msg) => {
                                    let msg_len = nl_buf.length() as usize;
                                    // NLMSG_ALIGN with overflow protection
                                    let new_offset = offset.saturating_add((msg_len + 3) & !3);
                                    if new_offset < offset || new_offset > n {
                                        warn!(
                                            event.name = "interface_controller.netlink.invalid_message_length",
                                            msg_len = msg_len,
                                            offset = offset,
                                            buffer_size = n,
                                            "invalid message length detected, stopping parse"
                                        );
                                        break;
                                    }
                                    offset = new_offset;

                                    if let NetlinkPayload::InnerMessage(rtnl_msg) = msg.payload {
                                        match rtnl_msg {
                                            RouteNetlinkMessage::NewLink(link_msg)
                                            | RouteNetlinkMessage::SetLink(link_msg) => {
                                                if let Some(if_name) =
                                                    link_msg.attributes.iter().find_map(|attr| {
                                                        match attr {
                                                            LinkAttribute::IfName(name) => {
                                                                Some(name.to_string())
                                                            }
                                                            _ => None,
                                                        }
                                                    })
                                                {
                                                    let is_up =
                                                        link_msg.header.flags.contains(LinkFlags::Up);

                                                    if is_up {
                                                        trace!(
                                                            event.name = "interface_controller.netlink.interface_up",
                                                            network.interface.name = %if_name,
                                                            "interface came up, sending event to controller"
                                                        );
                                                        if event_tx
                                                            .send(NetlinkEvent::InterfaceUp {
                                                                name: if_name,
                                                            })
                                                            .is_err()
                                                        {
                                                            error!(
                                                                event.name = "interface_controller.netlink.channel_send_failed",
                                                                "controller channel closed, exiting"
                                                            );
                                                            return;
                                                        }
                                                    } else {
                                                        trace!(
                                                            event.name = "interface_controller.netlink.interface_down_newlink",
                                                            network.interface.name = %if_name,
                                                            "interface reported without UP flag"
                                                        );
                                                    }
                                                }
                                            }
                                            RouteNetlinkMessage::DelLink(link_msg) => {
                                                if let Some(if_name) =
                                                    link_msg.attributes.iter().find_map(|attr| {
                                                        match attr {
                                                            LinkAttribute::IfName(name) => {
                                                                Some(name.to_string())
                                                            }
                                                            _ => None,
                                                        }
                                                    })
                                                {
                                                    trace!(
                                                        event.name = "interface_controller.netlink.interface_down",
                                                        network.interface.name = %if_name,
                                                        "interface went down, sending event to controller"
                                                    );
                                                    if event_tx
                                                        .send(NetlinkEvent::InterfaceDown {
                                                            name: if_name,
                                                        })
                                                        .is_err()
                                                    {
                                                        error!(
                                                            event.name = "interface_controller.netlink.channel_send_failed",
                                                            "controller channel closed, exiting"
                                                        );
                                                        return;
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        event.name = "interface_controller.netlink.message_parse_error",
                                        error = %e,
                                        "failed to parse netlink message, skipping"
                                    );
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            trace!(
                                event.name = "interface_controller.netlink.buffer_check_failed",
                                error = ?e,
                                offset = offset,
                                remaining = n - offset,
                                "not enough bytes for complete message, ending parse loop"
                            );
                            break;
                        }
                    }
                }
            }

            info!(
                event.name = "interface_controller.netlink.stopped",
                "netlink monitoring thread stopped, socket will be closed by RAII wrapper"
            );
        })
}
