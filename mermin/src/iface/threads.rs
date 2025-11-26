//! Thread spawning functions for the dual-thread controller architecture.
//!
//! This module provides functions to spawn:
//! 1. Netlink monitoring thread - permanently in host namespace, blocking netlink socket
//! 2. Controller thread - permanently in host namespace, handles commands and netlink events
//!
//! Also provides helper functions for coordinating with controller thread lifecycle.

use std::{mem, os::fd::RawFd, sync::Arc, thread, time};

use crossbeam::channel::{Receiver, Sender};
use libc::{
    AF_NETLINK, EFD_NONBLOCK, NETLINK_ADD_MEMBERSHIP, POLLERR, POLLHUP, POLLIN, POLLNVAL, SOCK_RAW,
    SOL_NETLINK, bind, c_void, eventfd, poll, pollfd, recv, setsockopt, sockaddr_nl, socket,
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
use crate::error::MerminError;

/// Default timeout for waiting for controller thread to become ready (in seconds)
pub const CONTROLLER_READY_TIMEOUT_SECS: u64 = 30;

/// Default timeout for waiting for controller initialization to complete (in seconds)
pub const CONTROLLER_INIT_TIMEOUT_SECS: u64 = 30;

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

/// RAII wrapper for eventfd used to signal shutdown to netlink thread.
/// Automatically closes the eventfd when dropped.
pub struct ShutdownEventFd(RawFd);

impl ShutdownEventFd {
    pub fn new() -> Result<Self, std::io::Error> {
        // SAFETY: eventfd() is safe to call, we check for errors
        let fd = unsafe { eventfd(0, EFD_NONBLOCK) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    fn as_raw_fd(&self) -> RawFd {
        self.0
    }

    /// Signal shutdown by writing to the eventfd
    pub fn signal(&self) -> Result<(), std::io::Error> {
        let val: u64 = 1;
        // SAFETY: self.0 is valid, val is properly initialized
        let ret = unsafe {
            libc::write(
                self.0,
                &val as *const u64 as *const c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for ShutdownEventFd {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid file descriptor that we own
        unsafe {
            libc::close(self.0);
        }
        trace!(
            event.name = "interface_controller.netlink.shutdown_fd_closed",
            fd = self.0,
            "shutdown eventfd closed via RAII cleanup"
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
/// - `host_netns` - Arc-wrapped File handle for `/proc/1/ns/net` (host namespace)
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
    host_netns: Arc<std::fs::File>,
    mut controller: IfaceController,
    cmd_rx: Receiver<ControllerCommand>,
    netlink_rx: Receiver<NetlinkEvent>,
    event_tx: Option<Sender<ControllerEvent>>,
) -> Result<thread::JoinHandle<()>, std::io::Error> {
    thread::Builder::new()
        .name("mermin-controller".to_string())
        .spawn(move || {
            // Enter host namespace permanently. Thread holds Arc reference to File,
            // ensuring FD stays open for the duration of setns() call. No risk of
            // use-after-close since each thread has its own reference count.
            if let Err(e) = setns(host_netns.as_ref(), CloneFlags::CLONE_NEWNET) {
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

            if let Some(ref tx) = event_tx && tx.send(ControllerEvent::Ready).is_err() {
                error!(
                    event.name = "interface_controller.ready_send_failed",
                    "failed to send ready event, main thread may have exited"
                );
                return;
            }
            info!(
                event.name = "interface_controller.ready",
                "controller ready to receive commands"
            );

            // Buffer for netlink events received before initialization completes
            let mut netlink_event_buffer: Vec<NetlinkEvent> = Vec::new();
            let mut initialized = false;

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
                                    ControllerCommand::Initialize => {
                                        info!(
                                            event.name = "interface_controller.init_command_received",
                                            "processing initialize command"
                                        );

                                        match controller.initialize() {
                                            Ok(_) => {
                                                initialized = true;

                                                if let Some(ref tx) = event_tx {
                                                    let _ = tx.send(ControllerEvent::Initialized {
                                                        interface_count: controller.iface_map().len(),
                                                    });
                                                }

                                                // Process buffered netlink events that arrived during initialization
                                                if !netlink_event_buffer.is_empty() {
                                                    debug!(
                                                        event.name = "interface_controller.processing_buffered_events",
                                                        event_count = netlink_event_buffer.len(),
                                                        "processing netlink events buffered during initialization"
                                                    );

                                                    for buffered_event in netlink_event_buffer.drain(..) {
                                                        if let Err(e) = controller.handle_netlink_event(buffered_event) {
                                                            warn!(
                                                                event.name = "interface_controller.buffered_event_failed",
                                                                error = %e,
                                                                "failed to handle buffered netlink event"
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    event.name = "interface_controller.init_failed",
                                                    error = %e,
                                                    "controller initialization failed"
                                                );
                                            }
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
                                if initialized {
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
                                } else {
                                    debug!(
                                        event.name = "interface_controller.netlink_event_buffered",
                                        netlink_event = %event,
                                        "buffering netlink event until initialization completes"
                                    );
                                    netlink_event_buffer.push(event);
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
/// - Blocks on `recv()` with 1-second timeout waiting for kernel netlink messages
/// - Parses RTM_NEWLINK/RTM_SETLINK/RTM_DELLINK messages
/// - Extracts interface name and UP flag from link attributes
/// - Sends `NetlinkEvent::InterfaceUp` or `InterfaceDown` to controller thread
/// - Handles message boundaries correctly using NLMSG_ALIGN
/// - Exits gracefully when channel is disconnected (detected during recv timeout)
///
/// ## Graceful Shutdown
///
/// Uses `poll()` to wait on both the netlink socket and a shutdown eventfd. When shutdown
/// is requested, the main thread signals the eventfd, causing `poll()` to wake immediately.
/// This avoids busy loops and provides instant shutdown response with zero CPU overhead.
///
/// ## Arguments
///
/// - `host_netns` - Arc-wrapped File handle for `/proc/1/ns/net` (host namespace)
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
    host_netns: Arc<std::fs::File>,
    event_tx: Sender<NetlinkEvent>,
) -> Result<(thread::JoinHandle<()>, Arc<ShutdownEventFd>), std::io::Error> {
    // Create shutdown eventfd before spawning thread
    let shutdown_fd = Arc::new(ShutdownEventFd::new()?);
    let shutdown_fd_clone = Arc::clone(&shutdown_fd);
    thread::Builder::new()
        .name("mermin-netlink".to_string())
        .spawn(move || {
            // Enter host namespace permanently. Thread holds Arc reference to File,
            // ensuring FD stays open for the duration of setns() call. No risk of
            // use-after-close since each thread has its own reference count.
            if let Err(e) = setns(host_netns.as_ref(), CloneFlags::CLONE_NEWNET) {
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
            let mut total_messages_received = 0u64;
            let mut total_messages_skipped = 0u64;

            // Setup poll fds: watch both netlink socket and shutdown eventfd
            let mut fds = [
                pollfd {
                    fd: sock.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                },
                pollfd {
                    fd: shutdown_fd_clone.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                },
            ];

            loop {
                // Wait for events on either socket or shutdown signal
                // SAFETY: fds array is properly initialized, timeout -1 means wait indefinitely
                let poll_ret = unsafe { poll(fds.as_mut_ptr(), fds.len() as u64, -1) };

                if poll_ret < 0 {
                    let err = std::io::Error::last_os_error();
                    error!(
                        event.name = "interface_controller.netlink.poll_error",
                        error = %err,
                        "poll() failed, exiting"
                    );
                    break;
                }

                // Check for errors on either FD first
                if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 {
                    error!(
                        event.name = "interface_controller.netlink.socket_error",
                        revents = fds[0].revents,
                        "netlink socket error detected via poll(), exiting"
                    );
                    break;
                }
                if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 {
                    error!(
                        event.name = "interface_controller.netlink.shutdown_fd_error",
                        revents = fds[1].revents,
                        "shutdown eventfd error detected via poll(), exiting"
                    );
                    break;
                }

                // Check if shutdown was signaled
                if (fds[1].revents & POLLIN) != 0 {
                    info!(
                        event.name = "interface_controller.netlink.shutdown_signaled",
                        total_messages_received = total_messages_received,
                        total_messages_skipped = total_messages_skipped,
                        "shutdown signal received, exiting gracefully"
                    );
                    break;
                }

                // Check if socket has data ready
                if (fds[0].revents & POLLIN) == 0 {
                    // No data on socket, loop again
                    continue;
                }

                // SAFETY: sock is valid, buf is properly sized and mutable,
                // and we pass the correct buffer length. Return value checked for errors.
                let n = unsafe { recv(sock.as_raw_fd(), buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };

                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    error!(
                        event.name = "interface_controller.netlink.socket_recv_error",
                        error = %err,
                        total_messages_received = total_messages_received,
                        total_messages_skipped = total_messages_skipped,
                        "error receiving from netlink socket, exiting"
                    );
                    break;
                }

                let n = n as usize;
                if n == 0 {
                    warn!(
                        event.name = "interface_controller.netlink.socket_closed",
                        total_messages_received = total_messages_received,
                        total_messages_skipped = total_messages_skipped,
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
                let mut messages_in_batch = 0;
                let mut skipped_in_batch = 0;
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
                                            "invalid message length detected, stopping parse - skipping remaining messages in batch"
                                        );
                                        skipped_in_batch += 1;
                                        break;
                                    }
                                    offset = new_offset;
                                    messages_in_batch += 1;

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
                                        "failed to parse netlink message, skipping remaining messages in batch"
                                    );
                                    skipped_in_batch += 1;
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

                // Update counters
                total_messages_received += messages_in_batch;
                total_messages_skipped += skipped_in_batch;

                if skipped_in_batch > 0 {
                    warn!(
                        event.name = "interface_controller.netlink.messages_skipped",
                        skipped_in_batch = skipped_in_batch,
                        total_skipped = total_messages_skipped,
                        total_received = total_messages_received,
                        "skipped netlink messages due to parsing errors or invalid lengths"
                    );
                }
            }

            info!(
                event.name = "interface_controller.netlink.stopped",
                "netlink monitoring thread stopped, socket will be closed by RAII wrapper"
            );
        })
        .map(|handle| (handle, shutdown_fd))
}

/// Wait for controller thread to enter host namespace and become ready.
///
/// This function blocks until the controller thread sends the `Ready` event,
/// indicating it has successfully entered the host network namespace and is
/// ready to receive commands.
///
/// Timeout is controlled by `CONTROLLER_READY_TIMEOUT_SECS` constant.
///
/// ## Arguments
///
/// - `event_rx` - Receiver for controller events
/// - `cmd_tx` - Sender for commands (used to send shutdown on timeout)
///
/// ## Returns
///
/// - `Ok(())` if controller becomes ready within timeout
/// - `Err(MerminError)` if timeout occurs or unexpected event received
pub fn wait_for_controller_ready(
    event_rx: &Receiver<ControllerEvent>,
    cmd_tx: &Sender<ControllerCommand>,
) -> Result<(), MerminError> {
    info!(
        event.name = "interface_controller.waiting_for_ready",
        timeout_secs = CONTROLLER_READY_TIMEOUT_SECS,
        "waiting for controller thread to enter host namespace and become ready"
    );

    match event_rx.recv_timeout(time::Duration::from_secs(CONTROLLER_READY_TIMEOUT_SECS)) {
        Ok(ControllerEvent::Ready) => {
            info!(
                event.name = "interface_controller.ready_received",
                "controller thread is ready to receive commands"
            );
            Ok(())
        }
        Ok(other) => Err(MerminError::internal(format!(
            "unexpected controller event while waiting for ready: {other:?}",
        ))),
        Err(_) => {
            warn!(
                event.name = "interface_controller.ready_timeout",
                "ready signal timed out, controller thread may have failed to start"
            );
            let _ = cmd_tx.send(ControllerCommand::Shutdown);
            Err(MerminError::internal(format!(
                "controller ready timeout after {CONTROLLER_READY_TIMEOUT_SECS}s"
            )))
        }
    }
}

/// Wait for controller initialization to complete.
///
/// This function blocks until the controller thread sends the `Initialized` event,
/// draining intermediate events like `InterfaceAttached` and `AttachmentFailed` that
/// may arrive during the initialization process.
///
/// Timeout is controlled by `CONTROLLER_INIT_TIMEOUT_SECS` constant.
///
/// ## Arguments
///
/// - `event_rx` - Receiver for controller events
/// - `cmd_tx` - Sender for commands (used to send shutdown on timeout)
///
/// ## Returns
///
/// - `Ok(interface_count)` if initialization completes successfully
/// - `Err(MerminError)` if timeout occurs or unexpected event received
pub fn wait_for_controller_initialized(
    event_rx: &Receiver<ControllerEvent>,
    cmd_tx: &Sender<ControllerCommand>,
) -> Result<usize, MerminError> {
    info!(
        event.name = "interface_controller.waiting_for_initialized",
        timeout_secs = CONTROLLER_INIT_TIMEOUT_SECS,
        "waiting for initialization to complete"
    );

    // Loop to drain intermediate events (InterfaceAttached, AttachmentFailed) until we receive
    // the final Initialized event. During initialization, the controller sends an event for each
    // interface attachment (success or failure), which may arrive before the Initialized event.
    let init_deadline =
        time::Instant::now() + time::Duration::from_secs(CONTROLLER_INIT_TIMEOUT_SECS);

    loop {
        let remaining_timeout = init_deadline.saturating_duration_since(time::Instant::now());

        match event_rx.recv_timeout(remaining_timeout) {
            Ok(ControllerEvent::Initialized { interface_count }) => {
                info!(
                    event.name = "interface_controller.initialized",
                    interface_count = interface_count,
                    "controller initialized successfully"
                );
                return Ok(interface_count);
            }
            Ok(ControllerEvent::InterfaceAttached { iface }) => {
                debug!(
                    event.name = "interface_controller.init_interface_attached",
                    network.interface.name = %iface,
                    "interface attached during initialization (expected)"
                );
            }
            Ok(ControllerEvent::AttachmentFailed { iface, error }) => {
                debug!(
                    event.name = "interface_controller.init_attachment_failed",
                    network.interface.name = %iface,
                    error = %error,
                    "interface attachment failed during initialization (expected, will be retried)"
                );
            }
            Ok(ControllerEvent::InterfaceDetached { iface }) => {
                debug!(
                    event.name = "interface_controller.init_interface_detached",
                    network.interface.name = %iface,
                    "interface detached during initialization (unexpected but non-fatal)"
                );
            }
            Ok(other) => {
                return Err(MerminError::internal(format!(
                    "unexpected controller event during initialization: {other:?}",
                )));
            }
            Err(_) => {
                warn!(
                    event.name = "interface_controller.init_timeout",
                    "initialization timed out, sending shutdown to controller thread"
                );
                let _ = cmd_tx.send(ControllerCommand::Shutdown);
                return Err(MerminError::internal(format!(
                    "controller initialization timeout after {CONTROLLER_INIT_TIMEOUT_SECS}s"
                )));
            }
        }
    }
}

/// Spawn background task to handle controller events for observability.
///
/// This creates a blocking thread that continuously receives and logs controller events.
/// The task will exit when the controller sends `ShutdownComplete` or the channel closes.
///
/// ## Arguments
///
/// - `event_rx` - Receiver for controller events
///
/// ## Returns
///
/// - `JoinHandle` for the spawned thread
pub fn spawn_controller_event_handler(
    event_rx: Receiver<ControllerEvent>,
) -> Result<thread::JoinHandle<()>, std::io::Error> {
    thread::Builder::new()
        .name("mermin-controller-events".to_string())
        .spawn(move || {
            while let Ok(event) = event_rx.recv() {
                match event {
                    ControllerEvent::InterfaceAttached { iface } => {
                        info!(
                            event.name = "interface_controller.interface_attached",
                            network.interface.name = %iface,
                            "interface attached successfully"
                        );
                    }
                    ControllerEvent::InterfaceDetached { iface } => {
                        info!(
                            event.name = "interface_controller.interface_detached",
                            network.interface.name = %iface,
                            "interface detached successfully"
                        );
                    }
                    ControllerEvent::AttachmentFailed { iface, error } => {
                        warn!(
                            event.name = "interface_controller.attachment_failed",
                            network.interface.name = %iface,
                            error.message = %error,
                            "interface attachment failed"
                        );
                    }
                    ControllerEvent::Ready => {
                        // Ready event is waited for synchronously before this task spawns,
                        // but log it if we somehow receive it here
                        debug!(
                            event.name = "interface_controller.unexpected_ready",
                            "received ready event in background handler"
                        );
                    }
                    ControllerEvent::Initialized { interface_count } => {
                        // Initialization is waited for synchronously before this task spawns,
                        // but log it if we somehow receive it here
                        debug!(
                            event.name = "interface_controller.unexpected_initialization",
                            interface_count = interface_count,
                            "received initialization event in background handler"
                        );
                    }
                    ControllerEvent::ShutdownComplete => {
                        info!(
                            event.name = "interface_controller.shutdown_complete",
                            "controller thread shutdown successfully"
                        );
                        // Exit the event loop since controller is shutting down
                        break;
                    }
                }
            }
            debug!(
                event.name = "interface_controller.event_handler_stopped",
                "controller event handler stopped"
            );
        })
}
