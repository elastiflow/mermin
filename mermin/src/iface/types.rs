//! Types for inter-thread communication in the dual-thread controller architecture.
//!
//! This module defines the command and event types used for communication between:
//! - Main thread (container namespace) → Controller thread (host namespace)
//! - Netlink thread (host namespace) → Controller thread (host namespace)
//! - Controller thread (host namespace) → Main thread (container namespace)

use std::fmt;

/// Commands sent from main thread to controller thread.
///
/// The main thread (running in container namespace) sends these commands to the
/// controller thread (running in host namespace) to trigger eBPF program operations.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ControllerCommand {
    /// Perform initial attachment to all configured interfaces.
    ///
    /// This should be sent once after controller thread startup to attach eBPF
    /// programs to all interfaces matching the configured patterns.
    Initialize,

    /// Shutdown controller and detach all programs.
    ///
    /// This triggers graceful shutdown: detach all eBPF programs from all interfaces
    /// and exit the controller thread loop.
    Shutdown,
}

impl fmt::Display for ControllerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialize => write!(f, "initialize"),
            Self::Shutdown => write!(f, "shutdown"),
        }
    }
}

/// Events sent from controller thread to main thread for observability.
///
/// The controller thread sends these events to inform the main thread about
/// state changes and completion of operations. The main thread can use these
/// for logging, metrics, or coordination (e.g., waiting for initialization).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ControllerEvent {
    /// Interface attached successfully.
    ///
    /// Sent when eBPF programs are successfully attached to an interface
    /// (both ingress and egress programs).
    InterfaceAttached { iface: String },

    /// Interface detached successfully.
    ///
    /// Sent when eBPF programs are successfully detached from an interface
    /// (both ingress and egress programs).
    InterfaceDetached { iface: String },

    /// Attachment failed (non-fatal, will retry).
    ///
    /// Sent when interface attachment fails. The controller will automatically
    /// retry when the interface becomes available again via netlink events.
    AttachmentFailed { iface: String, error: String },

    /// Initialization complete.
    ///
    /// Sent when the Initialize command completes. Indicates how many interfaces
    /// were successfully attached.
    Initialized { interface_count: usize },

    /// Shutdown complete.
    ///
    /// Sent when the Shutdown command completes. Indicates the controller thread
    /// is about to exit.
    ShutdownComplete,
}

impl fmt::Display for ControllerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceAttached { iface } => write!(f, "interface_attached({iface})"),
            Self::InterfaceDetached { iface } => write!(f, "interface_detached({iface})"),
            Self::AttachmentFailed { iface, error } => {
                write!(f, "attachment_failed({iface}), ({error})")
            }
            Self::Initialized { interface_count } => {
                write!(f, "initialized({interface_count} interfaces)")
            }
            Self::ShutdownComplete => write!(f, "shutdown_complete"),
        }
    }
}

/// Netlink events sent from netlink thread to controller thread.
///
/// The netlink monitoring thread (running in host namespace) sends these events
/// to the controller thread when it detects interface state changes via netlink.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NetlinkEvent {
    /// Interface came up or was modified (RTM_NEWLINK with IFF_UP).
    ///
    /// Sent when an interface becomes active. The controller should check if it
    /// matches configured patterns and attach eBPF programs if needed.
    InterfaceUp { name: String },

    /// Interface went down or was removed (RTM_DELLINK or IFF_UP cleared).
    ///
    /// Sent when an interface becomes inactive. The controller should detach
    /// eBPF programs if they were attached.
    InterfaceDown { name: String },
}

impl fmt::Display for NetlinkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceUp { name } => write!(f, "interface_up({name})"),
            Self::InterfaceDown { name } => write!(f, "interface_down({name})"),
        }
    }
}
