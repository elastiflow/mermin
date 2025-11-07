// Pure Rust netlink implementation for monitoring network interface events
//
// This implementation uses netlink-sys to replace raw libc syscalls for netlink
// socket operations. It demonstrates the winning approach from the netlink
// evaluation (netlink-sys + netlink-packet-route).
//
// Key improvements over raw libc:
// - Pure Rust implementation (no unsafe syscalls for socket operations)
// - Type-safe netlink message handling
// - Better error handling and ergonomics
// - Maintains compatibility with namespace switching (setns)

use netlink_packet_core::{NetlinkHeader, NetlinkDeserializable};
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::io::{Error, ErrorKind};
use std::time::Duration;

/// RTMGRP_LINK multicast group bitmask
/// This is used to subscribe to link (network interface) events
const RTMGRP_LINK: u32 = 0x00000001;

/// Represents a network interface link event
#[derive(Debug, Clone)]
pub enum LinkEvent {
    /// A new network interface was added
    NewLink {
        /// Interface index
        index: u32,
        /// Interface name (if available)
        name: Option<String>,
        /// Interface flags
        flags: u32,
    },
    /// A network interface was deleted
    DelLink {
        /// Interface index
        index: u32,
        /// Interface name (if available)
        name: Option<String>,
    },
    /// Other link-related event
    Other,
}

/// Pure Rust netlink monitor for network interface events
///
/// This replaces the raw libc-based implementation with netlink-sys,
/// providing a safer and more idiomatic Rust interface.
///
/// # Example
///
/// ```no_run
/// use crate::iface::NetlinkMonitor;
///
/// let mut monitor = NetlinkMonitor::new().expect("Failed to create monitor");
///
/// // Poll for events with a timeout
/// match monitor.recv_event(std::time::Duration::from_secs(1)) {
///     Ok(Some(event)) => println!("Received event: {:?}", event),
///     Ok(None) => println!("Timeout, no events"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub struct NetlinkMonitor {
    /// The netlink socket (pure Rust, no raw libc)
    socket: Socket,
    /// Receive buffer
    buffer: Vec<u8>,
}

impl NetlinkMonitor {
    /// Create a new netlink monitor
    ///
    /// This creates a netlink socket and subscribes to the RTMGRP_LINK multicast group
    /// to receive network interface change events.
    ///
    /// # Pure Rust Implementation
    ///
    /// This replaces the following raw libc code:
    /// ```c
    /// let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
    /// let addr = sockaddr_nl { nl_family: AF_NETLINK, nl_groups: RTMGRP_LINK, ... };
    /// libc::bind(fd, &addr, ...);
    /// ```
    ///
    /// With pure Rust:
    /// ```rust,no_run
    /// let socket = Socket::new(NETLINK_ROUTE)?;
    /// socket.bind(&SocketAddr::new(0, RTMGRP_LINK))?;
    /// ```
    pub fn new() -> Result<Self, Error> {
        // Create netlink socket (pure Rust, no raw libc)
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create netlink socket: {}", e)))?;

        // Bind with RTMGRP_LINK bitmask for multicast subscription
        // Key insight: SocketAddr expects a BITMASK in the groups field, not a group ID
        let addr = SocketAddr::new(0, RTMGRP_LINK);
        socket.bind(&addr)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to bind netlink socket: {}", e)))?;

        Ok(Self {
            socket,
            buffer: vec![0u8; 8192], // Standard netlink buffer size
        })
    }

    /// Receive a link event with a timeout
    ///
    /// This polls the netlink socket for events with the specified timeout.
    /// Returns `Ok(Some(event))` if an event was received, `Ok(None)` on timeout,
    /// or `Err(e)` on error.
    ///
    /// # Pure Rust Implementation
    ///
    /// This replaces:
    /// ```c
    /// let n = libc::recv(fd, buf, len, MSG_DONTWAIT);
    /// ```
    ///
    /// With:
    /// ```rust,no_run
    /// let n = socket.recv(&mut buf, libc::MSG_DONTWAIT as i32)?;
    /// ```
    pub fn recv_event(&mut self, timeout: Duration) -> Result<Option<LinkEvent>, Error> {
        let start = std::time::Instant::now();

        loop {
            // Check if timeout has elapsed
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            // Try to receive from socket (non-blocking)
            match self.socket.recv(&mut self.buffer, libc::MSG_DONTWAIT as i32) {
                Ok(n) => {
                    // Parse the received message
                    return self.parse_message(&self.buffer[..n]);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // No data available, sleep briefly and try again
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    /// Receive a link event (blocking)
    ///
    /// This blocks until an event is received or an error occurs.
    ///
    /// # Pure Rust Implementation
    ///
    /// This replaces:
    /// ```c
    /// let n = libc::recv(fd, buf, len, 0);
    /// ```
    ///
    /// With:
    /// ```rust,no_run
    /// let n = socket.recv(&mut buf, 0)?;
    /// ```
    pub fn recv_event_blocking(&mut self) -> Result<LinkEvent, Error> {
        loop {
            // Blocking receive
            let n = self.socket.recv(&mut self.buffer, 0)?;
            
            // Parse the received message
            match self.parse_message(&self.buffer[..n])? {
                Some(event) => return Ok(event),
                None => continue, // Skip unparseable messages
            }
        }
    }

    /// Parse a netlink message into a LinkEvent
    ///
    /// This uses netlink-packet-route for type-safe message parsing,
    /// replacing manual C struct manipulation.
    fn parse_message(&self, bytes: &[u8]) -> Result<Option<LinkEvent>, Error> {
        // Parse the netlink header first
        if bytes.len() < std::mem::size_of::<NetlinkHeader>() {
            return Ok(None); // Message too small
        }

        let header_bytes = &bytes[..std::mem::size_of::<NetlinkHeader>()];
        let header = NetlinkHeader::deserialize(header_bytes)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Failed to parse netlink header: {:?}", e)))?;

        // Parse the route message
        let payload_bytes = &bytes[header_bytes.len()..];
        let route_msg = RouteNetlinkMessage::deserialize(&header, payload_bytes)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Failed to parse route message: {:?}", e)))?;

        // Convert to LinkEvent
        let event = match route_msg {
            RouteNetlinkMessage::NewLink(link_msg) => {
                LinkEvent::NewLink {
                    index: link_msg.header.index,
                    name: extract_interface_name(&link_msg),
                    flags: link_msg.header.flags,
                }
            }
            RouteNetlinkMessage::DelLink(link_msg) => {
                LinkEvent::DelLink {
                    index: link_msg.header.index,
                    name: extract_interface_name(&link_msg),
                }
            }
            _ => LinkEvent::Other,
        };

        Ok(Some(event))
    }

    /// Get a reference to the underlying socket
    ///
    /// This can be used for advanced operations like switching network namespaces
    /// using `setns()` (which still requires libc as it's not a socket operation).
    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

/// Extract the interface name from a link message
fn extract_interface_name(link_msg: &LinkMessage) -> Option<String> {
    use netlink_packet_route::link::LinkAttribute;
    
    for attr in &link_msg.attributes {
        if let LinkAttribute::IfName(name) = attr {
            return Some(name.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_monitor() {
        // This test validates that the pure Rust netlink implementation works
        let monitor = NetlinkMonitor::new();
        assert!(monitor.is_ok(), "Failed to create netlink monitor: {:?}", monitor.err());
    }

    #[test]
    fn test_recv_with_timeout() {
        let mut monitor = NetlinkMonitor::new().expect("Failed to create monitor");
        
        // Try to receive with a short timeout (should timeout if no events)
        let result = monitor.recv_event(Duration::from_millis(100));
        
        // Should either timeout (Ok(None)) or receive an event (Ok(Some(_)))
        // Should NOT error in normal conditions
        match result {
            Ok(None) => {
                // Timeout is expected if no interface changes
                println!("No events received (timeout)");
            }
            Ok(Some(event)) => {
                // Event received
                println!("Received event: {:?}", event);
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }
}
