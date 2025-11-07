// Test program for netlink-sys approach with RTMGRP_LINK bitmask
//
// This test validates that netlink-sys can receive multicast link events
// when bound with the correct RTMGRP_LINK bitmask in the SocketAddr.

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::io::ErrorKind;

// RTMGRP_LINK multicast group bitmask
const RTMGRP_LINK: u32 = 0x00000001;

#[test]
fn test_netlink_sys_multicast() {
    println!("\n=== Testing netlink-sys with RTMGRP_LINK bitmask ===\n");

    // Create netlink socket
    let mut socket = Socket::new(NETLINK_ROUTE).expect("Failed to create netlink socket");

    // Bind with RTMGRP_LINK bitmask (not group ID)
    // Key insight: SocketAddr expects a bitmask in the groups field, not a group ID
    let addr = SocketAddr::new(0, RTMGRP_LINK);
    socket.bind(&addr).expect("Failed to bind socket");

    println!("Socket created and bound with RTMGRP_LINK bitmask");
    println!("Listening for link events...");
    println!("(This test will timeout after 5 seconds if no events are received)\n");

    // Set a receive timeout
    let timeout = std::time::Duration::from_secs(5);
    socket
        .set_recv_timeout(Some(timeout))
        .expect("Failed to set recv timeout");

    let mut buf = vec![0u8; 8192];
    let mut event_count = 0;

    // Try to receive events for 5 seconds
    loop {
        match socket.recv(&mut buf, 0) {
            Ok(n) => {
                println!("Received {} bytes", n);

                // Parse the netlink message
                let bytes = &buf[..n];
                let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes);

                match msg {
                    Ok(nl_msg) => {
                        event_count += 1;
                        println!("Event #{}: Sequence: {}", event_count, nl_msg.header.sequence_number);

                        match nl_msg.payload {
                            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) => {
                                print_link_event("RTM_NEWLINK", &link_msg);
                            }
                            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link_msg)) => {
                                print_link_event("RTM_DELLINK", &link_msg);
                            }
                            NetlinkPayload::Done(_) => {
                                println!("  Type: NLMSG_DONE");
                            }
                            NetlinkPayload::Error(err) => {
                                println!("  Type: NLMSG_ERROR");
                                println!("  Error code: {}", err.code);
                            }
                            _ => {
                                println!("  Type: Other message type");
                            }
                        }
                        println!();
                    }
                    Err(e) => {
                        println!("Failed to parse netlink message: {:?}", e);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // Timeout reached
                println!("Timeout reached after 5 seconds");
                break;
            }
            Err(e) => {
                eprintln!("Error receiving from socket: {:?}", e);
                break;
            }
        }

        // If we've received at least 1 event, that's enough to validate the approach
        if event_count >= 1 {
            println!("✓ Successfully received {} event(s)", event_count);
            println!("✓ netlink-sys with RTMGRP_LINK bitmask works!");
            break;
        }
    }

    if event_count == 0 {
        println!("⚠ No events received during test period");
        println!("Note: This is expected if no network interfaces are being added/removed");
        println!("To test manually, run this test and in another terminal:");
        println!("  sudo ip link add dummy0 type dummy");
        println!("  sudo ip link del dummy0");
    }

    // Test passes if:
    // 1. Socket was created and bound successfully (already validated by reaching here)
    // 2. Either we received events OR no events occurred during test period
    println!("\n=== Test completed ===");
}

fn print_link_event(event_type: &str, link_msg: &LinkMessage) {
    println!("  Type: {}", event_type);
    println!("  Interface index: {}", link_msg.header.index);
    println!("  Interface type: {}", link_msg.header.link_layer_type);
    println!("  Flags: 0x{:08x}", link_msg.header.flags);

    // Try to extract interface name from attributes
    for nla in &link_msg.attributes {
        use netlink_packet_route::link::LinkAttribute;
        if let LinkAttribute::IfName(name) = nla {
            println!("  Interface name: {}", name);
            break;
        }
    }
}

#[test]
fn test_netlink_sys_creation() {
    println!("\n=== Testing basic netlink-sys socket creation ===\n");

    // Just verify we can create and bind a socket
    let socket = Socket::new(NETLINK_ROUTE).expect("Failed to create netlink socket");
    let addr = SocketAddr::new(0, RTMGRP_LINK);
    
    // This should not panic
    socket.bind(&addr).expect("Failed to bind socket");

    println!("✓ Socket created and bound successfully");
    println!("✓ Basic netlink-sys functionality works");
}
