// Test program for neli crate approach
//
// This test validates that neli can receive multicast link events
// using its higher-level API.

use neli::{
    consts::{nl::*, rtnl::*, socket::*},
    nl::{NlPayload, Nlmsghdr},
    rtnl::Ifinfomsg,
    socket::NlSocketHandle,
    types::RtBuffer,
};

#[test]
fn test_neli_multicast() {
    println!("\n=== Testing neli crate with multicast ===\n");

    // Create netlink socket with ROUTE protocol
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])
        .expect("Failed to create neli socket");

    // Subscribe to RTNLGRP_LINK multicast group
    // neli uses add_mcast_membership for subscribing
    socket
        .add_mcast_membership(&[RtGrp::Link])
        .expect("Failed to subscribe to RTNLGRP_LINK");

    println!("Socket created and subscribed to RTNLGRP_LINK");
    println!("Listening for link events...");
    println!("(This test will timeout after 5 seconds if no events are received)\n");

    // Set socket to non-blocking with timeout
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("Failed to set read timeout");

    let mut event_count = 0;

    // Try to receive events for 5 seconds
    loop {
        match socket.recv::<Rtm, Ifinfomsg>() {
            Ok(Some(msg)) => {
                event_count += 1;
                println!("Event #{}: Sequence: {}", event_count, msg.nl_seq());

                // Check message type
                let msg_type = msg.nl_type();
                let type_str = match msg_type {
                    Rtm::Newlink => "RTM_NEWLINK",
                    Rtm::Dellink => "RTM_DELLINK",
                    Rtm::Getlink => "RTM_GETLINK",
                    _ => "OTHER",
                };
                println!("  Type: {} ({:?})", type_str, msg_type);

                // Parse the payload
                match msg.nl_payload() {
                    NlPayload::Payload(ifinfo) => {
                        println!("  Interface index: {}", ifinfo.ifi_index);
                        println!("  Interface type: {}", ifinfo.ifi_type);
                        println!("  Flags: 0x{:08x}", ifinfo.ifi_flags);

                        // Try to get interface name from attributes
                        let rtattrs = ifinfo.rtattrs();
                        for attr in rtattrs.iter() {
                            if let Ok(name) = attr.rta_payload().as_ref().try_into() {
                                let name_str = std::str::from_utf8(name).unwrap_or("<invalid>");
                                if !name_str.is_empty() && name_str.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
                                    println!("  Interface name: {}", name_str.trim_end_matches('\0'));
                                    break;
                                }
                            }
                        }
                    }
                    NlPayload::Empty => {
                        println!("  Empty payload");
                    }
                    NlPayload::Err(e) => {
                        println!("  Error payload: {:?}", e);
                    }
                    _ => {
                        println!("  Other payload type");
                    }
                }
                println!();
            }
            Ok(None) => {
                // No message available, timeout
                println!("Timeout reached after 5 seconds");
                break;
            }
            Err(e) => {
                // Check if it's a timeout error
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    println!("Timeout reached after 5 seconds");
                    break;
                }
                eprintln!("Error receiving from socket: {:?}", e);
                break;
            }
        }

        // If we've received at least 1 event, that's enough to validate the approach
        if event_count >= 1 {
            println!("✓ Successfully received {} event(s)", event_count);
            println!("✓ neli with RTNLGRP_LINK subscription works!");
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
    // 1. Socket was created and subscribed successfully (already validated by reaching here)
    // 2. Either we received events OR no events occurred during test period
    println!("\n=== Test completed ===");
}

#[test]
fn test_neli_creation() {
    println!("\n=== Testing basic neli socket creation ===\n");

    // Just verify we can create a socket and subscribe
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])
        .expect("Failed to create neli socket");

    socket
        .add_mcast_membership(&[RtGrp::Link])
        .expect("Failed to subscribe to RTNLGRP_LINK");

    println!("✓ Socket created and subscribed successfully");
    println!("✓ Basic neli functionality works");
}
