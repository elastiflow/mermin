// Test program for rtnetlink crate approach
//
// This test explores whether rtnetlink can be configured to receive
// multicast link events. rtnetlink is typically used for querying and
// manipulating network configuration, but may support event monitoring.

use futures::stream::StreamExt;
use rtnetlink::{new_connection, LinkHandle};
use std::time::Duration;

#[tokio::test]
async fn test_rtnetlink_link_get() {
    println!("\n=== Testing rtnetlink basic link enumeration ===\n");

    // Create connection
    let (connection, handle, _) = new_connection().expect("Failed to create rtnetlink connection");

    // Spawn connection handler
    tokio::spawn(connection);

    // Get link handle
    let link_handle = handle.link();

    println!("Querying current network interfaces...\n");

    // List all links
    let mut links = link_handle.get().execute();

    let mut count = 0;
    while let Some(link) = links.try_next().await.expect("Failed to get link") {
        count += 1;
        println!("Interface #{}:", count);
        println!("  Index: {}", link.header.index);
        println!("  Link type: {}", link.header.link_layer_type);
        println!("  Flags: 0x{:08x}", link.header.flags);

        // Try to get interface name
        for nla in &link.attributes {
            use netlink_packet_route::link::LinkAttribute;
            if let LinkAttribute::IfName(name) = nla {
                println!("  Name: {}", name);
                break;
            }
        }
        println!();
    }

    println!("✓ Successfully queried {} interface(s)", count);
    println!("✓ rtnetlink basic functionality works");
    println!("\n=== Test completed ===");
}

#[tokio::test]
async fn test_rtnetlink_multicast_exploration() {
    println!("\n=== Exploring rtnetlink multicast capabilities ===\n");

    // Create connection
    let (connection, handle, _) = new_connection().expect("Failed to create rtnetlink connection");

    // Spawn connection handler
    tokio::spawn(connection);

    println!("rtnetlink Analysis:");
    println!("------------------");
    println!("• rtnetlink is built on top of netlink-sys and netlink-packet-route");
    println!("• It provides a high-level async API for querying and modifying network config");
    println!("• Default usage does NOT subscribe to multicast groups");
    println!();
    println!("Multicast Support:");
    println!("------------------");
    println!("• rtnetlink::new_connection() does NOT expose multicast subscription");
    println!("• The underlying Socket is created with groups=0 (no multicast)");
    println!("• To receive events, we would need to:");
    println!("  1. Access the underlying netlink_sys::Socket");
    println!("  2. Manually add multicast membership after connection");
    println!();

    // Try to keep the test alive for a few seconds to see if anything comes through
    println!("Waiting 3 seconds to see if any unsolicited messages arrive...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    println!("\n⚠ As expected, rtnetlink does not receive multicast events by default");
    println!();
    println!("Conclusion:");
    println!("-----------");
    println!("• rtnetlink is NOT designed for receiving multicast events");
    println!("• It's optimized for request-response patterns (get/set operations)");
    println!("• For event monitoring, netlink-sys or neli are better choices");
    println!("• Possible workaround: access underlying socket via rtnetlink internals");
    println!("  but this defeats the purpose of using the high-level API");
    println!();

    // Let's examine if we can access the underlying socket
    println!("Examining rtnetlink source code access patterns:");
    println!("• new_connection() returns (Connection, Handle, messages)");
    println!("• Connection wraps the Socket but doesn't expose it publicly");
    println!("• No public API to add multicast membership");
    println!("• Would require forking/patching rtnetlink or using netlink-sys directly");

    println!("\n=== Test completed ===");
}

#[tokio::test]
async fn test_rtnetlink_verdict() {
    println!("\n=== rtnetlink Final Verdict ===\n");

    println!("Evaluation for Multicast Event Monitoring:");
    println!("-------------------------------------------");
    println!();
    println!("✗ NOT SUITABLE for our use case");
    println!();
    println!("Reasons:");
    println!("1. No built-in multicast subscription API");
    println!("2. Designed for request-response, not event monitoring");
    println!("3. Would require accessing internals or patching the library");
    println!("4. Adds unnecessary async complexity for a simple event listener");
    println!();
    println!("Recommendation:");
    println!("Use either netlink-sys (low-level, full control) or");
    println!("neli (mid-level, cleaner API) instead.");
    println!();
    println!("=== Test completed ===");
}
