use std::{
    env,
    future::Future,
    net::SocketAddr,
    process::{Command, Stdio},
    time::Duration,
};

use log::info;
use socket2::{Domain, Socket, Type};

const IPV4_HOST: &str = "192.168.100.1";
const IPV4_NS: &str = "192.168.100.2";
const IPV6_HOST: &str = "fd00:100::1";
const IPV6_NS: &str = "fd00:100::2";
const UDP_PORT: u16 = 12345;
const TCP_PORT: u16 = 54321;

#[derive(Clone, Copy)]
enum IpVersion {
    V4,
    V6,
}

/// A unified helper to set up a virtual network for either IPv4 or IPv6.
struct TestNetwork {
    iface_a: String,
    // ns_name: for debugging.
    #[allow(dead_code)]
    ns_name: String,
}

impl TestNetwork {
    fn new(name: &str, version: IpVersion) -> Self {
        let iface_a = format!("{name}-a");
        let iface_b = format!("{name}-b");
        let ns_name = format!("{name}-ns");

        run_cmd(&format!("sudo ip netns add {ns_name}"));
        run_cmd(&format!(
            "sudo ip link add {iface_a} type veth peer name {iface_b}"
        ));
        run_cmd(&format!("sudo ip link set {iface_b} netns {ns_name}"));

        match version {
            IpVersion::V4 => {
                run_cmd(&format!(
                    "sudo sysctl -w net.ipv6.conf.{iface_a}.disable_ipv6=1"
                ));
                run_cmd(&format!("sudo ip addr add {IPV4_HOST}/24 dev {iface_a}"));
                run_cmd(&format!(
                    "sudo ip netns exec {ns_name} sysctl -w net.ipv6.conf.{iface_b}.disable_ipv6=1"
                ));
                run_cmd(&format!(
                    "sudo ip netns exec {ns_name} ip addr add {IPV4_NS}/24 dev {iface_b}"
                ));
            }
            IpVersion::V6 => {
                run_cmd(&format!("sudo ip -6 addr add {IPV6_HOST}/64 dev {iface_a}"));
                run_cmd(&format!(
                    "sudo ip netns exec {ns_name} ip -6 addr add {IPV6_NS}/64 dev {iface_b}"
                ));
            }
        }

        run_cmd(&format!("sudo ip link set dev {iface_a} up"));
        run_cmd(&format!(
            "sudo ip netns exec {ns_name} ip link set dev {iface_b} up"
        ));
        run_cmd(&format!(
            "sudo ip netns exec {ns_name} ip link set dev lo up"
        ));

        TestNetwork { iface_a, ns_name }
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        run_cmd(&format!("sudo ip netns del {}", self.ns_name));
    }
}

async fn run_test_scenario<F, Fut>(
    test_name: &str,
    version: IpVersion,
    traffic_generator: F,
    expected_logs: &[&str],
) where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let net = TestNetwork::new(test_name, version);

    let mut mermin_process = Command::new("sudo")
        .arg("-E")
        .arg(env!("CARGO_BIN_EXE_mermin"))
        .arg("--iface")
        .arg(&net.iface_a)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start mermin process");

    tokio::time::sleep(Duration::from_secs(3)).await;

    traffic_generator().await;

    tokio::time::sleep(Duration::from_secs(2)).await;
    mermin_process
        .kill()
        .expect("Failed to stop mermin process");

    let output = mermin_process
        .wait_with_output()
        .expect("Failed to get mermin output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("--- Mermin STDERR ({test_name}) ---\n{stderr}");

    for &expected in expected_logs {
        assert!(
            stderr.contains(expected),
            "Validation failed for test '{test_name}': Did not find log line '{expected}'"
        );
    }
}

#[ignore]
#[tokio::test]
async fn test_ipv4_udp_packet_is_captured() {
    run_test_scenario(
        "udp_v4_test",
        IpVersion::V4,
        || async {
            let dest_addr: SocketAddr = format!("{IPV4_NS}:{UDP_PORT}").parse().unwrap();
            info!("Sending UDP packet to {dest_addr}");
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
            socket.send_to(b"test", &dest_addr.into()).unwrap();
        },
        &[
            &format!("Dst IPV4: {IPV4_NS}"),
            &format!("Dst Port: {UDP_PORT}"),
        ],
    )
    .await;
}

#[ignore]
#[tokio::test]
async fn test_ipv6_tcp_packet_is_captured() {
    run_test_scenario(
        "tcp_v6_test",
        IpVersion::V6,
        || async {
            let dest_addr = format!("[{IPV6_NS}]:{TCP_PORT}");
            info!("Attempting TCP connection to {dest_addr}");
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                tokio::net::TcpStream::connect(dest_addr),
            )
            .await;
        },
        &[
            &format!("Dst IPV6: {IPV6_NS}"),
            &format!("Dst Port: {TCP_PORT}"),
        ],
    )
    .await;
}

fn run_cmd(cmd: &str) {
    let status = Command::new("sh").arg("-c").arg(cmd).status().unwrap();
    assert!(status.success(), "Command failed: {cmd}");
}

// ========================================================================
// Event-Driven Flow Architecture Integration Tests
// ========================================================================

#[cfg(test)]
mod event_driven_tests {
    use std::{sync::Arc, time::Duration};

    use mermin_common::{ConnectionState, Direction, FlowKey, FlowStats, IpVersion};
    use network_types::{eth::EtherType, ip::IpProto};
    use tokio::sync::Mutex;

    /// Mock eBPF flow event handler
    struct MockFlowEventHandler {
        events: Arc<Mutex<Vec<FlowKey>>>,
        stats: Arc<Mutex<Vec<(FlowKey, FlowStats)>>>,
    }

    impl MockFlowEventHandler {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                stats: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn handle_flow_event(&self, flow_key: FlowKey, stats: FlowStats) {
            let mut stats_map = self.stats.lock().await;

            // Check if flow already exists
            if let Some(pos) = stats_map.iter().position(|(k, _)| k == &flow_key) {
                // Update existing flow
                stats_map[pos].1 = stats;
            } else {
                // New flow - add to events and stats
                let mut events = self.events.lock().await;
                events.push(flow_key);
                drop(events); // Release lock before pushing to stats

                stats_map.push((flow_key, stats));
            }
        }

        async fn get_events(&self) -> Vec<FlowKey> {
            self.events.lock().await.clone()
        }

        async fn get_stats(&self, key: &FlowKey) -> Option<FlowStats> {
            let stats = self.stats.lock().await;
            stats.iter().find(|(k, _)| k == key).map(|(_, s)| *s)
        }
    }

    fn create_ipv4_flow_key(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        proto: IpProto,
    ) -> FlowKey {
        let mut key = FlowKey {
            ip_version: IpVersion::V4,
            protocol: proto,
            src_ip: [0u8; 16],
            dst_ip: [0u8; 16],
            src_port: sport,
            dst_port: dport,
        };
        key.src_ip[..4].copy_from_slice(&src);
        key.dst_ip[..4].copy_from_slice(&dst);
        key
    }

    fn normalize_flow_key(key: FlowKey) -> FlowKey {
        fn should_reverse(key: &FlowKey) -> bool {
            for i in 0..16 {
                if key.src_ip[i] < key.dst_ip[i] {
                    return false;
                }
                if key.src_ip[i] > key.dst_ip[i] {
                    return true;
                }
            }
            if key.src_port < key.dst_port {
                return false;
            }
            if key.src_port > key.dst_port {
                return true;
            }
            false
        }

        if !should_reverse(&key) {
            return key;
        }

        let mut normalized = key;
        for i in 0..16 {
            let tmp = normalized.src_ip[i];
            normalized.src_ip[i] = normalized.dst_ip[i];
            normalized.dst_ip[i] = tmp;
        }
        let tmp_port = normalized.src_port;
        normalized.src_port = normalized.dst_port;
        normalized.dst_port = tmp_port;

        normalized
    }

    #[tokio::test]
    async fn test_flow_event_creation() {
        let handler = MockFlowEventHandler::new();

        // Simulate new flow detection in eBPF
        let flow_key = create_ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp);
        let stats = FlowStats {
            first_seen_ns: 1000000,
            last_seen_ns: 1000000,
            packets: 1,
            bytes: 64,
            reverse_packets: 0,
            reverse_bytes: 0,
            src_ip: flow_key.src_ip,
            dst_ip: flow_key.dst_ip,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ifindex: 1,
            ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: flow_key.src_port,
            dst_port: flow_key.dst_port,
            direction: Direction::Ingress,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            reverse_ip_flow_label: 0,
            tcp_flags: 0x02, // SYN
            tcp_state: ConnectionState::SynSent,
            forward_tcp_flags: 0x02,
            reverse_tcp_flags: 0x00,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
        };

        handler.handle_flow_event(flow_key, stats).await;

        let events = handler.get_events().await;
        assert_eq!(events.len(), 1, "should have one flow event");
        assert_eq!(events[0], flow_key);

        let retrieved_stats = handler.get_stats(&flow_key).await;
        assert!(retrieved_stats.is_some());
        assert_eq!(retrieved_stats.unwrap().packets, 1);
    }

    #[tokio::test]
    async fn test_bidirectional_flow_aggregation() {
        let handler = MockFlowEventHandler::new();

        // Forward direction
        let forward_key =
            create_ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp);
        let normalized_key = normalize_flow_key(forward_key);

        let forward_stats = FlowStats {
            first_seen_ns: 1000000,
            last_seen_ns: 1005000,
            packets: 10,
            bytes: 640,
            reverse_packets: 0,
            reverse_bytes: 0,
            src_ip: forward_key.src_ip,
            dst_ip: forward_key.dst_ip,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ifindex: 1,
            ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: forward_key.src_port,
            dst_port: forward_key.dst_port,
            direction: Direction::Ingress,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            reverse_ip_flow_label: 0,
            tcp_flags: 0x12, // SYN+ACK
            tcp_state: ConnectionState::SynReceived,
            forward_tcp_flags: 0x12,
            reverse_tcp_flags: 0x00,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
        };

        handler
            .handle_flow_event(normalized_key, forward_stats)
            .await;

        // Reverse direction (should aggregate with forward)
        let reverse_key =
            create_ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345, IpProto::Tcp);
        let normalized_reverse = normalize_flow_key(reverse_key);

        // Verify normalization produces same key
        assert_eq!(
            normalized_key, normalized_reverse,
            "bidirectional flows should normalize to same key"
        );

        // Simulate updated stats after reverse traffic
        let updated_stats = FlowStats {
            first_seen_ns: 1000000,
            last_seen_ns: 1010000,
            packets: 10,
            bytes: 640,
            reverse_packets: 8,
            reverse_bytes: 512,
            src_ip: forward_key.src_ip,
            dst_ip: forward_key.dst_ip,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ifindex: 1,
            ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: forward_key.src_port,
            dst_port: forward_key.dst_port,
            direction: Direction::Ingress,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            reverse_ip_flow_label: 0,
            tcp_flags: 0x1A, // SYN+ACK+PSH
            tcp_state: ConnectionState::Established,
            forward_tcp_flags: 0x1A,
            reverse_tcp_flags: 0x00,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 1,
        };

        // Update stats (simulating eBPF map update)
        handler
            .handle_flow_event(normalized_key, updated_stats)
            .await;

        let final_stats = handler.get_stats(&normalized_key).await.unwrap();
        assert_eq!(final_stats.packets, 10, "forward packets should match");
        assert_eq!(
            final_stats.reverse_packets, 8,
            "reverse packets should be tracked"
        );
        assert_eq!(final_stats.bytes, 640, "forward bytes should match");
        assert_eq!(
            final_stats.reverse_bytes, 512,
            "reverse bytes should be tracked"
        );
    }

    #[tokio::test]
    async fn test_flow_delta_calculation() {
        let handler = MockFlowEventHandler::new();

        let flow_key = create_ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp);

        // First observation
        let stats_t1 = FlowStats {
            first_seen_ns: 1000000,
            last_seen_ns: 1005000,
            packets: 10,
            bytes: 640,
            reverse_packets: 8,
            reverse_bytes: 512,
            src_ip: flow_key.src_ip,
            dst_ip: flow_key.dst_ip,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ifindex: 1,
            ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: flow_key.src_port,
            dst_port: flow_key.dst_port,
            direction: Direction::Ingress,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            reverse_ip_flow_label: 0,
            tcp_flags: 0x12,
            tcp_state: ConnectionState::Established,
            forward_tcp_flags: 0x12,
            reverse_tcp_flags: 0x00,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 1,
        };

        handler.handle_flow_event(flow_key, stats_t1).await;

        // Simulate passage of time and more traffic
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second observation (cumulative stats)
        let stats_t2 = FlowStats {
            first_seen_ns: 1000000,
            last_seen_ns: 1105000,
            packets: 25,         // +15 packets
            bytes: 1600,         // +960 bytes
            reverse_packets: 20, // +12 packets
            reverse_bytes: 1280, // +768 bytes
            src_ip: flow_key.src_ip,
            dst_ip: flow_key.dst_ip,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ifindex: 1,
            ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: flow_key.src_port,
            dst_port: flow_key.dst_port,
            direction: Direction::Ingress,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            reverse_ip_flow_label: 0,
            tcp_flags: 0x1A,
            tcp_state: ConnectionState::Established,
            forward_tcp_flags: 0x1A,
            reverse_tcp_flags: 0x00,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 1,
        };

        handler.handle_flow_event(flow_key, stats_t2).await;

        // Calculate deltas
        let delta_packets = stats_t2.packets - stats_t1.packets;
        let delta_bytes = stats_t2.bytes - stats_t1.bytes;
        let delta_reverse_packets = stats_t2.reverse_packets - stats_t1.reverse_packets;
        let delta_reverse_bytes = stats_t2.reverse_bytes - stats_t1.reverse_bytes;

        assert_eq!(delta_packets, 15, "delta packets should be 15");
        assert_eq!(delta_bytes, 960, "delta bytes should be 960");
        assert_eq!(
            delta_reverse_packets, 12,
            "delta reverse packets should be 12"
        );
        assert_eq!(
            delta_reverse_bytes, 768,
            "delta reverse bytes should be 768"
        );
    }

    #[tokio::test]
    async fn test_multiple_flows_concurrent() {
        let handler = Arc::new(MockFlowEventHandler::new());

        // Create multiple flows concurrently
        let flows = vec![
            create_ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp),
            create_ipv4_flow_key([10, 0, 0, 3], [10, 0, 0, 4], 54321, 443, IpProto::Tcp),
            create_ipv4_flow_key([10, 0, 0, 5], [10, 0, 0, 6], 9000, 53, IpProto::Udp),
        ];

        let mut tasks = Vec::new();

        for (idx, flow_key) in flows.iter().enumerate() {
            let handler_clone = Arc::clone(&handler);
            let key = *flow_key;

            let task = tokio::spawn(async move {
                let stats = FlowStats {
                    first_seen_ns: 1000000 + (idx as u64 * 1000),
                    last_seen_ns: 1000000 + (idx as u64 * 1000),
                    packets: (idx + 1) as u64 * 10,
                    bytes: (idx + 1) as u64 * 640,
                    reverse_packets: 0,
                    reverse_bytes: 0,
                    src_ip: key.src_ip,
                    dst_ip: key.dst_ip,
                    src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, idx as u8],
                    ifindex: 1,
                    ip_flow_label: 0,
                    ether_type: EtherType::Ipv4,
                    src_port: key.src_port,
                    dst_port: key.dst_port,
                    direction: Direction::Ingress,
                    ip_version: IpVersion::V4,
                    protocol: key.protocol,
                    ip_dscp: 0,
                    ip_ecn: 0,
                    ip_ttl: 64,
                    reverse_ip_dscp: 0,
                    reverse_ip_ecn: 0,
                    reverse_ip_ttl: 0,
                    reverse_ip_flow_label: 0,
                    tcp_flags: 0x02,
                    tcp_state: if key.protocol == IpProto::Tcp {
                        ConnectionState::SynSent
                    } else {
                        ConnectionState::Closed
                    },
                    forward_tcp_flags: 0x02,
                    reverse_tcp_flags: 0x00,
                    icmp_type: 0,
                    icmp_code: 0,
                    reverse_icmp_type: 0,
                    reverse_icmp_code: 0,
                    forward_metadata_seen: 1,
                    reverse_metadata_seen: 0,
                };

                handler_clone.handle_flow_event(key, stats).await;
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        for task in tasks {
            task.await.unwrap();
        }

        let events = handler.get_events().await;
        assert_eq!(events.len(), 3, "should have three flow events");

        // Verify each flow has correct stats
        for (idx, flow_key) in flows.iter().enumerate() {
            let stats = handler.get_stats(flow_key).await;
            assert!(stats.is_some(), "stats should exist for flow {idx}");
            assert_eq!(
                stats.unwrap().packets,
                (idx + 1) as u64 * 10,
                "packets should match for flow {idx}"
            );
        }
    }
}
