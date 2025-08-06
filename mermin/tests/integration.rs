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
        let iface_a = format!("{}-a", name);
        let iface_b = format!("{}-b", name);
        let ns_name = format!("{}-ns", name);

        run_cmd(&format!("sudo ip netns add {}", ns_name));
        run_cmd(&format!(
            "sudo ip link add {} type veth peer name {}",
            iface_a, iface_b
        ));
        run_cmd(&format!("sudo ip link set {} netns {}", iface_b, ns_name));

        match version {
            IpVersion::V4 => {
                run_cmd(&format!(
                    "sudo sysctl -w net.ipv6.conf.{}.disable_ipv6=1",
                    iface_a
                ));
                run_cmd(&format!(
                    "sudo ip addr add {}/24 dev {}",
                    IPV4_HOST, iface_a
                ));
                run_cmd(&format!(
                    "sudo ip netns exec {} sysctl -w net.ipv6.conf.{}.disable_ipv6=1",
                    ns_name, iface_b
                ));
                run_cmd(&format!(
                    "sudo ip netns exec {} ip addr add {}/24 dev {}",
                    ns_name, IPV4_NS, iface_b
                ));
            }
            IpVersion::V6 => {
                run_cmd(&format!(
                    "sudo ip -6 addr add {}/64 dev {}",
                    IPV6_HOST, iface_a
                ));
                run_cmd(&format!(
                    "sudo ip netns exec {} ip -6 addr add {}/64 dev {}",
                    ns_name, IPV6_NS, iface_b
                ));
            }
        }

        run_cmd(&format!("sudo ip link set dev {} up", iface_a));
        run_cmd(&format!(
            "sudo ip netns exec {} ip link set dev {} up",
            ns_name, iface_b
        ));
        run_cmd(&format!(
            "sudo ip netns exec {} ip link set dev lo up",
            ns_name
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
    println!("--- Mermin STDERR ({}) ---\n{}", test_name, stderr);

    for &expected in expected_logs {
        assert!(
            stderr.contains(expected),
            "Validation failed for test '{}': Did not find log line '{}'",
            test_name,
            expected
        );
    }
}

#[tokio::test]
async fn test_ipv4_udp_packet_is_captured() {
    run_test_scenario(
        "udp_v4_test",
        IpVersion::V4,
        || async {
            let dest_addr: SocketAddr = format!("{}:{}", IPV4_NS, UDP_PORT).parse().unwrap();
            info!("Sending UDP packet to {}", dest_addr);
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
            socket.send_to(b"test", &dest_addr.into()).unwrap();
        },
        &[
            &format!("Dst IPV4: {}", IPV4_NS),
            &format!("Dst Port: {}", UDP_PORT),
        ],
    )
    .await;
}

#[tokio::test]
async fn test_ipv6_tcp_packet_is_captured() {
    run_test_scenario(
        "tcp_v6_test",
        IpVersion::V6,
        || async {
            let dest_addr = format!("[{}]:{}", IPV6_NS, TCP_PORT);
            info!("Attempting TCP connection to {}", dest_addr);
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                tokio::net::TcpStream::connect(dest_addr),
            )
            .await;
        },
        &[
            &format!("Dst IPV6: {}", IPV6_NS),
            &format!("Dst Port: {}", TCP_PORT),
        ],
    )
    .await;
}

fn run_cmd(cmd: &str) {
    let status = Command::new("sh").arg("-c").arg(cmd).status().unwrap();
    assert!(status.success(), "Command failed: {}", cmd);
}
