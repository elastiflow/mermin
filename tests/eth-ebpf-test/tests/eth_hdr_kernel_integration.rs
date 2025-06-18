/*
//! End‑to‑end check that exercises the real eBPF classifier in kernel space.
//!
//! Requires root privileges (CAP_NET_ADMIN + CAP_BPF).  Run via
//!     sudo -E cargo test -p eth-ebpf-test -- --test-threads=1
//! or simply use `./run_tests.sh`.

use anyhow::{bail, Context, Result};
use aya::{
    maps::HashMap as UserHashMap,
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use std::{
    process::Command,
    thread,
    time::Duration,
};

// The path to the eBPF object file is determined at compile time relative
// to the package's manifest directory.
const BPF_ELF: &str = concat!(
env!("CARGO_MANIFEST_DIR"),
"/../target/bpfel-unknown-none/release/eth-ebpf-test"
);

const MAP_NAME: &str = "ETHHDR_RESULT";

fn run(cmd: &str) -> Result<()> {
    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if !status.success() {
        bail!("`{cmd}` failed with {status}");
    }
    Ok(())
}

fn destroy_veth() {
    let _ = Command::new("ip").args(["link", "del", "veth0"]).status();
}

fn create_veth() -> Result<()> {
    // Always clean up first
    destroy_veth();
    // Create the veth pair
    run("ip link add veth0 type veth peer name veth1")?;
    run("ip link set veth0 up")?;
    run("ip link set veth1 up")?;
    run("ip addr add 10.42.0.1/24 dev veth0")?;
    run("ip addr add 10.42.0.2/24 dev veth1")?;
    // Disable IPv6 on both interfaces to force IPv4 usage.
    // We ignore potential errors in case IPv6 is already disabled.
    let _ = run("sysctl -w net.ipv6.conf.veth0.disable_ipv6=1");
    let _ = run("sysctl -w net.ipv6.conf.veth1.disable_ipv6=1");
    // Wait a bit for interfaces to be ready
    thread::sleep(Duration::from_millis(100));
    // Get MAC addresses and add static ARP entries to avoid ARP resolution
    let veth0_mac = get_mac_address("veth0")?;
    let veth1_mac = get_mac_address("veth1")?;
    // Add static ARP entries
    run(&format!("ip neigh add 10.42.0.1 lladdr {} dev veth1", veth0_mac))?;
    run(&format!("ip neigh add 10.42.0.2 lladdr {} dev veth0", veth1_mac))?;
    // Verify interfaces exist
    let status = Command::new("ip")
        .args(["link", "show", "veth0"])
        .status()?;
    if !status.success() {
        bail!("veth0 interface was not created successfully");
    }
    Ok(())
}

fn get_mac_address(interface: &str) -> Result<String> {
    let output = Command::new("ip")
        .args(["link", "show", interface])
        .output()?;
    let output_str = String::from_utf8(output.stdout)?;
    // Parse MAC address from output like: "link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"
    for line in output_str.lines() {
        if line.contains("link/ether") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(mac_index) = parts.iter().position(|&x| x == "link/ether") {
                if let Some(mac) = parts.get(mac_index + 1) {
                    return Ok(mac.to_string());
                }
            }
        }
    }
    bail!("Could not find MAC address for interface {}", interface)
}

fn load_and_attach() -> Result<Ebpf> {
    // Add clsact qdisc and handle potential errors
    if let Err(e) = tc::qdisc_add_clsact("veth0") {
        eprintln!("Warning: Failed to add clsact qdisc: {}", e);
    }
    println!("Loading eBPF program from: {}", BPF_ELF);
    let mut bpf = Ebpf::load_file(BPF_ELF)?;
    let prog: &mut SchedClassifier = bpf
        .program_mut("eth_hdr_test")
        .context("failed to find program `eth_hdr_test`")?
        .try_into()
        .context("classifier cast")?;
    println!("Loading eBPF program...");
    prog.load()?;
    println!("Attaching eBPF program to veth0 ingress...");
    prog.attach("veth0", TcAttachType::Ingress)?;
    Ok(bpf)
}

fn fetch_result(bpf: &Ebpf) -> Result<u16> {
    let map = bpf
        .map(MAP_NAME)
        .context("failed to find map `ETHHDR_RESULT`")?;
    let map: UserHashMap<_, u32, u16> = UserHashMap::try_from(map)?;
    // Debug: Try to see if there are any keys in the map
    println!("Checking map contents...");
    for key in 0..10u32 {
        if let Ok(val) = map.get(&key, 0) {
            println!("Found key {}: value 0x{:04x}", key, val);
        }
    }
    map.get(&0u32, 0).context("ETHHDR_RESULT[0] was unset")
}

#[test]
fn ipv4_packet_sets_ethertype_0x0800() -> Result<()> {
    println!("Starting test...");
    create_veth()?;
    let bpf = load_and_attach()?;
    // Wait a bit after attachment
    thread::sleep(Duration::from_millis(200));
    // Instead of UDP, let's try ping which is more likely to trigger the eBPF program
    println!("Sending ping packet...");
    let ping_status = Command::new("ping")
        .args(["-c", "1", "-W", "1", "-I", "veth1", "10.42.0.1"])
        .status()?;
    if !ping_status.success() {
        println!("Warning: Ping failed, but this might be expected");
    }
    // Wait longer for processing
    thread::sleep(Duration::from_millis(500));
    println!("Fetching result...");
    let val = fetch_result(&bpf)?;
    println!("Got EtherType: 0x{:04x}", val);
    assert_eq!(val, 0x0800, "expected EtherType 0x0800 (IPv4)");
    destroy_veth();
    Ok(())
}
 */
