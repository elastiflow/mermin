//! Test‑only helper: backs a packet with a virtually‑addressed buffer that is
//! **guaranteed** to live below 0x1_0000_0000 so that the 32‑bit
//! `__sk_buff.data` and `data_end` fields can hold the address.

#![allow(dead_code)]

use core::{cmp, ptr};

use aya_ebpf::{bindings::__sk_buff, programs::TcContext};

use std::{
    net::{SocketAddr, UdpSocket},
    process::Command,
    sync::Once,
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    maps::HashMap as UserHashMap,
    programs::{SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use log::{error, info};
use socket2::{Domain, Socket, Type};
use tokio::time::sleep;


pub struct PacketBuf {
    ptr: *mut u8,
    len: usize,
}

impl PacketBuf {
    /// Allocate `len.max(page_size)` bytes below and copy `data` into it.
    pub fn new(data: &[u8]) -> Self {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let len = cmp::max(page_size, data.len());
            let hint = 0x1000_0000 as *mut libc::c_void;
            let addr = libc::mmap(
                hint,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | 0x100000, // MAP_FIXED_NOREPLACE
                -1,
                0,
            );
            if addr == libc::MAP_FAILED {
                panic!("mmap failed when creating PacketBuf");
            }
            ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
            Self {
                ptr: addr as *mut u8,
                len,
            }
        }
    }

    /// Fill the given `__sk_buff` and yield a real `TcContext`.
    pub fn as_ctx(&self, skb: &mut __sk_buff) -> TcContext {
        skb.data = self.ptr as u32;
        skb.data_end = (self.ptr as usize + self.len) as u32;
        skb.len = self.len as u32;
        // Safety: the lifetimes line up – we pin `self` for the duration of `ctx`.
        TcContext::new(skb)
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}

/// Path to the eBPF ELF file.
pub const BPF_ELF: &str = concat!(
env!("CARGO_MANIFEST_DIR"),
"/../target/bpfel-unknown-none/release/eth-ebpf-test"
);

/// Interval for retrying map reads.
pub const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum number of retries for map reads.
pub const MAX_RETRIES: u32 = 20;


/// IPv4 address for veth0.
pub const IP0_V4: &str = "10.42.0.1";
/// IPv4 address for veth1.
pub const IP1_V4: &str = "10.42.0.2";
/// IPv6 address for veth0.
pub const IP0_V6: &str = "fc00:42::1";
/// IPv6 address for veth1.
pub const IP1_V6: &str = "fc00:42::2";

static LOG_INIT: Once = Once::new();

/// Initializes logging for tests.
pub fn setup_logging() {
    LOG_INIT.call_once(|| {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    });
}
/// Executes a shell command and checks for success.
pub fn run(cmd: &mut Command) -> Result<()> {
    info!("Running command: {:?}", cmd);
    let status = cmd.status().with_context(|| format!("failed: {:?}", cmd))?;
    if !status.success() {
        error!("Command failed with status {}: {:?}", status, cmd);
        anyhow::bail!("command {:?} failed: {status}", cmd);
    }
    Ok(())
}

/// Destroys the veth pair `veth0`-`veth1` and cleans up associated `tc` qdiscs.
pub fn destroy_veth() {
    info!("Destroying veth pair...");
    // Attempt to delete qdiscs and interfaces; ignore errors as they might not exist.
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", "veth0", "clsact"])
        .status();
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", "veth1", "clsact"])
        .status();
    let _ = Command::new("ip").args(["link", "del", "veth0"]).status();
    std::thread::sleep(Duration::from_millis(50));
    info!("Veth pair destroyed.");
}

/// Creates a veth pair `veth0`-`veth1`, assigns IP addresses, and brings them up.
pub async fn create_veth() -> Result<()> {
    info!("Creating veth pair...");
    destroy_veth(); // Ensure a clean state before creation

    run(Command::new("ip").args([
        "link", "add", "veth0", "type", "veth", "peer", "name", "veth1",
    ]))?;
    run(Command::new("ip").args(["addr", "add", &format!("{IP0_V4}/24"), "dev", "veth0"]))?;
    run(Command::new("ip").args(["addr", "add", &format!("{IP1_V4}/24"), "dev", "veth1"]))?;
    run(Command::new("ip").args([
        "-6",
        "addr",
        "add",
        &format!("{IP0_V6}/64"),
        "dev",
        "veth0",
        "nodad",
    ]))?;
    run(Command::new("ip").args([
        "-6",
        "addr",
        "add",
        &format!("{IP1_V6}/64"),
        "dev",
        "veth1",
        "nodad",
    ]))?;

    run(Command::new("ip").args(["link", "set", "veth0", "up"]))?;
    run(Command::new("ip").args(["link", "set", "veth1", "up"]))?;

    run(Command::new("tc").args(["qdisc", "add", "dev", "veth0", "clsact"]))?;
    run(Command::new("tc").args(["qdisc", "add", "dev", "veth1", "clsact"]))?;

    info!("Priming neighbour caches…");
    run(Command::new("ping").args(["-c", "1", "-W", "1", "-I", IP1_V4, IP0_V4]))?;
    run(Command::new("ping").args(["-c", "1", "-W", "1", "-I", IP0_V4, IP1_V4]))?;
    run(Command::new("ping6").args(["-c", "1", "-W", "1", "-I", IP1_V6, IP0_V6]))?;
    run(Command::new("ping6").args(["-c", "1", "-W", "1", "-I", IP0_V6, IP1_V6]))?;

    sleep(Duration::from_millis(200)).await;
    info!("Veth setup complete.");
    Ok(())
}

/// Loads an eBPF program from the specified ELF file and attaches it to a network device.
///
/// # Arguments
/// * `bpf_elf_path` - The path to the eBPF ELF file.
/// * `program_name` - The name of the eBPF program to load from the ELF file.
/// * `attach_device` - The name of the network interface to attach the program to.
pub fn load_and_attach_bpf(program_name: &str) -> Result<Ebpf> {
    info!("Loading eBPF program from: {}", BPF_ELF);
    let mut bpf = Ebpf::load_file(BPF_ELF).context("load BPF object")?;

    let prog: &mut SchedClassifier = bpf
        .program_mut(program_name)
        .context("program not found")?
        .try_into()?;

    prog.load()?;
    prog.attach("veth0", TcAttachType::Ingress)?;
    info!("eBPF program loaded and attached successfully.");
    Ok(bpf)
}

/// Creates a UDP socket bound to a specific interface (veth1).
pub fn create_socket_for_sender(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = Socket::new(
        if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        None,
    )?;
    // Bind the socket to the 'veth1' device to ensure packets are sent from there.
    socket.bind_device(Some(b"veth1\0"))?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}
