use anyhow::{anyhow, Context};
use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, HashMap, MapData},
    programs::KProbe,
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use integration_common::{ParsedHeader, REQUEST_DATA_SIZE};
use log::warn;
use std::{mem::size_of, sync::Once};
use tokio::sync::mpsc;

// This ensures env_logger is initialized only once for all tests.
static LOG_INIT: Once = Once::new();

/// A harness that holds all the necessary components for a single test run.
/// The `bpf` field is important because it owns the programs and maps.
/// If it goes out of scope, they are unloaded from the kernel.
pub struct TestHarness {
    pub ebpf: Ebpf,
    pub in_data: HashMap<MapData, u32, [u8; REQUEST_DATA_SIZE]>,
    // The receiver is now an mpsc::Receiver to handle events from all CPUs.
    result_rx: mpsc::Receiver<ParsedHeader>,
}

impl TestHarness {
    /// A helper method to run the common test flow:
    /// 1. Send data to the kernel.
    /// 2. Trigger the eBPF program.
    /// 3. Wait for and return the result from the kernel.
    pub async fn trigger_and_receive(
        &mut self,
        data_to_send: [u8; REQUEST_DATA_SIZE],
    ) -> Result<ParsedHeader, anyhow::Error> {
        // Get our process ID to use as the map key.
        let pid = unsafe { libc::getpid() } as u32;

        // Insert the data into the map for the eBPF program to read.
        self.in_data.insert(pid, data_to_send, 0)?;

        // Trigger the kprobe by calling the hooked syscall.
        // We must use the result of the syscall in a way that the compiler
        // cannot optimize away, so we use `read_volatile`.
        let trigger_pid = unsafe { libc::getpid() };
        let _ = unsafe { core::ptr::read_volatile(&trigger_pid) };

        // Wait for a result from any of the CPU listener tasks.
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.result_rx.recv(),
        )
            .await?
            .ok_or_else(|| anyhow!("channel closed unexpectedly"))?;

        Ok(received)
    }
}

/// This function performs all the boilerplate setup for a test.
pub async fn setup_test() -> Result<TestHarness, anyhow::Error> {
    // Initialize the logger once.
    LOG_INIT.call_once(|| {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    });

    // Load the eBPF object file.
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/integration-ebpf-test"
    ))?;

    // Initialize the BPF logger.
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Define the syscall name based on the target architecture.
    #[cfg(target_arch = "x86_64")]
    let syscall = "__x64_sys_getpid";
    #[cfg(target_arch = "aarch64")]
    let syscall = "__arm64_sys_getpid";

    // Load and attach the eBPF program.
    let program: &mut KProbe = ebpf.program_mut("integration_test").unwrap().try_into()?;
    program.load()?;
    program.attach(syscall, 0)?;

    // Get handles to the BPF maps.
    let in_data: HashMap<MapData, u32, _> = ebpf
        .take_map("IN_DATA")
        .context("IN_DATA map not found")?
        .try_into()?;
    let mut out_data: AsyncPerfEventArray<MapData> = ebpf
        .take_map("OUT_DATA")
        .context("OUT_DATA map not found")?
        .try_into()?;

    // Create an MPSC channel to receive events from all CPU listeners.
    let (tx, rx) = mpsc::channel(10);

    // Spawn a listener task for each online CPU.
    let cpus = online_cpus().map_err(|(err_str, io_err)| anyhow!("{}: {}", err_str, io_err))?;
    for cpu_id in cpus {
        let mut perf_buf = out_data.open(cpu_id, None)?;
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(size_of::<ParsedHeader>()))
                .collect::<Vec<_>>();
            loop {
                let events = match perf_buf.read_events(&mut buffers).await {
                    Ok(e) => e,
                    Err(_) => break, // Perf buffer was closed
                };

                for i in 0..events.read {
                    let data =
                        unsafe { (buffers[i].as_ptr() as *const ParsedHeader).read_unaligned() };
                    if tx_clone.send(data).await.is_err() {
                        return; // Receiver was dropped
                    }
                }
            }
        });
    }

    // Return the completed harness.
    Ok(TestHarness {
        ebpf,
        in_data,
        result_rx: rx,
    })
}