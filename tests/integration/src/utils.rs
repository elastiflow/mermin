use aya::{
    include_bytes_aligned,
    maps::{HashMap, AsyncPerfEventArray},
    programs::KProbe,
    Bpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use integration_common::{ParsedHeader, REQUEST_DATA_SIZE};
use log::warn;
use std::{mem::size_of, sync::Once};
use tokio::sync::oneshot;

// This ensures env_logger is initialized only once for all tests.
static LOG_INIT: Once = Once::new();

/// A harness that holds all the necessary components for a single test run.
/// The `bpf` field is important because it owns the programs and maps.
/// If it goes out of scope, they are unloaded from the kernel.
pub struct TestHarness {
    pub bpf: Bpf,
    pub in_data: HashMap<std::os::fd::RawFd, u32, [u8; REQUEST_DATA_SIZE]>,
    result_rx: oneshot::Receiver<ParsedHeader>,
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
        unsafe { libc::getpid() };

        // Wait for the result from the listener task with a timeout.
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            &mut self.result_rx,
        )
            .await??;

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
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/integration-ebpf"
    ))?;

    // Initialize the BPF logger.
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Load and attach the eBPF program.
    let program: &mut KProbe = bpf.program_mut("integration_test").unwrap().try_into()?;
    program.load()?;
    program.attach("__x64_sys_getpid", 0)?;

    // Get handles to the BPF maps.
    let in_data: HashMap<_, u32, _> = HashMap::try_from(bpf.map_mut("IN_DATA"))?;
    let mut out_data: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(bpf.map_mut("OUT_DATA"))?;

    // Create a channel to receive the result from the kernel.
    let (tx, rx) = oneshot::channel::<ParsedHeader>();

    // Spawn a task to listen on the perf event array.
    tokio::spawn(async move {
        let mut perf_buf = out_data.open(0, None).unwrap();
        let mut buffers = [BytesMut::with_capacity(size_of::<ParsedHeader>())];
        let events = perf_buf.read_events(&mut buffers).await.unwrap();

        // When an event is received, parse it and send it through the channel.
        if events.read > 0 {
            let data = unsafe { (buffers[0].as_ptr() as *const ParsedHeader).read_unaligned() };
            let _ = tx.send(data);
        }
    });

    // Return the completed harness.
    Ok(TestHarness {
        bpf,
        in_data,
        result_rx: rx,
    })
}