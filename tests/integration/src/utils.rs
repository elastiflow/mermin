use anyhow::{anyhow, Context};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{TcAttachType},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use integration_common::ParsedHeader;
use log::warn;
use std::{mem::size_of, sync::Once};
use aya::programs::SchedClassifier;
use tokio::sync::mpsc;

// This ensures env_logger is initialized only once for all tests.
static LOG_INIT: Once = Once::new();

/// The harness no longer needs the in_data map.
pub struct TestHarness {
    pub ebpf: Ebpf,
    result_rx: mpsc::Receiver<ParsedHeader>,
}

impl TestHarness {
    /// This method now simply waits for an event from the eBPF program.
    /// The trigger (sending a packet) will happen in the test case itself.
    pub async fn receive_event(&mut self) -> Result<ParsedHeader, anyhow::Error> {
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.result_rx.recv(),
        )
            .await?
            .ok_or_else(|| anyhow!("channel closed unexpectedly"))?;

        Ok(received)
    }
}

/// This function is updated to load and attach a TC program.
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

    // Load the TC program instead of a KProbe.
    let program: &mut SchedClassifier = ebpf.program_mut("integration_test").unwrap().try_into()?;
    program.load()?;
    // Attach the program to the loopback interface's ingress hook.
    // The returned link guard will detach the program when it goes out of scope.
    let _link = program.attach("lo", TcAttachType::Ingress)?;

    // Get a handle to the OUT_DATA map.
    let mut out_data: AsyncPerfEventArray<_> = ebpf
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
        result_rx: rx,
    })
}