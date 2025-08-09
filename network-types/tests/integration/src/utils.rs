use std::{mem::size_of, sync::Once, time::Duration};

use anyhow::{Context, Result, anyhow};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{SchedClassifier, TcAttachType},
    util::online_cpus,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use integration_common::ParsedHeader;
use log::{LevelFilter, debug, info, warn};
use tokio::sync::mpsc;

static LOG_INIT: Once = Once::new();

/// Configuration options for the test harness.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// The interface to attach the eBPF program to.
    pub interface: String,

    /// The attachment type for the TC program.
    pub tc_attach_type: TcAttachType,

    /// The log level for the test.
    pub log_level: LevelFilter,

    /// The timeout for receiving events from the eBPF program.
    pub receive_timeout: Duration,

    /// The capacity of the channel for receiving events.
    pub channel_capacity: usize,

    /// The number of buffers to allocate for reading events.
    pub buffer_count: usize,

    /// The path to the eBPF program to load.
    pub ebpf_program_path: &'static [u8],

    /// The name of the eBPF program to attach.
    pub program_name: String,

    /// The name of the map to read events from.
    pub map_name: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            interface: "lo".to_string(),
            tc_attach_type: TcAttachType::Ingress,
            log_level: LevelFilter::Info,
            receive_timeout: Duration::from_secs(5),
            channel_capacity: 10,
            buffer_count: 10,
            ebpf_program_path: include_bytes_aligned!(
                "../../../../target/bpfel-unknown-none/release/integration-ebpf-test"
            ),
            program_name: "integration_test".to_string(),
            map_name: "OUT_DATA".to_string(),
        }
    }
}

/// A test harness for running integration tests with eBPF programs.
///
/// The TestHarness provides a way to load and attach an eBPF program,
/// and receive events from it via a channel.
pub struct TestHarness {
    /// The loaded eBPF program.
    pub ebpf: Ebpf,

    /// The receiver for events from the eBPF program.
    result_rx: mpsc::Receiver<ParsedHeader>,

    /// The configuration used to create this harness.
    config: TestConfig,
}

impl TestHarness {
    /// Receive an event from the eBPF program.
    ///
    /// This method waits for an event from the eBPF program with a timeout
    /// specified in the TestConfig. If no event is received within the timeout,
    /// an error is returned.
    ///
    /// # Returns
    ///
    /// - `Ok(ParsedHeader)` if an event was received.
    /// - `Err` if no event was received within the timeout or if the channel was closed.
    pub async fn receive_event(&mut self) -> Result<ParsedHeader> {
        debug!(
            "Waiting for event with timeout of {:?}",
            self.config.receive_timeout
        );
        let received = tokio::time::timeout(self.config.receive_timeout, self.result_rx.recv())
            .await
            .context("Timeout waiting for event")?
            .ok_or_else(|| anyhow!("Channel closed unexpectedly"))?;

        debug!("Received event: {:?}", received.type_);
        Ok(received)
    }
}

/// Set up a test harness with the default configuration.
///
/// This is a convenience function that calls `setup_test_with_config` with the default configuration.
///
/// # Returns
///
/// - `Ok(TestHarness)` if the test harness was successfully set up.
/// - `Err` if there was an error setting up the test harness.
pub async fn setup_test() -> Result<TestHarness> {
    setup_test_with_config(TestConfig::default()).await
}

/// Set up a test harness with the specified configuration.
///
/// This function:
/// 1. Initializes the logger
/// 2. Loads the eBPF program
/// 3. Attaches the program to the specified interface
/// 4. Sets up event listeners for each CPU
///
/// # Arguments
///
/// * `config` - The configuration for the test harness.
///
/// # Returns
///
/// - `Ok(TestHarness)` if the test harness was successfully set up.
/// - `Err` if there was an error setting up the test harness.
pub async fn setup_test_with_config(config: TestConfig) -> Result<TestHarness> {
    // Initialize the logger once.
    LOG_INIT.call_once(|| {
        env_logger::builder().filter_level(config.log_level).init();
    });

    info!("Setting up test harness with config");

    // Load the eBPF program
    let mut ebpf = Ebpf::load(config.ebpf_program_path)?;
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Get the program by name and convert it to the expected type
    let program: &mut SchedClassifier = ebpf
        .program_mut(&config.program_name)
        .context(format!("Program '{}' not found", config.program_name))?
        .try_into()?;

    // Load and attach the program
    program.load()?;
    let _link = program
        .attach(&config.interface, config.tc_attach_type)
        .context(format!(
            "Failed to attach program to interface '{}'",
            config.interface
        ))?;

    info!(
        "Successfully attached program to interface '{}'",
        config.interface
    );

    // Get the map for reading events
    let mut out_data: AsyncPerfEventArray<_> = ebpf
        .take_map(&config.map_name)
        .context(format!("Map '{}' not found", config.map_name))?
        .try_into()?;

    // Create an MPSC channel to receive events from all CPU listeners.
    let (tx, rx) = mpsc::channel(config.channel_capacity);

    // Spawn a listener task for each online CPU.
    let cpus = online_cpus().map_err(|(err_str, io_err)| anyhow!("{}: {}", err_str, io_err))?;
    info!("Setting up listeners for {} CPUs", cpus.len());

    for cpu_id in cpus {
        let mut perf_buf = out_data.open(cpu_id, None)?;
        let tx_clone = tx.clone();
        let buffer_count = config.buffer_count;

        tokio::spawn(async move {
            debug!("Started listener for CPU {}", cpu_id);
            let mut buffers = (0..buffer_count)
                .map(|_| BytesMut::with_capacity(size_of::<ParsedHeader>()))
                .collect::<Vec<_>>();

            loop {
                let events = match perf_buf.read_events(&mut buffers).await {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("Error reading events from perf buffer: {}", e);
                        break; // Perf buffer was closed or error occurred
                    }
                };

                debug!("Read {} events from CPU {}", events.read, cpu_id);
                for i in 0..events.read {
                    let data =
                        unsafe { (buffers[i].as_ptr() as *const ParsedHeader).read_unaligned() };
                    if tx_clone.send(data).await.is_err() {
                        debug!("Receiver was dropped, stopping listener for CPU {}", cpu_id);
                        return; // Receiver was dropped
                    }
                }
            }
        });
    }

    info!("Test harness setup complete");
    Ok(TestHarness {
        ebpf,
        result_rx: rx,
        config,
    })
}

/// Configuration for a header test.
///
/// This struct provides configuration options for the header tests created
/// with the `define_header_test!` macro.
#[derive(Debug, Clone)]
pub struct HeaderTestConfig {
    /// The address to bind the client socket to.
    pub client_bind_addr: &'static str,

    /// The address of the server to connect to.
    pub server_addr: &'static str,

    /// The configuration for the test harness.
    pub test_config: Option<TestConfig>,
}

impl Default for HeaderTestConfig {
    fn default() -> Self {
        Self {
            client_bind_addr: "127.0.0.1:0",
            server_addr: "127.0.0.1:8080",
            test_config: None,
        }
    }
}

/// Example usage:
///
/// Basic usage:
/// ```
/// define_header_test!(
///     test_parses_eth_header,
///     EthHdr,
///     PacketType::Eth,
///     create_eth_test_packet,
///     verify_eth_header
/// );
/// ```
///
/// With custom configuration:
/// ```
/// define_header_test!(
///     test_parses_eth_header_custom,
///     EthHdr,
///     PacketType::Eth,
///     create_eth_test_packet,
///     verify_eth_header,
///     {
///         let mut config = HeaderTestConfig::default();
///         config.server_addr = "127.0.0.1:9090";
///         config
///     }
/// );
/// ```
///
/// This will generate a complete test function that:
/// 1. Sets up the test harness with the specified configuration
/// 2. Creates a UDP socket and connects to the server
/// 3. Gets test data from the create_eth_test_packet function
/// 4. Sends the test data to the server
/// 5. Receives the parsed header from the eBPF program
/// 6. Verifies the results using the verify_eth_header function
///
/// To add a new test for a different header type, you just need to:
/// 1. Create helper functions for constructing test packets and verifying results
/// 2. Use the define_header_test macro to generate the test function
#[macro_export]
macro_rules! define_header_test {
    // Basic version with default configuration
    ($test_name:ident, $header_type:ty, $packet_type:expr, $setup_fn:expr, $verify_fn:expr) => {
        define_header_test!(
            $test_name,
            $header_type,
            $packet_type,
            $setup_fn,
            $verify_fn,
            { crate::utils::HeaderTestConfig::default() }
        );
    };

    // Version with custom configuration
    ($test_name:ident, $header_type:ty, $packet_type:expr, $setup_fn:expr, $verify_fn:expr, $config_expr:expr) => {
        #[tokio::test]
        async fn $test_name() -> Result<(), anyhow::Error> {
            use std::net::UdpSocket;

            use anyhow::Context;
            use log::{debug, info};

            info!("--- Running Test for {} ---", stringify!($header_type));

            // Get the test configuration
            let config = $config_expr;
            debug!("Using test configuration: {:?}", config);

            // Set up the test harness with the specified configuration
            let mut harness = match config.test_config {
                Some(test_config) => crate::utils::setup_test_with_config(test_config).await?,
                None => crate::utils::setup_test().await?,
            };

            // Create and connect the client socket
            debug!("Binding client socket to {}", config.client_bind_addr);
            let client = UdpSocket::bind(config.client_bind_addr).context(format!(
                "Failed to bind client socket to {}",
                config.client_bind_addr
            ))?;

            debug!("Connecting client socket to {}", config.server_addr);
            client.connect(config.server_addr).context(format!(
                "Failed to connect client socket to {}",
                config.server_addr
            ))?;

            // Get test data from setup function
            debug!("Getting test data from setup function");
            let (request_data, expected_header) = $setup_fn();

            // Send the test data
            debug!("Sending {} bytes of test data", request_data.len());
            client
                .send(&request_data)
                .context("Failed to send test data")?;

            // Receive and verify the event
            debug!("Waiting for event from eBPF program");
            let received = harness
                .receive_event()
                .await
                .context("Failed to receive event from eBPF program")?;

            debug!("Verifying received event");
            $verify_fn(received, expected_header);

            info!("Test for {} Passed!", stringify!($header_type));
            Ok(())
        }
    };
}
