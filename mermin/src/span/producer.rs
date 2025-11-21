use std::{
    os::fd::AsRawFd,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use aya::maps::{HashMap as EbpfHashMap, RingBuf};
use dashmap::DashMap;
use fxhash::FxBuildHasher;
use mermin_common::{FlowEvent, FlowKey, FlowStats};
use network_types::{
    eth::EtherType,
    ip::{IpDscp, IpEcn, IpProto},
    tcp::{TCP_FLAG_FIN, TCP_FLAG_RST},
};
use opentelemetry::trace::SpanKind;
use pnet::datalink::MacAddr;
use tokio::{
    io::unix::AsyncFd,
    sync::{Mutex, broadcast, mpsc},
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    filter::source::PacketFilter,
    ip::{Error, flow_key_to_ip_addrs},
    metrics,
    packet::{
        parser::{is_tunnel, parse_packet_from_offset},
        types::ParsedPacket,
    },
    runtime::conf::Conf,
    span::{
        community_id::CommunityIdGenerator,
        ebpf_guard::EbpfFlowGuard,
        flow::{FlowEndReason, FlowSpan, SpanAttributes},
        opts::SpanOptions,
        tcp::TcpFlags,
        trace_id::TraceIdCache,
    },
};

/// ### Concurrency Model
///
/// Multiple components access the flow map concurrently:
///
/// 1. **PacketWorker**: Creates new flows and updates existing ones
/// 2. **Record Task** (per flow): Periodically reads and records flow state
/// 3. **Timeout Task** (per flow): Removes flows on timeout
///
/// #### Synchronization
///
/// - `DashMap` provides per-shard locking for concurrent access
/// - Updates to flow attributes are performed under write lock
/// - Record task clones flow state while holding read lock
/// - Timeout task removes flow atomically
///
/// #### Potential Race Conditions
///
/// - Packet update vs. Record: Safe - record clones current state
/// - Packet update vs. Timeout removal: Safe - packet finds flow missing, no-op
/// - Record vs. Timeout: Safe - timeout waits for record to complete removal
pub type FlowStore = Arc<DashMap<String, FlowEntry, FxBuildHasher>>;

/// Entry in the flow map containing the flow span.
/// Polling tasks will handle record intervals and timeouts.
pub struct FlowEntry {
    pub flow_span: FlowSpan,
}

pub struct FlowSpanProducer {
    span_opts: SpanOptions,
    ring_buffer_capacity: usize,
    worker_count: usize,
    worker_poll_interval: Duration,
    boot_time_offset_nanos: u64,
    iface_map: Arc<DashMap<u32, String>>,
    flow_store: FlowStore,
    community_id_generator: CommunityIdGenerator,
    trace_id_cache: TraceIdCache,
    flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    flow_events_ringbuf: RingBuf<aya::maps::MapData>,
    flow_span_tx: mpsc::Sender<FlowSpan>,
    filter: Option<Arc<PacketFilter>>,
    vxlan_port: u16,
    geneve_port: u16,
    wireguard_port: u16,
}

impl FlowSpanProducer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        span_opts: SpanOptions,
        ring_buffer_capacity: usize,
        worker_count: usize,
        iface_map: Arc<DashMap<u32, String>>,
        flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
        flow_events_ringbuf: RingBuf<aya::maps::MapData>,
        flow_span_tx: mpsc::Sender<FlowSpan>,
        conf: &Conf,
    ) -> Result<Self, BootTimeError> {
        // Scale flow store capacity based on expected concurrent flows
        // At 100k flows/sec with 10s avg lifetime = 1M concurrent flows
        // Capacity: ring_buffer_capacity (8192) * 128 = 1,048,576 (~400MB)
        // DashMap will resize if needed, but this minimizes expensive resizing operations
        const FLOW_STORE_CAPACITY_MULTIPLIER: usize = 128;
        let flow_store_capacity = ring_buffer_capacity * FLOW_STORE_CAPACITY_MULTIPLIER;
        info!(
            event.name = "flow_store.initialized",
            capacity = flow_store_capacity,
            ring_buffer_capacity = ring_buffer_capacity,
            capacity_multiplier = FLOW_STORE_CAPACITY_MULTIPLIER,
            estimated_memory_mb = (flow_store_capacity * 400) / 1_048_576, // ~400 bytes per entry
            "flow store initialized with capacity for high-throughput operation"
        );
        let flow_store = Arc::new(DashMap::with_capacity_and_hasher(
            flow_store_capacity,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(span_opts.community_id_seed);

        // Initialize trace ID cache with configured timeout
        let trace_id_cache = TraceIdCache::new(span_opts.trace_id_timeout, flow_store_capacity);

        // Calculate boot time offset to convert kernel boot-relative timestamps to wall clock
        // This is critical - if we can't determine boot time, timestamps will be wrong
        let boot_time_offset_nanos = calculate_boot_time_offset_nanos()?;

        let filter = if conf.filter.is_some() {
            info!(
                event.name = "filter.initializing",
                "flow filtering enabled, loading configuration"
            );
            Some(Arc::new(PacketFilter::new(conf, iface_map.clone())))
        } else {
            info!(
                event.name = "filter.disabled",
                "flow filtering disabled, all flows will be tracked"
            );
            None
        };

        Ok(Self {
            span_opts,
            ring_buffer_capacity,
            worker_count,
            worker_poll_interval: conf.pipeline.worker_poll_interval,
            boot_time_offset_nanos,
            community_id_generator,
            trace_id_cache,
            iface_map,
            flow_store,
            flow_stats_map,
            flow_events_ringbuf,
            flow_span_tx,
            filter,
            vxlan_port: conf.parser.vxlan_port,
            geneve_port: conf.parser.geneve_port,
            wireguard_port: conf.parser.wireguard_port,
        })
    }

    pub async fn run(self, mut shutdown_rx: broadcast::Receiver<()>) {
        info!(
            event.name = "task.started",
            task.name = "span.producer",
            task.description = "producing flow spans from eBPF flow events",
            "userspace task started"
        );

        let flow_stats_map = self.flow_stats_map;
        let mut flow_events = self.flow_events_ringbuf;

        info!(
            event.name = "ebpf.maps_ready",
            "eBPF maps ready, starting event-driven flow processing"
        );

        let mut worker_handles = Vec::new();
        let mut worker_channels = Vec::new();
        let worker_capacity =
            self.ring_buffer_capacity.max(self.worker_count) / self.worker_count.max(1);

        for worker_id in 0..self.worker_count.max(1) {
            let (worker_tx, worker_rx) = mpsc::channel(worker_capacity);
            worker_channels.push(worker_tx);

            metrics::userspace::set_channel_capacity("packet_worker", worker_capacity);

            let flow_worker = FlowWorker::new(
                worker_id,
                self.span_opts.clone(),
                self.boot_time_offset_nanos,
                self.community_id_generator.clone(),
                self.trace_id_cache.clone(),
                Arc::clone(&self.iface_map),
                Arc::clone(&self.flow_store),
                Arc::clone(&flow_stats_map),
                worker_rx,
                self.filter.clone(),
                self.vxlan_port,
                self.geneve_port,
                self.wireguard_port,
            );

            let worker_handle = tokio::spawn(async move {
                flow_worker.run().await;
            });
            worker_handles.push(worker_handle);
        }
        info!(
            event.name = "workers.started",
            worker.count = self.worker_count.max(1),
            "flow workers spawned, starting event loop"
        );

        // Orphan threshold: 4x max_record_interval provides safety margin for processing delays
        // while catching truly orphaned entries much faster than a fixed long timeout.
        let max_orphan_age = self.span_opts.max_record_interval.saturating_mul(4);
        let community_id_gen = Arc::new(self.community_id_generator.clone());
        let orphan_scanner_shutdown_rx = shutdown_rx.resubscribe();
        let orphan_scanner_handle = tokio::spawn(orphan_scanner_task(
            Arc::clone(&flow_stats_map),
            Arc::clone(&self.flow_store),
            self.boot_time_offset_nanos,
            max_orphan_age,
            community_id_gen,
            orphan_scanner_shutdown_rx,
        ));
        worker_handles.push(orphan_scanner_handle);
        info!(
            event.name = "orphan_scanner.started",
            scan.interval_secs = 300,
            max_age_secs = max_orphan_age.as_secs(),
            "orphan scanner task started (safety net for stale eBPF entries)"
        );

        // Spawn trace ID cache cleanup task
        let trace_id_cache_clone = self.trace_id_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
            loop {
                interval.tick().await;
                let (scanned, removed) = trace_id_cache_clone.cleanup_expired();
                if removed > 0 {
                    trace!(
                        event.name = "trace_id_cache.cleanup",
                        entries.scanned = scanned,
                        entries.removed = removed,
                        "trace ID cache cleanup completed"
                    );
                }
            }
        });
        trace!(
            event.name = "trace_id_cache.cleanup_task.started",
            cleanup.interval_secs = 300,
            "trace ID cache cleanup task started"
        );

        // Spawn flow pollers (sharded by community_id hash) to replace per-flow tasks
        // Scale with worker count but cap at 32 for high-throughput (100k flows/sec)
        // Each poller can handle ~100K active flows efficiently
        let num_pollers = self.worker_count.clamp(1, 32);
        let max_record_interval = self.span_opts.max_record_interval;
        let poll_interval = self.worker_poll_interval;
        for poller_id in 0..num_pollers {
            let poller_flow_store = Arc::clone(&self.flow_store);
            let poller_stats_map = Arc::clone(&flow_stats_map);
            let poller_span_tx = self.flow_span_tx.clone();
            let poller_trace_id_cache = self.trace_id_cache.clone();
            let poller_shutdown_rx = shutdown_rx.resubscribe();

            let poller = FlowPoller {
                id: poller_id,
                num_pollers,
                flow_store: poller_flow_store,
                flow_stats_map: poller_stats_map,
                flow_span_tx: poller_span_tx,
                max_record_interval,
                poll_interval,
                trace_id_cache: poller_trace_id_cache,
                shutdown_rx: poller_shutdown_rx,
            };

            let poller_handle = tokio::spawn(async move {
                poller.run().await;
            });
            worker_handles.push(poller_handle);
        }
        info!(
            event.name = "flow_pollers.started",
            poller.count = num_pollers,
            poll.interval_secs = poll_interval.as_secs(),
            "flow pollers started (replaces per-flow record/timeout tasks)"
        );

        let async_fd = match AsyncFd::new(flow_events.as_raw_fd()) {
            Ok(fd) => fd,
            Err(e) => {
                error!(
                    event.name = "span.producer.error",
                    error.message = %e,
                    "failed to create async fd for ring buffer"
                );
                return;
            }
        };

        let mut worker_index = 0;
        let worker_count = self.worker_count.max(1);

        loop {
            tokio::select! {
            _ = shutdown_rx.recv() => {
                trace!(
                    event.name = "task.stopped",
                    task.name = "span.producer",
                    "userspace task stopping gracefully"
                );
                break;
            },
            result = async_fd.readable() => {
                let mut guard = match result {
                    Ok(guard) => guard,
                        Err(e) => {
                            error!(
                                event.name = "span.producer.error",
                                error.message = %e,
                                "error waiting for ring buffer readability"
                            );
                            break;
                        }
                    };

                    while let Some(item) = flow_events.next() {
                        let timer = metrics::registry::PROCESSING_LATENCY
                            .with_label_values(&["flow_ingestion"])
                            .start_timer();

                        let flow_event: FlowEvent =
                            unsafe { std::ptr::read_unaligned(item.as_ptr() as *const FlowEvent) };

                        metrics::userspace::inc_ringbuf_packets("received", 1);
                        metrics::userspace::inc_ringbuf_bytes(flow_event.snaplen as u64);

                        let mut sent = false;
                        for attempt in 0..worker_count {
                            let current_worker = (worker_index + attempt) % worker_count;
                            let worker_tx = &worker_channels[current_worker];

                            match worker_tx.try_send(flow_event) {
                                Ok(_) => {
                                    metrics::userspace::inc_channel_sends("packet_worker", "success");
                                    worker_index = (current_worker + 1) % worker_count;
                                    sent = true;
                                    break;
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    // This worker is full, try next one
                                    continue;
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                    // Worker is gone, try next one
                                    metrics::userspace::inc_channel_sends("packet_worker", "error");
                                    continue;
                                }
                            }
                        }

                        if !sent {
                            // All workers are full - drop event to prevent ring buffer backup
                            // CRITICAL: Blocking here prevents draining ring buffer, causing eBPF to drop MORE events
                            // This is a fail-safe to maintain pipeline throughput under extreme load.
                            metrics::registry::FLOW_EVENTS_DROPPED_BACKPRESSURE.inc();

                            // Log detailed backpressure info every 1000 drops (avoid log spam)
                            static BACKPRESSURE_DROP_COUNT: std::sync::atomic::AtomicU64 =
                                std::sync::atomic::AtomicU64::new(0);
                            let drop_count =
                                BACKPRESSURE_DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            if drop_count % 1000 == 0 {
                                warn!(
                                    event.name = "flow.worker_backpressure",
                                    worker_count = worker_count,
                                    total_drops = drop_count + 1,
                                    protocol = ?flow_event.flow_key.protocol,
                                    "worker backpressure detected - dropping flow events to prevent deadlock"
                                );
                            }

                            // Continue draining ring buffer - better to drop here with visibility
                            // than block and cause eBPF to drop events silently
                            //
                            // TODO: Implement adaptive sampling strategy:
                            // 1. Priority-based dropping (keep long-lived flows, drop short ones)
                            // 2. Sampling (keep 1 in N flows during overload)
                            // 3. Protocol-based priority (TCP > UDP > ICMP)
                        }

                        timer.observe_duration();
                    }

                    guard.clear_ready();
                }
            }
        }

        trace!(
            event.name = "shutdown.cleanup",
            task.name = "span.producer",
            "shutting down workers and pollers"
        );

        drop(worker_channels);

        // Wait for all spawned background tasks (workers, pollers, scanner) to finish concurrently.
        futures::future::join_all(worker_handles).await;

        info!(
            event.name = "shutdown.cleanup.all_joined",
            task.name = "span.producer",
            "all child tasks have been joined"
        );
    }
}

/// Flow worker that processes new flow events from the eBPF ring buffer.
/// Replaces PacketWorker in the new event-driven architecture.
pub struct FlowWorker {
    worker_id: usize,
    generic_timeout: Duration,
    icmp_timeout: Duration,
    tcp_timeout: Duration,
    tcp_fin_timeout: Duration,
    tcp_rst_timeout: Duration,
    udp_timeout: Duration,
    boot_time_offset_nanos: u64,
    community_id_generator: CommunityIdGenerator,
    trace_id_cache: TraceIdCache,
    iface_map: Arc<DashMap<u32, String>>,
    flow_store: FlowStore,
    flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    flow_event_rx: mpsc::Receiver<FlowEvent>,
    filter: Option<Arc<PacketFilter>>,
    vxlan_port: u16,
    geneve_port: u16,
    wireguard_port: u16,
}

impl FlowWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: usize,
        span_opts: SpanOptions,
        boot_time_offset_nanos: u64,
        community_id_generator: CommunityIdGenerator,
        trace_id_cache: TraceIdCache,
        iface_map: Arc<DashMap<u32, String>>,
        flow_store: FlowStore,
        flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
        flow_event_rx: mpsc::Receiver<FlowEvent>,
        filter: Option<Arc<PacketFilter>>,
        vxlan_port: u16,
        geneve_port: u16,
        wireguard_port: u16,
    ) -> Self {
        Self {
            worker_id,
            generic_timeout: span_opts.generic_timeout,
            icmp_timeout: span_opts.icmp_timeout,
            tcp_timeout: span_opts.tcp_timeout,
            tcp_fin_timeout: span_opts.tcp_fin_timeout,
            tcp_rst_timeout: span_opts.tcp_rst_timeout,
            udp_timeout: span_opts.udp_timeout,
            boot_time_offset_nanos,
            community_id_generator,
            trace_id_cache,
            iface_map,
            flow_store,
            flow_stats_map,
            flow_event_rx,
            filter,
            vxlan_port,
            geneve_port,
            wireguard_port,
        }
    }

    pub async fn run(mut self) {
        debug!(
            event.name = "flow_worker.started",
            worker.id = self.worker_id,
            "flow worker started"
        );

        while let Some(flow_event) = self.flow_event_rx.recv().await {
            if let Err(e) = self.process_new_flow(flow_event).await {
                warn!(
                    event.name = "flow.processing_failed",
                    worker.id = self.worker_id,
                    error.message = %e,
                    error.type = ?e,
                    protocol = ?flow_event.flow_key.protocol,
                    src_port = flow_event.flow_key.src_port,
                    dst_port = flow_event.flow_key.dst_port,
                    "failed to process flow event"
                );
            }
        }

        debug!(
            event.name = "flow_worker.stopped",
            worker.id = self.worker_id,
            "flow worker stopped"
        );
    }

    /// Process a new flow event from eBPF.
    /// This is the core of the event-driven architecture:
    /// 1. Check if tunneled (fast path vs slow path)
    /// 2. For direct traffic: Use FlowStats directly (no parsing!)
    /// 3. For tunneled traffic: Deep parse packet_data to extract innermost 5-tuple
    async fn process_new_flow(&self, event: FlowEvent) -> Result<(), Error> {
        if !is_tunnel(
            &event.flow_key,
            self.vxlan_port,
            self.geneve_port,
            self.wireguard_port,
        ) {
            return self.create_direct_flow(event).await;
        }

        // TODO: Skip tunneled flow processing for now - untested and needs refactoring
        debug!(
            event.name = "tunneled_flow.skipped",
            worker.id = self.worker_id,
            protocol = ?event.flow_key.protocol,
            src_ip = ?event.flow_key.src_ip,
            dst_ip = ?event.flow_key.dst_ip,
            "skipping tunneled flow processing - not yet implemented"
        );

        // Clean up eBPF map entry to prevent memory leak
        let mut map = self.flow_stats_map.lock().await;
        if let Err(e) = map.remove(&event.flow_key) {
            warn!(
                event.name = "tunneled_flow.cleanup_failed",
                worker.id = self.worker_id,
                error.message = %e,
                "failed to remove tunneled flow from eBPF map"
            );
        }

        Ok(())
    }

    /// Fast path for plain (non-tunneled) traffic.
    /// Uses FlowStats from eBPF directly
    async fn create_direct_flow(&self, event: FlowEvent) -> Result<(), Error> {
        // CRITICAL: Create guard to ensure eBPF cleanup on ANY error path
        // The guard will automatically clean up the eBPF entry if this function exits
        // early (via error return) or panics, preventing orphaned entries.
        let guard = EbpfFlowGuard::new(event.flow_key, Arc::clone(&self.flow_stats_map));

        // Read stats from eBPF map and immediately release lock to minimize contention.
        // The scoped block ensures the lock is dropped before expensive filtering logic.
        let stats = {
            let map = self.flow_stats_map.lock().await;
            map.get(&event.flow_key, 0)
                .map_err(|_| Error::FlowNotFound)?
        };

        // Early flow filtering: Check if this flow should be tracked
        // If filtered out, immediately remove from eBPF map to prevent memory leaks
        if !self.should_process_flow(&event.flow_key, &stats) {
            metrics::userspace::inc_ringbuf_packets("filtered", 1);

            let mut map = self.flow_stats_map.lock().await;
            if let Err(e) = map.remove(&event.flow_key) {
                warn!(
                    event.name = "flow.cleanup_failed",
                    worker.id = self.worker_id,
                    error.message = %e,
                    "failed to remove filtered flow from eBPF map"
                );
            }
            drop(map);

            trace!(
                event.name = "flow.filtered",
                worker.id = self.worker_id,
                protocol = ?event.flow_key.protocol,
                src_port = event.flow_key.src_port,
                dst_port = event.flow_key.dst_port,
                "flow filtered out, removed from tracking"
            );
            return Ok(());
        }

        // Convert eBPF FlowKey to Community ID
        // For plain traffic, outermost = innermost, so we use flow_key directly
        let (src_addr, dst_addr) = flow_key_to_ip_addrs(&event.flow_key)?;
        let community_id = self.community_id_generator.generate(
            src_addr,
            dst_addr,
            event.flow_key.src_port,
            event.flow_key.dst_port,
            event.flow_key.protocol,
        );

        self.create_flow_span(&community_id, &event.flow_key, &stats)
            .await?;

        // Flow successfully created and stored - disable guard cleanup
        // The entry is now managed by flow_store and will be cleaned up by timeout task
        guard.keep();

        Ok(())
    }

    /// Slow path for tunneled traffic.
    /// Parses packet_data to extract innermost 5-tuple and tunnel metadata.
    #[allow(dead_code)]
    async fn create_tunneled_flow(&self, event: FlowEvent) -> Result<(), Error> {
        // Parse only the UNPARSED portion (inner headers for tunnels)
        let unparsed_data = &event.packet_data[..];
        let parsed = parse_packet_from_offset(unparsed_data, event.parsed_offset)
            .map_err(|_| Error::UnknownIpAddrType)?;

        // Extract innermost 5-tuple for Community ID
        match parsed {
            ParsedPacket::Tunneled { inner, .. } => {
                // TODO: Generate Community ID from innermost 5-tuple
                // TODO: Map eBPF FlowKey → Community ID
                // TODO: Create FlowSpan with tunnel metadata

                warn!(
                    event.name = "tunneled_flow.not_implemented",
                    worker.id = self.worker_id,
                    inner.src_ip = %inner.src_ip,
                    inner.dst_ip = %inner.dst_ip,
                    "tunneled flow processing not yet fully implemented"
                );
            }
            ParsedPacket::Direct { .. } => {
                // This shouldn't happen - we already checked is_likely_tunnel
                warn!("expected tunneled packet but got plain, treating as error");
            }
        }

        Ok(())
    }

    /// Determine if a flow should be processed based on filtering rules.
    ///
    /// This method provides early flow filtering to:
    /// - Reduce memory usage in eBPF maps
    /// - Avoid unnecessary FlowSpan creation and tracking
    /// - Prevent wasted CPU on unwanted flows
    ///
    /// Filtering is configuration-driven through the `PacketFilter` loaded from config.
    /// If no filter is configured, all flows are accepted.
    fn should_process_flow(&self, flow_key: &FlowKey, stats: &FlowStats) -> bool {
        // If filter is configured, use it
        if let Some(filter) = &self.filter {
            match filter.should_track_flow(flow_key, stats) {
                Ok(should_track) => should_track,
                Err(e) => {
                    warn!(
                        event.name = "flow.filter_error",
                        worker.id = self.worker_id,
                        error.message = %e,
                        "error evaluating flow filter, accepting flow by default"
                    );
                    true // On error, accept the flow (fail open)
                }
            }
        } else {
            // No filter configured, accept all flows
            true
        }
    }

    /// Create a FlowSpan from eBPF FlowStats
    async fn create_flow_span(
        &self,
        community_id: &str,
        flow_key: &FlowKey,
        stats: &FlowStats,
    ) -> Result<(), Error> {
        let is_ip_flow = stats.ether_type == EtherType::Ipv4 || stats.ether_type == EtherType::Ipv6;
        let is_ipv6 = stats.ether_type == EtherType::Ipv6;
        let is_tcp = stats.protocol == IpProto::Tcp;
        let is_icmp = stats.protocol == IpProto::Icmp;
        let is_icmpv6 = stats.protocol == IpProto::Ipv6Icmp;
        let is_icmp_any = is_icmp || is_icmpv6;
        let start_time_nanos = stats.first_seen_ns + self.boot_time_offset_nanos;
        let end_time_nanos = stats.last_seen_ns + self.boot_time_offset_nanos;
        let iface_name = self
            .iface_map
            .get(&stats.ifindex)
            .map(|r| r.value().clone());
        let (src_addr, dst_addr) = flow_key_to_ip_addrs(flow_key)?;
        let timeout = self.calculate_timeout(flow_key.protocol, stats);

        let span = FlowSpan {
            trace_id: Some(self.trace_id_cache.get_or_create(community_id)),
            start_time: UNIX_EPOCH + Duration::from_nanos(start_time_nanos),
            end_time: UNIX_EPOCH + Duration::from_nanos(end_time_nanos),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes {
                // General flow attributes
                flow_community_id: community_id.to_string(),
                flow_connection_state: None,
                flow_end_reason: None,

                // Network endpoints
                source_address: src_addr,
                source_port: flow_key.src_port,
                destination_address: dst_addr,
                destination_port: flow_key.dst_port,

                // Network layer info
                network_transport: flow_key.protocol,
                network_type: stats.ether_type,
                network_interface_index: Some(stats.ifindex),
                network_interface_name: iface_name.clone(),
                network_interface_mac: Some(MacAddr::from(stats.src_mac)),

                // IP metadata
                flow_ip_dscp_id: is_ip_flow.then_some(stats.ip_dscp),
                flow_ip_dscp_name: is_ip_flow.then_some(
                    IpDscp::try_from_u8(stats.ip_dscp)
                        .unwrap_or_default()
                        .as_str()
                        .to_string(),
                ),
                flow_ip_ecn_id: is_ip_flow.then_some(stats.ip_ecn),
                flow_ip_ecn_name: is_ip_flow.then_some(
                    IpEcn::try_from_u8(stats.ip_ecn)
                        .unwrap_or_default()
                        .as_str()
                        .to_string(),
                ),
                flow_ip_ttl: is_ip_flow.then_some(stats.ip_ttl),
                flow_ip_flow_label: is_ipv6.then_some(stats.ip_flow_label),

                // Reverse direction IP metadata (first seen per interval)
                flow_reverse_ip_dscp_id: is_ip_flow.then_some(stats.reverse_ip_dscp),
                flow_reverse_ip_dscp_name: is_ip_flow.then_some(
                    IpDscp::try_from_u8(stats.reverse_ip_dscp)
                        .unwrap_or_default()
                        .as_str()
                        .to_string(),
                ),
                flow_reverse_ip_ecn_id: is_ip_flow.then_some(stats.reverse_ip_ecn),
                flow_reverse_ip_ecn_name: is_ip_flow.then_some(
                    IpEcn::try_from_u8(stats.reverse_ip_ecn)
                        .unwrap_or_default()
                        .as_str()
                        .to_string(),
                ),
                flow_reverse_ip_ttl: is_ip_flow.then_some(stats.reverse_ip_ttl),
                flow_reverse_ip_flow_label: is_ipv6.then_some(stats.reverse_ip_flow_label),

                // TCP metadata
                flow_tcp_flags_bits: is_tcp.then_some(stats.tcp_flags),
                flow_tcp_flags_tags: is_tcp.then(|| TcpFlags::from_stats(stats).active_flags()),

                // ICMP metadata
                flow_icmp_type_id: is_icmp_any.then_some(stats.icmp_type),
                flow_icmp_type_name: if is_icmp {
                    network_types::icmp::get_icmpv4_type_name(stats.icmp_type).map(String::from)
                } else if is_icmpv6 {
                    network_types::icmp::get_icmpv6_type_name(stats.icmp_type).map(String::from)
                } else {
                    None
                },
                flow_icmp_code_id: is_icmp_any.then_some(stats.icmp_code),
                flow_icmp_code_name: if is_icmp {
                    network_types::icmp::get_icmpv4_code_name(stats.icmp_type, stats.icmp_code)
                        .map(String::from)
                } else if is_icmpv6 {
                    network_types::icmp::get_icmpv6_code_name(stats.icmp_type, stats.icmp_code)
                        .map(String::from)
                } else {
                    None
                },
                flow_reverse_icmp_type_id: is_icmp_any.then_some(stats.reverse_icmp_type),
                flow_reverse_icmp_type_name: if is_icmp {
                    network_types::icmp::get_icmpv4_type_name(stats.reverse_icmp_type)
                        .map(String::from)
                } else if is_icmpv6 {
                    network_types::icmp::get_icmpv6_type_name(stats.reverse_icmp_type)
                        .map(String::from)
                } else {
                    None
                },
                flow_reverse_icmp_code_id: is_icmp_any.then_some(stats.reverse_icmp_code),
                flow_reverse_icmp_code_name: if is_icmp {
                    network_types::icmp::get_icmpv4_code_name(
                        stats.reverse_icmp_type,
                        stats.reverse_icmp_code,
                    )
                    .map(String::from)
                } else if is_icmpv6 {
                    network_types::icmp::get_icmpv6_code_name(
                        stats.reverse_icmp_type,
                        stats.reverse_icmp_code,
                    )
                    .map(String::from)
                } else {
                    None
                },

                // Initialize counters (will be updated from eBPF map on record intervals)
                flow_bytes_delta: stats.bytes as i64,
                flow_bytes_total: stats.bytes as i64,
                flow_packets_delta: stats.packets as i64,
                flow_packets_total: stats.packets as i64,
                flow_reverse_bytes_delta: stats.reverse_bytes as i64,
                flow_reverse_bytes_total: stats.reverse_bytes as i64,
                flow_reverse_packets_delta: stats.reverse_packets as i64,
                flow_reverse_packets_total: stats.reverse_packets as i64,

                // All other attributes default to None
                ..Default::default()
            },
            // Fields for eBPF map integration
            flow_key: Some(*flow_key),
            last_recorded_packets: stats.packets,
            last_recorded_bytes: stats.bytes,
            last_recorded_reverse_packets: stats.reverse_packets,
            last_recorded_reverse_bytes: stats.reverse_bytes,
            boot_time_offset: self.boot_time_offset_nanos,

            // Timing fields for polling architecture (initialized by insert_flow)
            last_recorded_time: UNIX_EPOCH,
            last_activity_time: UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };

        self.insert_flow(community_id.to_string(), span, timeout);

        trace!(
            event.name = "span.producer.created_flow",
            flow.community_id = %community_id,
            network.interface.name = iface_name.as_deref().unwrap_or(""),
            source.address = %src_addr,
            source.port = flow_key.src_port,
            destination.address = %dst_addr,
            destination.port = flow_key.dst_port,
            network.transport = ?flow_key.protocol,
            flow.bytes = stats.bytes,
            "created flow span from eBPF stats"
        );

        Ok(())
    }

    /// Calculate timeout duration based on protocol and flow stats
    fn calculate_timeout(&self, protocol: IpProto, stats: &FlowStats) -> Duration {
        match protocol {
            IpProto::Icmp | IpProto::Ipv6Icmp => self.icmp_timeout,
            IpProto::Tcp => {
                // TCP - check for FIN or RST flags
                if stats.tcp_flags & TCP_FLAG_FIN != 0 {
                    self.tcp_fin_timeout
                } else if stats.tcp_flags & TCP_FLAG_RST != 0 {
                    self.tcp_rst_timeout
                } else {
                    self.tcp_timeout
                }
            }
            IpProto::Udp => self.udp_timeout,
            _ => self.generic_timeout,
        }
    }

    /// Insert flow into tracking map with initialized timing fields.
    /// Polling tasks will handle record intervals and timeouts.
    fn insert_flow(&self, community_id: String, mut flow_span: FlowSpan, timeout: Duration) {
        let now = std::time::SystemTime::now();
        flow_span.last_recorded_time = now;
        flow_span.last_activity_time = flow_span.end_time;
        flow_span.timeout_duration = timeout;

        let iface_name = flow_span
            .attributes
            .network_interface_name
            .as_deref()
            .unwrap_or("unknown");
        metrics::flow::inc_flows_created(iface_name);

        let flow_entry = FlowEntry { flow_span };

        self.flow_store.insert(community_id, flow_entry);
    }
}

/// Individual poller task - handles flows hashed to this poller.
/// Polls at configured interval to check for record intervals and timeouts.
struct FlowPoller {
    id: usize,
    num_pollers: usize,
    flow_store: FlowStore,
    flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    flow_span_tx: mpsc::Sender<FlowSpan>,
    trace_id_cache: TraceIdCache,
    max_record_interval: Duration,
    poll_interval: Duration,
    shutdown_rx: broadcast::Receiver<()>,
}

impl FlowPoller {
    /// The main run loop for the poller task.
    async fn run(mut self) {
        let mut interval = tokio::time::interval(self.poll_interval);

        debug!(
            event.name = "flow_poller.started",
            poller.id = self.id,
            poller.total = self.num_pollers,
            "flow poller started"
        );

        let mut iteration_count = 0u64;
        let mut last_stats_log = std::time::Instant::now();

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    trace!(event.name = "task.shutdown", task.name = "flow_poller", poller.id = self.id, "shutdown signal received");

                    debug!(event.name = "flow_poller.final_flush", poller.id = self.id, "performing final flush of remaining flows");

                    let mut flows_to_flush = Vec::new();
                    for entry in self.flow_store.iter() {
                        let community_id = entry.key();
                        if hash_string(community_id) % self.num_pollers == self.id {
                            flows_to_flush.push(community_id.clone());
                        }
                    }

                    trace!(
                        event.name = "flow_poller.final_flush.start",
                        poller.id = self.id,
                        flow.count = flows_to_flush.len(),
                        "flushing all remaining flows for this poller."
                    );

                    for community_id in flows_to_flush {
                        timeout_and_remove_flow(
                            community_id,
                            &self.flow_store,
                            &self.flow_stats_map,
                            &self.flow_span_tx,
                            &self.trace_id_cache,
                        )
                        .await;
                    }

                    trace!(event.name = "flow_poller.final_flush.complete", poller.id = self.id, "final flush completed.");

                    break;
                },
                _ = interval.tick() => {
                    let tick_start = std::time::Instant::now();
                let now = std::time::SystemTime::now();
                let mut flows_to_remove = Vec::new();
                let mut flows_checked = 0usize;
                let mut flows_recorded = 0usize;
                let mut flows_skipped_partition = 0usize;

                trace!(
                    event.name = "flow_poller.tick_start",
                    poller.id = self.id,
                    iteration.count = iteration_count + 1,
                    "poller tick started"
                );

                // Collect flows to process - CRITICAL: Must collect IDs first, then drop iterator
                // before calling record_flow/timeout_and_remove_flow to avoid iterator deadlock
                let mut flows_to_record = Vec::new();

                let collection_start = std::time::Instant::now();
                for entry in self.flow_store.iter() {
                    let community_id = entry.key();

                    // Partition: only process flows hashed to this poller
                    if hash_string(community_id) % self.num_pollers != self.id {
                        flows_skipped_partition += 1;
                        continue;
                    }

                    // Extract all needed data from entry
                    let flow_span = &entry.flow_span;
                    let last_recorded_time = flow_span.last_recorded_time;
                    let last_activity_time = flow_span.last_activity_time;
                    let timeout_duration = flow_span.timeout_duration;

                    flows_checked += 1;

                    // Check if record interval elapsed
                    if let Ok(elapsed) = now.duration_since(last_recorded_time)
                        && elapsed >= self.max_record_interval
                    {
                        flows_to_record.push(community_id.clone());
                    }

                    // Check if timeout elapsed
                    if let Ok(elapsed) = now.duration_since(last_activity_time)
                        && elapsed >= timeout_duration
                    {
                        flows_to_remove.push(community_id.clone());
                    }
                } // Iterator dropped here - no longer holding DashMap locks
                let collection_duration = collection_start.elapsed();

                trace!(
                    event.name = "flow_poller.collection_phase",
                    poller.id = self.id,
                    flows.total_checked = flows_checked,
                    flows.to_record = flows_to_record.len(),
                    flows.to_timeout = flows_to_remove.len(),
                    collection.duration_ms = collection_duration.as_millis(),
                    "collection phase completed"
                );

                // Now process flows WITHOUT holding iterator locks
                let record_start = std::time::Instant::now();
                for community_id in &flows_to_record {
                    flows_recorded += 1;
                    trace!(
                        event.name = "flow_poller.recording",
                        poller.id = self.id,
                        flow.community_id = %community_id,
                        "calling record_flow"
                    );
                    if !record_flow(community_id, &self.flow_store, &self.flow_stats_map, &self.flow_span_tx).await {
                        // Export channel closed, stop poller
                        warn!(
                            event.name = "flow_poller.stopped",
                            poller.id = self.id,
                            reason = "export_channel_closed",
                            "flow poller stopping due to closed export channel"
                        );
                        return;
                    }
                }
                let record_duration = record_start.elapsed();

                if !flows_to_record.is_empty() {
                    trace!(
                        event.name = "flow_poller.record_phase",
                        poller.id = self.id,
                        flows.recorded = flows_to_record.len(),
                        record.duration_ms = record_duration.as_millis(),
                        "record phase completed"
                    );
                }

                // Remove timed out flows
                let timeout_start = std::time::Instant::now();
                for community_id in flows_to_remove.iter() {
                    trace!(
                        event.name = "flow_poller.timing_out",
                        poller.id = self.id,
                        flow.community_id = %community_id,
                        "calling timeout_and_remove_flow"
                    );
                    timeout_and_remove_flow(
                        community_id.clone(),
                        &self.flow_store,
                        &self.flow_stats_map,
                        &self.flow_span_tx,
                        &self.trace_id_cache,
                    )
                    .await;
                }
                let timeout_duration_elapsed = timeout_start.elapsed();

                if !flows_to_remove.is_empty() {
                    trace!(
                        event.name = "flow_poller.timeout_phase",
                        poller.id = self.id,
                        flows.timed_out = flows_to_remove.len(),
                        timeout.duration_ms = timeout_duration_elapsed.as_millis(),
                        "timeout phase completed"
                    );
                }

                let tick_duration = tick_start.elapsed();
                iteration_count += 1;

                if last_stats_log.elapsed() >= Duration::from_secs(30) {
                    info!(
                        event.name = "flow_poller.stats",
                        poller.id = self.id,
                        iteration.count = iteration_count,
                        flows.checked = flows_checked,
                        flows.recorded = flows_recorded,
                        flows.timed_out = flows_to_remove.len(),
                        flows.skipped_partition = flows_skipped_partition,
                        tick.duration_ms = tick_duration.as_millis(),
                        collection.duration_ms = collection_duration.as_millis(),
                        record.duration_ms = record_duration.as_millis(),
                        timeout.duration_ms = timeout_duration_elapsed.as_millis(),
                        "flow poller iteration stats"
                    );
                    last_stats_log = std::time::Instant::now();
                }

                // Warn if iteration took > 500ms (should complete much faster)
                if tick_duration.as_millis() > 500 {
                    warn!(
                        event.name = "flow_poller.slow_iteration",
                        poller.id = self.id,
                        tick.duration_ms = tick_duration.as_millis(),
                        flows.checked = flows_checked,
                        "flow poller iteration took longer than expected"
                    );
                }
                }
            }
        }
    }
}

/// Errors that can occur during boot time offset calculation
#[derive(Debug)]
pub enum BootTimeError {
    /// System clock is before UNIX epoch
    SystemClockBeforeEpoch(std::time::SystemTimeError),
    /// Failed to read /proc/uptime
    ReadProcUptime(std::io::Error),
    /// Failed to parse uptime value from /proc/uptime
    ParseUptime(String),
}

impl std::fmt::Display for BootTimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootTimeError::SystemClockBeforeEpoch(e) => {
                write!(f, "system clock is before unix epoch: {e}")
            }
            BootTimeError::ReadProcUptime(e) => {
                write!(f, "failed to read /proc/uptime: {e}")
            }
            BootTimeError::ParseUptime(content) => {
                write!(
                    f,
                    "failed to parse uptime from /proc/uptime (content: '{content}')",
                )
            }
        }
    }
}

impl std::error::Error for BootTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BootTimeError::SystemClockBeforeEpoch(e) => Some(e),
            BootTimeError::ReadProcUptime(e) => Some(e),
            BootTimeError::ParseUptime(_) => None,
        }
    }
}

/// Hash a string for flow partitioning across pollers
fn hash_string(s: &str) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = fxhash::FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish() as usize
}

/// Record a flow span by reading from eBPF map, updating counters, and sending to exporter.
/// Returns true if the flow should continue being tracked, false if export channel is closed.
async fn record_flow(
    community_id: &str,
    flow_store: &FlowStore,
    flow_stats_map: &Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    flow_span_tx: &mpsc::Sender<FlowSpan>,
) -> bool {
    // Extract flow_key and boot_time_offset WITHOUT holding DashMap reference
    let (
        flow_key,
        boot_time_offset,
        last_recorded_packets,
        last_recorded_bytes,
        last_recorded_reverse_packets,
        last_recorded_reverse_bytes,
    ) = {
        let entry_ref = match flow_store.get(community_id) {
            Some(entry) => entry,
            None => return true, // Flow removed, but that's ok
        };

        let flow_span = &entry_ref.flow_span;
        let flow_key = match flow_span.flow_key {
            Some(key) => key,
            None => {
                warn!(
                    event.name = "record.missing_ebpf_key",
                    flow.community_id = %community_id,
                    "flow span missing eBPF key, skipping record"
                );
                return true;
            }
        };

        (
            flow_key,
            flow_span.boot_time_offset,
            flow_span.last_recorded_packets,
            flow_span.last_recorded_bytes,
            flow_span.last_recorded_reverse_packets,
            flow_span.last_recorded_reverse_bytes,
        )
    }; // entry_ref dropped here

    // Now acquire mutex WITHOUT holding DashMap reference
    let lock_start = std::time::Instant::now();
    let map = flow_stats_map.lock().await;
    let lock_duration = lock_start.elapsed();

    if lock_duration.as_millis() > 100 {
        warn!(
            event.name = "record_flow.slow_lock",
            flow.community_id = %community_id,
            lock.duration_ms = lock_duration.as_millis(),
            "mutex acquisition took longer than expected"
        );
    } else {
        trace!(
            event.name = "record_flow.lock_acquired",
            flow.community_id = %community_id,
            lock.duration_ms = lock_duration.as_millis(),
            "acquired flow_stats_map mutex"
        );
    }
    let stats = match map.get(&flow_key, 0) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                event.name = "record.ebpf_read_failed",
                flow.community_id = %community_id,
                error.message = %e,
                "failed to read stats from eBPF map, flow may have been evicted"
            );
            drop(map);
            return true;
        }
    };
    drop(map);

    // Calculate deltas using extracted values
    let delta_packets = stats.packets.saturating_sub(last_recorded_packets);
    let delta_bytes = stats.bytes.saturating_sub(last_recorded_bytes);
    let delta_reverse_packets = stats
        .reverse_packets
        .saturating_sub(last_recorded_reverse_packets);
    let delta_reverse_bytes = stats
        .reverse_bytes
        .saturating_sub(last_recorded_reverse_bytes);

    // Now get mutable reference to update flow span attributes
    let mut entry_ref = match flow_store.get_mut(community_id) {
        Some(entry) => entry,
        None => return true, // Flow removed during processing
    };

    let flow_span = &mut entry_ref.flow_span;
    flow_span.attributes.flow_bytes_delta = delta_bytes as i64;
    flow_span.attributes.flow_packets_delta = delta_packets as i64;
    flow_span.attributes.flow_reverse_bytes_delta = delta_reverse_bytes as i64;
    flow_span.attributes.flow_reverse_packets_delta = delta_reverse_packets as i64;
    flow_span.attributes.flow_bytes_total = stats.bytes as i64;
    flow_span.attributes.flow_packets_total = stats.packets as i64;
    flow_span.attributes.flow_reverse_bytes_total = stats.reverse_bytes as i64;
    flow_span.attributes.flow_reverse_packets_total = stats.reverse_packets as i64;

    flow_span.last_recorded_packets = stats.packets;
    flow_span.last_recorded_bytes = stats.bytes;
    flow_span.last_recorded_reverse_packets = stats.reverse_packets;
    flow_span.last_recorded_reverse_bytes = stats.reverse_bytes;

    // Update end_time and last_activity_time from eBPF map's latest timestamp
    let end_time_nanos = stats.last_seen_ns + boot_time_offset;
    let end_time = UNIX_EPOCH + Duration::from_nanos(end_time_nanos);
    flow_span.end_time = end_time;
    flow_span.last_activity_time = end_time;

    // Update IP metadata from eBPF stats
    let is_ip_flow = stats.ether_type == EtherType::Ipv4 || stats.ether_type == EtherType::Ipv6;
    let is_ipv6 = stats.ether_type == EtherType::Ipv6;

    if is_ip_flow {
        flow_span.attributes.flow_ip_dscp_id = Some(stats.ip_dscp);
        flow_span.attributes.flow_ip_dscp_name = Some(
            IpDscp::try_from_u8(stats.ip_dscp)
                .unwrap_or_default()
                .as_str()
                .to_string(),
        );
        flow_span.attributes.flow_ip_ecn_id = Some(stats.ip_ecn);
        flow_span.attributes.flow_ip_ecn_name = Some(
            IpEcn::try_from_u8(stats.ip_ecn)
                .unwrap_or_default()
                .as_str()
                .to_string(),
        );
        flow_span.attributes.flow_ip_ttl = Some(stats.ip_ttl);

        flow_span.attributes.flow_reverse_ip_dscp_id = Some(stats.reverse_ip_dscp);
        flow_span.attributes.flow_reverse_ip_dscp_name = Some(
            IpDscp::try_from_u8(stats.reverse_ip_dscp)
                .unwrap_or_default()
                .as_str()
                .to_string(),
        );
        flow_span.attributes.flow_reverse_ip_ecn_id = Some(stats.reverse_ip_ecn);
        flow_span.attributes.flow_reverse_ip_ecn_name = Some(
            IpEcn::try_from_u8(stats.reverse_ip_ecn)
                .unwrap_or_default()
                .as_str()
                .to_string(),
        );
        flow_span.attributes.flow_reverse_ip_ttl = Some(stats.reverse_ip_ttl);
    }

    if is_ipv6 {
        flow_span.attributes.flow_ip_flow_label = Some(stats.ip_flow_label);
        flow_span.attributes.flow_reverse_ip_flow_label = Some(stats.reverse_ip_flow_label);
    }

    flow_span.last_recorded_time = std::time::SystemTime::now();

    let mut recorded_span = flow_span.clone();
    recorded_span.attributes.flow_end_reason = Some(determine_flow_end_reason(
        flow_span.attributes.flow_tcp_flags_bits,
        FlowEndReason::ActiveTimeout,
    ));

    // Ensure end_time is never before start_time (OTLP requirement)
    if recorded_span.end_time < recorded_span.start_time {
        std::mem::swap(&mut recorded_span.start_time, &mut recorded_span.end_time);
    }

    drop(entry_ref);

    // Send to exporter
    match flow_span_tx.try_send(recorded_span) {
        Ok(_) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            metrics::registry::FLOW_SPANS_DROPPED_EXPORT_FAILURE.inc();
            debug!(
                event.name = "span.dropped",
                flow.community_id = %community_id,
                reason = "export_channel_full",
                export.context = "active_record",
                "dropped flow span - export channel at capacity"
            );
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            error!(
                event.name = "span.export_failed",
                flow.community_id = %community_id,
                reason = "channel_closed",
                export.context = "active_record",
                "export channel closed, stopping poller"
            );
            return false; // Signal to stop poller
        }
    }

    // Reset metadata flags AND values in eBPF map for next interval
    // Extract ebpf_key first, then drop DashMap reference before acquiring mutex
    let ebpf_key = flow_store
        .get(community_id)
        .and_then(|entry| entry.flow_span.flow_key);

    if let Some(ebpf_key) = ebpf_key {
        let mut map = flow_stats_map.lock().await;
        if let Ok(stats) = map.get(&ebpf_key, 0) {
            let mut updated_stats = stats;
            updated_stats.forward_metadata_seen = 0;
            updated_stats.reverse_metadata_seen = 0;
            updated_stats.ip_dscp = 0;
            updated_stats.ip_ecn = 0;
            updated_stats.ip_ttl = 0;
            updated_stats.ip_flow_label = 0;
            updated_stats.reverse_ip_dscp = 0;
            updated_stats.reverse_ip_ecn = 0;
            updated_stats.reverse_ip_ttl = 0;
            updated_stats.reverse_ip_flow_label = 0;
            updated_stats.icmp_type = 0;
            updated_stats.icmp_code = 0;
            updated_stats.reverse_icmp_type = 0;
            updated_stats.reverse_icmp_code = 0;

            if let Err(e) = map.insert(ebpf_key, updated_stats, 0) {
                debug!(
                    event.name = "record.metadata_reset_failed",
                    flow.community_id = %community_id,
                    error.message = %e,
                    "failed to reset metadata flags and values in eBPF map"
                );
            }
        }
    }

    true
}

/// Timeout and remove a flow, recording it one final time if it has packets.
async fn timeout_and_remove_flow(
    community_id: String,
    flow_store: &FlowStore,
    flow_stats_map: &Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    flow_span_tx: &mpsc::Sender<FlowSpan>,
    trace_id_cache: &TraceIdCache,
) {
    // Remove from flow store (get ebpf_key before removing)
    let (ebpf_key, boot_time_offset) = if let Some(entry) = flow_store.get(&community_id) {
        (entry.flow_span.flow_key, entry.flow_span.boot_time_offset)
    } else {
        return; // Flow already removed
    };

    // Drop DashMap reference before acquiring mutex
    let entry = match flow_store.remove(&community_id) {
        Some((_, entry)) => entry,
        None => return, // Race condition, already removed
    };

    let mut flow_span = entry.flow_span;

    // Update end_time from eBPF map one last time
    if let Some(key) = ebpf_key {
        let lock_start = std::time::Instant::now();
        let map = flow_stats_map.lock().await;
        let lock_duration = lock_start.elapsed();

        if lock_duration.as_millis() > 100 {
            warn!(
                event.name = "timeout_flow.slow_lock_read",
                flow.community_id = %community_id,
                lock.duration_ms = lock_duration.as_millis(),
                "mutex acquisition took longer than expected"
            );
        }

        if let Ok(stats) = map.get(&key, 0) {
            let end_time_nanos = stats.last_seen_ns + boot_time_offset;
            flow_span.end_time = UNIX_EPOCH + Duration::from_nanos(end_time_nanos);
        }
        drop(map);
    }

    // Record final span if it has packets
    let has_packets = flow_span.attributes.flow_packets_total > 0
        || flow_span.attributes.flow_reverse_packets_total > 0;

    if has_packets {
        let mut recorded_span = flow_span.clone();
        recorded_span.attributes.flow_end_reason = Some(determine_flow_end_reason(
            flow_span.attributes.flow_tcp_flags_bits,
            FlowEndReason::IdleTimeout,
        ));

        // Ensure end_time is never before start_time (OTLP requirement)
        if recorded_span.end_time < recorded_span.start_time {
            std::mem::swap(&mut recorded_span.start_time, &mut recorded_span.end_time);
        }

        match flow_span_tx.try_send(recorded_span) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                metrics::registry::FLOW_SPANS_DROPPED_EXPORT_FAILURE.inc();
                debug!(
                    event.name = "span.dropped",
                    flow.community_id = %community_id,
                    reason = "export_channel_full",
                    export.context = "idle_timeout",
                    "dropped flow span - export channel at capacity"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(
                    event.name = "span.export_failed",
                    flow.community_id = %community_id,
                    reason = "channel_closed",
                    export.context = "idle_timeout",
                    "export channel closed"
                );
            }
        }
    }

    // Clean up eBPF map entry
    if let Some(key) = ebpf_key {
        let lock_start = std::time::Instant::now();
        let mut map = flow_stats_map.lock().await;
        let lock_duration = lock_start.elapsed();

        if lock_duration.as_millis() > 100 {
            warn!(
                event.name = "timeout_flow.slow_lock_cleanup",
                flow.community_id = %community_id,
                lock.duration_ms = lock_duration.as_millis(),
                "mutex acquisition for cleanup took longer than expected"
            );
        }

        if let Err(e) = map.remove(&key) {
            debug!(
                event.name = "ebpf.map_cleanup_failed",
                flow.community_id = %community_id,
                error.message = %e,
                "failed to remove eBPF map entry (may have been evicted already)"
            );
        }
        drop(map);
    }

    trace_id_cache.remove(&community_id);

    // Metrics
    let iface_name = flow_span
        .attributes
        .network_interface_name
        .as_deref()
        .unwrap_or("unknown");
    metrics::flow::inc_flows_expired(iface_name, "timeout");
}

/// Periodic orphan scanner task - safety net for cleaning up stale eBPF entries.
///
/// Scans the eBPF `FLOW_STATS_MAP` periodically and removes entries that are:
/// - Old (exceed max_age threshold, typically 4x max_record_interval)
/// - Not tracked in the userspace `flow_store`
///
/// This task acts as a safety net to catch any orphaned entries that slipped
/// through the primary cleanup mechanisms (guard, timeout task).
///
/// Note: The max_age threshold is based on max_record_interval, not absolute time.
/// Active flows are tracked in userspace and updated regularly, so only truly
/// orphaned entries (failed initialization) will exceed the threshold without tracking.
///
/// ### Arguments
///
/// - `flow_stats_map` - Shared eBPF map containing flow statistics
/// - `flow_store` - Userspace flow tracking store
/// - `boot_time_offset` - Offset to convert boot time to wall clock time
/// - `max_age` - Maximum age for entries before they're considered orphans
/// - `community_id_generator` - For generating community IDs from flow keys
pub async fn orphan_scanner_task(
    flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    flow_store: FlowStore,
    boot_time_offset: u64,
    max_age: Duration,
    community_id_generator: Arc<CommunityIdGenerator>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let scan_interval = Duration::from_secs(300);

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!(event.name = "task.shutdown", task.name = "orphan_scanner", "shutdown signal received");
                break;
            },
            _ = tokio::time::sleep(scan_interval) => {
                let current_time_ns = std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                let current_boot_time_ns = current_time_ns.saturating_sub(boot_time_offset);
                let max_age_ns = max_age.as_nanos() as u64;

                let mut removed = 0u64;
                let mut scanned = 0u64;

                // Get all keys first (to avoid holding lock during iteration)
                let keys: Vec<FlowKey> = {
                    let map = flow_stats_map.lock().await;
                    map.keys().filter_map(|k| k.ok()).collect()
                };

        let ebpf_map_entries = keys.len() as u64;
        metrics::ebpf::set_map_entries(ebpf_map_entries);

                for key in keys {
                    scanned += 1;

                    // Check if entry is very old
                    let is_old = {
                        let map = flow_stats_map.lock().await;
                        match map.get(&key, 0) {
                            Ok(stats) => {
                                let age_ns = current_boot_time_ns.saturating_sub(stats.last_seen_ns);
                                age_ns > max_age_ns
                            }
                            Err(_) => continue, // Entry already removed
                        }
                    };

                    if !is_old {
                        continue;
                    }

                    // Convert FlowKey to IP addresses for Community ID generation
                    let (src_addr, dst_addr) = match flow_key_to_ip_addrs(&key) {
                        Ok(addrs) => addrs,
                        Err(_) => continue, // Skip invalid IP version
                    };

                    let community_id = community_id_generator.generate(
                        src_addr,
                        dst_addr,
                        key.src_port,
                        key.dst_port,
                        key.protocol,
                    );

                    if flow_store.contains_key(&community_id) {
                        // Entry is old but still being tracked - don't remove
                        continue;
                    }

                    // Orphan detected - remove it
                    let mut map = flow_stats_map.lock().await;
                    if map.remove(&key).is_ok() {
                        removed += 1;
                        crate::metrics::ebpf::inc_orphans_cleaned(1);
                        warn!(
                            event.name = "orphan_scanner.entry_removed",
                            flow.key = ?key,
                            "removed orphaned eBPF entry (age exceeded threshold and not tracked in userspace)"
                        );
                    }
                    drop(map);
                }

                if removed > 0 {
                    warn!(
                        event.name = "orphan_scanner.scan_completed",
                        entries.scanned = scanned,
                        entries.removed = removed,
                        scan.interval_secs = scan_interval.as_secs(),
                        "orphan scanner completed - removed stale entries"
                    );
                } else {
                    debug!(
                        event.name = "orphan_scanner.scan_completed_clean",
                        entries.scanned = scanned,
                        "orphan scanner completed - no orphans found"
                    );
                }
            }
        }
    }
}

/// Calculate the offset needed to convert boot-relative timestamps (from bpf_ktime_get_boot_ns)
/// to wall clock timestamps.
///
/// bpf_ktime_get_boot_ns() returns time in nanoseconds since boot using CLOCK_BOOTTIME,
/// which includes suspend time. This matches /proc/uptime in userspace.
///
/// This function calculates: wall_clock_time_ns - boot_time_ns = offset
///
/// Returns an error if the boot time cannot be determined, as this would make all
/// timestamps incorrect and render the program's output useless.
/// Convert a normalized FlowKey to a Community ID (v1) hash
/// The FlowKey must already be normalized (src < dst)
fn calculate_boot_time_offset_nanos() -> Result<u64, BootTimeError> {
    use std::time::SystemTime;

    // Get current wall clock time since UNIX epoch
    let now = SystemTime::now();
    let now_since_epoch = now
        .duration_since(UNIX_EPOCH)
        .map_err(BootTimeError::SystemClockBeforeEpoch)?;
    let wall_clock_nanos = now_since_epoch.as_nanos() as u64;

    // Read boot time from /proc/uptime (uses CLOCK_BOOTTIME, matching bpf_ktime_get_boot_ns)
    // Format: "uptime_seconds idle_seconds"
    let uptime_content =
        std::fs::read_to_string("/proc/uptime").map_err(BootTimeError::ReadProcUptime)?;

    let uptime_secs = uptime_content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .ok_or_else(|| BootTimeError::ParseUptime(uptime_content.clone()))?;

    // Convert uptime to nanoseconds
    let uptime_nanos = (uptime_secs * 1_000_000_000.0) as u64;

    // Calculate offset: current_time - uptime = boot_time
    let offset = wall_clock_nanos.saturating_sub(uptime_nanos);

    debug!(
        event.name = "system.boot_time_offset_calculated",
        system.boot_time_offset_ns = offset,
        system.wall_clock_ns = wall_clock_nanos,
        system.uptime_ns = uptime_nanos,
        "calculated boot time offset"
    );

    Ok(offset)
}

/// Determine the appropriate flow end reason based on TCP flags
///
/// If FIN or RST flags are present, returns EndOfFlowDetected.
/// Otherwise, returns the provided default reason.
fn determine_flow_end_reason(
    tcp_flags: Option<u8>,
    default_reason: FlowEndReason,
) -> FlowEndReason {
    if let Some(flags) = tcp_flags {
        if (flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) != 0 {
            FlowEndReason::EndOfFlowDetected
        } else {
            default_reason
        }
    } else {
        default_reason
    }
}

#[cfg(test)]
mod tests {
    use mermin_common::IpVersion;

    use super::*;

    /// Helper to create test FlowStats with specific TCP flags
    fn create_test_stats(proto: IpProto, tcp_flags: u8) -> FlowStats {
        FlowStats {
            direction: mermin_common::Direction::Egress,
            ether_type: EtherType::Ipv4,
            ip_version: IpVersion::V4,
            protocol: proto,
            src_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            packets: 1,
            bytes: 100,
            reverse_packets: 0,
            reverse_bytes: 0,
            src_mac: [0; 6],
            ifindex: 1,
            ip_flow_label: 0,
            reverse_ip_flow_label: 0,
            first_seen_ns: 1_000_000_000,
            last_seen_ns: 1_000_000_000,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            tcp_flags,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
        }
    }

    /// Helper to create a test FlowWorker for timeout calculations
    fn create_test_worker_for_timeout() -> FlowWorker {
        let span_opts = SpanOptions::default();
        let (_flow_event_tx, flow_event_rx) = mpsc::channel::<FlowEvent>(100);
        let flow_store = Arc::new(DashMap::with_capacity_and_hasher(
            100,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(span_opts.community_id_seed);
        let trace_id_cache = TraceIdCache::new(span_opts.trace_id_timeout, 100);
        let iface_map = Arc::new(DashMap::new());
        // Create a dummy eBPF map - won't be used in unit tests
        let flow_stats_map = Arc::new(Mutex::new(unsafe {
            std::mem::zeroed::<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>()
        }));

        FlowWorker {
            worker_id: 0,
            generic_timeout: span_opts.generic_timeout,
            icmp_timeout: span_opts.icmp_timeout,
            tcp_timeout: span_opts.tcp_timeout,
            tcp_fin_timeout: span_opts.tcp_fin_timeout,
            tcp_rst_timeout: span_opts.tcp_rst_timeout,
            udp_timeout: span_opts.udp_timeout,
            boot_time_offset_nanos: 0,
            community_id_generator,
            trace_id_cache,
            iface_map,
            flow_store,
            flow_stats_map,
            flow_event_rx,
            filter: None,
            vxlan_port: 4789,
            geneve_port: 6081,
            wireguard_port: 51820,
        }
    }

    #[test]
    fn test_calculate_timeout_icmp() {
        let worker = create_test_worker_for_timeout();
        let stats = create_test_stats(IpProto::Icmp, 0);

        let timeout = worker.calculate_timeout(IpProto::Icmp, &stats);
        assert_eq!(timeout, worker.icmp_timeout);

        // Prevent drop to avoid IO Safety violation from zeroed eBPF map
        std::mem::forget(worker);
    }

    #[test]
    fn test_calculate_timeout_icmpv6() {
        let worker = create_test_worker_for_timeout();
        let stats = create_test_stats(IpProto::Ipv6Icmp, 0);

        let timeout = worker.calculate_timeout(IpProto::Ipv6Icmp, &stats);
        assert_eq!(timeout, worker.icmp_timeout);

        // Prevent drop to avoid IO Safety violation from zeroed eBPF map
        std::mem::forget(worker);
    }

    #[test]
    fn test_calculate_timeout_tcp_normal() {
        let worker = create_test_worker_for_timeout();
        let stats = create_test_stats(IpProto::Tcp, 0x10); // ACK only

        let timeout = worker.calculate_timeout(IpProto::Tcp, &stats);
        assert_eq!(timeout, worker.tcp_timeout);

        // Prevent drop to avoid IO Safety violation from zeroed eBPF map
        std::mem::forget(worker);
    }

    #[test]
    fn test_calculate_timeout_tcp_with_fin() {
        let worker = create_test_worker_for_timeout();
        let stats = create_test_stats(IpProto::Tcp, TCP_FLAG_FIN);

        let timeout = worker.calculate_timeout(IpProto::Tcp, &stats);
        assert_eq!(timeout, worker.tcp_fin_timeout);

        // Prevent drop to avoid IO Safety violation from zeroed eBPF map
        std::mem::forget(worker);
    }

    #[test]
    fn test_calculate_timeout_tcp_with_rst() {
        let worker = create_test_worker_for_timeout();
        let stats = create_test_stats(IpProto::Tcp, TCP_FLAG_RST);

        let timeout = worker.calculate_timeout(IpProto::Tcp, &stats);
        assert_eq!(timeout, worker.tcp_rst_timeout);

        // Prevent drop to avoid IO Safety violation from zeroed eBPF map
        std::mem::forget(worker);
    }

    #[test]
    fn test_calculate_timeout_udp() {
        let worker = create_test_worker_for_timeout();
        let stats = create_test_stats(IpProto::Udp, 0);

        let timeout = worker.calculate_timeout(IpProto::Udp, &stats);
        assert_eq!(timeout, worker.udp_timeout);

        // Prevent drop to avoid IO Safety violation from zeroed eBPF map
        std::mem::forget(worker);
    }

    #[test]
    fn test_calculate_timeout_generic() {
        let worker = create_test_worker_for_timeout();
        let stats = create_test_stats(IpProto::Gre, 0); // GRE is generic

        let timeout = worker.calculate_timeout(IpProto::Gre, &stats);
        assert_eq!(timeout, worker.generic_timeout);

        // Prevent drop to avoid IO Safety violation from zeroed eBPF map
        std::mem::forget(worker);
    }

    // NOTE: Most integration tests removed - the architecture has changed to an event-driven model
    // where FlowWorker receives FlowEvent from eBPF ring buffer instead of PacketMeta.
    // Tests would need to mock the entire eBPF infrastructure to work properly.
    // Simple unit tests for individual functions (like calculate_timeout, determine_flow_end_reason)
    // are retained above and below.

    #[test]
    fn test_determine_flow_end_reason_with_fin() {
        let reason = determine_flow_end_reason(Some(TCP_FLAG_FIN), FlowEndReason::IdleTimeout);
        assert_eq!(reason, FlowEndReason::EndOfFlowDetected);
    }

    #[test]
    fn test_determine_flow_end_reason_with_rst() {
        let reason = determine_flow_end_reason(Some(TCP_FLAG_RST), FlowEndReason::ActiveTimeout);
        assert_eq!(reason, FlowEndReason::EndOfFlowDetected);
    }

    #[test]
    fn test_determine_flow_end_reason_with_both_fin_and_rst() {
        let reason = determine_flow_end_reason(
            Some(TCP_FLAG_FIN | TCP_FLAG_RST),
            FlowEndReason::IdleTimeout,
        );
        assert_eq!(reason, FlowEndReason::EndOfFlowDetected);
    }

    #[test]
    fn test_determine_flow_end_reason_no_flags() {
        let reason = determine_flow_end_reason(None, FlowEndReason::IdleTimeout);
        assert_eq!(reason, FlowEndReason::IdleTimeout);
    }

    #[test]
    fn test_determine_flow_end_reason_other_flags() {
        let reason = determine_flow_end_reason(Some(0x10), FlowEndReason::ActiveTimeout); // ACK only
        assert_eq!(reason, FlowEndReason::ActiveTimeout);
    }
}
