//! Pipeline lifecycle management for hot-reload support.
//!
//! This module owns the boundary between the generic [`ComponentManager`] and
//! Mermin-specific pre/post-shutdown logic (flow preservation and eBPF resource
//! recovery). It provides:
//!
//! - [`EbpfResources`] — the set of kernel-side resources that must survive a
//!   pipeline restart (eBPF object, ring buffers, shared maps).
//! - [`Pipeline`] — a running pipeline instance with ordered dehydration and
//!   resource-return semantics for restart support.
//! - [`EbpfRecoveryError`] — typed errors for the resource-handback path.

use std::{fs::File, sync::Arc};

use aya::{
    Ebpf,
    maps::{HashMap as EbpfHashMap, RingBuf},
};
use crossbeam::channel::Sender;
use dashmap::DashMap;
use mermin_common::{FlowKey, FlowStats, ListeningPortKey};
use tokio::sync::{Mutex, oneshot};
use tracing::{error, info, warn};

use crate::{
    iface::types::ControllerCommand,
    metrics::registry::SHUTDOWN_FLOWS_TOTAL,
    runtime::{
        component::{ComponentManager, ShutdownResult},
        shutdown::ShutdownConfig,
    },
    span::{producer::FlowSpanComponents, trace_id::TraceIdCache},
};

/// Errors that can occur when recovering eBPF resources after a pipeline shutdown.
///
/// Each variant corresponds to a component that failed to return its owned
/// resource via the oneshot channel — most likely because the component panicked
/// before reaching its final send. This is fatal: the caller cannot restart the
/// pipeline without the resource.
#[derive(Debug)]
pub enum EbpfRecoveryError {
    /// The `span-producer` task did not return the flow-events ring buffer.
    FlowEvents,
    /// The `ebpf-log-consumer` task did not return the log-events ring buffer.
    LogEvents,
    /// The controller thread did not return the [`Ebpf`] object.
    EbpfObject,
}

impl std::fmt::Display for EbpfRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EbpfRecoveryError::FlowEvents => write!(
                f,
                "span-producer did not return flow_events ring buffer (component panicked?) — restart is not possible"
            ),
            EbpfRecoveryError::LogEvents => write!(
                f,
                "ebpf-log-consumer did not return log_events ring buffer (component panicked?) — restart is not possible"
            ),
            EbpfRecoveryError::EbpfObject => write!(
                f,
                "controller thread did not return Ebpf object (thread panicked?) — restart is not possible"
            ),
        }
    }
}

impl std::error::Error for EbpfRecoveryError {}

/// Resources from the eBPF layer that persist across pipeline restarts.
///
/// These cannot be cheaply re-created: the [`Ebpf`] object keeps programs loaded
/// and attached (dropping it detaches them from all interfaces), and the ring
/// buffers are `mmap`-backed kernel objects whose file descriptors were already
/// consumed by `take_map()`. They are "returned" by each owning component via a
/// [`oneshot`] channel on shutdown and threaded into the next call to
/// `start_pipeline()` in `main.rs`.
pub struct EbpfResources {
    pub ebpf: Ebpf,
    pub flow_events_ringbuf: RingBuf<aya::maps::MapData>,
    pub log_events_ringbuf: RingBuf<aya::maps::MapData>,
    pub flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    pub listening_ports_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, ListeningPortKey, u8>>>,
    /// Shared between controller and producer; reusing across reloads avoids a
    /// window where the restarted producer sees no interface names.
    pub iface_map: Arc<DashMap<u32, String>>,
    pub host_netns: Arc<File>,
}

/// A running instance of the Mermin processing pipeline.
///
/// Wraps the [`ComponentManager`] together with the Mermin-specific state
/// required for ordered dehydration (flow preservation) before shutdown and
/// eBPF resource recovery after shutdown.
///
/// Obtain an instance from `start_pipeline()` in `main.rs` and dispose of it
/// via [`Pipeline::preserve_and_shutdown`].
pub struct Pipeline {
    pub manager: ComponentManager,
    pub flow_span_components: Arc<FlowSpanComponents>,
    pub trace_id_cache: TraceIdCache,
    /// Sends `ControllerCommand::Shutdown` to the controller thread before the
    /// manager broadcasts the general shutdown signal. The controller needs this
    /// to detach eBPF programs in an orderly fashion before the thread exits.
    pub cmd_tx: Sender<ControllerCommand>,
    /// Invariant: the sender fires as the **last action** of the `span-producer`
    /// task body, before the task returns. Because [`ComponentManager::shutdown`]
    /// joins the task handle before returning, the send is guaranteed to have
    /// occurred by the time [`Pipeline::preserve_and_shutdown`] awaits this receiver.
    pub flow_events_return: oneshot::Receiver<RingBuf<aya::maps::MapData>>,
    /// Invariant: same as [`Self::flow_events_return`] but for the
    /// `ebpf-log-consumer` task and the log-events ring buffer.
    pub log_events_return: oneshot::Receiver<RingBuf<aya::maps::MapData>>,
    /// Invariant: the sender fires as the last action of the controller **thread**
    /// body. [`ComponentManager::shutdown`] joins the thread before returning, so
    /// the send is guaranteed to have occurred before this receiver is awaited.
    pub ebpf_return: oneshot::Receiver<Ebpf>,
    // Arc-wrapped shared maps — carried through directly without handoff overhead.
    pub flow_stats_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, FlowStats>>>,
    pub listening_ports_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, ListeningPortKey, u8>>>,
    pub iface_map: Arc<DashMap<u32, String>>,
    pub host_netns: Arc<File>,
}

impl Pipeline {
    /// Flush active flows, shut down all components in reverse registration
    /// order, then collect the eBPF resources returned by exiting components.
    ///
    /// # Shutdown sequence
    ///
    /// 1. `preserve_active_flows()` — flush in-flight flow spans to the exporter
    ///    (only when `config.preserve_flows` is true).
    /// 2. `cmd_tx.send(Shutdown)` — signal the controller thread to detach eBPF
    ///    programs and exit (separate from the broadcast that wakes async tasks).
    /// 3. `manager.shutdown()` — broadcasts the shutdown signal and joins all
    ///    handles in reverse registration order.
    /// 4. Await the three oneshot receivers **after** `manager.shutdown()` so that
    ///    all senders have already fired (there is no race).
    ///
    /// # Errors
    ///
    /// Returns [`Err(EbpfRecoveryError)`] if any of the three eBPF resources
    /// could not be recovered because the owning component panicked before
    /// sending. This is fatal — the caller should propagate the error and exit.
    pub async fn preserve_and_shutdown(
        self,
        config: ShutdownConfig,
    ) -> (ShutdownResult, Result<EbpfResources, EbpfRecoveryError>) {
        let pre_shutdown_start = std::time::Instant::now();

        if config.preserve_flows {
            info!(
                event.name = "pipeline.shutdown.preserving_flows",
                timeout_seconds = config.flow_preservation_timeout.as_secs(),
                "attempting to preserve active flows before shutdown"
            );
            match self
                .flow_span_components
                .preserve_active_flows(&self.trace_id_cache, config.flow_preservation_timeout)
                .await
            {
                Ok(preserved_count) => {
                    SHUTDOWN_FLOWS_TOTAL
                        .with_label_values(&["preserved"])
                        .inc_by(preserved_count as u64);
                    info!(
                        event.name = "pipeline.shutdown.flows_preserved",
                        count = preserved_count,
                        "successfully preserved active flows"
                    );
                }
                Err(lost_count) => {
                    SHUTDOWN_FLOWS_TOTAL
                        .with_label_values(&["lost"])
                        .inc_by(lost_count as u64);
                    warn!(
                        event.name = "pipeline.shutdown.flows_lost",
                        count = lost_count,
                        "some flows were lost during preservation"
                    );
                }
            }
        }

        // Deduct flow preservation time from the component shutdown budget.
        let mut component_config = config;
        component_config.timeout = component_config
            .timeout
            .saturating_sub(pre_shutdown_start.elapsed());

        // Signal controller thread to detach eBPF programs before the broadcast
        // shutdown wakes async components — the controller needs this separate
        // signal because it listens on a crossbeam channel, not the broadcast.
        let _ = self.cmd_tx.send(ControllerCommand::Shutdown);

        // Shut down all components (broadcast + reverse-order join).
        let shutdown_result = self.manager.shutdown(component_config).await;

        // Collect eBPF resources. The sends happen inside each component body as
        // their very last action before returning; manager.shutdown() joining the
        // handles guarantees the sends have already occurred.
        let flow_events_ringbuf = match self.flow_events_return.await {
            Ok(rb) => rb,
            Err(_) => {
                let err = EbpfRecoveryError::FlowEvents;
                error!(
                    event.name = "pipeline.shutdown.flow_events_return_failed",
                    "{err}"
                );
                return (shutdown_result, Err(err));
            }
        };

        let log_events_ringbuf = match self.log_events_return.await {
            Ok(rb) => rb,
            Err(_) => {
                let err = EbpfRecoveryError::LogEvents;
                error!(
                    event.name = "pipeline.shutdown.log_events_return_failed",
                    "{err}"
                );
                return (shutdown_result, Err(err));
            }
        };

        let ebpf = match self.ebpf_return.await {
            Ok(e) => e,
            Err(_) => {
                let err = EbpfRecoveryError::EbpfObject;
                error!(event.name = "pipeline.shutdown.ebpf_return_failed", "{err}");
                return (shutdown_result, Err(err));
            }
        };

        let ebpf_resources = EbpfResources {
            ebpf,
            flow_events_ringbuf,
            log_events_ringbuf,
            flow_stats_map: self.flow_stats_map,
            listening_ports_map: self.listening_ports_map,
            iface_map: self.iface_map,
            host_netns: self.host_netns,
        };

        (shutdown_result, Ok(ebpf_resources))
    }
}
