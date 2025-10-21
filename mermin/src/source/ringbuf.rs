//! Ring buffer reader for eBPF packet metadata.
//!
//! This module provides the `RingBufReader` which handles reading packet metadata
//! from the eBPF ring buffer in an event-driven manner. It applies filtering rules
//! before forwarding packets to the processing pipeline.

use std::{os::fd::AsRawFd, sync::Arc};

use aya::maps::RingBuf;
use mermin_common::PacketMeta;
use tokio::{io::unix::AsyncFd, sync::mpsc};
use tracing::{error, info, trace, warn};

use crate::source::filter::PacketFilter;

/// Handles reading packet metadata from the eBPF ring buffer and routing it through pipelines.
///
/// The reader operates in an event-driven fashion using `AsyncFd` to avoid busy-waiting.
/// Each packet is validated, deserialized, filtered, and then forwarded to the processing
/// pipeline via an async channel.
pub struct RingBufReader {
    ring_buf: RingBuf<aya::maps::MapData>,
    router: Arc<PacketFilter>,
    packet_meta_tx: mpsc::Sender<PacketMeta>,
}

impl RingBufReader {
    /// Creates a new RingBufReader
    pub fn new(
        ring_buf: RingBuf<aya::maps::MapData>,
        router: Arc<PacketFilter>,
        packet_meta_tx: mpsc::Sender<PacketMeta>,
    ) -> Self {
        Self {
            ring_buf,
            router,
            packet_meta_tx,
        }
    }

    /// Starts the ring buffer reading task.
    ///
    /// This method runs indefinitely, polling the ring buffer for new packets.
    /// It uses event-driven I/O to avoid busy-waiting. Each packet is:
    /// 1. Validated for size
    /// 2. Deserialized from raw bytes
    /// 3. Filtered against configured rules
    /// 4. Forwarded to the processing pipeline if it passes filters
    ///
    /// This method consumes `self` and should be spawned in a separate tokio task.
    pub async fn run(mut self) {
        info!("userspace task started: reading from ring buffer for packet metadata");

        // Wrap the ring buffer's fd in AsyncFd for event-driven polling
        let async_fd = match AsyncFd::new(self.ring_buf.as_raw_fd()) {
            Ok(fd) => fd,
            Err(e) => {
                error!("failed to create AsyncFd for ring buffer: {e}");
                return;
            }
        };

        loop {
            // Wait for the ring buffer to be readable (event-driven, no busy-loop)
            let mut guard = match async_fd.readable().await {
                Ok(guard) => guard,
                Err(e) => {
                    error!("error waiting for ring buffer readability: {e}");
                    break;
                }
            };

            // Consume all available data in a batch
            while let Some(bytes) = self.ring_buf.next() {
                // Validate that we have enough bytes for a PacketMeta
                if bytes.len() < std::mem::size_of::<PacketMeta>() {
                    warn!(
                        "ring buffer provided insufficient bytes for PacketMeta: got {}, expected {}",
                        bytes.len(),
                        std::mem::size_of::<PacketMeta>()
                    );
                    continue;
                }

                // SAFETY: The eBPF ring buffer is guaranteed to contain properly aligned
                // PacketMeta structures written by the kernel-side eBPF program.
                // We've verified above that bytes.len() >= size_of::<PacketMeta>().
                // The pointer cast is valid because PacketMeta is repr(C) and the
                // eBPF program writes the struct with the same memory layout.
                let packet_meta: PacketMeta =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };

                // Apply per-pipeline filtering at PacketMeta level
                match self.router.should_process(&packet_meta) {
                    Ok(true) => {
                        if let Err(e) = self.packet_meta_tx.send(packet_meta).await {
                            error!("failed to send packet to k8s attribution channel: {e}");
                        }
                    }
                    Ok(false) => {
                        trace!("packet meta did not match any filters; skipping.");
                    }
                    Err(e) => {
                        warn!(
                            "failed to parse packet metadata for filtering: {e}; skipping packet"
                        );
                    }
                }
            }

            guard.clear_ready();
        }
    }
}
