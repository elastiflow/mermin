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
        info!(
            event.name = "task.started",
            task.name = "source.ringbuf",
            task.description = "reading from ring buffer for packet metadata",
            "userspace task started"
        );

        // Wrap the ring buffer's fd in AsyncFd for event-driven polling
        let async_fd = match AsyncFd::new(self.ring_buf.as_raw_fd()) {
            Ok(fd) => fd,
            Err(e) => {
                error!(
                    event.name = "task.error",
                    task.name = "source.ringbuf",
                    error.message = %e,
                    "failed to create asyncfd for ring buffer"
                );
                return;
            }
        };

        loop {
            // Wait for the ring buffer to be readable (event-driven, no busy-loop)
            let mut guard = match async_fd.readable().await {
                Ok(guard) => guard,
                Err(e) => {
                    error!(
                        event.name = "task.error",
                        task.name = "source.ringbuf",
                        error.message = %e,
                        "error waiting for ring buffer readability"
                    );
                    break;
                }
            };

            // Consume all available data in a batch
            while let Some(bytes) = self.ring_buf.next() {
                // Validate that we have enough bytes for a PacketMeta
                if bytes.len() < std::mem::size_of::<PacketMeta>() {
                    warn!(
                        event.name = "packet.malformed",
                        reason = "invalid_size",
                        packet.size.received = bytes.len(),
                        packet.size.expected = std::mem::size_of::<PacketMeta>(),
                        "ring buffer provided insufficient bytes for packet meta"
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
                            error!(
                                event.name = "channel.send_failed",
                                channel.name = "packet_processing",
                                error.message = %e,
                                "failed to send packet to processing channel"
                            );
                        }
                    }
                    Ok(false) => {
                        trace!(
                            event.name = "packet.filtered",
                            "packet meta did not match any filters; skipping"
                        );
                    }
                    Err(e) => {
                        warn!(
                            event.name = "packet.filter_error",
                            error.message = %e,
                            network.interface.index = packet_meta.ifindex,
                            network.type = packet_meta.ether_type.as_str(),
                            network.transport = %packet_meta.proto,
                            "failed to parse packet metadata for filtering; skipping"
                        );
                    }
                }
            }

            guard.clear_ready();
        }
    }
}
