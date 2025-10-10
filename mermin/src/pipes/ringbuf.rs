use std::{os::fd::AsRawFd, sync::Arc};

use aya::maps::RingBuf;
use mermin_common::PacketMeta;
use tokio::{io::unix::AsyncFd, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::pipes::router::PipelineRouter;

/// Handles reading packet metadata from the eBPF ring buffer and routing it through pipelines
pub struct RingBufReader {
    ring_buf: RingBuf<aya::maps::MapData>,
    pipeline_router: Arc<PipelineRouter>,
    packet_meta_tx: mpsc::Sender<PacketMeta>,
}

impl RingBufReader {
    /// Creates a new RingBufReader
    pub fn new(
        ring_buf: RingBuf<aya::maps::MapData>,
        pipeline_router: Arc<PipelineRouter>,
        packet_meta_tx: mpsc::Sender<PacketMeta>,
    ) -> Self {
        Self {
            ring_buf,
            pipeline_router,
            packet_meta_tx,
        }
    }

    /// Starts the ring buffer reading task
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
                let packet_meta: PacketMeta =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };

                // Apply per-pipeline filtering at PacketMeta level
                match self.pipeline_router.route_packet(&packet_meta) {
                    Ok(matching_pipelines) => {
                        if !matching_pipelines.is_empty() {
                            if let Err(e) = self.packet_meta_tx.send(packet_meta).await {
                                warn!("failed to send packet to k8s attribution channel: {e}");
                            }
                        } else {
                            debug!("packet meta did not match any pipeline filters; skipping.");
                        }
                    }
                    Err(e) => {
                        warn!("failed to route packet meta: {e}; skipping.");
                    }
                }
            }

            guard.clear_ready();
        }
    }
}
