//! eBPF log consumer that reads log entries from the LOG_EVENTS ring buffer.
//!
//! This module replaces aya_log_ebpf to avoid BTF issues with generic types.
//! Log entries are sent from eBPF via a ring buffer and converted to tracing events.

use std::os::fd::AsRawFd;

use aya::maps::RingBuf;
use mermin_common::{LogEntry, LogErrorCode, LogLevel};
use tokio::{
    io::unix::AsyncFd,
    sync::{broadcast, oneshot},
};
use tracing::{error, trace, warn};

/// Consumes log entries from the eBPF LOG_EVENTS ring buffer.
///
/// Log entries are read from the ring buffer and converted to tracing events at the
/// appropriate log level. This provides visibility into eBPF-side errors without the
/// BTF compatibility issues of aya_log.
pub async fn run_log_consumer(
    mut log_events: RingBuf<aya::maps::MapData>,
    mut shutdown_rx: broadcast::Receiver<()>,
    log_events_return: oneshot::Sender<RingBuf<aya::maps::MapData>>,
) {
    let async_fd = match AsyncFd::new(log_events.as_raw_fd()) {
        Ok(fd) => fd,
        Err(e) => {
            error!(
                event.name = "ebpf_log.init_failed",
                error.message = %e,
                "failed to create async fd for log ring buffer"
            );
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                break;
            }
            result = async_fd.readable() => {
                let mut guard = match result {
                    Ok(guard) => guard,
                    Err(e) => {
                        warn!(
                            event.name = "ebpf_log.read_error",
                            error.message = %e,
                            "error waiting for log ring buffer readability"
                        );
                        break;
                    }
                };

                while let Some(item) = log_events.next() {
                    // SAFETY: LogEntry is a POD type (repr(C), all primitive fields), and
                    // read_unaligned handles any alignment issues. The ring buffer guarantees
                    // the data is at least LogEntry-sized (16 bytes) when next() returns Some.
                    let log_entry: LogEntry =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const LogEntry) };

                    emit_log_entry(&log_entry);
                }

                guard.clear_ready();
            }
        }
    }

    // Return the ring buffer for reuse across pipeline restarts.
    // async_fd borrows the ring buffer's raw fd; drop it first so epoll
    // deregistration happens before the receiver takes ownership.
    drop(async_fd);
    let _ = log_events_return.send(log_events);
}

fn emit_log_entry(entry: &LogEntry) {
    let error_str = LogErrorCode::try_from(entry.error_code)
        .map(|e| e.as_str())
        .unwrap_or("unknown");

    let direction_str = if entry.direction == 0 {
        "egress"
    } else {
        "ingress"
    };

    match LogLevel::try_from(entry.level) {
        Ok(LogLevel::Error) => {
            error!(
                event.name = "ebpf.error",
                ebpf.error = error_str,
                ebpf.direction = direction_str,
                ebpf.ifindex = entry.ifindex,
                "ebpf error"
            );
        }
        Ok(LogLevel::Warn) => {
            warn!(
                event.name = "ebpf.warn",
                ebpf.error = error_str,
                ebpf.direction = direction_str,
                ebpf.ifindex = entry.ifindex,
                "ebpf warning"
            );
        }
        _ => {
            trace!(
                event.name = "ebpf.trace",
                ebpf.error = error_str,
                ebpf.direction = direction_str,
                ebpf.ifindex = entry.ifindex,
                "ebpf trace"
            );
        }
    }
}
