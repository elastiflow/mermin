//! Enums for eBPF-related metrics labels and ring buffer metrics.

use std::{
    os::fd::{AsRawFd, RawFd},
    ptr::NonNull,
    sync::OnceLock,
};

use mermin_common::MapUnit;
use tracing::warn;

use crate::metrics::registry::EBPF_MAP_SIZE;

/// Global ring buffer metrics accessor.
/// Initialized once at startup and used by the metrics server to read ring buffer size.
static RINGBUF_METRICS: OnceLock<RingBufMetrics> = OnceLock::new();

/// Ring buffer metrics reader.
///
/// Reads producer and consumer positions directly from the mmap'd ring buffer
/// memory to calculate current utilization. This is safe because the ring buffer
/// header positions are in the kernel's UAPI and are stable across versions.
///
/// Memory layout (from linux/bpf.h):
/// - Consumer page (offset 0): consumer position at byte 0 as u64
/// - Producer page (offset page_size): producer position at byte 0 as u64
pub struct RingBufMetrics {
    /// Pointer to consumer position (first u64 in consumer page).
    consumer_pos_ptr: *const u64,
    /// Pointer to producer position (first u64 in producer page).
    producer_pos_ptr: *const u64,
    /// Mmap'd region base pointer (needed for munmap in Drop).
    mmap_ptr: NonNull<libc::c_void>,
    /// Length of mmap'd region (needed for munmap in Drop).
    mmap_len: usize,
}

// SAFETY: Send is safe because:
// - The mmap'd memory is read-only from userspace
// - The pointers remain valid for the program's lifetime (tied to eBPF map lifetime)
// - No mutable access from userspace
//
// Sync is safe because:
// - We only read via volatile reads which see kernel's atomic updates
// - No userspace writes means no data races
unsafe impl Send for RingBufMetrics {}
unsafe impl Sync for RingBufMetrics {}

impl RingBufMetrics {
    /// Create a new ring buffer metrics reader from a raw file descriptor.
    ///
    /// The fd must be a valid ring buffer map file descriptor. The mmap will fail
    /// if the fd is invalid or not a ring buffer.
    ///
    /// Returns [`None`] if mmap fails (e.g., invalid fd or not a ring buffer map).
    pub fn new(fd: RawFd) -> Option<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        // mmap both consumer and producer pages (2 pages total)
        // Consumer page is at offset 0, producer page is at offset page_size
        let mmap_len = 2 * page_size;

        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if mmap_ptr == libc::MAP_FAILED {
            warn!(
                event.name = "ringbuf_metrics.mmap_failed",
                error.code = std::io::Error::last_os_error().raw_os_error(),
                "failed to mmap ring buffer for metrics"
            );
            return None;
        }

        // SAFETY: mmap succeeded (not MAP_FAILED), and MAP_FAILED is -1 (not null)
        let mmap_nonnull =
            NonNull::new(mmap_ptr).expect("mmap returned null (should be impossible)");

        // Consumer position is at the start of the consumer page (offset 0)
        let consumer_pos_ptr = mmap_ptr as *const u64;

        // Producer position is at the start of the producer page (offset page_size)
        // SAFETY: page_size is from sysconf, mmap succeeded with 2*page_size length
        let producer_pos_ptr = unsafe { (mmap_ptr as *const u8).add(page_size) as *const u64 };

        Some(Self {
            consumer_pos_ptr,
            producer_pos_ptr,
            mmap_ptr: mmap_nonnull,
            mmap_len,
        })
    }

    /// Read the current ring buffer size in bytes.
    ///
    /// This is the difference between producer and consumer positions,
    /// representing the number of bytes currently pending in the ring buffer.
    #[must_use]
    pub fn current_size(&self) -> u64 {
        // SAFETY: These pointers were set up in new() from a valid mmap
        // and point to kernel-managed u64 values that are atomically updated.
        let consumer_pos = unsafe { std::ptr::read_volatile(self.consumer_pos_ptr) };
        let producer_pos = unsafe { std::ptr::read_volatile(self.producer_pos_ptr) };

        // Handle wrap-around (though rare for u64)
        producer_pos.wrapping_sub(consumer_pos)
    }
}

impl Drop for RingBufMetrics {
    fn drop(&mut self) {
        // SAFETY: mmap_ptr and mmap_len were set in new() from a successful mmap call
        unsafe {
            libc::munmap(self.mmap_ptr.as_ptr(), self.mmap_len);
        }
    }
}

/// Initialize the global ring buffer metrics from a ring buffer's file descriptor.
///
/// This should be called once at startup before the ring buffer is moved to the producer.
/// Returns true if initialization succeeded, false if it failed or was already initialized.
pub fn init_ringbuf_metrics<T: AsRawFd>(ringbuf: &T) -> bool {
    let Some(metrics) = RingBufMetrics::new(ringbuf.as_raw_fd()) else {
        return false;
    };

    if RINGBUF_METRICS.set(metrics).is_err() {
        warn!(
            event.name = "ringbuf_metrics.already_initialized",
            "ring buffer metrics already initialized"
        );
        return false;
    }

    true
}

/// Update the EBPF_MAP_SIZE metric for FLOW_EVENTS ring buffer.
///
/// Reads the current ring buffer size and updates the prometheus gauge.
/// This is called when the metrics endpoint is scraped.
pub fn update_ringbuf_size_metric() {
    if let Some(metrics) = RINGBUF_METRICS.get() {
        let size = metrics.current_size();
        EBPF_MAP_SIZE
            .with_label_values(&[EbpfMapName::FlowEvents.as_str(), MapUnit::Bytes.as_str()])
            .set(size as i64);
    }
}

/// Size of a LISTENING_PORTS entry (ListeningPortKey + u8 value).
/// Used for bytes_total metric tracking on read operations.
pub const LISTENING_PORTS_ENTRY_SIZE: u64 = 4;

/// eBPF map names for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapName {
    FlowStats,
    FlowEvents,
    IcmpStats,
    ListeningPorts,
    TcpStats,
}

impl EbpfMapName {
    pub const fn as_str(self) -> &'static str {
        match self {
            EbpfMapName::FlowStats => "FLOW_STATS",
            EbpfMapName::FlowEvents => "FLOW_EVENTS",
            EbpfMapName::IcmpStats => "ICMP_STATS",
            EbpfMapName::ListeningPorts => "LISTENING_PORTS",
            EbpfMapName::TcpStats => "TCP_STATS",
        }
    }
}

/// eBPF map operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapOperation {
    Read,
    Write,
    Delete,
}

impl EbpfMapOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            EbpfMapOperation::Read => "read",
            EbpfMapOperation::Write => "write",
            EbpfMapOperation::Delete => "delete",
        }
    }
}

/// eBPF map operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapStatus {
    Ok,
    Error,
    NotFound,
}

impl EbpfMapStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            EbpfMapStatus::Ok => "ok",
            EbpfMapStatus::Error => "error",
            EbpfMapStatus::NotFound => "not_found",
        }
    }
}

/// TC program operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcOperation {
    Attached,
    Detached,
}

impl TcOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            TcOperation::Attached => "attached",
            TcOperation::Detached => "detached",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // RingBufMetrics Tests
    // ============================================================================

    /// Create a RingBufMetrics with controllable memory for testing.
    /// Returns (metrics, consumer_ptr, producer_ptr) so tests can modify positions.
    fn create_test_metrics() -> Option<(RingBufMetrics, *mut u64, *mut u64)> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mmap_len = 2 * page_size;

        // Create anonymous mmap (not backed by a file)
        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE, // Need write for testing
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mmap_ptr == libc::MAP_FAILED {
            return None;
        }

        let mmap_nonnull = NonNull::new(mmap_ptr)?;
        let consumer_pos_ptr = mmap_ptr as *mut u64;
        let producer_pos_ptr = unsafe { (mmap_ptr as *mut u8).add(page_size) as *mut u64 };

        // Initialize positions to 0
        unsafe {
            *consumer_pos_ptr = 0;
            *producer_pos_ptr = 0;
        }

        let metrics = RingBufMetrics {
            consumer_pos_ptr,
            producer_pos_ptr,
            mmap_ptr: mmap_nonnull,
            mmap_len,
        };

        Some((metrics, consumer_pos_ptr, producer_pos_ptr))
    }

    #[test]
    fn test_ringbuf_metrics_empty_buffer() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        unsafe {
            *consumer_ptr = 0;
            *producer_ptr = 0;
        }

        assert_eq!(metrics.current_size(), 0);
    }

    #[test]
    fn test_ringbuf_metrics_with_data() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        unsafe {
            *consumer_ptr = 1000;
            *producer_ptr = 5000;
        }

        assert_eq!(metrics.current_size(), 4000);
    }

    #[test]
    fn test_ringbuf_metrics_producer_advances() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        unsafe {
            *consumer_ptr = 0;
            *producer_ptr = 100;
        }
        assert_eq!(metrics.current_size(), 100);

        // Simulate producer writing more data
        unsafe {
            *producer_ptr = 500;
        }
        assert_eq!(metrics.current_size(), 500);
    }

    #[test]
    fn test_ringbuf_metrics_consumer_catches_up() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        unsafe {
            *consumer_ptr = 0;
            *producer_ptr = 1000;
        }
        assert_eq!(metrics.current_size(), 1000);

        // Simulate consumer reading half the data
        unsafe {
            *consumer_ptr = 500;
        }
        assert_eq!(metrics.current_size(), 500);

        // Consumer catches up completely
        unsafe {
            *consumer_ptr = 1000;
        }
        assert_eq!(metrics.current_size(), 0);
    }

    #[test]
    fn test_ringbuf_metrics_wraparound() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        // Simulate wraparound: consumer near MAX, producer wrapped to low value
        unsafe {
            *consumer_ptr = u64::MAX - 100;
            *producer_ptr = 50;
        }

        // Expected size: (MAX - (MAX-100)) + 50 + 1 = 101 + 50 = 151
        // Using wrapping_sub: 50 - (MAX - 100) = 50 + 101 = 151
        assert_eq!(metrics.current_size(), 151);
    }

    #[test]
    fn test_ringbuf_metrics_wraparound_edge_cases() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        // Producer at 0, consumer at MAX (1 byte pending after wrap)
        unsafe {
            *consumer_ptr = u64::MAX;
            *producer_ptr = 0;
        }
        assert_eq!(metrics.current_size(), 1);

        // Both at MAX (empty)
        unsafe {
            *consumer_ptr = u64::MAX;
            *producer_ptr = u64::MAX;
        }
        assert_eq!(metrics.current_size(), 0);
    }

    #[test]
    fn test_ringbuf_metrics_large_values() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        let gb: u64 = 1024 * 1024 * 1024;

        // 1 GB pending
        unsafe {
            *consumer_ptr = 9 * gb;
            *producer_ptr = 10 * gb;
        }
        assert_eq!(metrics.current_size(), gb);

        // Large positions, small difference
        unsafe {
            *consumer_ptr = 100 * gb;
            *producer_ptr = 100 * gb + 500;
        }
        assert_eq!(metrics.current_size(), 500);
    }

    #[test]
    fn test_ringbuf_metrics_same_position_various_values() {
        let Some((metrics, consumer_ptr, producer_ptr)) = create_test_metrics() else {
            eprintln!("Skipping test: mmap not available");
            return;
        };

        // Empty at 0
        unsafe {
            *consumer_ptr = 0;
            *producer_ptr = 0;
        }
        assert_eq!(metrics.current_size(), 0);

        // Empty at 1000
        unsafe {
            *consumer_ptr = 1000;
            *producer_ptr = 1000;
        }
        assert_eq!(metrics.current_size(), 0);

        // Empty at large value
        unsafe {
            *consumer_ptr = u64::MAX / 2;
            *producer_ptr = u64::MAX / 2;
        }
        assert_eq!(metrics.current_size(), 0);
    }

    // ============================================================================
    // Invalid FD Tests
    // ============================================================================

    #[test]
    fn test_new_with_invalid_fd() {
        // Invalid file descriptor should return None
        let result = RingBufMetrics::new(-1);
        assert!(result.is_none());
    }

    #[test]
    fn test_new_with_non_ringbuf_fd() {
        // A regular file fd won't work as a ring buffer
        // This should fail gracefully
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open("/dev/null").ok();
        if let Some(f) = file {
            let result = RingBufMetrics::new(f.as_raw_fd());
            // mmap on /dev/null may succeed or fail depending on OS
            // The important thing is it doesn't crash
            drop(result);
        }
    }

    // ============================================================================
    // Enum Tests
    // ============================================================================

    #[test]
    fn test_ebpf_map_name_as_str() {
        assert_eq!(EbpfMapName::FlowStats.as_str(), "FLOW_STATS");
        assert_eq!(EbpfMapName::FlowEvents.as_str(), "FLOW_EVENTS");
        assert_eq!(EbpfMapName::IcmpStats.as_str(), "ICMP_STATS");
        assert_eq!(EbpfMapName::ListeningPorts.as_str(), "LISTENING_PORTS");
        assert_eq!(EbpfMapName::TcpStats.as_str(), "TCP_STATS");
    }

    #[test]
    fn test_ebpf_map_operation_as_str() {
        assert_eq!(EbpfMapOperation::Read.as_str(), "read");
        assert_eq!(EbpfMapOperation::Write.as_str(), "write");
        assert_eq!(EbpfMapOperation::Delete.as_str(), "delete");
    }

    #[test]
    fn test_ebpf_map_status_as_str() {
        assert_eq!(EbpfMapStatus::Ok.as_str(), "ok");
        assert_eq!(EbpfMapStatus::Error.as_str(), "error");
        assert_eq!(EbpfMapStatus::NotFound.as_str(), "not_found");
    }

    #[test]
    fn test_tc_operation_as_str() {
        assert_eq!(TcOperation::Attached.as_str(), "attached");
        assert_eq!(TcOperation::Detached.as_str(), "detached");
    }

    // ============================================================================
    // update_ringbuf_size_metric Tests
    // ============================================================================

    #[test]
    fn test_update_ringbuf_size_metric_without_init() {
        // Should not panic when called before initialization
        // The global RINGBUF_METRICS will be None, so this is a no-op
        // Note: This test may interact with other tests if they initialize the global
        update_ringbuf_size_metric();
    }
}
