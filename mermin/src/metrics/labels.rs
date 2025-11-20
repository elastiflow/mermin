//! Constants for metric labels.

// Flow Event Status
pub const EVENT_RECEIVED: &str = "received";
pub const EVENT_DROPPED_BACKPRESSURE: &str = "dropped_backpressure";
pub const EVENT_DROPPED_ERROR: &str = "dropped_error";

// Flow Span Status
pub const SPAN_CREATED: &str = "created";
pub const SPAN_RECORDED: &str = "recorded";
pub const SPAN_IDLED: &str = "idled";
pub const SPAN_DROPPED: &str = "dropped";

// Map Access Status
pub const MAP_ACCESS_OK: &str = "ok";
pub const MAP_ACCESS_ERROR: &str = "error";
pub const MAP_ACCESS_NOT_FOUND: &str = "not_found";

// Ringbuf Packet Status
pub const PACKET_RECEIVED: &str = "received";
pub const PACKET_FILTERED: &str = "filtered";

// Export Status
pub const EXPORT_QUEUED: &str = "queued";
pub const EXPORT_DROPPED: &str = "dropped";
pub const EXPORT_OK: &str = "ok";
pub const EXPORT_ERROR: &str = "error";

// Channel Names
pub const CHANNEL_PACKET_WORKER: &str = "packet_worker";
pub const CHANNEL_EXPORTER: &str = "exporter";

// Channel Send Status
pub const SEND_SUCCESS: &str = "success";
pub const SEND_ERROR: &str = "error";
