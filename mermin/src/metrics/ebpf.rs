//! Enums for eBPF-related metrics labels.

/// eBPF map names for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapName {
    FlowStats,
    FlowEvents,
    ListeningPorts,
}

impl EbpfMapName {
    pub const fn as_str(self) -> &'static str {
        match self {
            EbpfMapName::FlowStats => "FLOW_STATS",
            EbpfMapName::FlowEvents => "FLOW_EVENTS",
            EbpfMapName::ListeningPorts => "LISTENING_PORTS",
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
