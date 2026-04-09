use mermin_common::tcp::{
    TCP_FLAG_ACK, TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST,
    TCP_FLAG_SYN, TCP_FLAG_URG,
};

/// Individual TCP flag as specified in the TCP header
/// Based on IANA "TCP Header Flags" registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpFlag {
    /// FIN: No more data from sender
    Fin,
    /// SYN: Synchronize sequence numbers
    Syn,
    /// RST: Reset the connection
    Rst,
    /// PSH: Push function
    Psh,
    /// ACK: Acknowledgment field is significant
    Ack,
    /// URG: Urgent pointer field is significant
    Urg,
    /// ECE: ECN-Echo
    Ece,
    /// CWR: Congestion Window Reduced
    Cwr,
}

impl TcpFlag {
    pub const fn as_str(&self) -> &'static str {
        match self {
            TcpFlag::Fin => "fin",
            TcpFlag::Syn => "syn",
            TcpFlag::Rst => "rst",
            TcpFlag::Psh => "psh",
            TcpFlag::Ack => "ack",
            TcpFlag::Urg => "urg",
            TcpFlag::Ece => "ece",
            TcpFlag::Cwr => "cwr",
        }
    }
}

impl std::fmt::Display for TcpFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    flags: [bool; 8],
}

impl TcpFlags {
    /// Convert a bit-flag byte into an iterator of active [`TcpFlag`] variants.
    /// Order: [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]
    ///
    /// Returns a lazy iterator with no heap allocation. Callers that need a
    /// collected value can call `.collect::<Vec<_>>()`.
    pub fn flags_from_bits(bits: u8) -> impl Iterator<Item = TcpFlag> {
        const FLAG_MAP: [(u8, TcpFlag); 8] = [
            (TCP_FLAG_FIN, TcpFlag::Fin),
            (TCP_FLAG_SYN, TcpFlag::Syn),
            (TCP_FLAG_RST, TcpFlag::Rst),
            (TCP_FLAG_PSH, TcpFlag::Psh),
            (TCP_FLAG_ACK, TcpFlag::Ack),
            (TCP_FLAG_URG, TcpFlag::Urg),
            (TCP_FLAG_ECE, TcpFlag::Ece),
            (TCP_FLAG_CWR, TcpFlag::Cwr),
        ];
        FLAG_MAP
            .into_iter()
            .filter_map(move |(mask, flag)| (bits & mask != 0).then_some(flag))
    }

    /// Latency between SYN and SYN+ACK timestamps (nanoseconds).
    pub fn handshake_latency_from_stats(syn_ns: u64, syn_ack_ns: u64) -> i64 {
        if syn_ns == 0 || syn_ack_ns == 0 || syn_ack_ns <= syn_ns {
            return 0;
        }

        syn_ack_ns.saturating_sub(syn_ns) as i64
    }

    /// Average transaction latency from sum and count (nanoseconds).
    pub fn transaction_latency_from_stats(sum: u64, count: u32) -> i64 {
        if count == 0 {
            return 0;
        }
        (sum / count as u64) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_from_struct() {
        let tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

        let flags = TcpFlags::flags_from_bits(tcp_flags).collect::<Vec<_>>();
        assert_eq!(flags, [TcpFlag::Syn, TcpFlag::Ack]);
    }

    #[test]
    fn test_flags_from_bits() {
        // Test no flags
        assert_eq!(
            TcpFlags::flags_from_bits(0x00).collect::<Vec<_>>(),
            [] as [TcpFlag; 0]
        );

        // Test individual flags
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_FIN).collect::<Vec<_>>(),
            [TcpFlag::Fin]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_SYN).collect::<Vec<_>>(),
            [TcpFlag::Syn]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_RST).collect::<Vec<_>>(),
            [TcpFlag::Rst]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_PSH).collect::<Vec<_>>(),
            [TcpFlag::Psh]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_ACK).collect::<Vec<_>>(),
            [TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_URG).collect::<Vec<_>>(),
            [TcpFlag::Urg]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_ECE).collect::<Vec<_>>(),
            [TcpFlag::Ece]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_CWR).collect::<Vec<_>>(),
            [TcpFlag::Cwr]
        );

        // Test common flag combinations
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_SYN | TCP_FLAG_ACK).collect::<Vec<_>>(), // SYN+ACK
            [TcpFlag::Syn, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_FIN | TCP_FLAG_ACK).collect::<Vec<_>>(), // FIN+ACK
            [TcpFlag::Fin, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_PSH | TCP_FLAG_ACK).collect::<Vec<_>>(), // PSH+ACK
            [TcpFlag::Psh, TcpFlag::Ack]
        );

        // Test all flags
        assert_eq!(
            TcpFlags::flags_from_bits(0xFF).collect::<Vec<_>>(),
            [
                TcpFlag::Fin,
                TcpFlag::Syn,
                TcpFlag::Rst,
                TcpFlag::Psh,
                TcpFlag::Ack,
                TcpFlag::Urg,
                TcpFlag::Ece,
                TcpFlag::Cwr
            ]
        );
    }

    #[test]
    fn test_handshake_latency_from_stats() {
        assert_eq!(
            TcpFlags::handshake_latency_from_stats(1000u64, 1500u64),
            500
        );
    }

    #[test]
    fn test_transaction_latency_from_stats() {
        assert_eq!(TcpFlags::transaction_latency_from_stats(8u64, 4u32), 2);
        assert_eq!(TcpFlags::transaction_latency_from_stats(16u64, 0u32), 0);
    }
}
