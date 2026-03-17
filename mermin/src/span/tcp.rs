use arrayvec::ArrayVec;
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
    /// Convert a bit-flag byte to a stack-allocated array of active [`TcpFlag`] variants.
    /// Order: [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]
    ///
    /// Returns an [`ArrayVec`] with capacity 8 (one per flag bit), avoiding heap allocation
    /// since the maximum number of active flags is bounded by the bit-width of the input.
    pub fn flags_from_bits(bits: u8) -> ArrayVec<TcpFlag, 8> {
        Self::active_flags_from_array(&Self::bits_to_array(bits))
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

    fn bits_to_array(bits: u8) -> [bool; 8] {
        [
            (bits & TCP_FLAG_FIN) != 0, // FIN
            (bits & TCP_FLAG_SYN) != 0, // SYN
            (bits & TCP_FLAG_RST) != 0, // RST
            (bits & TCP_FLAG_PSH) != 0, // PSH
            (bits & TCP_FLAG_ACK) != 0, // ACK
            (bits & TCP_FLAG_URG) != 0, // URG
            (bits & TCP_FLAG_ECE) != 0, // ECE
            (bits & TCP_FLAG_CWR) != 0, // CWR
        ]
    }

    fn active_flags_from_array(flags: &[bool; 8]) -> ArrayVec<TcpFlag, 8> {
        const FLAG_ENUMS: [TcpFlag; 8] = [
            TcpFlag::Fin,
            TcpFlag::Syn,
            TcpFlag::Rst,
            TcpFlag::Psh,
            TcpFlag::Ack,
            TcpFlag::Urg,
            TcpFlag::Ece,
            TcpFlag::Cwr,
        ];

        let mut result = ArrayVec::new();
        for (is_set, flag) in flags.iter().zip(FLAG_ENUMS.iter()) {
            if *is_set {
                result.push(*flag);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_from_struct() {
        let tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

        let flags = TcpFlags::flags_from_bits(tcp_flags);
        assert_eq!(flags.as_slice(), &[TcpFlag::Syn, TcpFlag::Ack]);
    }

    #[test]
    fn test_flags_from_bits() {
        // Test no flags
        assert_eq!(
            TcpFlags::flags_from_bits(0x00).as_slice(),
            &[] as &[TcpFlag]
        );

        // Test individual flags
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_FIN).as_slice(),
            &[TcpFlag::Fin]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_SYN).as_slice(),
            &[TcpFlag::Syn]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_RST).as_slice(),
            &[TcpFlag::Rst]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_PSH).as_slice(),
            &[TcpFlag::Psh]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_ACK).as_slice(),
            &[TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_URG).as_slice(),
            &[TcpFlag::Urg]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_ECE).as_slice(),
            &[TcpFlag::Ece]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_CWR).as_slice(),
            &[TcpFlag::Cwr]
        );

        // Test common flag combinations
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_SYN | TCP_FLAG_ACK).as_slice(), // SYN+ACK
            &[TcpFlag::Syn, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_FIN | TCP_FLAG_ACK).as_slice(), // FIN+ACK
            &[TcpFlag::Fin, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_PSH | TCP_FLAG_ACK).as_slice(), // PSH+ACK
            &[TcpFlag::Psh, TcpFlag::Ack]
        );

        // Test all flags
        assert_eq!(
            TcpFlags::flags_from_bits(0xFF).as_slice(),
            &[
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
