use network_types::tcp::{
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
    /// Convert the TCP flag to its string representation
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

/// Represents TCP flags as an array of 8 boolean values
/// Order: [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    flags: [bool; 8],
}

impl TcpFlags {
    /// Convert bit flags (u8) to a vector of active TcpFlag enum variants
    pub fn flags_from_bits(bits: u8) -> Vec<TcpFlag> {
        Self::active_flags_from_array(&Self::bits_to_array(bits))
    }

    /// Calculate latency between SYN and SYN+ACK packets
    pub fn handshake_latency_from_stats(syn_ns: u64, syn_ack_ns: u64) -> i64 {
        if syn_ns == 0 || syn_ack_ns == 0 || syn_ack_ns <= syn_ns {
            return 0;
        }

        syn_ack_ns.saturating_sub(syn_ns) as i64
    }

    /// Calculate latency from duration sum (ns) and transaction counts
    pub fn transaction_latency_from_stats(sum: u64, count: u32) -> i64 {
        if count == 0 {
            return 0;
        }
        (sum / count as u64) as i64
    }

    /// Convert u8 bit flags to a boolean array
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

    /// Convert a boolean array to a vector of active TcpFlag enum variants
    fn active_flags_from_array(flags: &[bool; 8]) -> Vec<TcpFlag> {
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

        flags
            .iter()
            .zip(FLAG_ENUMS.iter())
            .filter_map(|(is_set, flag)| if *is_set { Some(*flag) } else { None })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_from_struct() {
        let tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

        let flags = TcpFlags::flags_from_bits(tcp_flags);
        assert_eq!(flags, vec![TcpFlag::Syn, TcpFlag::Ack]);
    }

    #[test]
    fn test_flags_from_bits() {
        // Test no flags
        assert_eq!(TcpFlags::flags_from_bits(0x00), Vec::<TcpFlag>::new());

        // Test individual flags
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_FIN), vec![TcpFlag::Fin]);
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_SYN), vec![TcpFlag::Syn]);
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_RST), vec![TcpFlag::Rst]);
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_PSH), vec![TcpFlag::Psh]);
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_ACK), vec![TcpFlag::Ack]);
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_URG), vec![TcpFlag::Urg]);
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_ECE), vec![TcpFlag::Ece]);
        assert_eq!(TcpFlags::flags_from_bits(TCP_FLAG_CWR), vec![TcpFlag::Cwr]);

        // Test common flag combinations
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_SYN | TCP_FLAG_ACK), // SYN+ACK
            vec![TcpFlag::Syn, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_FIN | TCP_FLAG_ACK), // FIN+ACK
            vec![TcpFlag::Fin, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(TCP_FLAG_PSH | TCP_FLAG_ACK), // PSH+ACK
            vec![TcpFlag::Psh, TcpFlag::Ack]
        );

        // Test all flags
        assert_eq!(
            TcpFlags::flags_from_bits(0xFF),
            vec![
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
