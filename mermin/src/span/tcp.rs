use mermin_common::PacketMeta;
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

#[allow(dead_code)]
impl TcpFlags {
    /// Create TcpFlags from a packet
    pub fn from_packet(packet: &PacketMeta) -> Self {
        Self {
            flags: [
                packet.fin(),
                packet.syn(),
                packet.rst(),
                packet.psh(),
                packet.ack(),
                packet.urg(),
                packet.ece(),
                packet.cwr(),
            ],
        }
    }

    /// Get only the flags that are set
    pub fn active_flags(&self) -> Vec<TcpFlag> {
        Self::active_flags_from_array(&self.flags)
    }

    /// Convert bit flags (u8) to a vector of active TcpFlag enum variants
    pub fn flags_from_bits(bits: u8) -> Vec<TcpFlag> {
        Self::active_flags_from_array(&Self::bits_to_array(bits))
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

/// TCP connection state based on RFC 9293 section 3.3.2:
/// https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
///
/// Note that we can only infer certain states from packet flags alone.
/// Full TCP state machine tracking would require following the entire connection lifecycle.
///
/// States match OpenTelemetry semantic conventions:
/// https://opentelemetry.io/docs/specs/semconv/attributes/network/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Some states will be used in future when tracking state transitions
pub enum ConnectionState {
    /// No connection state at all
    Closed,
    /// Waiting for a matching connection request after having sent a connection request
    SynSent,
    /// Waiting for a confirming connection request acknowledgment after having both received and sent a connection request
    SynReceived,
    /// An open connection, data received can be delivered to the user. The normal state for the data transfer phase
    Established,
    /// Waiting for a connection termination request from the remote TCP peer, or an acknowledgment of the connection termination request previously sent
    FinWait1,
    /// Waiting for a connection termination request from the remote TCP peer
    FinWait2,
    /// Waiting for a connection termination request from the local user
    CloseWait,
    /// Waiting for a connection termination request acknowledgment from the remote TCP peer
    Closing,
    /// Waiting for an acknowledgment of the connection termination request previously sent to the remote TCP peer
    LastAck,
    /// Waiting for enough time to pass to be sure the remote TCP peer received the acknowledgment of its connection termination request
    TimeWait,
}

impl ConnectionState {
    /// Convert the connection state to a string representation matching
    /// OpenTelemetry semantic conventions
    pub const fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Closed => "closed",
            ConnectionState::SynSent => "syn_sent",
            ConnectionState::SynReceived => "syn_received",
            ConnectionState::Established => "established",
            ConnectionState::FinWait1 => "fin_wait_1",
            ConnectionState::FinWait2 => "fin_wait_2",
            ConnectionState::CloseWait => "close_wait",
            ConnectionState::Closing => "closing",
            ConnectionState::LastAck => "last_ack",
            ConnectionState::TimeWait => "time_wait",
        }
    }

    /// Initialize connection state from the first packet
    ///
    /// This method infers the initial connection state from TCP flags according to RFC 9293.
    /// Note: This provides a best-effort state determination from a single packet's flags.
    pub fn from_packet(packet: &PacketMeta) -> Option<Self> {
        // Check flag combinations in order of specificity
        match (packet.syn(), packet.ack(), packet.fin(), packet.rst()) {
            // RST flag indicates connection closed/reset
            (_, _, _, true) => Some(ConnectionState::Closed),

            // SYN only - connection initiation (SYN-SENT state)
            (true, false, false, false) => Some(ConnectionState::SynSent),

            // SYN+ACK - connection response (SYN-RECEIVED state)
            (true, true, false, false) => Some(ConnectionState::SynReceived),

            // FIN+ACK - connection termination (FIN-WAIT-1 or CLOSING)
            // Note: We can't distinguish between FIN-WAIT-1 and CLOSING from flags alone
            (false, true, true, false) => Some(ConnectionState::FinWait1),

            // ACK flag - established connection (ESTABLISHED state)
            // This includes PSH+ACK for data transfer
            (false, true, false, false) => Some(ConnectionState::Established),

            // FIN only - uncommon but could indicate FIN-WAIT-1
            (false, false, true, false) => Some(ConnectionState::FinWait1),

            // No meaningful flags or unusual combinations
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use network_types::ip::IpProto;

    use super::*;

    #[test]
    fn test_tcp_flags_from_packet() {
        let mut packet = PacketMeta::default();
        packet.proto = IpProto::Tcp;

        // Test no flags
        packet.tcp_flags = 0;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(flags.active_flags(), Vec::<TcpFlag>::new());

        // Test SYN flag only
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(flags.active_flags(), vec![TcpFlag::Syn]);

        // Test SYN+ACK
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN | PacketMeta::TCP_FLAG_ACK;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(flags.active_flags(), vec![TcpFlag::Syn, TcpFlag::Ack]);

        // Test FIN+ACK
        packet.tcp_flags = PacketMeta::TCP_FLAG_FIN | PacketMeta::TCP_FLAG_ACK;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(flags.active_flags(), vec![TcpFlag::Fin, TcpFlag::Ack]);

        // Test all flags
        packet.tcp_flags = 0xFF;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(
            flags.active_flags(),
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
    fn test_flags_from_bits() {
        // Test no flags
        assert_eq!(TcpFlags::flags_from_bits(0x00), Vec::<TcpFlag>::new());

        // Test individual flags
        assert_eq!(TcpFlags::flags_from_bits(0x01), vec![TcpFlag::Fin]);
        assert_eq!(TcpFlags::flags_from_bits(0x02), vec![TcpFlag::Syn]);
        assert_eq!(TcpFlags::flags_from_bits(0x04), vec![TcpFlag::Rst]);
        assert_eq!(TcpFlags::flags_from_bits(0x08), vec![TcpFlag::Psh]);
        assert_eq!(TcpFlags::flags_from_bits(0x10), vec![TcpFlag::Ack]);
        assert_eq!(TcpFlags::flags_from_bits(0x20), vec![TcpFlag::Urg]);
        assert_eq!(TcpFlags::flags_from_bits(0x40), vec![TcpFlag::Ece]);
        assert_eq!(TcpFlags::flags_from_bits(0x80), vec![TcpFlag::Cwr]);

        // Test common flag combinations
        assert_eq!(
            TcpFlags::flags_from_bits(0x02 | 0x10), // SYN+ACK
            vec![TcpFlag::Syn, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(0x01 | 0x10), // FIN+ACK
            vec![TcpFlag::Fin, TcpFlag::Ack]
        );
        assert_eq!(
            TcpFlags::flags_from_bits(0x08 | 0x10), // PSH+ACK
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

        // Test that flags_from_bits and from_packet produce the same results
        let mut packet = PacketMeta::default();
        packet.tcp_flags = 0x12; // SYN+ACK
        let from_packet = TcpFlags::from_packet(&packet).active_flags();
        let from_bits = TcpFlags::flags_from_bits(0x12);
        assert_eq!(from_packet, from_bits);
    }

    #[test]
    fn test_connection_state_from_packet() {
        let mut packet = PacketMeta::default();
        packet.proto = IpProto::Tcp;

        // Test SYN only - connection initiation
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::SynSent)
        );

        // Test SYN+ACK - connection response
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN | PacketMeta::TCP_FLAG_ACK;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::SynReceived)
        );

        // Test ACK only - established connection
        packet.tcp_flags = PacketMeta::TCP_FLAG_ACK;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::Established)
        );

        // Test PSH+ACK - established connection with data
        packet.tcp_flags = PacketMeta::TCP_FLAG_PSH | PacketMeta::TCP_FLAG_ACK;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::Established)
        );

        // Test FIN only - connection termination
        packet.tcp_flags = PacketMeta::TCP_FLAG_FIN;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::FinWait1)
        );

        // Test FIN+ACK - graceful close
        packet.tcp_flags = PacketMeta::TCP_FLAG_FIN | PacketMeta::TCP_FLAG_ACK;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::FinWait1)
        );

        // Test RST - connection reset
        packet.tcp_flags = PacketMeta::TCP_FLAG_RST;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::Closed)
        );

        // Test RST+ACK - connection reset with ack
        packet.tcp_flags = PacketMeta::TCP_FLAG_RST | PacketMeta::TCP_FLAG_ACK;
        assert_eq!(
            ConnectionState::from_packet(&packet),
            Some(ConnectionState::Closed)
        );

        // Test no flags
        packet.tcp_flags = 0;
        assert_eq!(ConnectionState::from_packet(&packet), None);

        // Test as_str() conversion
        assert_eq!(ConnectionState::SynSent.as_str(), "syn_sent");
        assert_eq!(ConnectionState::SynReceived.as_str(), "syn_received");
        assert_eq!(ConnectionState::Established.as_str(), "established");
        assert_eq!(ConnectionState::FinWait1.as_str(), "fin_wait_1");
        assert_eq!(ConnectionState::FinWait2.as_str(), "fin_wait_2");
        assert_eq!(ConnectionState::CloseWait.as_str(), "close_wait");
        assert_eq!(ConnectionState::Closing.as_str(), "closing");
        assert_eq!(ConnectionState::LastAck.as_str(), "last_ack");
        assert_eq!(ConnectionState::TimeWait.as_str(), "time_wait");
        assert_eq!(ConnectionState::Closed.as_str(), "closed");
    }
}
