use mermin_common::PacketMeta;

/// TCP flag names in order (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
pub const TCP_FLAG_NAMES: [&str; 8] = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"];

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

    /// Get flags as a fixed-size array of booleans
    pub fn as_array(&self) -> [bool; 8] {
        self.flags
    }

    /// Get only the names of flags that are set
    pub fn active_flags(&self) -> Vec<String> {
        self.flags
            .iter()
            .zip(TCP_FLAG_NAMES.iter())
            .filter_map(|(is_set, name)| {
                if *is_set {
                    Some(String::from(*name))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all flag names with their states (for consistent 8-element output)
    /// Returns tuples of (flag_name, is_set)
    pub fn all_flags_with_state(&self) -> Vec<(String, bool)> {
        TCP_FLAG_NAMES
            .iter()
            .zip(self.flags.iter())
            .map(|(name, is_set)| (String::from(*name), *is_set))
            .collect()
    }

    /// Get a specific flag by index
    pub fn get(&self, index: usize) -> Option<bool> {
        self.flags.get(index).copied()
    }

    /// Check if any flags are set
    pub fn any_set(&self) -> bool {
        self.flags.iter().any(|&f| f)
    }

    /// Check if no flags are set
    pub fn none_set(&self) -> bool {
        !self.any_set()
    }

    /// Count the number of set flags
    pub fn count_set(&self) -> usize {
        self.flags.iter().filter(|&&f| f).count()
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
        assert_eq!(flags.as_array(), [false; 8]);
        assert_eq!(flags.active_flags(), Vec::<String>::new());
        assert!(flags.none_set());
        assert_eq!(flags.count_set(), 0);

        // Test SYN flag only
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(flags.as_array()[1], true); // SYN is at index 1
        assert_eq!(flags.active_flags(), vec!["syn"]);
        assert!(flags.any_set());
        assert_eq!(flags.count_set(), 1);

        // Test SYN+ACK
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN | PacketMeta::TCP_FLAG_ACK;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(flags.active_flags(), vec!["syn", "ack"]);
        assert_eq!(flags.count_set(), 2);

        // Test all flags
        packet.tcp_flags = 0xFF;
        let flags = TcpFlags::from_packet(&packet);
        assert_eq!(flags.as_array(), [true; 8]);
        assert_eq!(
            flags.active_flags(),
            vec!["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"]
        );
        assert_eq!(flags.count_set(), 8);

        // Test all_flags_with_state
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN | PacketMeta::TCP_FLAG_ACK;
        let flags = TcpFlags::from_packet(&packet);
        let all_flags = flags.all_flags_with_state();
        assert_eq!(all_flags.len(), 8);
        assert_eq!(all_flags[0], ("fin".to_string(), false));
        assert_eq!(all_flags[1], ("syn".to_string(), true));
        assert_eq!(all_flags[4], ("ack".to_string(), true));
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
