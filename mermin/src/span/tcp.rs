use mermin_common::FlowStats;
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
    /// Create TcpFlags from a packet
    pub fn from_stats(stats: &FlowStats) -> Self {
        Self {
            flags: [
                stats.fin(),
                stats.syn(),
                stats.rst(),
                stats.psh(),
                stats.ack(),
                stats.urg(),
                stats.ece(),
                stats.cwr(),
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
/// This implementation tracks TCP connection states by observing packet flags and
/// state transitions. Note that as a passive observer, we may not see all packets
/// (e.g., LISTEN state), so some transitions are inferred from available information.
///
/// States match OpenTelemetry semantic conventions:
/// https://opentelemetry.io/docs/specs/semconv/attributes/network/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Convert the raw eBPF u8 state into the strongly typed Enum.
    pub fn from_ebpf_u8(state: u8) -> Self {
        // Use the constants we defined in FlowStats
        match state {
            1 => ConnectionState::Closed, // Map LISTEN to Closed or add Listen variant
            2 => ConnectionState::SynSent,
            3 => ConnectionState::SynReceived,
            4 => ConnectionState::Established,
            5 => ConnectionState::FinWait1,
            6 => ConnectionState::FinWait2,
            7 => ConnectionState::CloseWait,
            8 => ConnectionState::Closing,
            9 => ConnectionState::LastAck,
            10 => ConnectionState::TimeWait,
            _ => ConnectionState::Closed, // Default/Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use network_types::ip::IpProto;

    use super::*;

    #[test]
    fn test_tcp_flags_from_packet() {
        // Helper to create FlowStats with specific TCP flags
        fn create_stats_with_flags(tcp_flags: u8) -> FlowStats {
            use mermin_common::IpVersion;
            use network_types::{eth::EtherType, ip::IpProto};

            FlowStats {
                direction: mermin_common::Direction::Egress,
                ether_type: EtherType::Ipv4,
                ip_version: IpVersion::V4,
                protocol: IpProto::Tcp,
                src_ip: [0; 16],
                dst_ip: [0; 16],
                src_port: 0,
                dst_port: 0,
                packets: 0,
                bytes: 0,
                reverse_packets: 0,
                reverse_bytes: 0,
                src_mac: [0; 6],
                ifindex: 0,
                ip_flow_label: 0,
                first_seen_ns: 0,
                last_seen_ns: 0,
                ip_dscp: 0,
                ip_ecn: 0,
                ip_ttl: 0,
                reverse_ip_dscp: 0,
                reverse_ip_ecn: 0,
                reverse_ip_ttl: 0,
                reverse_ip_flow_label: 0,
                tcp_flags,
                tcp_state: 0,
                forward_tcp_flags: tcp_flags,
                reverse_tcp_flags: 0,
                icmp_type: 0,
                icmp_code: 0,
                reverse_icmp_type: 0,
                reverse_icmp_code: 0,
                forward_metadata_seen: 1,
                reverse_metadata_seen: 0,
            }
        }

        // Test no flags
        let stats = create_stats_with_flags(0);
        let flags = TcpFlags::from_stats(&stats);
        assert_eq!(flags.active_flags(), Vec::<TcpFlag>::new());

        // Test SYN flag only
        let stats = create_stats_with_flags(TCP_FLAG_SYN);
        let flags = TcpFlags::from_stats(&stats);
        assert_eq!(flags.active_flags(), vec![TcpFlag::Syn]);

        // Test SYN+ACK
        let stats = create_stats_with_flags(TCP_FLAG_SYN | TCP_FLAG_ACK);
        let flags = TcpFlags::from_stats(&stats);
        assert_eq!(flags.active_flags(), vec![TcpFlag::Syn, TcpFlag::Ack]);

        // Test FIN+ACK
        let stats = create_stats_with_flags(TCP_FLAG_FIN | TCP_FLAG_ACK);
        let flags = TcpFlags::from_stats(&stats);
        assert_eq!(flags.active_flags(), vec![TcpFlag::Fin, TcpFlag::Ack]);

        // Test all flags
        let stats = create_stats_with_flags(0xFF);
        let flags = TcpFlags::from_stats(&stats);
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
        use mermin_common::IpVersion;
        use network_types::eth::EtherType;

        let stats = FlowStats {
            direction: mermin_common::Direction::Egress,
            ether_type: EtherType::Ipv4,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            packets: 0,
            bytes: 0,
            reverse_packets: 0,
            reverse_bytes: 0,
            src_mac: [0; 6],
            ifindex: 0,
            ip_flow_label: 0,
            first_seen_ns: 0,
            last_seen_ns: 0,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 0,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            reverse_ip_flow_label: 0,
            tcp_flags: 0x12, // SYN+ACK
            tcp_state: 0,
            forward_tcp_flags: 0x12,
            reverse_tcp_flags: 0x00,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
        };
        let from_packet = TcpFlags::from_stats(&stats).active_flags();
        let from_bits = TcpFlags::flags_from_bits(0x12);
        assert_eq!(from_packet, from_bits);
    }

    #[test]
    fn test_as_str_conversion() {
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

    #[test]
    fn test_ebpf_state_mapping() {
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_CLOSED),
            ConnectionState::Closed
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_LISTEN),
            ConnectionState::Closed
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_SYN_SENT),
            ConnectionState::SynSent
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_SYN_RECEIVED),
            ConnectionState::SynReceived
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_ESTABLISHED),
            ConnectionState::Established
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_FIN_WAIT_1),
            ConnectionState::FinWait1
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_FIN_WAIT_2),
            ConnectionState::FinWait2
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_CLOSE_WAIT),
            ConnectionState::CloseWait
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_CLOSING),
            ConnectionState::Closing
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_LAST_ACK),
            ConnectionState::LastAck
        );
        assert_eq!(
            ConnectionState::from_ebpf_u8(FlowStats::TCP_STATE_TIME_WAIT),
            ConnectionState::TimeWait
        );

        assert_eq!(ConnectionState::from_ebpf_u8(99), ConnectionState::Closed);
    }
}
