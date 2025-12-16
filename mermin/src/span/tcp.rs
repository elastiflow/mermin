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

    /// Calculate latency between SYN and SYN+ACK packets
    pub fn handshake_latency_from_stats(syn_ns: u64, syn_ack_ns: u64) -> i64 {
        (syn_ack_ns - syn_ns) as i64
    }

    /// Calculate latency from duration sum (ns) and transaction counts
    pub fn transaction_latency_from_stats(sum: u64, count: u64) -> i64 {
        if count == 0 {
            return 0;
        }
        (sum / count) as i64
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
    use mermin_common::ConnectionState;
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
                tcp_syn_ns: 0,
                tcp_syn_ack_ns: 0,
                tcp_last_payload_fwd_ns: 0,
                tcp_last_payload_rev_ns: 0,
                tcp_txn_sum_ns: 0,
                tcp_txn_count: 0,
                tcp_jitter_avg_ns: 0,
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
                tcp_state: ConnectionState::Closed,
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
            tcp_syn_ns: 0,
            tcp_syn_ack_ns: 0,
            tcp_last_payload_fwd_ns: 0,
            tcp_last_payload_rev_ns: 0,
            tcp_txn_sum_ns: 0,
            tcp_txn_count: 0,
            tcp_jitter_avg_ns: 0,
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
            tcp_state: ConnectionState::Closed,
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
    fn test_handshake_latency_from_stats() {
        assert_eq!(
            TcpFlags::handshake_latency_from_stats(1 as u64, 2 as u64),
            1
        );
    }

    #[test]
    fn test_transaction_latency_from_stats() {
        assert_eq!(
            TcpFlags::transaction_latency_from_stats(8 as u64, 4 as u64),
            2
        );
        assert_eq!(
            TcpFlags::transaction_latency_from_stats(16 as u64, 0 as u64),
            0
        );
    }

    #[test]
    fn test_connection_state_from_packet() {
        // Helper to create FlowStats with specific TCP flags
        fn create_stats_with_flags(tcp_flags: u8) -> FlowStats {
            use mermin_common::IpVersion;
            use network_types::eth::EtherType;

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
                tcp_syn_ns: 0,
                tcp_syn_ack_ns: 0,
                tcp_last_payload_fwd_ns: 0,
                tcp_last_payload_rev_ns: 0,
                tcp_txn_sum_ns: 0,
                tcp_txn_count: 0,
                tcp_jitter_avg_ns: 0,
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

        // Test SYN only - connection initiation
        let stats = create_stats_with_flags(TCP_FLAG_SYN);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::SynSent)
        );

        // Test SYN+ACK - connection response
        let stats = create_stats_with_flags(TCP_FLAG_SYN | TCP_FLAG_ACK);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::SynReceived)
        );

        // Test ACK only - established connection
        let stats = create_stats_with_flags(TCP_FLAG_ACK);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::Established)
        );

        // Test PSH+ACK - established connection with data
        let stats = create_stats_with_flags(TCP_FLAG_PSH | TCP_FLAG_ACK);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::Established)
        );

        // Test FIN only - connection termination
        let stats = create_stats_with_flags(TCP_FLAG_FIN);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::FinWait1)
        );

        // Test FIN+ACK - graceful close
        let stats = create_stats_with_flags(TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::FinWait1)
        );

        // Test RST - connection reset
        let stats = create_stats_with_flags(TCP_FLAG_RST);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::Closed)
        );

        // Test RST+ACK - connection reset with ack
        let stats = create_stats_with_flags(TCP_FLAG_RST | TCP_FLAG_ACK);
        assert_eq!(
            ConnectionState::from_stats(&stats),
            Some(ConnectionState::Closed)
        );

        // Test no flags
        let stats = create_stats_with_flags(0);
        assert_eq!(ConnectionState::from_stats(&stats), None);

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

    // Helper function to create a packet with specific flags
    fn stats_with_flags(syn: bool, ack: bool, fin: bool, rst: bool) -> FlowStats {
        let mut stats = FlowStats {
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
            tcp_syn_ns: 0,
            tcp_syn_ack_ns: 0,
            tcp_last_payload_fwd_ns: 0,
            tcp_last_payload_rev_ns: 0,
            tcp_txn_sum_ns: 0,
            tcp_txn_count: 0,
            tcp_jitter_avg_ns: 0,
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
            tcp_flags: 0,
            forward_tcp_flags: 0,
            reverse_tcp_flags: 0,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
        };
        if syn {
            stats.tcp_flags |= TCP_FLAG_SYN;
        }
        if ack {
            stats.tcp_flags |= TCP_FLAG_ACK;
        }
        if fin {
            stats.tcp_flags |= TCP_FLAG_FIN;
        }
        if rst {
            stats.tcp_flags |= TCP_FLAG_RST;
        }
        stats
    }

    #[test]
    fn test_state_transition_normal_handshake() {
        // Test normal TCP 3-way handshake: SYN → SYN-ACK → ACK

        // Client sends SYN (forward direction)
        let syn_stats = stats_with_flags(true, false, false, false);
        let state = ConnectionState::from_stats(&syn_stats).unwrap();
        assert_eq!(state, ConnectionState::SynSent);

        // Server responds with SYN+ACK (reverse direction)
        let syn_ack_stats = stats_with_flags(true, true, false, false);
        let state = ConnectionState::next_state(state, &syn_ack_stats, false);
        assert_eq!(state, ConnectionState::SynReceived);

        // Client sends final ACK (forward direction)
        let ack_stats = stats_with_flags(false, true, false, false);
        let state = ConnectionState::next_state(state, &ack_stats, true);
        assert_eq!(state, ConnectionState::Established);
    }

    #[test]
    fn test_state_transition_normal_close() {
        // Test normal TCP close: FIN → FIN-ACK → ACK

        // Start from established
        let mut state = ConnectionState::Established;

        // Client sends FIN (forward direction)
        let fin_stats = stats_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_stats, true);
        assert_eq!(state, ConnectionState::FinWait1);

        // Server sends FIN+ACK (reverse direction)
        let fin_ack_stats = stats_with_flags(false, true, true, false);
        state = ConnectionState::next_state(state, &fin_ack_stats, false);
        assert_eq!(state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_graceful_close_sequence() {
        // Test graceful close where ACK and FIN are separate

        let mut state = ConnectionState::Established;

        // Client sends FIN (forward direction)
        let fin_stats = stats_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_stats, true);
        assert_eq!(state, ConnectionState::FinWait1);

        // Server sends ACK (reverse direction)
        let ack_stats = stats_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_stats, false);
        assert_eq!(state, ConnectionState::FinWait2);

        // Server sends FIN (reverse direction)
        let fin_stats = stats_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_stats, false);
        assert_eq!(state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_simultaneous_close() {
        // Test simultaneous close where both sides send FIN

        let mut state = ConnectionState::Established;

        // Client sends FIN (forward direction)
        let fin_stats = stats_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_stats, true);
        assert_eq!(state, ConnectionState::FinWait1);

        // Server also sends FIN before ACKing client's FIN (reverse direction)
        let fin_stats = stats_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_stats, false);
        assert_eq!(state, ConnectionState::Closing);

        // Server sends ACK (reverse direction)
        let ack_stats = stats_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_stats, false);
        assert_eq!(state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_passive_close() {
        // Test passive close (server closes first, client in CLOSE-WAIT)

        let mut state = ConnectionState::Established;

        // Server sends FIN (reverse direction)
        let fin_stats = stats_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_stats, false);
        assert_eq!(state, ConnectionState::CloseWait);

        // Client sends FIN (forward direction)
        let fin_stats = stats_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_stats, true);
        assert_eq!(state, ConnectionState::LastAck);

        // Server sends ACK (reverse direction)
        let ack_stats = stats_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_stats, false);
        assert_eq!(state, ConnectionState::Closed);
    }

    #[test]
    fn test_state_transition_rst_from_any_state() {
        // Test that RST transitions to CLOSED from any state

        let rst_stats = stats_with_flags(false, false, false, true);

        let states = [
            ConnectionState::SynSent,
            ConnectionState::SynReceived,
            ConnectionState::Established,
            ConnectionState::FinWait1,
            ConnectionState::FinWait2,
            ConnectionState::CloseWait,
            ConnectionState::Closing,
            ConnectionState::LastAck,
            ConnectionState::TimeWait,
        ];

        for state in states {
            let new_state = ConnectionState::next_state(state, &rst_stats, true);
            assert_eq!(
                new_state,
                ConnectionState::Closed,
                "RST should transition {:?} to CLOSED",
                state
            );
        }
    }

    #[test]
    fn test_state_transition_simultaneous_open() {
        // Test simultaneous open where both sides send SYN

        let mut state = ConnectionState::SynSent;

        // Receive SYN from the other side (both sent SYN)
        let syn_stats = stats_with_flags(true, false, false, false);
        state = ConnectionState::next_state(state, &syn_stats, false);
        assert_eq!(state, ConnectionState::SynReceived);

        // Both sides ACK each other's SYN
        let ack_stats = stats_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_stats, true);
        assert_eq!(state, ConnectionState::Established);
    }

    #[test]
    fn test_state_transition_data_transfer() {
        // Test that data packets don't change ESTABLISHED state

        let state = ConnectionState::Established;

        // Data packet with ACK (forward)
        let data_stats = stats_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &data_stats, true);
        assert_eq!(new_state, ConnectionState::Established);

        // Data packet with PSH+ACK (reverse)
        let mut psh_ack_stats = stats_with_flags(false, true, false, false);
        psh_ack_stats.tcp_flags |= TCP_FLAG_PSH;
        let new_state = ConnectionState::next_state(new_state, &psh_ack_stats, false);
        assert_eq!(new_state, ConnectionState::Established);
    }

    #[test]
    fn test_state_transition_stay_in_state() {
        // Test that states stay in same state when receiving unexpected packets

        // FIN-WAIT-1 receiving data packets stays in FIN-WAIT-1
        let state = ConnectionState::FinWait1;
        let data_stats = stats_with_flags(false, false, false, false);
        let new_state = ConnectionState::next_state(state, &data_stats, true);
        assert_eq!(new_state, ConnectionState::FinWait1);

        // FIN-WAIT-2 receiving data packets stays in FIN-WAIT-2
        let state = ConnectionState::FinWait2;
        let data_stats = stats_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &data_stats, true);
        assert_eq!(new_state, ConnectionState::FinWait2);

        // CLOSE-WAIT stays until local application closes (forward FIN)
        let state = ConnectionState::CloseWait;
        let ack_stats = stats_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &ack_stats, false);
        assert_eq!(new_state, ConnectionState::CloseWait);
    }

    #[test]
    fn test_state_transition_time_wait_stays() {
        // TIME-WAIT should stay in TIME-WAIT (waiting for 2MSL timeout)

        let state = ConnectionState::TimeWait;

        // Any packet should keep it in TIME-WAIT
        let ack_stats = stats_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &ack_stats, true);
        assert_eq!(new_state, ConnectionState::TimeWait);

        let data_stats = stats_with_flags(false, false, false, false);
        let new_state = ConnectionState::next_state(state, &data_stats, false);
        assert_eq!(new_state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_closed_to_syn_sent() {
        // CLOSED can transition to SYN-SENT on receiving SYN

        let state = ConnectionState::Closed;

        let syn_stats = stats_with_flags(true, false, false, false);
        let new_state = ConnectionState::next_state(state, &syn_stats, true);
        assert_eq!(new_state, ConnectionState::SynSent);
    }
}
