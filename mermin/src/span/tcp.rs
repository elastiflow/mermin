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

    /// Initialize connection state from the first packet
    ///
    /// This method infers the initial connection state from TCP flags according to RFC 9293.
    /// Used when we first observe a connection (no prior state).
    pub fn from_packet(packet: &PacketMeta) -> Option<Self> {
        // Check flag combinations in order of specificity
        match (packet.syn(), packet.ack(), packet.fin(), packet.rst()) {
            // RST flag indicates connection closed/reset
            (_, _, _, true) => Some(ConnectionState::Closed),

            // SYN only - connection initiation (SYN-SENT state)
            (true, false, false, false) => Some(ConnectionState::SynSent),

            // SYN+ACK - connection response (SYN-RECEIVED state)
            (true, true, false, false) => Some(ConnectionState::SynReceived),

            // FIN+ACK - connection termination
            // Without prior state, we assume this is FIN-WAIT-1
            (false, true, true, false) => Some(ConnectionState::FinWait1),

            // FIN only - connection termination initiated
            (false, false, true, false) => Some(ConnectionState::FinWait1),

            // ACK flag - established connection (ESTABLISHED state)
            // This includes PSH+ACK for data transfer
            (false, true, false, false) => Some(ConnectionState::Established),

            // No meaningful flags or unusual combinations
            _ => None,
        }
    }

    /// Update connection state based on current state and new packet
    ///
    /// Implements TCP state machine transitions according to RFC 9293 Figure 5.
    /// This tracks state changes as we observe packets in the flow.
    ///
    /// Note: As a passive observer, we may miss some packets, so this is best-effort.
    /// We track both forward and reverse direction packets in the same flow.
    pub fn next_state(current: Self, packet: &PacketMeta, is_forward: bool) -> Self {
        let syn = packet.syn();
        let ack = packet.ack();
        let fin = packet.fin();
        let rst = packet.rst();

        // RST can transition from any state to CLOSED (RFC 9293 Note 3)
        if rst {
            return ConnectionState::Closed;
        }

        match current {
            // CLOSED state - should not normally receive packets, but if we do:
            ConnectionState::Closed => {
                // A SYN can reopen the connection
                if syn && !ack {
                    ConnectionState::SynSent
                } else {
                    ConnectionState::Closed
                }
            }

            // SYN-SENT: Waiting for matching SYN
            ConnectionState::SynSent => {
                if syn && ack {
                    // Received SYN+ACK → move to SYN-RECEIVED
                    ConnectionState::SynReceived
                } else if syn {
                    // Simultaneous open: both sides send SYN
                    ConnectionState::SynReceived
                } else {
                    // Stay in SYN-SENT
                    current
                }
            }

            // SYN-RECEIVED: Waiting for ACK of our SYN
            ConnectionState::SynReceived => {
                if ack && !syn && !fin {
                    // Received final ACK of 3-way handshake → ESTABLISHED
                    ConnectionState::Established
                } else if fin {
                    // FIN received during handshake → FIN-WAIT-1
                    ConnectionState::FinWait1
                } else {
                    // Stay in SYN-RECEIVED
                    current
                }
            }

            // ESTABLISHED: Connection is open
            ConnectionState::Established => {
                if fin {
                    // FIN received or sent
                    if is_forward {
                        // We (source) are sending FIN → FIN-WAIT-1
                        ConnectionState::FinWait1
                    } else {
                        // Remote is sending FIN → CLOSE-WAIT
                        ConnectionState::CloseWait
                    }
                } else {
                    // Stay ESTABLISHED
                    current
                }
            }

            // FIN-WAIT-1: Waiting for FIN or ACK of our FIN
            ConnectionState::FinWait1 => {
                if fin && ack {
                    // Received FIN+ACK (simultaneous close or ACK of our FIN with their FIN)
                    // Per RFC 9293 Note 2: can go directly to TIME-WAIT
                    ConnectionState::TimeWait
                } else if ack && !fin {
                    // Received ACK of our FIN → FIN-WAIT-2
                    ConnectionState::FinWait2
                } else if fin && !ack {
                    // Received FIN (simultaneous close, no ACK yet) → CLOSING
                    ConnectionState::Closing
                } else {
                    // Stay in FIN-WAIT-1
                    current
                }
            }

            // FIN-WAIT-2: Waiting for FIN from remote
            ConnectionState::FinWait2 => {
                if fin {
                    // Received FIN from remote → TIME-WAIT
                    ConnectionState::TimeWait
                } else {
                    // Stay in FIN-WAIT-2
                    current
                }
            }

            // CLOSE-WAIT: Waiting for local application to close
            ConnectionState::CloseWait => {
                if fin && is_forward {
                    // Local side sends FIN → LAST-ACK
                    ConnectionState::LastAck
                } else {
                    // Stay in CLOSE-WAIT
                    current
                }
            }

            // CLOSING: Waiting for ACK of our FIN (simultaneous close)
            ConnectionState::Closing => {
                if ack {
                    // Received ACK of our FIN → TIME-WAIT
                    ConnectionState::TimeWait
                } else {
                    // Stay in CLOSING
                    current
                }
            }

            // LAST-ACK: Waiting for ACK of our FIN
            ConnectionState::LastAck => {
                if ack {
                    // Received ACK → CLOSED
                    ConnectionState::Closed
                } else {
                    // Stay in LAST-ACK
                    current
                }
            }

            // TIME-WAIT: Waiting for 2MSL timeout
            // In practice, we'll timeout this state via idle timeout
            ConnectionState::TimeWait => {
                // Stay in TIME-WAIT until timeout
                // Note: In real TCP, this would timeout after 2*MSL
                current
            }
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

    // Helper function to create a packet with specific flags
    fn packet_with_flags(syn: bool, ack: bool, fin: bool, rst: bool) -> PacketMeta {
        let mut packet = PacketMeta::default();
        packet.proto = IpProto::Tcp;
        packet.tcp_flags = 0;
        if syn {
            packet.tcp_flags |= PacketMeta::TCP_FLAG_SYN;
        }
        if ack {
            packet.tcp_flags |= PacketMeta::TCP_FLAG_ACK;
        }
        if fin {
            packet.tcp_flags |= PacketMeta::TCP_FLAG_FIN;
        }
        if rst {
            packet.tcp_flags |= PacketMeta::TCP_FLAG_RST;
        }
        packet
    }

    #[test]
    fn test_state_transition_normal_handshake() {
        // Test normal TCP 3-way handshake: SYN → SYN-ACK → ACK

        // Client sends SYN (forward direction)
        let syn_packet = packet_with_flags(true, false, false, false);
        let state = ConnectionState::from_packet(&syn_packet).unwrap();
        assert_eq!(state, ConnectionState::SynSent);

        // Server responds with SYN+ACK (reverse direction)
        let syn_ack_packet = packet_with_flags(true, true, false, false);
        let state = ConnectionState::next_state(state, &syn_ack_packet, false);
        assert_eq!(state, ConnectionState::SynReceived);

        // Client sends final ACK (forward direction)
        let ack_packet = packet_with_flags(false, true, false, false);
        let state = ConnectionState::next_state(state, &ack_packet, true);
        assert_eq!(state, ConnectionState::Established);
    }

    #[test]
    fn test_state_transition_normal_close() {
        // Test normal TCP close: FIN → FIN-ACK → ACK

        // Start from established
        let mut state = ConnectionState::Established;

        // Client sends FIN (forward direction)
        let fin_packet = packet_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_packet, true);
        assert_eq!(state, ConnectionState::FinWait1);

        // Server sends FIN+ACK (reverse direction)
        let fin_ack_packet = packet_with_flags(false, true, true, false);
        state = ConnectionState::next_state(state, &fin_ack_packet, false);
        assert_eq!(state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_graceful_close_sequence() {
        // Test graceful close where ACK and FIN are separate

        let mut state = ConnectionState::Established;

        // Client sends FIN (forward direction)
        let fin_packet = packet_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_packet, true);
        assert_eq!(state, ConnectionState::FinWait1);

        // Server sends ACK (reverse direction)
        let ack_packet = packet_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_packet, false);
        assert_eq!(state, ConnectionState::FinWait2);

        // Server sends FIN (reverse direction)
        let fin_packet = packet_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_packet, false);
        assert_eq!(state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_simultaneous_close() {
        // Test simultaneous close where both sides send FIN

        let mut state = ConnectionState::Established;

        // Client sends FIN (forward direction)
        let fin_packet = packet_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_packet, true);
        assert_eq!(state, ConnectionState::FinWait1);

        // Server also sends FIN before ACKing client's FIN (reverse direction)
        let fin_packet = packet_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_packet, false);
        assert_eq!(state, ConnectionState::Closing);

        // Server sends ACK (reverse direction)
        let ack_packet = packet_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_packet, false);
        assert_eq!(state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_passive_close() {
        // Test passive close (server closes first, client in CLOSE-WAIT)

        let mut state = ConnectionState::Established;

        // Server sends FIN (reverse direction)
        let fin_packet = packet_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_packet, false);
        assert_eq!(state, ConnectionState::CloseWait);

        // Client sends FIN (forward direction)
        let fin_packet = packet_with_flags(false, false, true, false);
        state = ConnectionState::next_state(state, &fin_packet, true);
        assert_eq!(state, ConnectionState::LastAck);

        // Server sends ACK (reverse direction)
        let ack_packet = packet_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_packet, false);
        assert_eq!(state, ConnectionState::Closed);
    }

    #[test]
    fn test_state_transition_rst_from_any_state() {
        // Test that RST transitions to CLOSED from any state

        let rst_packet = packet_with_flags(false, false, false, true);

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
            let new_state = ConnectionState::next_state(state, &rst_packet, true);
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
        let syn_packet = packet_with_flags(true, false, false, false);
        state = ConnectionState::next_state(state, &syn_packet, false);
        assert_eq!(state, ConnectionState::SynReceived);

        // Both sides ACK each other's SYN
        let ack_packet = packet_with_flags(false, true, false, false);
        state = ConnectionState::next_state(state, &ack_packet, true);
        assert_eq!(state, ConnectionState::Established);
    }

    #[test]
    fn test_state_transition_data_transfer() {
        // Test that data packets don't change ESTABLISHED state

        let state = ConnectionState::Established;

        // Data packet with ACK (forward)
        let data_packet = packet_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &data_packet, true);
        assert_eq!(new_state, ConnectionState::Established);

        // Data packet with PSH+ACK (reverse)
        let mut psh_ack_packet = packet_with_flags(false, true, false, false);
        psh_ack_packet.tcp_flags |= PacketMeta::TCP_FLAG_PSH;
        let new_state = ConnectionState::next_state(new_state, &psh_ack_packet, false);
        assert_eq!(new_state, ConnectionState::Established);
    }

    #[test]
    fn test_state_transition_stay_in_state() {
        // Test that states stay in same state when receiving unexpected packets

        // FIN-WAIT-1 receiving data packets stays in FIN-WAIT-1
        let state = ConnectionState::FinWait1;
        let data_packet = packet_with_flags(false, false, false, false);
        let new_state = ConnectionState::next_state(state, &data_packet, true);
        assert_eq!(new_state, ConnectionState::FinWait1);

        // FIN-WAIT-2 receiving data packets stays in FIN-WAIT-2
        let state = ConnectionState::FinWait2;
        let data_packet = packet_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &data_packet, true);
        assert_eq!(new_state, ConnectionState::FinWait2);

        // CLOSE-WAIT stays until local application closes (forward FIN)
        let state = ConnectionState::CloseWait;
        let ack_packet = packet_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &ack_packet, false);
        assert_eq!(new_state, ConnectionState::CloseWait);
    }

    #[test]
    fn test_state_transition_time_wait_stays() {
        // TIME-WAIT should stay in TIME-WAIT (waiting for 2MSL timeout)

        let state = ConnectionState::TimeWait;

        // Any packet should keep it in TIME-WAIT
        let ack_packet = packet_with_flags(false, true, false, false);
        let new_state = ConnectionState::next_state(state, &ack_packet, true);
        assert_eq!(new_state, ConnectionState::TimeWait);

        let data_packet = packet_with_flags(false, false, false, false);
        let new_state = ConnectionState::next_state(state, &data_packet, false);
        assert_eq!(new_state, ConnectionState::TimeWait);
    }

    #[test]
    fn test_state_transition_closed_to_syn_sent() {
        // CLOSED can transition to SYN-SENT on receiving SYN

        let state = ConnectionState::Closed;

        let syn_packet = packet_with_flags(true, false, false, false);
        let new_state = ConnectionState::next_state(state, &syn_packet, true);
        assert_eq!(new_state, ConnectionState::SynSent);
    }
}
