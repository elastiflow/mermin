use core::mem;

/// ICMP header for IPv4, which is present after the IP header.
///
/// ICMP (Internet Control Message Protocol) is used for diagnostic and error
/// reporting purposes. Unlike TCP and UDP, ICMP does not use port numbers.
///
/// Basic ICMP Header Format:
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |     Type      |     Code      |          Checksum             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                             Data                              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// This struct represents the basic ICMP header as defined in RFC 792.
/// The ICMP header is 8 bytes long (including the 4-byte data field).
/// All fields are stored in network byte order (big-endian).
///
/// # Example
/// ```
/// use network_types::icmp::IcmpHdr;
///
/// let mut icmp_header = IcmpHdr {
///     _type: 8,  // Echo Request
///     code: 0,       // Code 0 for Echo Request
///     checksum: [0, 0],
///     data: [0, 0, 0, 0],
/// };
///
/// icmp_header.set_checksum(0x1234);
/// assert_eq!(icmp_header.checksum(), 0x1234);
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct IcmpHdr {
    /// ICMP message type (8 bits)
    pub _type: u8,
    /// ICMP message code (8 bits)
    pub code: u8,
    /// ICMP checksum in network byte order (big-endian)
    pub checksum: [u8; 2],
    /// ICMP data field - varies by message type (4 bytes)
    pub data: [u8; 4],
}

/// Common ICMP message types
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IcmpType {
    /// Echo Reply
    EchoReply = 0,
    /// Destination Unreachable
    DestinationUnreachable = 3,
    /// Redirect
    Redirect = 5,
    /// Echo Request (ping)
    EchoRequest = 8,
    /// Router Advertisement
    RouterAdvertisement = 9,
    /// Router Solicitation
    RouterSelection = 10,
    /// Time Exceeded
    TimeExceeded = 11,
    /// Parameter Problem
    ParameterProblem = 12,
    /// Timestamp Request
    Timestamp = 13,
    /// Timestamp Reply
    TimestampReply = 14,
    /// Information Request (deprecated)
    InformationRequest = 15,
    /// Information Reply (deprecated)
    InformationReply = 16,
    /// Address Mask Request
    AddressMaskRequest = 17,
    /// Address Mask Reply
    AddressMaskReply = 18,
    /// Photuris
    Photuris = 40,
    /// Extended Echo Request
    ExtendedEchoRequest = 42,
    /// Extended Echo Reply
    ExtendedEchoReply = 43,
    // ICMPv6 specific types (RFC 4443)
    /// Destination Unreachable (ICMPv6)
    Icmpv6DestinationUnreachable = 1,
    /// Packet Too Big (ICMPv6)
    PacketTooBig = 2,
    /// Time Exceeded (ICMPv6) - Note: different from IPv4 type 11
    // TODO: this is a problem because it overlaps with Icmp 3 Destionation Unreachable
    Icmpv6TimeExceeded = 3,
    /// Parameter Problem (ICMPv6) - Note: different from IPv4 type 12
    Icmpv6ParameterProblem = 4,
    /// Echo Request (ICMPv6)
    Icmpv6EchoRequest = 128,
    /// Echo Reply (ICMPv6)
    Icmpv6EchoReply = 129,
    /// Multicast Listener Discovery (MLD) Query (ICMPv6)
    MldQuery = 130,
    /// Multicast Listener Discovery (MLD) Report (ICMPv6)
    MldReport = 131,
    /// Multicast Listener Discovery (MLD) Done (ICMPv6)
    MldDone = 132,
    /// Router Solicitation (ICMPv6)
    Icmpv6RouterSolicitation = 133,
    /// Router Advertisement (ICMPv6)
    Icmpv6RouterAdvertisement = 134,
    /// Neighbor Solicitation (ICMPv6)
    NeighborSolicitation = 135,
    /// Neighbor Advertisement (ICMPv6)
    NeighborAdvertisement = 136,
    /// Redirect Message (ICMPv6)
    Icmpv6Redirect = 137,
    /// Router Renumbering (ICMPv6)
    RouterRenumbering = 138,
    /// ICMP Node Information Query (ICMPv6)
    NodeInformationQuery = 139,
    /// ICMP Node Information Response (ICMPv6)
    NodeInformationResponse = 140,
    /// Inverse Neighbor Discovery Solicitation (ICMPv6)
    InverseNeighborDiscoverySolicitation = 141,
    /// Inverse Neighbor Discovery Advertisement (ICMPv6)
    InverseNeighborDiscoveryAdvertisement = 142,
    /// MLDv2 Multicast Listener Report (ICMPv6)
    Mldv2MulticastListenerReport = 143,
    /// Home Agent Address Discovery Request (ICMPv6)
    HomeAgentAddressDiscoveryRequest = 144,
    /// Home Agent Address Discovery Reply (ICMPv6)
    HomeAgentAddressDiscoveryReply = 145,
    /// Mobile Prefix Solicitation (ICMPv6)
    MobilePrefixSolicitation = 146,
    /// Mobile Prefix Advertisement (ICMPv6)
    MobilePrefixAdvertisement = 147,
    /// Certification Path Solicitation (ICMPv6)
    CertificationPathSolicitation = 148,
    /// Certification Path Advertisement (ICMPv6)
    CertificationPathAdvertisement = 149,
    /// ICMP messages utilized by experimental mobility protocols (ICMPv6)
    ExperimentalMobilityProtocols = 150,
    /// Multicast Router Advertisement (ICMPv6)
    MulticastRouterAdvertisement = 151,
    /// Multicast Router Solicitation (ICMPv6)
    MulticastRouterSolicitation = 152,
    /// Multicast Router Termination (ICMPv6)
    MulticastRouterTermination = 153,
    /// FMIPv6 Messages (ICMPv6)
    Fmipv6Messages = 154,
    /// RPL Control Message (ICMPv6)
    RplControlMessage = 155,
    /// MPL Control Message (ICMPv6)
    MplControlMessage = 156,
    /// Duplicate Address Request Code Suffix (ICMPv6)
    DuplicateAddressRequestCodeSuffix = 157,
    /// Duplicate Address Confirmation Code Suffix (ICMPv6)
    DuplicateAddressConfirmationCodeSuffix = 158,
    /// Extended Echo Request (ICMPv6)
    Icmpv6ExtendedEchoRequest = 160,
    /// Extended Echo Reply (ICMPv6)
    Icmpv6ExtendedEchoReply = 161,
}

impl IcmpType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IcmpType::EchoReply => "echo_reply",
            IcmpType::DestinationUnreachable => "destination_unreachable",
            IcmpType::Redirect => "redirect",
            IcmpType::EchoRequest => "echo_request",
            IcmpType::RouterAdvertisement => "router_advertisement",
            IcmpType::RouterSelection => "router_selection",
            IcmpType::TimeExceeded => "time_exceeded",
            IcmpType::ParameterProblem => "parameter_problem",
            IcmpType::Timestamp => "timestamp",
            IcmpType::TimestampReply => "timestamp_reply",
            IcmpType::InformationRequest => "information_request",
            IcmpType::InformationReply => "information_reply",
            IcmpType::AddressMaskRequest => "address_mask_request",
            IcmpType::AddressMaskReply => "address_mask_reply",
            IcmpType::Photuris => "photuris",
            IcmpType::ExtendedEchoRequest => "extended_echo_request",
            IcmpType::ExtendedEchoReply => "extended_echo_reply",
            IcmpType::Icmpv6DestinationUnreachable => "icmpv6_destination_unreachable",
            IcmpType::PacketTooBig => "packet_too_big",
            IcmpType::Icmpv6TimeExceeded => "icmpv6_time_exceeded",
            IcmpType::Icmpv6ParameterProblem => "ipv6_parameter_problem",
            IcmpType::Icmpv6EchoRequest => "icmpv6_echo_request",
            IcmpType::Icmpv6EchoReply => "icmpv6_echo_reply",
            IcmpType::MldQuery => "mld_query",
            IcmpType::MldReport => "mld_report",
            IcmpType::MldDone => "mld_done",
            IcmpType::Icmpv6RouterSolicitation => "icmpv6_router_solicitation",
            IcmpType::Icmpv6RouterAdvertisement => "icmpv6_router_advertisement",
            IcmpType::NeighborSolicitation => "neighbor_solicitation",
            IcmpType::NeighborAdvertisement => "neighbor_advertisement",
            IcmpType::Icmpv6Redirect => "icmpv6_redirect",
            IcmpType::RouterRenumbering => "router_renumbering",
            IcmpType::NodeInformationQuery => "node_information_query",
            IcmpType::NodeInformationResponse => "node_information_response",
            IcmpType::InverseNeighborDiscoverySolicitation => {
                "inverse_neighbor_discovery_solicitation"
            }
            IcmpType::InverseNeighborDiscoveryAdvertisement => {
                "inverse_neighbor_discovery_advertisement"
            }
            IcmpType::Mldv2MulticastListenerReport => "mldv2_multicast_listener_report",
            IcmpType::HomeAgentAddressDiscoveryRequest => "home_agent_address_discovery_request",
            IcmpType::HomeAgentAddressDiscoveryReply => "home_agent_address_discovery_reply",
            IcmpType::MobilePrefixSolicitation => "mobile_prefix_solicitation",
            IcmpType::MobilePrefixAdvertisement => "mobile_prefix_advertisement",
            IcmpType::CertificationPathSolicitation => "certification_path_solicitation",
            IcmpType::CertificationPathAdvertisement => "certification_path_advertisement",
            IcmpType::ExperimentalMobilityProtocols => "experimental_mobility_protocols",
            IcmpType::MulticastRouterAdvertisement => "multicast_router_advertisement",
            IcmpType::MulticastRouterSolicitation => "multicast_router_solicitation",
            IcmpType::MulticastRouterTermination => "multicast_router_termination",
            IcmpType::Fmipv6Messages => "fmipv6_messages",
            IcmpType::RplControlMessage => "rpl_control_message",
            IcmpType::MplControlMessage => "mpl_control_message",
            IcmpType::DuplicateAddressRequestCodeSuffix => "duplicate_address_request_code_suffix",
            IcmpType::DuplicateAddressConfirmationCodeSuffix => {
                "duplicate_address_confirmation_code_suffix"
            }
            IcmpType::Icmpv6ExtendedEchoRequest => "icmpv6_extended_echo_request",
            IcmpType::Icmpv6ExtendedEchoReply => "icmpv6_extended_echo_reply",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(IcmpType::EchoReply),
            3 => Some(IcmpType::DestinationUnreachable),
            5 => Some(IcmpType::Redirect),
            8 => Some(IcmpType::EchoRequest),
            9 => Some(IcmpType::RouterAdvertisement),
            10 => Some(IcmpType::RouterSelection),
            11 => Some(IcmpType::TimeExceeded),
            12 => Some(IcmpType::ParameterProblem),
            13 => Some(IcmpType::Timestamp),
            14 => Some(IcmpType::TimestampReply),
            15 => Some(IcmpType::InformationRequest),
            16 => Some(IcmpType::InformationReply),
            17 => Some(IcmpType::AddressMaskRequest),
            18 => Some(IcmpType::AddressMaskReply),
            40 => Some(IcmpType::Photuris),
            42 => Some(IcmpType::ExtendedEchoRequest),
            43 => Some(IcmpType::ExtendedEchoReply),
            1 => Some(IcmpType::Icmpv6DestinationUnreachable),
            2 => Some(IcmpType::PacketTooBig),
            3 => Some(IcmpType::Icmpv6TimeExceeded),
            4 => Some(IcmpType::Icmpv6ParameterProblem),
            128 => Some(IcmpType::Icmpv6EchoRequest),
            129 => Some(IcmpType::Icmpv6EchoReply),
            130 => Some(IcmpType::MldQuery),
            131 => Some(IcmpType::MldReport),
            132 => Some(IcmpType::MldDone),
            133 => Some(IcmpType::Icmpv6RouterSolicitation),
            134 => Some(IcmpType::Icmpv6RouterAdvertisement),
            135 => Some(IcmpType::NeighborSolicitation),
            136 => Some(IcmpType::NeighborAdvertisement),
            137 => Some(IcmpType::Icmpv6Redirect),
            138 => Some(IcmpType::RouterRenumbering),
            139 => Some(IcmpType::NodeInformationQuery),
            140 => Some(IcmpType::NodeInformationResponse),
            141 => Some(IcmpType::InverseNeighborDiscoverySolicitation),
            142 => Some(IcmpType::InverseNeighborDiscoveryAdvertisement),
            143 => Some(IcmpType::Mldv2MulticastListenerReport),
            144 => Some(IcmpType::HomeAgentAddressDiscoveryRequest),
            145 => Some(IcmpType::HomeAgentAddressDiscoveryReply),
            146 => Some(IcmpType::MobilePrefixSolicitation),
            147 => Some(IcmpType::MobilePrefixAdvertisement),
            148 => Some(IcmpType::CertificationPathSolicitation),
            149 => Some(IcmpType::CertificationPathAdvertisement),
            150 => Some(IcmpType::ExperimentalMobilityProtocols),
            151 => Some(IcmpType::MulticastRouterAdvertisement),
            152 => Some(IcmpType::MulticastRouterSolicitation),
            153 => Some(IcmpType::MulticastRouterTermination),
            154 => Some(IcmpType::Fmipv6Messages),
            155 => Some(IcmpType::RplControlMessage),
            156 => Some(IcmpType::MplControlMessage),
            157 => Some(IcmpType::DuplicateAddressRequestCodeSuffix),
            158 => Some(IcmpType::DuplicateAddressConfirmationCodeSuffix),
            160 => Some(IcmpType::Icmpv6ExtendedEchoRequest),
            161 => Some(IcmpType::Icmpv6ExtendedEchoReply),
            _ => None,
        }
    }
}

/// Echo Reply and Echo Request codes (types 0, 8)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EchoCode {
    NoCode = 0,
}

impl EchoCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            EchoCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(EchoCode::NoCode),
            _ => None,
        }
    }
}

/// Destination Unreachable codes (type 3)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DestinationUnreachableCode {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    SourceRouteFailed = 5,
    DestinationNetworkUnknown = 6,
    DestinationHostUnknown = 7,
    SourceHostIsolated = 8,
    NetworkAdministrativelyProhibited = 9,
    HostAdministrativelyProhibited = 10,
    NetworkUnreachableForTos = 11,
    HostUnreachableForTos = 12,
    CommunicationAdministrativelyProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoffInEffect = 15,
}

impl DestinationUnreachableCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DestinationUnreachableCode::NetUnreachable => "net_unreachable",
            DestinationUnreachableCode::HostUnreachable => "host_unreachable",
            DestinationUnreachableCode::ProtocolUnreachable => "protocol_unreachable",
            DestinationUnreachableCode::PortUnreachable => "port_unreachable",
            DestinationUnreachableCode::FragmentationNeeded => "fragmentation_needed",
            DestinationUnreachableCode::SourceRouteFailed => "source_route_failed",
            DestinationUnreachableCode::DestinationNetworkUnknown => "destination_network_unknown",
            DestinationUnreachableCode::DestinationHostUnknown => "destination_host_unknown",
            DestinationUnreachableCode::SourceHostIsolated => "source_host_isolated",
            DestinationUnreachableCode::NetworkAdministrativelyProhibited => {
                "network_administratively_prohibited"
            }
            DestinationUnreachableCode::HostAdministrativelyProhibited => {
                "host_administratively_prohibited"
            }
            DestinationUnreachableCode::NetworkUnreachableForTos => "network_unreachable_for_tos",
            DestinationUnreachableCode::HostUnreachableForTos => "host_unreachable_for_tos",
            DestinationUnreachableCode::CommunicationAdministrativelyProhibited => {
                "communication_administratively_prohibited"
            }
            DestinationUnreachableCode::HostPrecedenceViolation => "host_precedence_violation",
            DestinationUnreachableCode::PrecedenceCutoffInEffect => "precedence_cutoff_in_effect",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(DestinationUnreachableCode::NetUnreachable),
            1 => Some(DestinationUnreachableCode::HostUnreachable),
            2 => Some(DestinationUnreachableCode::ProtocolUnreachable),
            3 => Some(DestinationUnreachableCode::PortUnreachable),
            4 => Some(DestinationUnreachableCode::FragmentationNeeded),
            5 => Some(DestinationUnreachableCode::SourceRouteFailed),
            6 => Some(DestinationUnreachableCode::DestinationNetworkUnknown),
            7 => Some(DestinationUnreachableCode::DestinationHostUnknown),
            8 => Some(DestinationUnreachableCode::SourceHostIsolated),
            9 => Some(DestinationUnreachableCode::NetworkAdministrativelyProhibited),
            10 => Some(DestinationUnreachableCode::HostAdministrativelyProhibited),
            11 => Some(DestinationUnreachableCode::NetworkUnreachableForTos),
            12 => Some(DestinationUnreachableCode::HostUnreachableForTos),
            13 => Some(DestinationUnreachableCode::CommunicationAdministrativelyProhibited),
            14 => Some(DestinationUnreachableCode::HostPrecedenceViolation),
            15 => Some(DestinationUnreachableCode::PrecedenceCutoffInEffect),
            _ => None,
        }
    }
}

/// Redirect codes (type 5)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RedirectCode {
    RedirectForNetwork = 0,
    RedirectForHost = 1,
    RedirectForTosAndNetwork = 2,
    RedirectForTosAndHost = 3,
}

impl RedirectCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RedirectCode::RedirectForNetwork => "redirect_for_network",
            RedirectCode::RedirectForHost => "redirect_for_host",
            RedirectCode::RedirectForTosAndNetwork => "redirect_for_tos_and_network",
            RedirectCode::RedirectForTosAndHost => "redirect_for_tos_and_host",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RedirectCode::RedirectForNetwork),
            1 => Some(RedirectCode::RedirectForHost),
            2 => Some(RedirectCode::RedirectForTosAndNetwork),
            3 => Some(RedirectCode::RedirectForTosAndHost),
            _ => None,
        }
    }
}

/// Router Advertisement codes (type 9)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RouterAdvertisementCode {
    NoCode = 0,
    DoesNotRouteCommonTraffic = 16,
}

impl RouterAdvertisementCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RouterAdvertisementCode::NoCode => "",
            RouterAdvertisementCode::DoesNotRouteCommonTraffic => "does_not_route_common_traffic",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RouterAdvertisementCode::NoCode),
            16 => Some(RouterAdvertisementCode::DoesNotRouteCommonTraffic),
            _ => None,
        }
    }
}

/// Router Solicitation codes (type 10)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RouterSelectionCode {
    NoCode = 0,
}

impl RouterSelectionCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RouterSelectionCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RouterSelectionCode::NoCode),
            _ => None,
        }
    }
}

/// Time Exceeded codes (type 11)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimeExceededCode {
    TtlExpired = 0,
    FragmentReassemblyTimeExceeded = 1,
}

impl TimeExceededCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TimeExceededCode::TtlExpired => "ttl_expired",
            TimeExceededCode::FragmentReassemblyTimeExceeded => "fragment_reassembly_time_exceeded",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(TimeExceededCode::TtlExpired),
            1 => Some(TimeExceededCode::FragmentReassemblyTimeExceeded),
            _ => None,
        }
    }
}

/// Parameter Problem codes (type 12)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParameterProblemCode {
    PointerIndicatesError = 0,
    MissingRequiredOption = 1,
    BadLength = 2,
}

impl ParameterProblemCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParameterProblemCode::PointerIndicatesError => "pointer_indicates_error",
            ParameterProblemCode::MissingRequiredOption => "missing_required_option",
            ParameterProblemCode::BadLength => "bad_length",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ParameterProblemCode::PointerIndicatesError),
            1 => Some(ParameterProblemCode::MissingRequiredOption),
            2 => Some(ParameterProblemCode::BadLength),
            _ => None,
        }
    }
}

/// Timestamp Request codes (type 13)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimestampCode {
    NoCode = 0,
}

impl TimestampCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TimestampCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(TimestampCode::NoCode),
            _ => None,
        }
    }
}

/// Timestamp Reply codes (type 14)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimestampReplyCode {
    NoCode = 0,
}

impl TimestampReplyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TimestampReplyCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(TimestampReplyCode::NoCode),
            _ => None,
        }
    }
}

/// Information Request codes (type 15) - deprecated
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InformationRequestCode {
    NoCode = 0,
}

impl InformationRequestCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            InformationRequestCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(InformationRequestCode::NoCode),
            _ => None,
        }
    }
}

/// Information Reply codes (type 16) - deprecated
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InformationReplyCode {
    NoCode = 0,
}

impl InformationReplyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            InformationReplyCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(InformationReplyCode::NoCode),
            _ => None,
        }
    }
}

/// Address Mask Request codes (type 17)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressMaskRequestCode {
    NoCode = 0,
}

impl AddressMaskRequestCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressMaskRequestCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(AddressMaskRequestCode::NoCode),
            _ => None,
        }
    }
}

/// Address Mask Reply codes (type 18)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressMaskReplyCode {
    NoCode = 0,
}

impl AddressMaskReplyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressMaskReplyCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(AddressMaskReplyCode::NoCode),
            _ => None,
        }
    }
}

/// Photuris codes (type 40)

/// Photuris codes (type 40)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PhoturisCode {
    BadSpi = 0,
    AuthenticationFailed = 1,
    DecompressionFailed = 2,
    DecryptionFailed = 3,
    NeedAuthentication = 4,
    NeedAuthorization = 5,
}

impl PhoturisCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PhoturisCode::BadSpi => "bad_spi",
            PhoturisCode::AuthenticationFailed => "authentication_failed",
            PhoturisCode::DecompressionFailed => "decompression_failed",
            PhoturisCode::DecryptionFailed => "decryption_failed",
            PhoturisCode::NeedAuthentication => "need_authentication",
            PhoturisCode::NeedAuthorization => "need_authorization",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PhoturisCode::BadSpi),
            1 => Some(PhoturisCode::AuthenticationFailed),
            2 => Some(PhoturisCode::DecompressionFailed),
            3 => Some(PhoturisCode::DecryptionFailed),
            4 => Some(PhoturisCode::NeedAuthentication),
            5 => Some(PhoturisCode::NeedAuthorization),
            _ => None,
        }
    }
}

/// Extended Echo Request codes (type 42)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExtendedEchoRequestCode {
    NoError = 0,
}

impl ExtendedEchoRequestCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtendedEchoRequestCode::NoError => "no_error",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ExtendedEchoRequestCode::NoError),
            _ => None,
        }
    }
}

/// Extended Echo Reply codes (type 43)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExtendedEchoReplyCode {
    NoError = 0,
    MalformedQuery = 1,
    NoSuchInterface = 2,
    NoSuchTableEntry = 3,
    MultipleInterfacesSatisfyQuery = 4,
}

impl ExtendedEchoReplyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtendedEchoReplyCode::NoError => "no_error",
            ExtendedEchoReplyCode::MalformedQuery => "malformed_query",
            ExtendedEchoReplyCode::NoSuchInterface => "no_such_interface",
            ExtendedEchoReplyCode::NoSuchTableEntry => "no_such_table_entry",
            ExtendedEchoReplyCode::MultipleInterfacesSatisfyQuery => {
                "multiple_interfaces_satisfy_query"
            }
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ExtendedEchoReplyCode::NoError),
            1 => Some(ExtendedEchoReplyCode::MalformedQuery),
            2 => Some(ExtendedEchoReplyCode::NoSuchInterface),
            3 => Some(ExtendedEchoReplyCode::NoSuchTableEntry),
            4 => Some(ExtendedEchoReplyCode::MultipleInterfacesSatisfyQuery),
            _ => None,
        }
    }
}

// ICMPv6 specific code enums (RFC 4443)

/// ICMPv6 Destination Unreachable codes (type 1)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6DestinationUnreachableCode {
    NoRouteToDestination = 0,
    CommunicationWithDestinationAdministrativelyProhibited = 1,
    BeyondScopeOfSourceAddress = 2,
    AddressUnreachable = 3,
    PortUnreachable = 4,
    SourceAddressFailedIngressEgressPolicy = 5,
    RejectRouteToDestination = 6,
    ErrorInSourceRoutingHeader = 7,
    HeadersTooLong = 8,
    ErrorInPRoute = 9,
}

impl Icmpv6DestinationUnreachableCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6DestinationUnreachableCode::NoRouteToDestination => "no_route_to_destination",
            Icmpv6DestinationUnreachableCode::CommunicationWithDestinationAdministrativelyProhibited => "communication_with_destination_administratively_prohibited",
            Icmpv6DestinationUnreachableCode::BeyondScopeOfSourceAddress => "beyond_scope_of_source_address",
            Icmpv6DestinationUnreachableCode::AddressUnreachable => "address_unreachable",
            Icmpv6DestinationUnreachableCode::PortUnreachable => "port_unreachable",
            Icmpv6DestinationUnreachableCode::SourceAddressFailedIngressEgressPolicy => "source_address_failed_ingress_egress_policy",
            Icmpv6DestinationUnreachableCode::RejectRouteToDestination => "reject_route_to_destination",
            Icmpv6DestinationUnreachableCode::ErrorInSourceRoutingHeader => "error_in_source_routing_header",
            Icmpv6DestinationUnreachableCode::HeadersTooLong => "headers_too_long",
            Icmpv6DestinationUnreachableCode::ErrorInPRoute => "error_in_p_route",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6DestinationUnreachableCode::NoRouteToDestination),
            1 => Some(Icmpv6DestinationUnreachableCode::CommunicationWithDestinationAdministrativelyProhibited),
            2 => Some(Icmpv6DestinationUnreachableCode::BeyondScopeOfSourceAddress),
            3 => Some(Icmpv6DestinationUnreachableCode::AddressUnreachable),
            4 => Some(Icmpv6DestinationUnreachableCode::PortUnreachable),
            5 => Some(Icmpv6DestinationUnreachableCode::SourceAddressFailedIngressEgressPolicy),
            6 => Some(Icmpv6DestinationUnreachableCode::RejectRouteToDestination),
            7 => Some(Icmpv6DestinationUnreachableCode::ErrorInSourceRoutingHeader),
            8 => Some(Icmpv6DestinationUnreachableCode::HeadersTooLong),
            9 => Some(Icmpv6DestinationUnreachableCode::ErrorInPRoute),
            _ => None,
        }
    }
}

/// ICMPv6 Packet Too Big codes (type 2)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PacketTooBigCode {
    NoCode = 0,
}

impl PacketTooBigCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PacketTooBigCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PacketTooBigCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Time Exceeded codes (type 101)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6TimeExceededCode {
    HopLimitExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,
}

impl Icmpv6TimeExceededCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6TimeExceededCode::HopLimitExceeded => "hop_limit_exceeded",
            Icmpv6TimeExceededCode::FragmentReassemblyTimeExceeded => {
                "fragment_reassembly_time_exceeded"
            }
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6TimeExceededCode::HopLimitExceeded),
            1 => Some(Icmpv6TimeExceededCode::FragmentReassemblyTimeExceeded),
            _ => None,
        }
    }
}

/// Parameter Problem codes (type 12)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6ParameterProblemCode {
    ErroneousHeaderFieldEncountered = 0,
    UnrecognizedNextHeaderTypeEncountered = 1,
    UnrecognizedIPv6OptionEncountered = 2,
    IPv6FirstFragmentHasIncompleteIPv6HeaderChain = 3,
    SRUpperLayerHeaderError = 4,
    UnrecognizedNextHeaderTypeEncounteredByIntermediateNode = 5,
    ExtensionHeaderTooBig = 6,
    ExtensionHeaderChainTooLong = 7,
    TooManyExtensionHeaders = 8,
    TooManyOptionsInExtensionHeader = 9,
    OptionTooBig = 10,
}

impl Icmpv6ParameterProblemCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6ParameterProblemCode::ErroneousHeaderFieldEncountered => {
                "erroneous_header_field_encountered"
            }
            Icmpv6ParameterProblemCode::UnrecognizedNextHeaderTypeEncountered => {
                "unrecognized_next_header_type_encountered"
            }
            Icmpv6ParameterProblemCode::UnrecognizedIPv6OptionEncountered => {
                "unrecognized_ipv6_option_encountered"
            }
            Icmpv6ParameterProblemCode::IPv6FirstFragmentHasIncompleteIPv6HeaderChain => {
                "ipv6_first_fragment_has_incomplete_ipv6_header_chain"
            }
            Icmpv6ParameterProblemCode::SRUpperLayerHeaderError => "sr_upper_layer_header_error",
            Icmpv6ParameterProblemCode::UnrecognizedNextHeaderTypeEncounteredByIntermediateNode => {
                "unrecognized_next_header_type_encountered_by_intermediate_node"
            }
            Icmpv6ParameterProblemCode::ExtensionHeaderTooBig => "extension_header_too_big",
            Icmpv6ParameterProblemCode::ExtensionHeaderChainTooLong => {
                "extension_header_chain_too_long"
            }
            Icmpv6ParameterProblemCode::TooManyExtensionHeaders => "too_many_extension_headers",
            Icmpv6ParameterProblemCode::TooManyOptionsInExtensionHeader => {
                "too_many_options_in_extension_header"
            }
            Icmpv6ParameterProblemCode::OptionTooBig => "option_too_big",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6ParameterProblemCode::ErroneousHeaderFieldEncountered),
            1 => Some(Icmpv6ParameterProblemCode::UnrecognizedNextHeaderTypeEncountered),
            2 => Some(Icmpv6ParameterProblemCode::UnrecognizedIPv6OptionEncountered),
            3 => Some(Icmpv6ParameterProblemCode::IPv6FirstFragmentHasIncompleteIPv6HeaderChain),
            4 => Some(Icmpv6ParameterProblemCode::SRUpperLayerHeaderError),
            5 => Some(
                Icmpv6ParameterProblemCode::UnrecognizedNextHeaderTypeEncounteredByIntermediateNode,
            ),
            6 => Some(Icmpv6ParameterProblemCode::ExtensionHeaderTooBig),
            7 => Some(Icmpv6ParameterProblemCode::ExtensionHeaderChainTooLong),
            8 => Some(Icmpv6ParameterProblemCode::TooManyExtensionHeaders),
            9 => Some(Icmpv6ParameterProblemCode::TooManyOptionsInExtensionHeader),
            10 => Some(Icmpv6ParameterProblemCode::OptionTooBig),
            _ => None,
        }
    }
}

/// ICMPv6 Echo Request codes (type 128)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6EchoRequestCode {
    NoCode = 0,
}

impl Icmpv6EchoRequestCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6EchoRequestCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6EchoRequestCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Echo Reply codes (type 129)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6EchoReplyCode {
    NoCode = 0,
}

impl Icmpv6EchoReplyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6EchoReplyCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6EchoReplyCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 MLD Query codes (type 130)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MldQueryCode {
    NoCode = 0,
}

impl MldQueryCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MldQueryCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MldQueryCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 MLD Report codes (type 131)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MldReportCode {
    NoCode = 0,
}

impl MldReportCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MldReportCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MldReportCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 MLD Done codes (type 132)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MldDoneCode {
    NoCode = 0,
}

impl MldDoneCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MldDoneCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MldDoneCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Router Solicitation codes (type 133)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6RouterSolicitationCode {
    NoCode = 0,
}

impl Icmpv6RouterSolicitationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6RouterSolicitationCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6RouterSolicitationCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Router Advertisement codes (type 134)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6RouterAdvertisementCode {
    NoCode = 0,
}

impl Icmpv6RouterAdvertisementCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6RouterAdvertisementCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6RouterAdvertisementCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Neighbor Solicitation codes (type 135)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NeighborSolicitationCode {
    NoCode = 0,
}

impl NeighborSolicitationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NeighborSolicitationCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(NeighborSolicitationCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Neighbor Advertisement codes (type 136)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NeighborAdvertisementCode {
    NoCode = 0,
}

impl NeighborAdvertisementCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NeighborAdvertisementCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(NeighborAdvertisementCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Redirect codes (type 137)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6RedirectCode {
    NoCode = 0,
}

impl Icmpv6RedirectCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6RedirectCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6RedirectCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Router Renumbering codes (type 138)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RouterRenumberingCode {
    RouterRenumberingCommand = 0,
    RouterRenumberingResult = 1,
    SequenceNumberReset = 255,
}

impl RouterRenumberingCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RouterRenumberingCode::RouterRenumberingCommand => "router_renumbering_command",
            RouterRenumberingCode::RouterRenumberingResult => "router_renumbering_result",
            RouterRenumberingCode::SequenceNumberReset => "sequence_number_reset",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RouterRenumberingCode::RouterRenumberingCommand),
            1 => Some(RouterRenumberingCode::RouterRenumberingResult),
            255 => Some(RouterRenumberingCode::SequenceNumberReset),
            _ => None,
        }
    }
}

/// ICMPv6 Node Information Query codes (type 139)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NodeInformationQueryCode {
    Data = 0,
    Name = 1,
    NameOrAddress = 2,
}

impl NodeInformationQueryCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeInformationQueryCode::Data => "data",
            NodeInformationQueryCode::Name => "name",
            NodeInformationQueryCode::NameOrAddress => "name_or_address",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(NodeInformationQueryCode::Data),
            1 => Some(NodeInformationQueryCode::Name),
            2 => Some(NodeInformationQueryCode::NameOrAddress),
            _ => None,
        }
    }
}

/// ICMPv6 Node Information Response codes (type 140)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NodeInformationResponseCode {
    SuccessfulResponse = 0,
    RespondingNodeIsTheNodeQueried = 1,
    QueryIsRecognizedButTheRequestedInfoIsUnavailable = 2,
    QueryIsNotRecognized = 3,
}

impl NodeInformationResponseCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeInformationResponseCode::SuccessfulResponse => "successful_response",
            NodeInformationResponseCode::RespondingNodeIsTheNodeQueried => {
                "responding_node_is_the_node_queried"
            }
            NodeInformationResponseCode::QueryIsRecognizedButTheRequestedInfoIsUnavailable => {
                "query_is_recognized_but_the_requested_info_is_unavailable"
            }
            NodeInformationResponseCode::QueryIsNotRecognized => "query_is_not_recognized",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(NodeInformationResponseCode::SuccessfulResponse),
            1 => Some(NodeInformationResponseCode::RespondingNodeIsTheNodeQueried),
            2 => {
                Some(NodeInformationResponseCode::QueryIsRecognizedButTheRequestedInfoIsUnavailable)
            }
            3 => Some(NodeInformationResponseCode::QueryIsNotRecognized),
            _ => None,
        }
    }
}

/// ICMPv6 Inverse Neighbor Discovery Solicitation codes (type 141)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InverseNeighborDiscoverySolicitationCode {
    NoCode = 0,
}

impl InverseNeighborDiscoverySolicitationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            InverseNeighborDiscoverySolicitationCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(InverseNeighborDiscoverySolicitationCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Inverse Neighbor Discovery Advertisement codes (type 142)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InverseNeighborDiscoveryAdvertisementCode {
    NoCode = 0,
}

impl InverseNeighborDiscoveryAdvertisementCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            InverseNeighborDiscoveryAdvertisementCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(InverseNeighborDiscoveryAdvertisementCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 MLDv2 Multicast Listener Report codes (type 143)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Mldv2MulticastListenerReportCode {
    NoCode = 0,
}

impl Mldv2MulticastListenerReportCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mldv2MulticastListenerReportCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Mldv2MulticastListenerReportCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Home Agent Address Discovery Request codes (type 144)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HomeAgentAddressDiscoveryRequestCode {
    NoCode = 0,
}

impl HomeAgentAddressDiscoveryRequestCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            HomeAgentAddressDiscoveryRequestCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(HomeAgentAddressDiscoveryRequestCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Home Agent Address Discovery Reply codes (type 145)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HomeAgentAddressDiscoveryReplyCode {
    NoCode = 0,
}

impl HomeAgentAddressDiscoveryReplyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            HomeAgentAddressDiscoveryReplyCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(HomeAgentAddressDiscoveryReplyCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Mobile Prefix Solicitation codes (type 146)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MobilePrefixSolicitationCode {
    NoCode = 0,
}

impl MobilePrefixSolicitationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MobilePrefixSolicitationCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MobilePrefixSolicitationCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Mobile Prefix Advertisement codes (type 147)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MobilePrefixAdvertisementCode {
    NoCode = 0,
}

impl MobilePrefixAdvertisementCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MobilePrefixAdvertisementCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MobilePrefixAdvertisementCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Certification Path Solicitation codes (type 148)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertificationPathSolicitationCode {
    NoCode = 0,
}

impl CertificationPathSolicitationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificationPathSolicitationCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(CertificationPathSolicitationCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Certification Path Advertisement codes (type 149)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertificationPathAdvertisementCode {
    NoCode = 0,
}

impl CertificationPathAdvertisementCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificationPathAdvertisementCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(CertificationPathAdvertisementCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Experimental Mobility Protocols codes (type 150)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExperimentalMobilityProtocolsCode {
    NoCode = 0,
}

impl ExperimentalMobilityProtocolsCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExperimentalMobilityProtocolsCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ExperimentalMobilityProtocolsCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Multicast Router Advertisement codes (type 151)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MulticastRouterAdvertisementCode {
    NoCode = 0,
}

impl MulticastRouterAdvertisementCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MulticastRouterAdvertisementCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MulticastRouterAdvertisementCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Multicast Router Solicitation codes (type 152)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MulticastRouterSolicitationCode {
    NoCode = 0,
}

impl MulticastRouterSolicitationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MulticastRouterSolicitationCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MulticastRouterSolicitationCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Multicast Router Termination codes (type 153)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MulticastRouterTerminationCode {
    NoCode = 0,
}

impl MulticastRouterTerminationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MulticastRouterTerminationCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MulticastRouterTerminationCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 FMIPv6 Messages codes (type 154)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Fmipv6MessagesCode {
    NoCode = 0,
}

impl Fmipv6MessagesCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Fmipv6MessagesCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Fmipv6MessagesCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 RPL Control Message codes (type 155)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RplControlMessageCode {
    NoCode = 0,
}

impl RplControlMessageCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RplControlMessageCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RplControlMessageCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 MPL Control Message codes (type 156)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MplControlMessageCode {
    NoCode = 0,
}

impl MplControlMessageCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MplControlMessageCode::NoCode => "",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(MplControlMessageCode::NoCode),
            _ => None,
        }
    }
}

/// ICMPv6 Duplicate Address Request Code Suffix codes (type 157)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DuplicateAddressRequestCodeSuffixCode {
    DarMessage = 0,
    EdarMessageWith64BitRovrField = 1,
    EdarMessageWith128BitRovrField = 2,
    EdarMessageWith192BitRovrField = 3,
    EdarMessageWith256BitRovrField = 4,
}

impl DuplicateAddressRequestCodeSuffixCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DuplicateAddressRequestCodeSuffixCode::DarMessage => "dar_message",
            DuplicateAddressRequestCodeSuffixCode::EdarMessageWith64BitRovrField => {
                "edar_message_with_64_bit_rovr_field"
            }
            DuplicateAddressRequestCodeSuffixCode::EdarMessageWith128BitRovrField => {
                "edar_message_with_128_bit_rovr_field"
            }
            DuplicateAddressRequestCodeSuffixCode::EdarMessageWith192BitRovrField => {
                "edar_message_with_192_bit_rovr_field"
            }
            DuplicateAddressRequestCodeSuffixCode::EdarMessageWith256BitRovrField => {
                "edar_message_with_256_bit_rovr_field"
            }
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(DuplicateAddressRequestCodeSuffixCode::DarMessage),
            1 => Some(DuplicateAddressRequestCodeSuffixCode::EdarMessageWith64BitRovrField),
            2 => Some(DuplicateAddressRequestCodeSuffixCode::EdarMessageWith128BitRovrField),
            3 => Some(DuplicateAddressRequestCodeSuffixCode::EdarMessageWith192BitRovrField),
            4 => Some(DuplicateAddressRequestCodeSuffixCode::EdarMessageWith256BitRovrField),
            _ => None,
        }
    }
}

/// ICMPv6 Duplicate Address Confirmation Code Suffix codes (type 158)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DuplicateAddressConfirmationCodeSuffixCode {
    DarMessage = 0,
    EdarMessageWith64BitRovrField = 1,
    EdarMessageWith128BitRovrField = 2,
    EdarMessageWith192BitRovrField = 3,
    EdarMessageWith256BitRovrField = 4,
}

impl DuplicateAddressConfirmationCodeSuffixCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DuplicateAddressConfirmationCodeSuffixCode::DarMessage => "dar_message",
            DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith64BitRovrField => {
                "edar_message_with_64_bit_rovr_field"
            }
            DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith128BitRovrField => {
                "edar_message_with_128_bit_rovr_field"
            }
            DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith192BitRovrField => {
                "edar_message_with_192_bit_rovr_field"
            }
            DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith256BitRovrField => {
                "edar_message_with_256_bit_rovr_field"
            }
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(DuplicateAddressConfirmationCodeSuffixCode::DarMessage),
            1 => Some(DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith64BitRovrField),
            2 => Some(DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith128BitRovrField),
            3 => Some(DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith192BitRovrField),
            4 => Some(DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith256BitRovrField),
            _ => None,
        }
    }
}

/// ICMPv6 Extended Echo Request codes (type 160)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6ExtendedEchoRequestCode {
    NoError = 0,
}

impl Icmpv6ExtendedEchoRequestCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6ExtendedEchoRequestCode::NoError => "no_error",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6ExtendedEchoRequestCode::NoError),
            _ => None,
        }
    }
}

/// ICMPv6 Extended Echo Reply codes (type 161)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6ExtendedEchoReplyCode {
    NoError = 0,
    MalformedQuery = 1,
    NoSuchInterface = 2,
    NoSuchTableEntry = 3,
    MultipleInterfacesSatisfyQuery = 4,
}

impl Icmpv6ExtendedEchoReplyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Icmpv6ExtendedEchoReplyCode::NoError => "no_error",
            Icmpv6ExtendedEchoReplyCode::MalformedQuery => "malformed_query",
            Icmpv6ExtendedEchoReplyCode::NoSuchInterface => "no_such_interface",
            Icmpv6ExtendedEchoReplyCode::NoSuchTableEntry => "no_such_table_entry",
            Icmpv6ExtendedEchoReplyCode::MultipleInterfacesSatisfyQuery => {
                "multiple_interfaces_satisfy_query"
            }
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Icmpv6ExtendedEchoReplyCode::NoError),
            1 => Some(Icmpv6ExtendedEchoReplyCode::MalformedQuery),
            2 => Some(Icmpv6ExtendedEchoReplyCode::NoSuchInterface),
            3 => Some(Icmpv6ExtendedEchoReplyCode::NoSuchTableEntry),
            4 => Some(Icmpv6ExtendedEchoReplyCode::MultipleInterfacesSatisfyQuery),
            _ => None,
        }
    }
}

/// Generic ICMP code enum that can represent codes for any ICMP message type
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IcmpCode {
    Echo(EchoCode),
    DestinationUnreachable(DestinationUnreachableCode),
    Redirect(RedirectCode),
    RouterAdvertisement(RouterAdvertisementCode),
    RouterSolicitation(RouterSelectionCode),
    TimeExceeded(TimeExceededCode),
    ParameterProblem(ParameterProblemCode),
    Timestamp(TimestampCode),
    TimestampReply(TimestampReplyCode),
    InformationRequest(InformationRequestCode),
    InformationReply(InformationReplyCode),
    AddressMaskRequest(AddressMaskRequestCode),
    AddressMaskReply(AddressMaskReplyCode),
    Photuris(PhoturisCode),
    ExtendedEchoRequest(ExtendedEchoRequestCode),
    ExtendedEchoReply(ExtendedEchoReplyCode),
    // ICMPv6 specific codes
    Icmpv6DestinationUnreachable(Icmpv6DestinationUnreachableCode),
    PacketTooBig(PacketTooBigCode),
    Icmpv6TimeExceeded(Icmpv6TimeExceededCode),
    Icmpv6ParameterProblem(Icmpv6ParameterProblemCode),
    Icmpv6EchoRequest(Icmpv6EchoRequestCode),
    Icmpv6EchoReply(Icmpv6EchoReplyCode),
    Icmpv6RouterSolicitation(Icmpv6RouterSolicitationCode),
    Icmpv6RouterAdvertisement(Icmpv6RouterAdvertisementCode),
    NeighborSolicitation(NeighborSolicitationCode),
    NeighborAdvertisement(NeighborAdvertisementCode),
    Icmpv6Redirect(Icmpv6RedirectCode),
    RouterRenumbering(RouterRenumberingCode),
    NodeInformationQuery(NodeInformationQueryCode),
    NodeInformationResponse(NodeInformationResponseCode),
    InverseNeighborDiscoverySolicitation(InverseNeighborDiscoverySolicitationCode),
    InverseNeighborDiscoveryAdvertisement(InverseNeighborDiscoveryAdvertisementCode),
    Mldv2MulticastListenerReport(Mldv2MulticastListenerReportCode),
    HomeAgentAddressDiscoveryRequest(HomeAgentAddressDiscoveryRequestCode),
    HomeAgentAddressDiscoveryReply(HomeAgentAddressDiscoveryReplyCode),
    MobilePrefixSolicitation(MobilePrefixSolicitationCode),
    MobilePrefixAdvertisement(MobilePrefixAdvertisementCode),
    CertificationPathSolicitation(CertificationPathSolicitationCode),
    CertificationPathAdvertisement(CertificationPathAdvertisementCode),
    ExperimentalMobilityProtocols(ExperimentalMobilityProtocolsCode),
    MulticastRouterAdvertisement(MulticastRouterAdvertisementCode),
    MulticastRouterSolicitation(MulticastRouterSolicitationCode),
    MulticastRouterTermination(MulticastRouterTerminationCode),
    Fmipv6Messages(Fmipv6MessagesCode),
    RplControlMessage(RplControlMessageCode),
    MplControlMessage(MplControlMessageCode),
    DuplicateAddressRequestCodeSuffix(DuplicateAddressRequestCodeSuffixCode),
    DuplicateAddressConfirmationCodeSuffix(DuplicateAddressConfirmationCodeSuffixCode),
    Icmpv6ExtendedEchoRequest(Icmpv6ExtendedEchoRequestCode),
    Icmpv6ExtendedEchoReply(Icmpv6ExtendedEchoReplyCode),
    MldQuery(MldQueryCode),
    MldReport(MldReportCode),
    MldDone(MldDoneCode),
}

impl IcmpCode {
    /// Returns a string representation of the ICMP code.
    pub fn as_str(&self) -> &'static str {
        match self {
            IcmpCode::Echo(code) => code.as_str(),
            IcmpCode::DestinationUnreachable(code) => code.as_str(),
            IcmpCode::Redirect(code) => code.as_str(),
            IcmpCode::RouterAdvertisement(code) => code.as_str(),
            IcmpCode::RouterSolicitation(code) => code.as_str(),
            IcmpCode::TimeExceeded(code) => code.as_str(),
            IcmpCode::ParameterProblem(code) => code.as_str(),
            IcmpCode::Timestamp(code) => code.as_str(),
            IcmpCode::TimestampReply(code) => code.as_str(),
            IcmpCode::InformationRequest(code) => code.as_str(),
            IcmpCode::InformationReply(code) => code.as_str(),
            IcmpCode::AddressMaskRequest(code) => code.as_str(),
            IcmpCode::AddressMaskReply(code) => code.as_str(),
            IcmpCode::Photuris(code) => code.as_str(),
            IcmpCode::ExtendedEchoRequest(code) => code.as_str(),
            IcmpCode::ExtendedEchoReply(code) => code.as_str(),
            IcmpCode::Icmpv6DestinationUnreachable(code) => code.as_str(),
            IcmpCode::PacketTooBig(code) => code.as_str(),
            IcmpCode::Icmpv6TimeExceeded(code) => code.as_str(),
            IcmpCode::Icmpv6ParameterProblem(code) => code.as_str(),
            IcmpCode::Icmpv6EchoRequest(code) => code.as_str(),
            IcmpCode::Icmpv6EchoReply(code) => code.as_str(),
            IcmpCode::Icmpv6RouterSolicitation(code) => code.as_str(),
            IcmpCode::Icmpv6RouterAdvertisement(code) => code.as_str(),
            IcmpCode::NeighborSolicitation(code) => code.as_str(),
            IcmpCode::NeighborAdvertisement(code) => code.as_str(),
            IcmpCode::Icmpv6Redirect(code) => code.as_str(),
            IcmpCode::RouterRenumbering(code) => code.as_str(),
            IcmpCode::NodeInformationQuery(code) => code.as_str(),
            IcmpCode::NodeInformationResponse(code) => code.as_str(),
            IcmpCode::InverseNeighborDiscoverySolicitation(code) => code.as_str(),
            IcmpCode::InverseNeighborDiscoveryAdvertisement(code) => code.as_str(),
            IcmpCode::Mldv2MulticastListenerReport(code) => code.as_str(),
            IcmpCode::HomeAgentAddressDiscoveryRequest(code) => code.as_str(),
            IcmpCode::HomeAgentAddressDiscoveryReply(code) => code.as_str(),
            IcmpCode::MobilePrefixSolicitation(code) => code.as_str(),
            IcmpCode::MobilePrefixAdvertisement(code) => code.as_str(),
            IcmpCode::CertificationPathSolicitation(code) => code.as_str(),
            IcmpCode::CertificationPathAdvertisement(code) => code.as_str(),
            IcmpCode::ExperimentalMobilityProtocols(code) => code.as_str(),
            IcmpCode::MulticastRouterAdvertisement(code) => code.as_str(),
            IcmpCode::MulticastRouterSolicitation(code) => code.as_str(),
            IcmpCode::MulticastRouterTermination(code) => code.as_str(),
            IcmpCode::Fmipv6Messages(code) => code.as_str(),
            IcmpCode::RplControlMessage(code) => code.as_str(),
            IcmpCode::MplControlMessage(code) => code.as_str(),
            IcmpCode::DuplicateAddressRequestCodeSuffix(code) => code.as_str(),
            IcmpCode::DuplicateAddressConfirmationCodeSuffix(code) => code.as_str(),
            IcmpCode::Icmpv6ExtendedEchoRequest(code) => code.as_str(),
            IcmpCode::Icmpv6ExtendedEchoReply(code) => code.as_str(),
            IcmpCode::MldQuery(code) => code.as_str(),
            IcmpCode::MldReport(code) => code.as_str(),
            IcmpCode::MldDone(code) => code.as_str(),
        }
    }
}

impl IcmpHdr {
    /// The size of the ICMP header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<IcmpHdr>();

    /// Attempts to convert the raw icmp_type field into an IcmpType enum.
    /// Returns either the corresponding IcmpType variant or the raw value if unknown.
    ///
    /// # Returns
    /// - `Ok(IcmpType)` if a known message type
    /// - `Err(u8)` if an unknown message type (returns the raw value)
    #[inline]
    pub fn icmp_type(&self) -> Result<IcmpType, u8> {
        IcmpType::try_from(self._type)
    }

    /// Sets the ICMP message type.
    ///
    /// # Parameters
    /// * `icmp_type` - The ICMP message type to set.
    #[inline]
    pub fn set_icmp_type(&mut self, icmp_type: IcmpType) {
        self._type = icmp_type as u8;
    }

    /// Attempts to convert the raw code field into a type-specific IcmpCode enum variant.
    /// The interpretation depends on the message type.
    ///
    /// # Returns
    /// - `Ok(IcmpCode)` if a known code value for the current message type
    /// - `Err(u8)` if an unknown code value (returns the raw value)
    #[inline]
    pub fn code(&self) -> Result<IcmpCode, u8> {
        let icmp_type = self.icmp_type()?;
        parse_code_for_type(icmp_type, self.code)
    }

    /// Sets the ICMP message code using a type-specific IcmpCode enum.
    ///
    /// # Parameters
    /// * `code` - The ICMP message code to set.
    #[inline]
    pub fn set_code(&mut self, code: IcmpCode) {
        self.code = code.into();
    }

    /// Returns the ICMP checksum.
    ///
    /// This method converts the checksum from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The checksum as a u16 value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the ICMP checksum.
    ///
    /// This method converts the checksum from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `checksum` - The checksum to set.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Returns the ICMP data field as a u32.
    ///
    /// This method converts the data field from network byte order (big-endian)
    /// to host byte order. The interpretation of this field depends on the ICMP type.
    ///
    /// # Returns
    /// The data field as a u32 value.
    #[inline]
    pub fn data(&self) -> u32 {
        u32::from_be_bytes(self.data)
    }

    /// Sets the ICMP data field.
    ///
    /// This method converts the data field from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `data` - The data field to set.
    #[inline]
    pub fn set_data(&mut self, data: u32) {
        self.data = data.to_be_bytes();
    }

    /// Returns the identifier field for Echo Request/Reply messages.
    ///
    /// For Echo Request and Echo Reply messages, the first 2 bytes of the data
    /// field contain an identifier that can be used to match requests with replies.
    ///
    /// # Returns
    /// The identifier as a u16 value.
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Sets the identifier field for Echo Request/Reply messages.
    ///
    /// # Parameters
    /// * `id` - The identifier to set.
    #[inline]
    pub fn set_identifier(&mut self, id: u16) {
        let bytes = id.to_be_bytes();
        self.data[0] = bytes[0];
        self.data[1] = bytes[1];
    }

    /// Returns the sequence number field for Echo Request/Reply messages.
    ///
    /// For Echo Request and Echo Reply messages, the last 2 bytes of the data
    /// field contain a sequence number that can be used to match requests with replies.
    ///
    /// # Returns
    /// The sequence number as a u16 value.
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Sets the sequence number field for Echo Request/Reply messages.
    ///
    /// # Parameters
    /// * `seq` - The sequence number to set.
    #[inline]
    pub fn set_sequence(&mut self, seq: u16) {
        let bytes = seq.to_be_bytes();
        self.data[2] = bytes[0];
        self.data[3] = bytes[1];
    }
}

// This allows converting a u8 value into an IcmpType enum variant.
// This is useful when parsing headers.
impl TryFrom<u8> for IcmpType {
    type Error = u8; // Return the unknown value itself as the error

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IcmpType::EchoReply),
            3 => Ok(IcmpType::DestinationUnreachable),
            4 => Ok(IcmpType::ParameterProblem),
            5 => Ok(IcmpType::Redirect),
            8 => Ok(IcmpType::EchoRequest),
            9 => Ok(IcmpType::RouterAdvertisement),
            10 => Ok(IcmpType::RouterSelection),
            11 => Ok(IcmpType::TimeExceeded),
            12 => Ok(IcmpType::ParameterProblem),
            13 => Ok(IcmpType::Timestamp),
            14 => Ok(IcmpType::TimestampReply),
            15 => Ok(IcmpType::InformationRequest),
            16 => Ok(IcmpType::InformationReply),
            17 => Ok(IcmpType::AddressMaskRequest),
            18 => Ok(IcmpType::AddressMaskReply),
            40 => Ok(IcmpType::Photuris),
            42 => Ok(IcmpType::ExtendedEchoRequest),
            43 => Ok(IcmpType::ExtendedEchoReply),
            // ICMPv6 specific types (RFC 4443)
            1 => Ok(IcmpType::Icmpv6DestinationUnreachable),
            2 => Ok(IcmpType::PacketTooBig),
            3 => Ok(IcmpType::Icmpv6TimeExceeded),
            128 => Ok(IcmpType::Icmpv6EchoRequest),
            129 => Ok(IcmpType::Icmpv6EchoReply),
            130 => Ok(IcmpType::MldQuery),
            131 => Ok(IcmpType::MldReport),
            132 => Ok(IcmpType::MldDone),
            133 => Ok(IcmpType::Icmpv6RouterSolicitation),
            134 => Ok(IcmpType::Icmpv6RouterAdvertisement),
            135 => Ok(IcmpType::NeighborSolicitation),
            136 => Ok(IcmpType::NeighborAdvertisement),
            137 => Ok(IcmpType::Icmpv6Redirect),
            138 => Ok(IcmpType::RouterRenumbering),
            139 => Ok(IcmpType::NodeInformationQuery),
            140 => Ok(IcmpType::NodeInformationResponse),
            141 => Ok(IcmpType::InverseNeighborDiscoverySolicitation),
            142 => Ok(IcmpType::InverseNeighborDiscoveryAdvertisement),
            143 => Ok(IcmpType::Mldv2MulticastListenerReport),
            144 => Ok(IcmpType::HomeAgentAddressDiscoveryRequest),
            145 => Ok(IcmpType::HomeAgentAddressDiscoveryReply),
            146 => Ok(IcmpType::MobilePrefixSolicitation),
            147 => Ok(IcmpType::MobilePrefixAdvertisement),
            148 => Ok(IcmpType::CertificationPathSolicitation),
            149 => Ok(IcmpType::CertificationPathAdvertisement),
            150 => Ok(IcmpType::ExperimentalMobilityProtocols),
            151 => Ok(IcmpType::MulticastRouterAdvertisement),
            152 => Ok(IcmpType::MulticastRouterSolicitation),
            153 => Ok(IcmpType::MulticastRouterTermination),
            154 => Ok(IcmpType::Fmipv6Messages),
            155 => Ok(IcmpType::RplControlMessage),
            156 => Ok(IcmpType::MplControlMessage),
            157 => Ok(IcmpType::DuplicateAddressRequestCodeSuffix),
            158 => Ok(IcmpType::DuplicateAddressConfirmationCodeSuffix),
            160 => Ok(IcmpType::Icmpv6ExtendedEchoRequest),
            161 => Ok(IcmpType::Icmpv6ExtendedEchoReply),

            _ => Err(value),
        }
    }
}

// This allows converting an IcmpType enum variant back to its u8 representation.
// This is useful when constructing headers.
impl From<IcmpType> for u8 {
    fn from(icmp_type: IcmpType) -> Self {
        icmp_type as u8
    }
}

// Helper trait implementations for each code enum
impl From<EchoCode> for u8 {
    fn from(code: EchoCode) -> Self {
        code as u8
    }
}

impl From<DestinationUnreachableCode> for u8 {
    fn from(code: DestinationUnreachableCode) -> Self {
        code as u8
    }
}

impl From<RedirectCode> for u8 {
    fn from(code: RedirectCode) -> Self {
        code as u8
    }
}

impl From<RouterAdvertisementCode> for u8 {
    fn from(code: RouterAdvertisementCode) -> Self {
        code as u8
    }
}

impl From<RouterSelectionCode> for u8 {
    fn from(code: RouterSelectionCode) -> Self {
        code as u8
    }
}

impl From<TimeExceededCode> for u8 {
    fn from(code: TimeExceededCode) -> Self {
        code as u8
    }
}

impl From<ParameterProblemCode> for u8 {
    fn from(code: ParameterProblemCode) -> Self {
        code as u8
    }
}

impl From<TimestampCode> for u8 {
    fn from(code: TimestampCode) -> Self {
        code as u8
    }
}

impl From<TimestampReplyCode> for u8 {
    fn from(code: TimestampReplyCode) -> Self {
        code as u8
    }
}

impl From<InformationRequestCode> for u8 {
    fn from(code: InformationRequestCode) -> Self {
        code as u8
    }
}

impl From<InformationReplyCode> for u8 {
    fn from(code: InformationReplyCode) -> Self {
        code as u8
    }
}

impl From<AddressMaskRequestCode> for u8 {
    fn from(code: AddressMaskRequestCode) -> Self {
        code as u8
    }
}

impl From<AddressMaskReplyCode> for u8 {
    fn from(code: AddressMaskReplyCode) -> Self {
        code as u8
    }
}

impl From<PhoturisCode> for u8 {
    fn from(code: PhoturisCode) -> Self {
        code as u8
    }
}

impl From<ExtendedEchoRequestCode> for u8 {
    fn from(code: ExtendedEchoRequestCode) -> Self {
        code as u8
    }
}

impl From<ExtendedEchoReplyCode> for u8 {
    fn from(code: ExtendedEchoReplyCode) -> Self {
        code as u8
    }
}

// ICMPv6 code enum From implementations
impl From<Icmpv6DestinationUnreachableCode> for u8 {
    fn from(code: Icmpv6DestinationUnreachableCode) -> Self {
        code as u8
    }
}

impl From<PacketTooBigCode> for u8 {
    fn from(code: PacketTooBigCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6TimeExceededCode> for u8 {
    fn from(code: Icmpv6TimeExceededCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6ParameterProblemCode> for u8 {
    fn from(code: Icmpv6ParameterProblemCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6EchoRequestCode> for u8 {
    fn from(code: Icmpv6EchoRequestCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6EchoReplyCode> for u8 {
    fn from(code: Icmpv6EchoReplyCode) -> Self {
        code as u8
    }
}

impl From<MldQueryCode> for u8 {
    fn from(code: MldQueryCode) -> Self {
        code as u8
    }
}

impl From<MldReportCode> for u8 {
    fn from(code: MldReportCode) -> Self {
        code as u8
    }
}

impl From<MldDoneCode> for u8 {
    fn from(code: MldDoneCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6RouterSolicitationCode> for u8 {
    fn from(code: Icmpv6RouterSolicitationCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6RouterAdvertisementCode> for u8 {
    fn from(code: Icmpv6RouterAdvertisementCode) -> Self {
        code as u8
    }
}

impl From<NeighborSolicitationCode> for u8 {
    fn from(code: NeighborSolicitationCode) -> Self {
        code as u8
    }
}

impl From<NeighborAdvertisementCode> for u8 {
    fn from(code: NeighborAdvertisementCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6RedirectCode> for u8 {
    fn from(code: Icmpv6RedirectCode) -> Self {
        code as u8
    }
}

impl From<RouterRenumberingCode> for u8 {
    fn from(code: RouterRenumberingCode) -> Self {
        code as u8
    }
}

impl From<NodeInformationQueryCode> for u8 {
    fn from(code: NodeInformationQueryCode) -> Self {
        code as u8
    }
}

impl From<NodeInformationResponseCode> for u8 {
    fn from(code: NodeInformationResponseCode) -> Self {
        code as u8
    }
}

impl From<InverseNeighborDiscoverySolicitationCode> for u8 {
    fn from(code: InverseNeighborDiscoverySolicitationCode) -> Self {
        code as u8
    }
}

impl From<InverseNeighborDiscoveryAdvertisementCode> for u8 {
    fn from(code: InverseNeighborDiscoveryAdvertisementCode) -> Self {
        code as u8
    }
}

impl From<Mldv2MulticastListenerReportCode> for u8 {
    fn from(code: Mldv2MulticastListenerReportCode) -> Self {
        code as u8
    }
}

impl From<HomeAgentAddressDiscoveryRequestCode> for u8 {
    fn from(code: HomeAgentAddressDiscoveryRequestCode) -> Self {
        code as u8
    }
}

impl From<HomeAgentAddressDiscoveryReplyCode> for u8 {
    fn from(code: HomeAgentAddressDiscoveryReplyCode) -> Self {
        code as u8
    }
}

impl From<MobilePrefixSolicitationCode> for u8 {
    fn from(code: MobilePrefixSolicitationCode) -> Self {
        code as u8
    }
}

impl From<MobilePrefixAdvertisementCode> for u8 {
    fn from(code: MobilePrefixAdvertisementCode) -> Self {
        code as u8
    }
}

impl From<CertificationPathSolicitationCode> for u8 {
    fn from(code: CertificationPathSolicitationCode) -> Self {
        code as u8
    }
}

impl From<CertificationPathAdvertisementCode> for u8 {
    fn from(code: CertificationPathAdvertisementCode) -> Self {
        code as u8
    }
}

impl From<ExperimentalMobilityProtocolsCode> for u8 {
    fn from(code: ExperimentalMobilityProtocolsCode) -> Self {
        code as u8
    }
}

impl From<MulticastRouterAdvertisementCode> for u8 {
    fn from(code: MulticastRouterAdvertisementCode) -> Self {
        code as u8
    }
}

impl From<MulticastRouterSolicitationCode> for u8 {
    fn from(code: MulticastRouterSolicitationCode) -> Self {
        code as u8
    }
}

impl From<MulticastRouterTerminationCode> for u8 {
    fn from(code: MulticastRouterTerminationCode) -> Self {
        code as u8
    }
}

impl From<Fmipv6MessagesCode> for u8 {
    fn from(code: Fmipv6MessagesCode) -> Self {
        code as u8
    }
}

impl From<RplControlMessageCode> for u8 {
    fn from(code: RplControlMessageCode) -> Self {
        code as u8
    }
}

impl From<MplControlMessageCode> for u8 {
    fn from(code: MplControlMessageCode) -> Self {
        code as u8
    }
}

impl From<DuplicateAddressRequestCodeSuffixCode> for u8 {
    fn from(code: DuplicateAddressRequestCodeSuffixCode) -> Self {
        code as u8
    }
}

impl From<DuplicateAddressConfirmationCodeSuffixCode> for u8 {
    fn from(code: DuplicateAddressConfirmationCodeSuffixCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6ExtendedEchoRequestCode> for u8 {
    fn from(code: Icmpv6ExtendedEchoRequestCode) -> Self {
        code as u8
    }
}

impl From<Icmpv6ExtendedEchoReplyCode> for u8 {
    fn from(code: Icmpv6ExtendedEchoReplyCode) -> Self {
        code as u8
    }
}

// This allows converting an IcmpCode enum variant back to its u8 representation.
// This is useful when constructing headers.
impl From<IcmpCode> for u8 {
    fn from(icmp_code: IcmpCode) -> Self {
        match icmp_code {
            IcmpCode::Echo(code) => code.into(),
            IcmpCode::DestinationUnreachable(code) => code.into(),
            IcmpCode::Redirect(code) => code.into(),
            IcmpCode::RouterAdvertisement(code) => code.into(),
            IcmpCode::RouterSolicitation(code) => code.into(),
            IcmpCode::TimeExceeded(code) => code.into(),
            IcmpCode::ParameterProblem(code) => code.into(),
            IcmpCode::Timestamp(code) => code.into(),
            IcmpCode::TimestampReply(code) => code.into(),
            IcmpCode::InformationRequest(code) => code.into(),
            IcmpCode::InformationReply(code) => code.into(),
            IcmpCode::AddressMaskRequest(code) => code.into(),
            IcmpCode::AddressMaskReply(code) => code.into(),
            IcmpCode::Photuris(code) => code.into(),
            IcmpCode::ExtendedEchoRequest(code) => code.into(),
            IcmpCode::ExtendedEchoReply(code) => code.into(),
            // ICMPv6 specific codes
            IcmpCode::Icmpv6DestinationUnreachable(code) => code.into(),
            IcmpCode::PacketTooBig(code) => code.into(),
            IcmpCode::Icmpv6TimeExceeded(code) => code.into(),
            IcmpCode::Icmpv6ParameterProblem(code) => code.into(),
            IcmpCode::Icmpv6EchoRequest(code) => code.into(),
            IcmpCode::Icmpv6EchoReply(code) => code.into(),
            IcmpCode::MldQuery(code) => code.into(),
            IcmpCode::MldReport(code) => code.into(),
            IcmpCode::MldDone(code) => code.into(),
            IcmpCode::Icmpv6RouterSolicitation(code) => code.into(),
            IcmpCode::Icmpv6RouterAdvertisement(code) => code.into(),
            IcmpCode::NeighborSolicitation(code) => code.into(),
            IcmpCode::NeighborAdvertisement(code) => code.into(),
            IcmpCode::Icmpv6Redirect(code) => code.into(),
            IcmpCode::RouterRenumbering(code) => code.into(),
            IcmpCode::NodeInformationQuery(code) => code.into(),
            IcmpCode::NodeInformationResponse(code) => code.into(),
            IcmpCode::InverseNeighborDiscoverySolicitation(code) => code.into(),
            IcmpCode::InverseNeighborDiscoveryAdvertisement(code) => code.into(),
            IcmpCode::Mldv2MulticastListenerReport(code) => code.into(),
            IcmpCode::HomeAgentAddressDiscoveryRequest(code) => code.into(),
            IcmpCode::HomeAgentAddressDiscoveryReply(code) => code.into(),
            IcmpCode::MobilePrefixSolicitation(code) => code.into(),
            IcmpCode::MobilePrefixAdvertisement(code) => code.into(),
            IcmpCode::CertificationPathSolicitation(code) => code.into(),
            IcmpCode::CertificationPathAdvertisement(code) => code.into(),
            IcmpCode::ExperimentalMobilityProtocols(code) => code.into(),
            IcmpCode::MulticastRouterAdvertisement(code) => code.into(),
            IcmpCode::MulticastRouterSolicitation(code) => code.into(),
            IcmpCode::MulticastRouterTermination(code) => code.into(),
            IcmpCode::Fmipv6Messages(code) => code.into(),
            IcmpCode::RplControlMessage(code) => code.into(),
            IcmpCode::MplControlMessage(code) => code.into(),
            IcmpCode::DuplicateAddressRequestCodeSuffix(code) => code.into(),
            IcmpCode::DuplicateAddressConfirmationCodeSuffix(code) => code.into(),
            IcmpCode::Icmpv6ExtendedEchoRequest(code) => code.into(),
            IcmpCode::Icmpv6ExtendedEchoReply(code) => code.into(),
        }
    }
}

/// Helper method to parse code based on message type
fn parse_code_for_type(icmp_type: IcmpType, code_value: u8) -> Result<IcmpCode, u8> {
    match icmp_type {
        IcmpType::EchoReply | IcmpType::EchoRequest => match code_value {
            0 => Ok(IcmpCode::Echo(EchoCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::DestinationUnreachable => match code_value {
            0 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::NetUnreachable,
            )),
            1 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::HostUnreachable,
            )),
            2 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::ProtocolUnreachable,
            )),
            3 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::PortUnreachable,
            )),
            4 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::FragmentationNeeded,
            )),
            5 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::SourceRouteFailed,
            )),
            6 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::DestinationNetworkUnknown,
            )),
            7 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::DestinationHostUnknown,
            )),
            8 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::SourceHostIsolated,
            )),
            9 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::NetworkAdministrativelyProhibited,
            )),
            10 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::HostAdministrativelyProhibited,
            )),
            11 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::NetworkUnreachableForTos,
            )),
            12 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::HostUnreachableForTos,
            )),
            13 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::CommunicationAdministrativelyProhibited,
            )),
            14 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::HostPrecedenceViolation,
            )),
            15 => Ok(IcmpCode::DestinationUnreachable(
                DestinationUnreachableCode::PrecedenceCutoffInEffect,
            )),
            _ => Err(code_value),
        },
        IcmpType::Redirect => match code_value {
            0 => Ok(IcmpCode::Redirect(RedirectCode::RedirectForNetwork)),
            1 => Ok(IcmpCode::Redirect(RedirectCode::RedirectForHost)),
            2 => Ok(IcmpCode::Redirect(RedirectCode::RedirectForTosAndNetwork)),
            3 => Ok(IcmpCode::Redirect(RedirectCode::RedirectForTosAndHost)),
            _ => Err(code_value),
        },
        IcmpType::RouterAdvertisement => match code_value {
            0 => Ok(IcmpCode::RouterAdvertisement(
                RouterAdvertisementCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::RouterSelection => match code_value {
            0 => Ok(IcmpCode::RouterSolicitation(RouterSelectionCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::TimeExceeded => match code_value {
            0 => Ok(IcmpCode::TimeExceeded(TimeExceededCode::TtlExpired)),
            1 => Ok(IcmpCode::TimeExceeded(
                TimeExceededCode::FragmentReassemblyTimeExceeded,
            )),
            _ => Err(code_value),
        },
        IcmpType::ParameterProblem => match code_value {
            0 => Ok(IcmpCode::ParameterProblem(
                ParameterProblemCode::PointerIndicatesError,
            )),
            1 => Ok(IcmpCode::ParameterProblem(
                ParameterProblemCode::MissingRequiredOption,
            )),
            2 => Ok(IcmpCode::ParameterProblem(ParameterProblemCode::BadLength)),
            _ => Err(code_value),
        },
        IcmpType::Timestamp => match code_value {
            0 => Ok(IcmpCode::Timestamp(TimestampCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::TimestampReply => match code_value {
            0 => Ok(IcmpCode::TimestampReply(TimestampReplyCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::InformationRequest => match code_value {
            0 => Ok(IcmpCode::InformationRequest(InformationRequestCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::InformationReply => match code_value {
            0 => Ok(IcmpCode::InformationReply(InformationReplyCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::AddressMaskRequest => match code_value {
            0 => Ok(IcmpCode::AddressMaskRequest(AddressMaskRequestCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::AddressMaskReply => match code_value {
            0 => Ok(IcmpCode::AddressMaskReply(AddressMaskReplyCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::Photuris => match code_value {
            0 => Ok(IcmpCode::Photuris(PhoturisCode::BadSpi)),
            1 => Ok(IcmpCode::Photuris(PhoturisCode::AuthenticationFailed)),
            2 => Ok(IcmpCode::Photuris(PhoturisCode::DecompressionFailed)),
            3 => Ok(IcmpCode::Photuris(PhoturisCode::DecryptionFailed)),
            4 => Ok(IcmpCode::Photuris(PhoturisCode::NeedAuthentication)),
            5 => Ok(IcmpCode::Photuris(PhoturisCode::NeedAuthorization)),
            _ => Err(code_value),
        },
        IcmpType::ExtendedEchoRequest => match code_value {
            0 => Ok(IcmpCode::ExtendedEchoRequest(
                ExtendedEchoRequestCode::NoError,
            )),
            _ => Err(code_value),
        },
        IcmpType::ExtendedEchoReply => match code_value {
            0 => Ok(IcmpCode::ExtendedEchoReply(ExtendedEchoReplyCode::NoError)),
            1 => Ok(IcmpCode::ExtendedEchoReply(
                ExtendedEchoReplyCode::MalformedQuery,
            )),
            2 => Ok(IcmpCode::ExtendedEchoReply(
                ExtendedEchoReplyCode::NoSuchInterface,
            )),
            3 => Ok(IcmpCode::ExtendedEchoReply(
                ExtendedEchoReplyCode::NoSuchTableEntry,
            )),
            4 => Ok(IcmpCode::ExtendedEchoReply(
                ExtendedEchoReplyCode::MultipleInterfacesSatisfyQuery,
            )),
            _ => Err(code_value),
        },
        // ICMPv6 specific types
        IcmpType::Icmpv6DestinationUnreachable => match code_value {
            0 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::NoRouteToDestination,
            )),
            1 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::CommunicationWithDestinationAdministrativelyProhibited,
            )),
            2 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::BeyondScopeOfSourceAddress,
            )),
            3 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::AddressUnreachable,
            )),
            4 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::PortUnreachable,
            )),
            5 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::SourceAddressFailedIngressEgressPolicy,
            )),
            6 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::RejectRouteToDestination,
            )),
            7 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::ErrorInSourceRoutingHeader,
            )),
            8 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::HeadersTooLong,
            )),
            9 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::ErrorInPRoute,
            )),
            _ => Err(code_value),
        },
        IcmpType::PacketTooBig => match code_value {
            0 => Ok(IcmpCode::PacketTooBig(PacketTooBigCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6TimeExceeded => match code_value {
            0 => Ok(IcmpCode::Icmpv6TimeExceeded(
                Icmpv6TimeExceededCode::HopLimitExceeded,
            )),
            1 => Ok(IcmpCode::Icmpv6TimeExceeded(
                Icmpv6TimeExceededCode::FragmentReassemblyTimeExceeded,
            )),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6ParameterProblem => match code_value {
            0 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::ErroneousHeaderFieldEncountered)),
            1 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::UnrecognizedNextHeaderTypeEncountered)),
            2 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::UnrecognizedIPv6OptionEncountered)),
            3 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::IPv6FirstFragmentHasIncompleteIPv6HeaderChain)),
            4 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::SRUpperLayerHeaderError)),
            5 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::UnrecognizedNextHeaderTypeEncounteredByIntermediateNode)),
            6 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::ExtensionHeaderTooBig)),
            7 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::ExtensionHeaderChainTooLong)),
            8 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::TooManyExtensionHeaders)),
            9 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::TooManyOptionsInExtensionHeader)),
            10 => Ok(IcmpCode::Icmpv6ParameterProblem(Icmpv6ParameterProblemCode::OptionTooBig)),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6EchoRequest => match code_value {
            0 => Ok(IcmpCode::Icmpv6EchoRequest(Icmpv6EchoRequestCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6EchoReply => match code_value {
            0 => Ok(IcmpCode::Icmpv6EchoReply(Icmpv6EchoReplyCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::MldQuery => match code_value {
            0 => Ok(IcmpCode::MldQuery(MldQueryCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::MldReport => match code_value {
            0 => Ok(IcmpCode::MldReport(MldReportCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::MldDone => match code_value {
            0 => Ok(IcmpCode::MldDone(MldDoneCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6RouterSolicitation => match code_value {
            0 => Ok(IcmpCode::Icmpv6RouterSolicitation(
                Icmpv6RouterSolicitationCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6RouterAdvertisement => match code_value {
            0 => Ok(IcmpCode::Icmpv6RouterAdvertisement(
                Icmpv6RouterAdvertisementCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::NeighborSolicitation => match code_value {
            0 => Ok(IcmpCode::NeighborSolicitation(NeighborSolicitationCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::NeighborAdvertisement => match code_value {
            0 => Ok(IcmpCode::NeighborAdvertisement(NeighborAdvertisementCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6Redirect => match code_value {
            0 => Ok(IcmpCode::Icmpv6Redirect(Icmpv6RedirectCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::RouterRenumbering => match code_value {
            0 => Ok(IcmpCode::RouterRenumbering(RouterRenumberingCode::RouterRenumberingCommand)),
            1 => Ok(IcmpCode::RouterRenumbering(RouterRenumberingCode::RouterRenumberingResult)),
            255 => Ok(IcmpCode::RouterRenumbering(RouterRenumberingCode::SequenceNumberReset)),
            _ => Err(code_value),
        },
        IcmpType::NodeInformationQuery => match code_value {
            0 => Ok(IcmpCode::NodeInformationQuery(NodeInformationQueryCode::Data)),
            1 => Ok(IcmpCode::NodeInformationQuery(NodeInformationQueryCode::Name)),
            2 => Ok(IcmpCode::NodeInformationQuery(NodeInformationQueryCode::NameOrAddress)),
            _ => Err(code_value),
        },
        IcmpType::NodeInformationResponse => match code_value {
            0 => Ok(IcmpCode::NodeInformationResponse(NodeInformationResponseCode::SuccessfulResponse)),
            1 => Ok(IcmpCode::NodeInformationResponse(NodeInformationResponseCode::RespondingNodeIsTheNodeQueried)),
            2 => Ok(IcmpCode::NodeInformationResponse(NodeInformationResponseCode::QueryIsRecognizedButTheRequestedInfoIsUnavailable)),
            3 => Ok(IcmpCode::NodeInformationResponse(NodeInformationResponseCode::QueryIsNotRecognized)),
            _ => Err(code_value),
        },
        IcmpType::InverseNeighborDiscoverySolicitation => match code_value {
            0 => Ok(IcmpCode::InverseNeighborDiscoverySolicitation(
                InverseNeighborDiscoverySolicitationCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::InverseNeighborDiscoveryAdvertisement => match code_value {
            0 => Ok(IcmpCode::InverseNeighborDiscoveryAdvertisement(
                InverseNeighborDiscoveryAdvertisementCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::Mldv2MulticastListenerReport => match code_value {
            0 => Ok(IcmpCode::Mldv2MulticastListenerReport(
                Mldv2MulticastListenerReportCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::HomeAgentAddressDiscoveryRequest => match code_value {
            0 => Ok(IcmpCode::HomeAgentAddressDiscoveryRequest(
                HomeAgentAddressDiscoveryRequestCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::HomeAgentAddressDiscoveryReply => match code_value {
            0 => Ok(IcmpCode::HomeAgentAddressDiscoveryReply(
                HomeAgentAddressDiscoveryReplyCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::MobilePrefixSolicitation => match code_value {
            0 => Ok(IcmpCode::MobilePrefixSolicitation(
                MobilePrefixSolicitationCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::MobilePrefixAdvertisement => match code_value {
            0 => Ok(IcmpCode::MobilePrefixAdvertisement(
                MobilePrefixAdvertisementCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::CertificationPathSolicitation => match code_value {
            0 => Ok(IcmpCode::CertificationPathSolicitation(
                CertificationPathSolicitationCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::CertificationPathAdvertisement => match code_value {
            0 => Ok(IcmpCode::CertificationPathAdvertisement(
                CertificationPathAdvertisementCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::ExperimentalMobilityProtocols => match code_value {
            0 => Ok(IcmpCode::ExperimentalMobilityProtocols(
                ExperimentalMobilityProtocolsCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::MulticastRouterAdvertisement => match code_value {
            0 => Ok(IcmpCode::MulticastRouterAdvertisement(
                MulticastRouterAdvertisementCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::MulticastRouterSolicitation => match code_value {
            0 => Ok(IcmpCode::MulticastRouterSolicitation(
                MulticastRouterSolicitationCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::MulticastRouterTermination => match code_value {
            0 => Ok(IcmpCode::MulticastRouterTermination(
                MulticastRouterTerminationCode::NoCode,
            )),
            _ => Err(code_value),
        },
        IcmpType::Fmipv6Messages => match code_value {
            0 => Ok(IcmpCode::Fmipv6Messages(Fmipv6MessagesCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::RplControlMessage => match code_value {
            0 => Ok(IcmpCode::RplControlMessage(RplControlMessageCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::MplControlMessage => match code_value {
            0 => Ok(IcmpCode::MplControlMessage(MplControlMessageCode::NoCode)),
            _ => Err(code_value),
        },
        IcmpType::DuplicateAddressRequestCodeSuffix => match code_value {
            0 => Ok(IcmpCode::DuplicateAddressRequestCodeSuffix(
                DuplicateAddressRequestCodeSuffixCode::DarMessage,
            )),
            1 => Ok(IcmpCode::DuplicateAddressRequestCodeSuffix(
                DuplicateAddressRequestCodeSuffixCode::EdarMessageWith64BitRovrField,
            )),
            2 => Ok(IcmpCode::DuplicateAddressRequestCodeSuffix(
                DuplicateAddressRequestCodeSuffixCode::EdarMessageWith128BitRovrField,
            )),
            3 => Ok(IcmpCode::DuplicateAddressRequestCodeSuffix(
                DuplicateAddressRequestCodeSuffixCode::EdarMessageWith192BitRovrField,
            )),
            4 => Ok(IcmpCode::DuplicateAddressRequestCodeSuffix(
                DuplicateAddressRequestCodeSuffixCode::EdarMessageWith256BitRovrField,
            )),
            _ => Err(code_value),
        },
        IcmpType::DuplicateAddressConfirmationCodeSuffix => match code_value {
            0 => Ok(IcmpCode::DuplicateAddressConfirmationCodeSuffix(
                DuplicateAddressConfirmationCodeSuffixCode::DarMessage,
            )),
            1 => Ok(IcmpCode::DuplicateAddressConfirmationCodeSuffix(
                DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith64BitRovrField,
            )),
            2 => Ok(IcmpCode::DuplicateAddressConfirmationCodeSuffix(
                DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith128BitRovrField,
            )),
            3 => Ok(IcmpCode::DuplicateAddressConfirmationCodeSuffix(
                DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith192BitRovrField,
            )),
            4 => Ok(IcmpCode::DuplicateAddressConfirmationCodeSuffix(
                DuplicateAddressConfirmationCodeSuffixCode::EdarMessageWith256BitRovrField,
            )),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6ExtendedEchoRequest => match code_value {
            0 => Ok(IcmpCode::Icmpv6ExtendedEchoRequest(
                Icmpv6ExtendedEchoRequestCode::NoError,
            )),
            _ => Err(code_value),
        },
        IcmpType::Icmpv6ExtendedEchoReply => match code_value {
            0 => Ok(IcmpCode::Icmpv6ExtendedEchoReply(
                Icmpv6ExtendedEchoReplyCode::NoError,
            )),
            1 => Ok(IcmpCode::Icmpv6ExtendedEchoReply(
                Icmpv6ExtendedEchoReplyCode::MalformedQuery,
            )),
            2 => Ok(IcmpCode::Icmpv6ExtendedEchoReply(
                Icmpv6ExtendedEchoReplyCode::NoSuchInterface,
            )),
            3 => Ok(IcmpCode::Icmpv6ExtendedEchoReply(
                Icmpv6ExtendedEchoReplyCode::NoSuchTableEntry,
            )),
            4 => Ok(IcmpCode::Icmpv6ExtendedEchoReply(
                Icmpv6ExtendedEchoReplyCode::MultipleInterfacesSatisfyQuery,
            )),
            _ => Err(code_value),
        },
    }
}

// Helper functions for easy access to ICMP type and code names

/// Get the string name for an ICMP type from its numeric value.
/// Returns None if the type is unknown.
pub fn get_icmp_type_name(type_value: u8) -> Option<&'static str> {
    IcmpType::try_from_u8(type_value).map(|t| t.as_str())
}

/// Get the string name for an ICMP code from its type and code numeric values.
/// Returns None if the type or code is unknown.
pub fn get_icmp_code_name(type_value: u8, code_value: u8) -> Option<&'static str> {
    let icmp_type = IcmpType::try_from_u8(type_value)?;
    parse_code_for_type(icmp_type, code_value)
        .ok()
        .map(|c| c.as_str())
}

/// Get both ICMP type and code names from their numeric values.
/// Returns (type_name, code_name) as Option tuples.
pub fn get_icmp_names(
    type_value: u8,
    code_value: u8,
) -> (Option<&'static str>, Option<&'static str>) {
    let type_name = get_icmp_type_name(type_value);
    let code_name = get_icmp_code_name(type_value, code_value);
    (type_name, code_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_hdr_size() {
        // IcmpHdr should be exactly 8 bytes
        assert_eq!(IcmpHdr::LEN, 8);
        assert_eq!(IcmpHdr::LEN, mem::size_of::<IcmpHdr>());
    }

    #[test]
    fn test_icmp_type_and_code() {
        let mut icmp_hdr = IcmpHdr {
            _type: 0,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test Echo Request
        icmp_hdr.set_icmp_type(IcmpType::EchoRequest);
        icmp_hdr.set_code(IcmpCode::Echo(EchoCode::NoCode));
        assert_eq!(icmp_hdr.icmp_type().unwrap(), IcmpType::EchoRequest);
        assert_eq!(icmp_hdr.code().unwrap(), IcmpCode::Echo(EchoCode::NoCode));

        // Test Echo Reply
        icmp_hdr.set_icmp_type(IcmpType::EchoReply);
        icmp_hdr.set_code(IcmpCode::Echo(EchoCode::NoCode));
        assert_eq!(icmp_hdr.icmp_type().unwrap(), IcmpType::EchoReply);
        assert_eq!(icmp_hdr.code().unwrap(), IcmpCode::Echo(EchoCode::NoCode));

        // Test Destination Unreachable
        icmp_hdr.set_icmp_type(IcmpType::DestinationUnreachable);
        icmp_hdr.set_code(IcmpCode::DestinationUnreachable(
            DestinationUnreachableCode::HostUnreachable,
        ));
        assert_eq!(
            icmp_hdr.icmp_type().unwrap(),
            IcmpType::DestinationUnreachable
        );
        assert_eq!(
            icmp_hdr.code().unwrap(),
            IcmpCode::DestinationUnreachable(DestinationUnreachableCode::HostUnreachable)
        );
    }

    #[test]
    fn test_checksum() {
        let mut icmp_hdr = IcmpHdr {
            _type: IcmpType::EchoRequest as u8,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_checksum: u16 = 0x1234;
        icmp_hdr.set_checksum(test_checksum);
        assert_eq!(icmp_hdr.checksum(), test_checksum);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(icmp_hdr.checksum, [0x12, 0x34]);

        // Test with zero
        icmp_hdr.set_checksum(0);
        assert_eq!(icmp_hdr.checksum(), 0);
        assert_eq!(icmp_hdr.checksum, [0, 0]);

        // Test with max value
        icmp_hdr.set_checksum(u16::MAX);
        assert_eq!(icmp_hdr.checksum(), u16::MAX);
        assert_eq!(icmp_hdr.checksum, [0xFF, 0xFF]);
    }

    #[test]
    fn test_data_field() {
        let mut icmp_hdr = IcmpHdr {
            _type: IcmpType::EchoRequest as u8,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_data: u32 = 0x12345678;
        icmp_hdr.set_data(test_data);
        assert_eq!(icmp_hdr.data(), test_data);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(icmp_hdr.data, [0x12, 0x34, 0x56, 0x78]);

        // Test with zero
        icmp_hdr.set_data(0);
        assert_eq!(icmp_hdr.data(), 0);
        assert_eq!(icmp_hdr.data, [0, 0, 0, 0]);

        // Test with max value
        icmp_hdr.set_data(u32::MAX);
        assert_eq!(icmp_hdr.data(), u32::MAX);
        assert_eq!(icmp_hdr.data, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_echo_request_reply_fields() {
        let mut icmp_hdr = IcmpHdr {
            _type: IcmpType::EchoRequest as u8,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test identifier
        let test_id: u16 = 0x1234;
        icmp_hdr.set_identifier(test_id);
        assert_eq!(icmp_hdr.identifier(), test_id);
        assert_eq!(icmp_hdr.data[0], 0x12);
        assert_eq!(icmp_hdr.data[1], 0x34);

        // Test sequence number
        let test_seq: u16 = 0x5678;
        icmp_hdr.set_sequence(test_seq);
        assert_eq!(icmp_hdr.sequence(), test_seq);
        assert_eq!(icmp_hdr.data[2], 0x56);
        assert_eq!(icmp_hdr.data[3], 0x78);

        // Verify identifier is still intact
        assert_eq!(icmp_hdr.identifier(), test_id);

        // Test combined data field
        assert_eq!(icmp_hdr.data(), 0x12345678);
    }

    #[test]
    fn test_icmp_type_enum() {
        assert_eq!(IcmpType::EchoReply as u8, 0);
        assert_eq!(IcmpType::DestinationUnreachable as u8, 3);
        assert_eq!(IcmpType::EchoRequest as u8, 8);
        assert_eq!(IcmpType::TimeExceeded as u8, 11);
    }

    #[test]
    fn test_get_icmp_type_name() {
        // Test IPv4 ICMP types
        assert_eq!(get_icmp_type_name(0), Some("echo_reply"));
        assert_eq!(get_icmp_type_name(3), Some("destination_unreachable"));
        assert_eq!(get_icmp_type_name(4), Some("source_quench"));
        assert_eq!(get_icmp_type_name(5), Some("redirect"));
        assert_eq!(get_icmp_type_name(8), Some("echo_request"));
        assert_eq!(get_icmp_type_name(9), Some("router_advertisement"));
        assert_eq!(get_icmp_type_name(10), Some("router_solicitation"));
        assert_eq!(get_icmp_type_name(11), Some("time_exceeded"));
        assert_eq!(get_icmp_type_name(12), Some("parameter_problem"));
        assert_eq!(get_icmp_type_name(42), Some("extended_echo_request"));
        assert_eq!(get_icmp_type_name(43), Some("extended_echo_reply"));

        // Test ICMPv6 types
        assert_eq!(
            get_icmp_type_name(1),
            Some("icmpv6_destination_unreachable")
        );
        assert_eq!(get_icmp_type_name(2), Some("packet_too_big"));
        assert_eq!(get_icmp_type_name(101), Some("icmpv6_time_exceeded"));
        assert_eq!(get_icmp_type_name(102), Some("icmpv6_parameter_problem"));
        assert_eq!(get_icmp_type_name(128), Some("icmpv6_echo_request"));
        assert_eq!(get_icmp_type_name(129), Some("icmpv6_echo_reply"));
        assert_eq!(get_icmp_type_name(130), Some("mld_query"));
        assert_eq!(get_icmp_type_name(131), Some("mld_report"));
        assert_eq!(get_icmp_type_name(132), Some("mld_done"));
        assert_eq!(get_icmp_type_name(133), Some("icmpv6_router_solicitation"));
        assert_eq!(get_icmp_type_name(134), Some("icmpv6_router_advertisement"));
        assert_eq!(get_icmp_type_name(135), Some("neighbor_solicitation"));
        assert_eq!(get_icmp_type_name(136), Some("neighbor_advertisement"));
        assert_eq!(get_icmp_type_name(137), Some("icmpv6_redirect"));
        assert_eq!(
            get_icmp_type_name(160),
            Some("icmpv6_extended_echo_request")
        );
        assert_eq!(get_icmp_type_name(161), Some("icmpv6_extended_echo_reply"));

        // Test unknown types
        assert_eq!(get_icmp_type_name(6), None);
        assert_eq!(get_icmp_type_name(7), None);
        assert_eq!(get_icmp_type_name(255), None);
    }

    #[test]
    fn test_get_icmp_code_name() {
        // Test Echo Request/Reply (should have no-code for code 0)
        assert_eq!(get_icmp_code_name(0, 0), Some("")); // Echo Reply
        assert_eq!(get_icmp_code_name(8, 0), Some("")); // Echo Request
        assert_eq!(get_icmp_code_name(0, 1), None); // Invalid code for Echo Reply
        assert_eq!(get_icmp_code_name(8, 1), None); // Invalid code for Echo Request

        // Test Destination Unreachable codes (type 3)
        assert_eq!(get_icmp_code_name(3, 0), Some("net_unreachable"));
        assert_eq!(get_icmp_code_name(3, 1), Some("host_unreachable"));
        assert_eq!(get_icmp_code_name(3, 2), Some("protocol_unreachable"));
        assert_eq!(get_icmp_code_name(3, 3), Some("port_unreachable"));
        assert_eq!(get_icmp_code_name(3, 4), Some("fragmentation_needed"));
        assert_eq!(
            get_icmp_code_name(3, 15),
            Some("precedence_cutoff_in_effect")
        );
        assert_eq!(get_icmp_code_name(3, 16), None); // Invalid code

        // Test Redirect codes (type 5)
        assert_eq!(get_icmp_code_name(5, 0), Some("redirect_for_network"));
        assert_eq!(get_icmp_code_name(5, 1), Some("redirect_for_host"));
        assert_eq!(
            get_icmp_code_name(5, 2),
            Some("redirect_for_tos_and_network")
        );
        assert_eq!(get_icmp_code_name(5, 3), Some("redirect_for_tos_and_host"));
        assert_eq!(get_icmp_code_name(5, 4), None); // Invalid code

        // Test Time Exceeded codes (type 11)
        assert_eq!(get_icmp_code_name(11, 0), Some("ttl_expired"));
        assert_eq!(
            get_icmp_code_name(11, 1),
            Some("fragment_reassembly_time_exceeded")
        );
        assert_eq!(get_icmp_code_name(11, 2), None); // Invalid code

        // Test Extended Echo Reply codes (type 43)
        assert_eq!(get_icmp_code_name(43, 0), Some("no_error"));
        assert_eq!(get_icmp_code_name(43, 1), Some("malformed_query"));
        assert_eq!(get_icmp_code_name(43, 2), Some("no_such_interface"));
        assert_eq!(get_icmp_code_name(43, 3), Some("no_such_table_entry"));
        assert_eq!(
            get_icmp_code_name(43, 4),
            Some("multiple_interfaces_satisfy_query")
        );
        assert_eq!(get_icmp_code_name(43, 5), None); // Invalid code

        // Test ICMPv6 Destination Unreachable codes (type 1)
        assert_eq!(get_icmp_code_name(1, 0), Some("no_route_to_destination"));
        assert_eq!(
            get_icmp_code_name(1, 1),
            Some("communication_with_destination_administratively_prohibited")
        );
        assert_eq!(get_icmp_code_name(1, 3), Some("address_unreachable"));
        assert_eq!(get_icmp_code_name(1, 4), Some("port_unreachable"));
        assert_eq!(get_icmp_code_name(1, 12), None); // Invalid code

        // Test ICMPv6 Parameter Problem codes (type 102)
        assert_eq!(
            get_icmp_code_name(102, 0),
            Some("erroneous_header_field_encountered")
        );
        assert_eq!(
            get_icmp_code_name(102, 1),
            Some("unrecognized_next_header_type_encountered")
        );
        assert_eq!(
            get_icmp_code_name(102, 2),
            Some("unrecognized_ipv6_option_encountered")
        );
        assert_eq!(get_icmp_code_name(102, 3), None); // Invalid code

        // Test Router Renumbering codes (type 138) - has special code 255
        assert_eq!(
            get_icmp_code_name(138, 0),
            Some("router_renumbering_command")
        );
        assert_eq!(
            get_icmp_code_name(138, 1),
            Some("router_renumbering_result")
        );
        assert_eq!(get_icmp_code_name(138, 255), Some("sequence_number_reset"));
        assert_eq!(get_icmp_code_name(138, 2), None); // Invalid code

        // Test Node Information Query codes (type 139)
        assert_eq!(get_icmp_code_name(139, 0), Some("data"));
        assert_eq!(get_icmp_code_name(139, 1), Some("name"));
        assert_eq!(get_icmp_code_name(139, 2), Some("name_or_address"));
        assert_eq!(get_icmp_code_name(139, 3), None); // Invalid code

        // Test unknown ICMP type
        assert_eq!(get_icmp_code_name(99, 0), None);
        assert_eq!(get_icmp_code_name(255, 0), None);
    }

    #[test]
    fn test_get_icmp_names() {
        // Test valid type and code combinations
        assert_eq!(get_icmp_names(8, 0), (Some("echo_request"), Some("")));
        assert_eq!(
            get_icmp_names(3, 1),
            (Some("destination_unreachable"), Some("host_unreachable"))
        );
        assert_eq!(
            get_icmp_names(11, 0),
            (Some("time_exceeded"), Some("ttl_expired"))
        );
        assert_eq!(
            get_icmp_names(43, 4),
            (
                Some("extended_echo_reply"),
                Some("multiple_interfaces_satisfy_query")
            )
        );

        // Test ICMPv6 combinations
        assert_eq!(
            get_icmp_names(128, 0),
            (Some("icmpv6_echo_request"), Some(""))
        );
        assert_eq!(
            get_icmp_names(1, 3),
            (
                Some("icmpv6_destination_unreachable"),
                Some("address_unreachable")
            )
        );
        assert_eq!(
            get_icmp_names(102, 1),
            (
                Some("icmpv6_parameter_problem"),
                Some("unrecognized_next_header_type_encountered")
            )
        );

        // Test unknown type (should return None for both)
        assert_eq!(get_icmp_names(99, 0), (None, None));

        // Test valid type but invalid code (should return type name but None for code)
        assert_eq!(get_icmp_names(8, 99), (Some("echo_request"), None));
        assert_eq!(
            get_icmp_names(3, 99),
            (Some("destination_unreachable"), None)
        );

        // Test boundary cases
        assert_eq!(
            get_icmp_names(138, 255), // Router Renumbering with special code 255
            (Some("router_renumbering"), Some("sequence_number_reset"))
        );
    }

    #[test]
    fn test_comprehensive_icmp_coverage() {
        // Test that all defined ICMP types can be resolved to names
        let test_types = [
            0, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 42, 43, // IPv4
            1, 2, 101, 102, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
            142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 160,
            161, // ICMPv6
        ];

        for &type_val in &test_types {
            let type_name = get_icmp_type_name(type_val);
            assert!(type_name.is_some(), "Type {} should have a name", type_val);

            // Test that we can get at least code 0 for each type (most common)
            let code_name = get_icmp_code_name(type_val, 0);
            assert!(
                code_name.is_some(),
                "Type {} should have a valid code 0",
                type_val
            );
        }
    }

    #[test]
    fn test_icmp_code_as_str_delegation() {
        // Test that IcmpCode::as_str properly delegates to individual code enums
        let echo_code = IcmpCode::Echo(EchoCode::NoCode);
        assert_eq!(echo_code.as_str(), "");

        let dest_unreach_code =
            IcmpCode::DestinationUnreachable(DestinationUnreachableCode::HostUnreachable);
        assert_eq!(dest_unreach_code.as_str(), "host_unreachable");

        let redirect_code = IcmpCode::Redirect(RedirectCode::RedirectForTosAndNetwork);
        assert_eq!(redirect_code.as_str(), "redirect_for_tos_and_network");

        let time_exceeded_code =
            IcmpCode::TimeExceeded(TimeExceededCode::FragmentReassemblyTimeExceeded);
        assert_eq!(
            time_exceeded_code.as_str(),
            "fragment_reassembly_time_exceeded"
        );

        // ICMPv6 examples
        let icmpv6_dest_unreach = IcmpCode::Icmpv6DestinationUnreachable(
            Icmpv6DestinationUnreachableCode::BeyondScopeOfSourceAddress,
        );
        assert_eq!(
            icmpv6_dest_unreach.as_str(),
            "beyond_scope_of_source_address"
        );

        let node_info_response = IcmpCode::NodeInformationResponse(
            NodeInformationResponseCode::QueryIsRecognizedButTheRequestedInfoIsUnavailable,
        );
        assert_eq!(
            node_info_response.as_str(),
            "query_is_recognized_but_the_requested_info_is_unavailable"
        );
    }

    #[test]
    fn test_parse_code_for_type_integration() {
        // Test that the internal parse_code_for_type function works correctly
        // by testing it through the public API

        // Test various type/code combinations that should work
        let test_cases = [
            (8, 0, ""),                                       // Echo Request
            (3, 1, "host_unreachable"),                       // Dest Unreachable
            (5, 2, "redirect_for_tos_and_network"),           // Redirect
            (11, 1, "fragment_reassembly_time_exceeded"),     // Time Exceeded
            (43, 4, "multiple_interfaces_satisfy_query"),     // Extended Echo Reply
            (1, 0, "no_route_to_destination"),                // ICMPv6 Dest Unreachable
            (102, 2, "unrecognized_ipv6_option_encountered"), // ICMPv6 Parameter Problem
            (138, 255, "sequence_number_reset"),              // Router Renumbering special code
            (139, 1, "name"),                                 // Node Information Query
        ];

        for &(type_val, code_val, expected_name) in &test_cases {
            let result = get_icmp_code_name(type_val, code_val);
            assert_eq!(
                result,
                Some(expected_name),
                "Failed for type {} code {}: expected '{}', got {:?}",
                type_val,
                code_val,
                expected_name,
                result
            );
        }
    }
}
