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
    /// Source Quench (deprecated)
    SourceQuench = 4,
    /// Redirect
    Redirect = 5,
    /// Echo Request (ping)
    EchoRequest = 8,
    /// Router Advertisement
    RouterAdvertisement = 9,
    /// Router Solicitation
    RouterSolicitation = 10,
    /// Time Exceeded
    TimeExceeded = 11,
    /// Parameter Problem
    ParameterProblem = 12,
    /// Timestamp Request
    TimestampRequest = 13,
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
    Icmpv6TimeExceeded = 101,
    /// Parameter Problem (ICMPv6) - Note: different from IPv4 type 12
    Icmpv6ParameterProblem = 102,
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
    /// Extended Echo Request (ICMPv6)
    Icmpv6ExtendedEchoRequest = 160,
    /// Extended Echo Reply (ICMPv6)
    Icmpv6ExtendedEchoReply = 161,
}

/// Echo Reply and Echo Request codes (types 0, 8)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EchoCode {
    NoCode = 0,
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

/// Source Quench codes (type 4) - deprecated
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SourceQuenchCode {
    NoCode = 0,
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

/// Router Advertisement codes (type 9)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RouterAdvertisementCode {
    NoCode = 0,
}

/// Router Solicitation codes (type 10)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RouterSolicitationCode {
    NoCode = 0,
}

/// Time Exceeded codes (type 11)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimeExceededCode {
    TtlExpired = 0,
    FragmentReassemblyTimeExceeded = 1,
}

/// Parameter Problem codes (type 12)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParameterProblemCode {
    PointerIndicatesError = 0,
    MissingRequiredOption = 1,
    BadLength = 2,
}

/// Timestamp Request codes (type 13)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimestampRequestCode {
    NoCode = 0,
}

/// Timestamp Reply codes (type 14)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimestampReplyCode {
    NoCode = 0,
}

/// Information Request codes (type 15) - deprecated
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InformationRequestCode {
    NoCode = 0,
}

/// Information Reply codes (type 16) - deprecated
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InformationReplyCode {
    NoCode = 0,
}

/// Address Mask Request codes (type 17)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressMaskRequestCode {
    NoCode = 0,
}

/// Address Mask Reply codes (type 18)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressMaskReplyCode {
    NoCode = 0,
}

/// Extended Echo Request codes (type 42)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExtendedEchoRequestCode {
    NoError = 0,
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
    UnknownNextHeaderType = 9,
    Icmpv6HeaderError = 10,
    UnrecognizedOption = 11,
}

/// ICMPv6 Packet Too Big codes (type 2)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PacketTooBigCode {
    NoCode = 0,
}

/// ICMPv6 Time Exceeded codes (type 101)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6TimeExceededCode {
    HopLimitExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,
}

/// ICMPv6 Parameter Problem codes (type 102)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6ParameterProblemCode {
    ErroneousHeaderFieldEncountered = 0,
    UnrecognizedNextHeaderTypeEncountered = 1,
    UnrecognizedIpv6OptionEncountered = 2,
}

/// ICMPv6 Echo Request codes (type 128)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6EchoRequestCode {
    NoCode = 0,
}

/// ICMPv6 Echo Reply codes (type 129)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6EchoReplyCode {
    NoCode = 0,
}

/// ICMPv6 MLD Query codes (type 130)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MldQueryCode {
    NoCode = 0,
}

/// ICMPv6 MLD Report codes (type 131)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MldReportCode {
    NoCode = 0,
}

/// ICMPv6 MLD Done codes (type 132)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MldDoneCode {
    NoCode = 0,
}

/// ICMPv6 Router Solicitation codes (type 133)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6RouterSolicitationCode {
    NoCode = 0,
}

/// ICMPv6 Router Advertisement codes (type 134)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6RouterAdvertisementCode {
    NoCode = 0,
}

/// ICMPv6 Neighbor Solicitation codes (type 135)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NeighborSolicitationCode {
    NoCode = 0,
}

/// ICMPv6 Neighbor Advertisement codes (type 136)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NeighborAdvertisementCode {
    NoCode = 0,
}

/// ICMPv6 Redirect codes (type 137)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6RedirectCode {
    RedirectForNetwork = 0,
    RedirectForHost = 1,
    RedirectForTosAndNetwork = 2,
    RedirectForTosAndHost = 3,
}

/// ICMPv6 Router Renumbering codes (type 138)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RouterRenumberingCode {
    RouterRenumberingCommand = 0,
    RouterRenumberingResult = 1,
    SequenceNumberReset = 255,
}

/// ICMPv6 Node Information Query codes (type 139)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NodeInformationQueryCode {
    Data = 0,
    Name = 1,
    NameOrAddress = 2,
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

/// ICMPv6 Inverse Neighbor Discovery Solicitation codes (type 141)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InverseNeighborDiscoverySolicitationCode {
    NoCode = 0,
}

/// ICMPv6 Inverse Neighbor Discovery Advertisement codes (type 142)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InverseNeighborDiscoveryAdvertisementCode {
    NoCode = 0,
}

/// ICMPv6 MLDv2 Multicast Listener Report codes (type 143)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Mldv2MulticastListenerReportCode {
    NoCode = 0,
}

/// ICMPv6 Home Agent Address Discovery Request codes (type 144)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HomeAgentAddressDiscoveryRequestCode {
    NoCode = 0,
}

/// ICMPv6 Home Agent Address Discovery Reply codes (type 145)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HomeAgentAddressDiscoveryReplyCode {
    NoCode = 0,
}

/// ICMPv6 Mobile Prefix Solicitation codes (type 146)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MobilePrefixSolicitationCode {
    NoCode = 0,
}

/// ICMPv6 Mobile Prefix Advertisement codes (type 147)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MobilePrefixAdvertisementCode {
    NoCode = 0,
}

/// ICMPv6 Certification Path Solicitation codes (type 148)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertificationPathSolicitationCode {
    NoCode = 0,
}

/// ICMPv6 Certification Path Advertisement codes (type 149)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertificationPathAdvertisementCode {
    NoCode = 0,
}

/// ICMPv6 Experimental Mobility Protocols codes (type 150)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExperimentalMobilityProtocolsCode {
    NoCode = 0,
}

/// ICMPv6 Multicast Router Advertisement codes (type 151)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MulticastRouterAdvertisementCode {
    NoCode = 0,
}

/// ICMPv6 Multicast Router Solicitation codes (type 152)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MulticastRouterSolicitationCode {
    NoCode = 0,
}

/// ICMPv6 Multicast Router Termination codes (type 153)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MulticastRouterTerminationCode {
    NoCode = 0,
}

/// ICMPv6 FMIPv6 Messages codes (type 154)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Fmipv6MessagesCode {
    NoCode = 0,
}

/// ICMPv6 RPL Control Message codes (type 155)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RplControlMessageCode {
    NoCode = 0,
}

/// ICMPv6 MPL Control Message codes (type 156)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MplControlMessageCode {
    NoCode = 0,
}

/// ICMPv6 Extended Echo Request codes (type 160)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6ExtendedEchoRequestCode {
    NoError = 0,
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

/// Generic ICMP code enum that can represent codes for any ICMP message type
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IcmpCode {
    Echo(EchoCode),
    DestinationUnreachable(DestinationUnreachableCode),
    SourceQuench(SourceQuenchCode),
    Redirect(RedirectCode),
    RouterAdvertisement(RouterAdvertisementCode),
    RouterSolicitation(RouterSolicitationCode),
    TimeExceeded(TimeExceededCode),
    ParameterProblem(ParameterProblemCode),
    TimestampRequest(TimestampRequestCode),
    TimestampReply(TimestampReplyCode),
    InformationRequest(InformationRequestCode),
    InformationReply(InformationReplyCode),
    AddressMaskRequest(AddressMaskRequestCode),
    AddressMaskReply(AddressMaskReplyCode),
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
    Icmpv6ExtendedEchoRequest(Icmpv6ExtendedEchoRequestCode),
    Icmpv6ExtendedEchoReply(Icmpv6ExtendedEchoReplyCode),
    MldQuery(MldQueryCode),
    MldReport(MldReportCode),
    MldDone(MldDoneCode),
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
            4 => Ok(IcmpType::SourceQuench),
            5 => Ok(IcmpType::Redirect),
            8 => Ok(IcmpType::EchoRequest),
            9 => Ok(IcmpType::RouterAdvertisement),
            10 => Ok(IcmpType::RouterSolicitation),
            11 => Ok(IcmpType::TimeExceeded),
            12 => Ok(IcmpType::ParameterProblem),
            13 => Ok(IcmpType::TimestampRequest),
            14 => Ok(IcmpType::TimestampReply),
            15 => Ok(IcmpType::InformationRequest),
            16 => Ok(IcmpType::InformationReply),
            17 => Ok(IcmpType::AddressMaskRequest),
            18 => Ok(IcmpType::AddressMaskReply),
            42 => Ok(IcmpType::ExtendedEchoRequest),
            43 => Ok(IcmpType::ExtendedEchoReply),
            // ICMPv6 specific types (RFC 4443)
            1 => Ok(IcmpType::Icmpv6DestinationUnreachable),
            2 => Ok(IcmpType::PacketTooBig),
            101 => Ok(IcmpType::Icmpv6TimeExceeded),
            102 => Ok(IcmpType::Icmpv6ParameterProblem),
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

impl From<SourceQuenchCode> for u8 {
    fn from(code: SourceQuenchCode) -> Self {
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

impl From<RouterSolicitationCode> for u8 {
    fn from(code: RouterSolicitationCode) -> Self {
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

impl From<TimestampRequestCode> for u8 {
    fn from(code: TimestampRequestCode) -> Self {
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
            IcmpCode::SourceQuench(code) => code.into(),
            IcmpCode::Redirect(code) => code.into(),
            IcmpCode::RouterAdvertisement(code) => code.into(),
            IcmpCode::RouterSolicitation(code) => code.into(),
            IcmpCode::TimeExceeded(code) => code.into(),
            IcmpCode::ParameterProblem(code) => code.into(),
            IcmpCode::TimestampRequest(code) => code.into(),
            IcmpCode::TimestampReply(code) => code.into(),
            IcmpCode::InformationRequest(code) => code.into(),
            IcmpCode::InformationReply(code) => code.into(),
            IcmpCode::AddressMaskRequest(code) => code.into(),
            IcmpCode::AddressMaskReply(code) => code.into(),
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
        IcmpType::SourceQuench => match code_value {
            0 => Ok(IcmpCode::SourceQuench(SourceQuenchCode::NoCode)),
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
        IcmpType::RouterSolicitation => match code_value {
            0 => Ok(IcmpCode::RouterSolicitation(RouterSolicitationCode::NoCode)),
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
        IcmpType::TimestampRequest => match code_value {
            0 => Ok(IcmpCode::TimestampRequest(TimestampRequestCode::NoCode)),
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
                Icmpv6DestinationUnreachableCode::UnknownNextHeaderType,
            )),
            10 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::Icmpv6HeaderError,
            )),
            11 => Ok(IcmpCode::Icmpv6DestinationUnreachable(
                Icmpv6DestinationUnreachableCode::UnrecognizedOption,
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
            0 => Ok(IcmpCode::Icmpv6ParameterProblem(
                Icmpv6ParameterProblemCode::ErroneousHeaderFieldEncountered,
            )),
            1 => Ok(IcmpCode::Icmpv6ParameterProblem(
                Icmpv6ParameterProblemCode::UnrecognizedNextHeaderTypeEncountered,
            )),
            2 => Ok(IcmpCode::Icmpv6ParameterProblem(
                Icmpv6ParameterProblemCode::UnrecognizedIpv6OptionEncountered,
            )),
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
            0 => Ok(IcmpCode::Icmpv6Redirect(Icmpv6RedirectCode::RedirectForNetwork)),
            1 => Ok(IcmpCode::Icmpv6Redirect(Icmpv6RedirectCode::RedirectForHost)),
            2 => Ok(IcmpCode::Icmpv6Redirect(Icmpv6RedirectCode::RedirectForTosAndNetwork)),
            3 => Ok(IcmpCode::Icmpv6Redirect(Icmpv6RedirectCode::RedirectForTosAndHost)),
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
}
