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
///     icmp_type: 8,  // Echo Request
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
    pub icmp_type: u8,
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
        IcmpType::try_from(self.icmp_type)
    }

    /// Sets the ICMP message type.
    ///
    /// # Parameters
    /// * `icmp_type` - The ICMP message type to set.
    #[inline]
    pub fn set_icmp_type(&mut self, icmp_type: IcmpType) {
        self.icmp_type = icmp_type as u8;
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
            icmp_type: 0,
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
            icmp_type: IcmpType::EchoRequest as u8,
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
            icmp_type: IcmpType::EchoRequest as u8,
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
            icmp_type: IcmpType::EchoRequest as u8,
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
