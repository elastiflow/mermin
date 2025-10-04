#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
use network_types::{eth::EtherType, wireguard::WireGuardType};

/// Test data structures containing only the fields actually extracted by the parser
/// These mirror what gets stored in PacketMeta, not the full protocol headers
#[cfg(feature = "user")]
unsafe impl Pod for ParsedHeader {}

/// An enum to tell the eBPF program which header to parse.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum PacketType {
    #[default]
    Eth = 1,
    Ipv4 = 2,
    Ipv6 = 3,
    Tcp = 4,
    Udp = 5,
    Ah = 6,
    Esp = 7,
    Hop = 8,
    Geneve = 9,
    GenericRoute = 10,
    Fragment = 15,
    DestOpts = 16,
    Vxlan = 17,
    Mobility = 18,
    Shim6 = 19,
    Hip = 20,
    Gre = 21,
    WireGuardInit = 22,
    WireGuardResponse = 23,
    WireGuardCookieReply = 24,
    WireGuardTransportData = 25,
}

/// A union to hold any of the possible parsed network headers.
/// This allows us to have a single, fixed-size return type.
/// Contains only the fields actually extracted by the parser, not full protocol headers.
#[repr(C)]
#[derive(Copy, Clone)]
pub union HeaderUnion {
    pub eth: EthernetTestData,
    pub ipv4: Ipv4TestData,
    pub ipv6: Ipv6TestData,
    pub tcp: TcpTestData,
    pub udp: UdpTestData,
    pub ah: AhTestData,
    pub esp: EspTestData,
    pub hop: HopOptTestData,
    pub fragment: FragmentTestData,
    pub destopts: DestOptsTestData,
    pub mobility: MobilityTestData,
    pub shim6: Shim6TestData,
    pub geneve: GeneveTestData,
    pub vxlan: VxlanTestData,
    pub hip: HipTestData,
    pub gre: GreTestData,
    pub generic_route: GenericRouteTestData,
    pub wireguard_init: WireGuardInitTestData,
    pub wireguard_response: WireGuardResponseTestData,
    pub wireguard_cookie_reply: WireGuardCookieReplyTestData,
    pub wireguard_transport_data: WireGuardTransportDataTestData,
    pub placeholder: [u8; 64],
}

/// The final struct sent back to user-space. It contains the type of
/// header that was parsed and the parsed data itself in the union.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct ParsedHeader {
    pub type_: PacketType,
    pub data: HeaderUnion,
}

/// Ethernet test data - only fields extracted from Ethernet header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EthernetTestData {
    pub mac_addr: [u8; 6], // First 6 bytes (dst MAC in actual frame, stored as src in meta)
    pub ether_type: EtherType, // Bytes 12-13
}

/// UDP test data - only fields extracted from UDP header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpTestData {
    pub src_port: [u8; 2], // Bytes 0-1
    pub dst_port: [u8; 2], // Bytes 2-3
}

/// TCP test data - only fields extracted from TCP header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TcpTestData {
    pub src_port: [u8; 2], // Bytes 0-1
    pub dst_port: [u8; 2], // Bytes 2-3
    pub tcp_flags: u8,     // Byte 13
    pub _padding: [u8; 3], // Explicit padding to 8 bytes for alignment
}

/// IPv4 test data - only fields extracted from IPv4 header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv4TestData {
    pub dscp_ecn: u8,      // Byte 1 - DSCP and ECN fields
    pub ttl: u8,           // Byte 8 - Time to Live
    pub proto: u8,         // Byte 9 - Protocol (IpProto)
    pub src_addr: [u8; 4], // Bytes 12-15 - Source IP address
    pub dst_addr: [u8; 4], // Bytes 16-19 - Destination IP address
}

/// IPv6 test data - only fields extracted from IPv6 header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv6TestData {
    pub vcf: [u8; 4],       // Bytes 0-3 - Version, Traffic Class, Flow Label
    pub proto: u8,          // Byte 6 - Next Header (IpProto)
    pub hop_limit: u8,      // Byte 7 - Hop Limit (TTL equivalent)
    pub src_addr: [u8; 16], // Bytes 8-23 - Source IPv6 address
    pub dst_addr: [u8; 16], // Bytes 24-39 - Destination IPv6 address
}

/// AH test data - only fields extracted from AH header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AhTestData {
    pub next_hdr: u8, // Byte 0 - Next Header (IpProto)
    pub spi: [u8; 4], // Bytes 4-7 - Security Parameters Index
}

/// ESP test data - only fields extracted from ESP header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EspTestData {
    pub spi: [u8; 4], // Bytes 0-3 - Security Parameters Index
}

/// HopOpt test data - only fields extracted from Hop-by-Hop Options header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HopOptTestData {
    pub next_hdr: u8, // Byte 0 - Next Header (IpProto)
}

/// Fragment test data - only fields extracted from Fragment header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FragmentTestData {
    pub next_hdr: u8, // Byte 0 - Next Header (IpProto)
}

/// DestOpts test data - only fields extracted from Destination Options header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DestOptsTestData {
    pub next_hdr: u8, // Byte 0 - Next Header (IpProto)
}

/// Mobility test data - only fields extracted from Mobility header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MobilityTestData {
    pub next_hdr: u8, // Byte 0 - Next Header (IpProto)
}

/// Shim6 test data - only fields extracted from Shim6 header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Shim6TestData {
    pub next_hdr: u8,    // Byte 0 - Next Header (IpProto)
    pub hdr_ext_len: u8, // Byte 1 - Header Extension Length
}

/// Geneve test data - only fields extracted from Geneve header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GeneveTestData {
    pub ver_opt_len: u8,            // Byte 0 - Version + Option Length
    pub tunnel_ether_type: [u8; 2], // Bytes 2-3 - Protocol Type (EtherType)
    pub vni: [u8; 3],               // Bytes 4-6 - Virtual Network Identifier
}

/// VXLAN test data - only fields extracted from VXLAN header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VxlanTestData {
    pub flags: u8,    // Byte 0 - Flags (I flag indicates VNI present)
    pub vni: [u8; 3], // Bytes 4-6 - VXLAN Network Identifier (only if I flag set)
}

/// HIP test data - only fields extracted from HIP header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HipTestData {
    pub next_hdr: u8,    // Byte 0 - Next Header (IpProto)
    pub hdr_ext_len: u8, // Byte 1 - Header Extension Length
}

/// GRE test data - only fields extracted from GRE header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GreTestData {
    pub flag_res: [u8; 2],   // Bytes 0-1 - Flags, Reserved, Version
    pub ether_type: [u8; 2], // Bytes 2-3 - Protocol Type (EtherType)
}

/// GenericRoute test data - only fields extracted from Generic Route header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GenericRouteTestData {
    pub next_hdr: u8,    // Byte 0 - Next Header (IpProto)
    pub hdr_ext_len: u8, // Byte 1 - Header Extension Length
}

/// WireGuard Init test data - only fields extracted from WireGuard Initiation header
/// Based on mermin-ebpf parsing: reads ctx.load(offset + 4) for sender_idx
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardInitTestData {
    pub type_: WireGuardType, // Byte 0 - Message type (1)
    pub sender_ind: [u8; 4],  // Bytes 4-7 - Sender Index (le32)
}

impl WireGuardInitTestData {
    pub const LEN: usize = core::mem::size_of::<WireGuardInitTestData>();

    #[inline]
    pub fn sender_ind(&self) -> u32 {
        u32::from_le_bytes(self.sender_ind)
    }
}

/// WireGuard Response test data - only fields extracted from WireGuard Response header
/// Based on mermin-ebpf parsing: reads ctx.load(offset + 4) for sender_idx and ctx.load(offset + 8) for receiver_idx
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardResponseTestData {
    pub type_: WireGuardType,  // Byte 0 - Message type (2)
    pub sender_ind: [u8; 4],   // Bytes 4-7 - Sender Index (le32)
    pub receiver_ind: [u8; 4], // Bytes 8-11 - Receiver Index (le32)
}

impl WireGuardResponseTestData {
    pub const LEN: usize = core::mem::size_of::<WireGuardResponseTestData>();

    #[inline]
    pub fn sender_ind(&self) -> u32 {
        u32::from_le_bytes(self.sender_ind)
    }

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_le_bytes(self.receiver_ind)
    }
}

/// WireGuard Cookie Reply test data - only fields extracted from WireGuard Cookie Reply header
/// Based on mermin-ebpf parsing: reads ctx.load(offset + 4) for receiver_idx
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardCookieReplyTestData {
    pub type_: WireGuardType,  // Byte 0 - Message type (3)
    pub receiver_ind: [u8; 4], // Bytes 4-7 - Receiver Index (le32)
}

impl WireGuardCookieReplyTestData {
    pub const LEN: usize = core::mem::size_of::<WireGuardCookieReplyTestData>();

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_le_bytes(self.receiver_ind)
    }
}

/// WireGuard Transport Data test data - only fields extracted from WireGuard Transport Data header
/// Based on mermin-ebpf parsing: reads ctx.load(offset + 4) for receiver_idx
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardTransportDataTestData {
    pub type_: WireGuardType,  // Byte 0 - Message type (4)
    pub receiver_ind: [u8; 4], // Bytes 4-7 - Receiver Index (le32)
}

impl WireGuardTransportDataTestData {
    pub const LEN: usize = core::mem::size_of::<WireGuardTransportDataTestData>();

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_le_bytes(self.receiver_ind)
    }
}
