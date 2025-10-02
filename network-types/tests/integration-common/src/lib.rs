#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
use network_types::{eth::EtherType, wireguard::WireGuardType};

/// Test data structures containing only the fields actually extracted by the parser
/// These mirror what gets stored in PacketMeta, not the full protocol headers

/// Ethernet test data - only fields extracted from Ethernet header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EthernetTestData {
    pub mac_addr: [u8; 6],      // First 6 bytes (dst MAC in actual frame, stored as src in meta)
    pub ether_type: EtherType,  // Bytes 12-13
}

/// UDP test data - only fields extracted from UDP header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpTestData {
    pub src_port: [u8; 2],  // Bytes 0-1
    pub dst_port: [u8; 2],  // Bytes 2-3
}

/// TCP test data - only fields extracted from TCP header
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TcpTestData {
    pub src_port: [u8; 2],  // Bytes 0-1
    pub dst_port: [u8; 2],  // Bytes 2-3
    pub tcp_flags: u8,      // Byte 13
}

/// Generic test data for IPv6 extension headers that only extract next_hdr
/// Used for: AH, ESP, Fragment, HopOpt, DestOpts, Mobility, Shim6, Generic Routing
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NextHdrOnlyTestData {
    pub next_hdr: u8,  // Byte 0 - IpProto
}

/// Minimal WireGuard header for eBPF processing - only essential fields (12 bytes)
/// This contains only the common fields across all WireGuard message types
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardMinimalHeader {
    pub type_: WireGuardType,
    pub reserved: [u8; 3],
    pub sender_ind: [u8; 4],
    pub receiver_ind: [u8; 4], // Only used in response/transport, zero in initiation/cookie
}

impl WireGuardMinimalHeader {
    pub const LEN: usize = core::mem::size_of::<WireGuardMinimalHeader>();

    #[inline]
    pub fn sender_ind(&self) -> u32 {
        u32::from_le_bytes(self.sender_ind)
    }

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_le_bytes(self.receiver_ind)
    }
}

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
    RplSourceRoute = 10,
    Type2 = 11,
    SegmentRouting = 12,
    Crh16 = 13,
    Crh32 = 14,
    Fragment = 15,
    DestOpts = 16,
    Vxlan = 17,
    Mobility = 18,
    Shim6 = 19,
    Hip = 20,
    Gre = 21,
    WireGuard = 22,
}

/// A union to hold any of the possible parsed network headers.
/// This allows us to have a single, fixed-size return type.
/// Contains only the fields actually extracted by the parser, not full protocol headers.
#[repr(C)]
#[derive(Copy, Clone)]
pub union HeaderUnion {
    pub eth: EthernetTestData,
    pub udp: UdpTestData,
    pub tcp: TcpTestData,
    pub wireguard: WireGuardMinimalHeader,
    // IPv6 extension headers that only extract next_hdr
    pub next_hdr_only: NextHdrOnlyTestData,  // Used for: AH, ESP, Fragment, HopOpt, DestOpts, Mobility, Shim6
    // Placeholder for remaining complex types
    pub placeholder: [u8; 64],
}

/// The final struct sent back to user-space. It contains the type of
/// header that was parsed and the parsed data itself in the union.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ParsedHeader {
    pub type_: PacketType,
    pub data: HeaderUnion,
}
