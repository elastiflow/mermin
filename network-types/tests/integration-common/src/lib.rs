#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
use network_types::{
    ah::AuthHdr,
    esp::Esp,
    eth::EthHdr,
    geneve::GeneveHdr,
    hop::HopOptHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    route::{CrhHeader, RplSourceRouteHeader, SegmentRoutingHeader, Type2RoutingHeader},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[cfg(feature = "user")]
unsafe impl Pod for ParsedHeader {}

/// An enum to tell the eBPF program which header to parse.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PacketType {
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
}

/// A union to hold any of the possible parsed network headers.
/// This allows us to have a single, fixed-size return type.
#[repr(C)]
#[derive(Copy, Clone)]
pub union HeaderUnion {
    pub eth: EthHdr,
    pub ipv4: Ipv4Hdr,
    pub ipv6: Ipv6Hdr,
    pub tcp: TcpHdr,
    pub udp: UdpHdr,
    pub ah: AuthHdr,
    pub esp: Esp,
    pub hop: HopOptHdr,
    pub geneve: GeneveHdr,
    pub rpl: RplSourceRouteParsed,
    pub type2: Type2RoutingHeader,
    pub segment_routing: SegmentRoutingParsed,
    pub crh16: CrhParsed,
    pub crh32: CrhParsed,
}

/// The final struct sent back to user-space. It contains the type of
/// header that was parsed and the parsed data itself in the union.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ParsedHeader {
    pub type_: PacketType,
    pub data: HeaderUnion,
}

pub const MAX_RPL_ADDR_STORAGE: usize = 128;
pub const MAX_SRH_SEGMENTS_STORAGE: usize = 128;
pub const MAX_CRH_SID_STORAGE: usize = 128;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RplSourceRouteParsed {
    pub header: RplSourceRouteHeader,
    pub addresses: [u8; MAX_RPL_ADDR_STORAGE],
    pub addresses_len: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SegmentRoutingParsed {
    pub header: SegmentRoutingHeader,
    pub segments_and_tlvs: [u8; MAX_SRH_SEGMENTS_STORAGE],
    pub segments_and_tlvs_len: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CrhParsed {
    pub header: CrhHeader,
    pub sids: [u8; MAX_CRH_SID_STORAGE],
    pub sids_len: u8,
}
