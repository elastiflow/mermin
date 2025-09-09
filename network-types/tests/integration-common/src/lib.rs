#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
use network_types::{
    ah::AuthHdr,
    destopts::DestOptsHdr,
    esp::Esp,
    eth::EthHdr,
    fragment::Fragment,
    geneve::GeneveHdr,
    hop::HopOptHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    route::{CrhHeader, RplSourceRouteHeader, SegmentRoutingHeader, Type2RoutingHeader},
    tcp::TcpHdr,
    udp::UdpHdr,
    vxlan::VxlanHdr,
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
    Fragment = 15,
    DestOpts = 16,
    Vxlan = 17,
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
    pub rpl: RplSourceRouteHeader,
    pub type2: Type2RoutingHeader,
    pub segment_routing: SegmentRoutingHeader,
    pub crh16: CrhHeader,
    pub crh32: CrhHeader,
    pub fragment: Fragment,
    pub destopts: DestOptsHdr,
    pub vxlan: VxlanHdr,
}

/// The final struct sent back to user-space. It contains the type of
/// header that was parsed and the parsed data itself in the union.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ParsedHeader {
    pub type_: PacketType,
    pub data: HeaderUnion,
}
