#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
use network_types::{
    ah::AuthHdr,
    destopts::DestOptsHdr,
    esp::Esp,
    eth::EthHdr,
    fragment::FragmentHdr,
    geneve::GeneveHdr,
    gre::GreHdr,
    hop::HopOptHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    mobility::MobilityHdr,
    route::{CrhHeader, RplSourceRouteHeader, SegmentRoutingHeader, Type2RoutingHeader},
    shim6::Shim6Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
    vxlan::VxlanHdr,
    wireguard::WireGuardType,
};

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
        u32::from_be_bytes(self.sender_ind)
    }

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_be_bytes(self.receiver_ind)
    }
}

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
    Mobility = 18,
    Shim6 = 19,
    Hip = 20,
    Gre = 21,
    WireGuard = 22,
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
    pub fragment: FragmentHdr,
    pub destopts: DestOptsHdr,
    pub vxlan: VxlanHdr,
    pub mobility: MobilityHdr,
    pub shim6: Shim6Hdr,
    pub hip: network_types::hip::HipHdr,
    pub gre: GreHdr,
    pub wireguard: WireGuardMinimalHeader,
}

/// The final struct sent back to user-space. It contains the type of
/// header that was parsed and the parsed data itself in the union.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ParsedHeader {
    pub type_: PacketType,
    pub data: HeaderUnion,
}
