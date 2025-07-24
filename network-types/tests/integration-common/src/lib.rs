#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

use network_types::{
    eth::EthHdr as NetEthHdr,
    ip::{Ipv4Hdr as NetIpv4Hdr, Ipv6Hdr as NetIpv6Hdr},
    tcp::TcpHdr as NetTcpHdr,
    udp::UdpHdr as NetUdpHdr,
};

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct EthHdr(pub NetEthHdr);

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Ipv4Hdr(pub NetIpv4Hdr);

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Ipv6Hdr(pub NetIpv6Hdr);

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct TcpHdr(pub NetTcpHdr);

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct UdpHdr(pub NetUdpHdr);

#[cfg(feature = "user")]
unsafe impl Pod for EthHdr {}
#[cfg(feature = "user")]
unsafe impl Pod for Ipv4Hdr {}
#[cfg(feature = "user")]
unsafe impl Pod for Ipv6Hdr {}
#[cfg(feature = "user")]
unsafe impl Pod for TcpHdr {}
#[cfg(feature = "user")]
unsafe impl Pod for UdpHdr {}

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
}

/// The final struct sent back to user-space. It contains the type of
/// header that was parsed and the parsed data itself in the union.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ParsedHeader {
    pub ty: PacketType,
    pub data: HeaderUnion,
}
