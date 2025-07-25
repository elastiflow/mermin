#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
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
    pub type_: PacketType,
    pub data: HeaderUnion,
}
