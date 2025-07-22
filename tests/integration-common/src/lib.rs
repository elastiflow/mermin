#![no_std]

// Your existing shared data structure
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ParsedRequest {
    pub user_id: u32,
    pub request_id: u64,
}

#[cfg(feature = "user")]
use aya::Pod;

#[cfg(feature = "user")]
unsafe impl Pod for ParsedRequest {}

use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

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

// Required for user-space to safely read this struct from a perf buffer.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ParsedHeader {}

// --- CONSTANTS ---
// The size of our input buffer must be large enough to hold the type byte
// plus the largest possible header we might send. In this case, it's IPv6.
const MAX_PAYLOAD_SIZE: usize = size_of::<Ipv6Hdr>(); // 40 bytes
pub const REQUEST_DATA_SIZE: usize = 1 + MAX_PAYLOAD_SIZE; // 1 + 40 = 41 bytes

// --- VETH PAIR FIXTURE ---
// This section is only compiled for the user-space test runner (`integration` crate)
