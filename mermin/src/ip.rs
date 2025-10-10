use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mermin_common::IpAddrType;

/// Resolve IP addresses from raw byte arrays based on the provided IP address type.
pub fn resolve_addrs(
    ip_addr_type: IpAddrType,
    src_ipv4_addr: [u8; 4],
    dst_ipv4_addr: [u8; 4],
    src_ipv6_addr: [u8; 16],
    dst_ipv6_addr: [u8; 16],
) -> Result<(IpAddr, IpAddr), Error> {
    match ip_addr_type {
        IpAddrType::Unknown => Err(Error::UnknownIpAddrType),
        IpAddrType::Ipv4 => {
            let src = IpAddr::V4(Ipv4Addr::from(src_ipv4_addr));
            let dst = IpAddr::V4(Ipv4Addr::from(dst_ipv4_addr));
            Ok((src, dst))
        }
        IpAddrType::Ipv6 => {
            let src = IpAddr::V6(Ipv6Addr::from(src_ipv6_addr));
            let dst = IpAddr::V6(Ipv6Addr::from(dst_ipv6_addr));
            Ok((src, dst))
        }
    }
}

/// Custom error type for router operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnknownIpAddrType,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownIpAddrType => write!(f, "unknown ip address type"),
        }
    }
}

impl std::error::Error for Error {}
