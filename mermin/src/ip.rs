//! IP address resolution utilities.
//!
//! This module provides utilities for converting raw byte arrays into standard
//! Rust `IpAddr` types, handling both IPv4 and IPv6 addresses.

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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use mermin_common::IpAddrType;

    use crate::ip::{Error, resolve_addrs};

    #[test]
    fn test_resolve_addrs_ipv4() {
        let result = resolve_addrs(
            IpAddrType::Ipv4,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [0; 16],
            [0; 16],
        );

        assert!(result.is_ok());
        let (src, dst) = result.unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn test_resolve_addrs_ipv6() {
        let result = resolve_addrs(
            IpAddrType::Ipv6,
            [0; 4],
            [0; 4],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        );

        assert!(result.is_ok());
        let (src, dst) = result.unwrap();
        match src {
            IpAddr::V6(addr) => assert!(addr.to_string().starts_with("2001:db8")),
            _ => panic!("Expected IPv6 address"),
        }
        match dst {
            IpAddr::V6(addr) => assert!(addr.to_string().starts_with("2001:db8")),
            _ => panic!("Expected IPv6 address"),
        }
    }

    #[test]
    fn test_resolve_addrs_unknown() {
        let result = resolve_addrs(
            IpAddrType::Unknown,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [0; 16],
            [0; 16],
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::UnknownIpAddrType);
    }
}
