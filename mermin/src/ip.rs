//! IP address resolution utilities.
//!
//! This module provides utilities for converting raw byte arrays into standard
//! Rust `IpAddr` types, handling both IPv4 and IPv6 addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mermin_common::{FlowKey, IpVersion};

use crate::packet::types::InnerHeaders;

/// Resolve IP addresses from raw byte arrays based on the provided IP address type.
#[allow(dead_code)]
pub fn resolve_addrs(
    ip_addr_type: IpVersion,
    src_ipv4_addr: [u8; 4],
    dst_ipv4_addr: [u8; 4],
    src_ipv6_addr: [u8; 16],
    dst_ipv6_addr: [u8; 16],
) -> Result<(IpAddr, IpAddr), Error> {
    match ip_addr_type {
        IpVersion::Unknown => Err(Error::UnknownIpAddrType),
        IpVersion::V4 => {
            let src = IpAddr::V4(Ipv4Addr::from(src_ipv4_addr));
            let dst = IpAddr::V4(Ipv4Addr::from(dst_ipv4_addr));
            Ok((src, dst))
        }
        IpVersion::V6 => {
            let src = IpAddr::V6(Ipv6Addr::from(src_ipv6_addr));
            let dst = IpAddr::V6(Ipv6Addr::from(dst_ipv6_addr));
            Ok((src, dst))
        }
    }
}

/// Build a normalized FlowKey from parsed inner tunnel headers.
pub fn flow_key_from_inner_headers(inner: &InnerHeaders) -> FlowKey {
    fn field(ip: IpAddr) -> ([u8; 16], IpVersion) {
        match ip {
            IpAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                bytes[..4].copy_from_slice(&v4.octets());
                (bytes, IpVersion::V4)
            }
            IpAddr::V6(v6) => (v6.octets(), IpVersion::V6),
        }
    }

    let (src_ip, ip_version) = field(inner.src_ip);
    let (dst_ip, _) = field(inner.dst_ip);

    FlowKey {
        src_ip,
        dst_ip,
        src_port: inner.src_port,
        dst_port: inner.dst_port,
        ip_version,
        protocol: inner.protocol,
    }
    .normalize()
}

/// Convert FlowKey IPs to IpAddr for Community ID generation.
pub fn flow_key_to_ip_addrs(key: &FlowKey) -> Result<(IpAddr, IpAddr), Error> {
    match key.ip_version {
        IpVersion::V4 => {
            let src = Ipv4Addr::new(key.src_ip[0], key.src_ip[1], key.src_ip[2], key.src_ip[3]);
            let dst = Ipv4Addr::new(key.dst_ip[0], key.dst_ip[1], key.dst_ip[2], key.dst_ip[3]);
            Ok((IpAddr::V4(src), IpAddr::V4(dst)))
        }
        IpVersion::V6 => {
            let src = Ipv6Addr::from(key.src_ip);
            let dst = Ipv6Addr::from(key.dst_ip);
            Ok((IpAddr::V6(src), IpAddr::V6(dst)))
        }
        _ => Err(Error::UnknownIpAddrType),
    }
}

/// Custom error type for router operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnknownIpAddrType,
    FlowNotFound,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownIpAddrType => write!(f, "unknown ip address type"),
            Error::FlowNotFound => write!(f, "flow not found in ebpf map"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use mermin_common::{IpVersion, ip::IpProto};

    use crate::{
        ip::{Error, flow_key_from_inner_headers, flow_key_to_ip_addrs, resolve_addrs},
        packet::types::InnerHeaders,
    };

    #[test]
    fn test_resolve_addrs_ipv4() {
        let result = resolve_addrs(
            IpVersion::V4,
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
            IpVersion::V6,
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
    fn test_flow_key_from_inner_headers_normalizes() {
        let inner = InnerHeaders {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 244, 2, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 244, 1, 1)),
            src_port: (8 << 8) | 0,
            dst_port: 0,
            protocol: IpProto::Icmp,
            src_mac: [0; 6],
            dst_mac: [0; 6],
        };

        let key = flow_key_from_inner_headers(&inner);
        let (src, dst) = flow_key_to_ip_addrs(&key).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 244, 1, 1)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(10, 244, 2, 2)));
        assert_eq!(key.protocol, IpProto::Icmp);
    }

    #[test]
    fn test_resolve_addrs_unknown() {
        let result = resolve_addrs(
            IpVersion::Unknown,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [0; 16],
            [0; 16],
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::UnknownIpAddrType);
    }
}
