//! Packet parsing types for deep inspection of captured packet data.
//!
//! These types support extracting innermost 5-tuples from tunneled/encapsulated traffic
//! and identifying tunnel metadata (VXLAN VNI, Geneve, GRE, etc.)

use std::net::IpAddr;

use mermin_common::TunnelType;
use network_types::{eth::EtherType, ip::IpProto};

/// Result of deep packet parsing
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ParsedPacket {
    /// No tunnel/encapsulation detected
    Direct {
        five_tuple: FiveTuple,
        l2_metadata: L2Metadata,
        ip_metadata: IpMetadata,
    },
    /// Tunneled/encapsulated traffic (VXLAN, Geneve, GRE, etc.)
    Tunneled {
        outer: OuterHeaders,
        inner: InnerHeaders,
        tunnel_info: TunnelInfo,
    },
}

/// Five-tuple identifier for a flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProto,
    pub ip_version: u8,
}

/// Tunnel-specific metadata
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TunnelInfo {
    pub tunnel_type: TunnelType,
    pub vni: u32, // VNI for VXLAN/Geneve, Key for GRE
}

/// Outer headers (tunnel transport)
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct OuterHeaders {
    pub five_tuple: FiveTuple,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

/// Inner headers (actual traffic)
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct InnerHeaders {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProto,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

/// Layer 2 metadata
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct L2Metadata {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ether_type: EtherType,
}

/// IP layer metadata
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct IpMetadata {
    pub dscp: u8,
    pub ecn: u8,
    pub ttl: u8,
    pub flow_label: Option<u32>, // IPv6 only
    pub ipsec_ah_spi: Option<u32>,
    pub ipsec_esp_spi: Option<u32>,
}

/// Parsing errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ParseError {
    TooShort,
    InvalidHeader,
    UnsupportedEtherType,
    UnsupportedProtocol,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "packet too short"),
            ParseError::InvalidHeader => write!(f, "invalid header"),
            ParseError::UnsupportedEtherType => write!(f, "unsupported ether type"),
            ParseError::UnsupportedProtocol => write!(f, "unsupported protocol"),
        }
    }
}

impl std::error::Error for ParseError {}
