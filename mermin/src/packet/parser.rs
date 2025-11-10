//! Deep packet parser for extracting innermost 5-tuples and tunnel metadata.
//!
//! This parser handles:
//! - VXLAN (UDP port 4789)
//! - Geneve (UDP port 6081)
//! - GRE (IP protocol 47)
//! - Plain (non-tunneled) packets
//!
//! The parser extracts:
//! 1. Innermost 5-tuple (for correct Community ID calculation)
//! 2. Outermost headers (tunnel transport)
//! 3. Tunnel metadata (VNI, type, etc.)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mermin_common::{FlowKey, TunnelType};
use network_types::{eth::EtherType, ip::IpProto};

use crate::packet::types::{
    FiveTuple, InnerHeaders, IpMetadata, L2Metadata, OuterHeaders, ParseError, ParsedPacket,
    TunnelInfo,
};

/// Check if a flow is likely tunneled based on protocol and ports.
/// This is a fast check to avoid unnecessary deep parsing for plain traffic.
pub fn is_tunnel(
    flow_key: &FlowKey,
    vxlan_port: u16,
    geneve_port: u16,
    wireguard_port: u16,
) -> bool {
    match flow_key.protocol {
        IpProto::Tcp | IpProto::Udp => {
            let src = flow_key.src_port;
            let dst = flow_key.dst_port;
            src == vxlan_port
                || dst == vxlan_port
                || src == geneve_port
                || dst == geneve_port
                || src == wireguard_port
                || dst == wireguard_port
        }
        IpProto::Gre => true, // GRE is always a tunnel
        _ => false,
    }
}

/// Parse packet data starting from a specific offset (skipping already-parsed headers).
/// This is used when eBPF has already parsed outer headers into FlowStats.
///
/// Arguments:
/// - `data`: Raw packet bytes (only the UNPARSED portion from FlowEvent.packet_data)
/// - `parsed_offset`: How many bytes were already parsed by eBPF (not in data)
///
/// Returns: ParsedPacket starting from the given offset
pub fn parse_packet_from_offset(
    data: &[u8],
    _parsed_offset: u16,
) -> Result<ParsedPacket, ParseError> {
    // For tunnels, data starts at inner Ethernet header (outer already parsed by eBPF)
    // For plain traffic, this shouldn't be called (fast path skips parsing)
    parse_packet_deep(data)
}

/// Parse packet from raw bytes (up to 256 bytes captured)
pub fn parse_packet_deep(data: &[u8]) -> Result<ParsedPacket, ParseError> {
    let mut offset = 0;

    // Parse Ethernet header
    let (src_mac, dst_mac, ether_type) = parse_ethernet(data, &mut offset)?;

    let l2_meta = L2Metadata {
        src_mac,
        dst_mac,
        ether_type,
    };

    // Parse outer IP layer
    let (outer_src_ip, outer_dst_ip, outer_protocol, ip_meta) = match ether_type {
        EtherType::Ipv4 => parse_ipv4(data, &mut offset)?,
        EtherType::Ipv6 => parse_ipv6(data, &mut offset)?,
        _ => return Err(ParseError::UnsupportedEtherType),
    };

    // Check if this is a tunnel based on protocol and ports
    match outer_protocol {
        IpProto::Udp => {
            // Parse UDP ports to check for VXLAN/Geneve
            let (outer_src_port, outer_dst_port) = parse_udp_ports(data, offset)?;

            // VXLAN (port 4789) or Geneve (port 6081)
            if outer_dst_port == 4789 || outer_src_port == 4789 {
                return parse_vxlan(
                    data,
                    &mut offset,
                    outer_src_ip,
                    outer_dst_ip,
                    outer_src_port,
                    outer_dst_port,
                    src_mac,
                    dst_mac,
                );
            } else if outer_dst_port == 6081 || outer_src_port == 6081 {
                return parse_geneve(
                    data,
                    &mut offset,
                    outer_src_ip,
                    outer_dst_ip,
                    outer_src_port,
                    outer_dst_port,
                    src_mac,
                    dst_mac,
                );
            }

            // Regular UDP (not a tunnel)
            Ok(ParsedPacket::Direct {
                five_tuple: FiveTuple {
                    src_ip: outer_src_ip,
                    dst_ip: outer_dst_ip,
                    src_port: outer_src_port,
                    dst_port: outer_dst_port,
                    protocol: IpProto::Udp,
                    ip_version: if outer_src_ip.is_ipv4() { 4 } else { 6 },
                },
                l2_metadata: l2_meta,
                ip_metadata: ip_meta,
            })
        }
        IpProto::Tcp => {
            let (src_port, dst_port) = parse_tcp_ports(data, offset)?;
            Ok(ParsedPacket::Direct {
                five_tuple: FiveTuple {
                    src_ip: outer_src_ip,
                    dst_ip: outer_dst_ip,
                    src_port,
                    dst_port,
                    protocol: IpProto::Tcp,
                    ip_version: if outer_src_ip.is_ipv4() { 4 } else { 6 },
                },
                l2_metadata: l2_meta,
                ip_metadata: ip_meta,
            })
        }
        IpProto::Icmp => {
            let (type_code, _) = parse_icmp_type_code(data, offset)?;
            Ok(ParsedPacket::Direct {
                five_tuple: FiveTuple {
                    src_ip: outer_src_ip,
                    dst_ip: outer_dst_ip,
                    src_port: type_code,
                    dst_port: 0,
                    protocol: outer_protocol,
                    ip_version: if outer_src_ip.is_ipv4() { 4 } else { 6 },
                },
                l2_metadata: l2_meta,
                ip_metadata: ip_meta,
            })
        }
        IpProto::Gre => {
            // TODO: Implement GRE parsing
            Err(ParseError::UnsupportedProtocol)
        }
        _ => {
            // Other protocols (no ports)
            Ok(ParsedPacket::Direct {
                five_tuple: FiveTuple {
                    src_ip: outer_src_ip,
                    dst_ip: outer_dst_ip,
                    src_port: 0,
                    dst_port: 0,
                    protocol: outer_protocol,
                    ip_version: if outer_src_ip.is_ipv4() { 4 } else { 6 },
                },
                l2_metadata: l2_meta,
                ip_metadata: ip_meta,
            })
        }
    }
}

// Helper functions

fn parse_ethernet(
    data: &[u8],
    offset: &mut usize,
) -> Result<([u8; 6], [u8; 6], EtherType), ParseError> {
    if data.len() < *offset + 14 {
        return Err(ParseError::TooShort);
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[*offset..*offset + 6]);
    src_mac.copy_from_slice(&data[*offset + 6..*offset + 12]);

    let ether_type_raw = u16::from_be_bytes([data[*offset + 12], data[*offset + 13]]);
    let ether_type = EtherType::try_from(ether_type_raw).unwrap_or(EtherType::Reserved);

    *offset += 14;
    Ok((src_mac, dst_mac, ether_type))
}

fn parse_ipv4(
    data: &[u8],
    offset: &mut usize,
) -> Result<(IpAddr, IpAddr, IpProto, IpMetadata), ParseError> {
    if data.len() < *offset + 20 {
        return Err(ParseError::TooShort);
    }

    let ihl = ((data[*offset] & 0x0F) * 4) as usize;
    let protocol_num = data[*offset + 9];
    let protocol = match protocol_num {
        6 => IpProto::Tcp,
        17 => IpProto::Udp,
        1 => IpProto::Icmp,
        47 => IpProto::Gre,
        _ => IpProto::Reserved,
    };
    let src_ip = Ipv4Addr::new(
        data[*offset + 12],
        data[*offset + 13],
        data[*offset + 14],
        data[*offset + 15],
    );
    let dst_ip = Ipv4Addr::new(
        data[*offset + 16],
        data[*offset + 17],
        data[*offset + 18],
        data[*offset + 19],
    );

    let dscp = (data[*offset + 1] >> 2) & 0x3F;
    let ecn = data[*offset + 1] & 0x03;
    let ttl = data[*offset + 8];

    *offset += ihl;

    Ok((
        IpAddr::V4(src_ip),
        IpAddr::V4(dst_ip),
        protocol,
        IpMetadata {
            dscp,
            ecn,
            ttl,
            ..Default::default()
        },
    ))
}

fn parse_ipv6(
    data: &[u8],
    offset: &mut usize,
) -> Result<(IpAddr, IpAddr, IpProto, IpMetadata), ParseError> {
    if data.len() < *offset + 40 {
        return Err(ParseError::TooShort);
    }

    let next_hdr_num = data[*offset + 6];
    let next_hdr = match next_hdr_num {
        6 => IpProto::Tcp,
        17 => IpProto::Udp,
        58 => IpProto::Icmp, // ICMPv6 uses protocol 58
        47 => IpProto::Gre,
        _ => IpProto::Reserved,
    };

    let mut src_ip_bytes = [0u8; 16];
    let mut dst_ip_bytes = [0u8; 16];
    src_ip_bytes.copy_from_slice(&data[*offset + 8..*offset + 24]);
    dst_ip_bytes.copy_from_slice(&data[*offset + 24..*offset + 40]);

    let src_ip = Ipv6Addr::from(src_ip_bytes);
    let dst_ip = Ipv6Addr::from(dst_ip_bytes);

    let dscp = (data[*offset] & 0x0F) << 2 | (data[*offset + 1] >> 6);
    let ecn = (data[*offset + 1] >> 4) & 0x03;
    let ttl = data[*offset + 7]; // Hop limit
    let flow_label = u32::from_be_bytes([
        0,
        data[*offset + 1] & 0x0F,
        data[*offset + 2],
        data[*offset + 3],
    ]) & 0xFFFFF;

    *offset += 40;

    Ok((
        IpAddr::V6(src_ip),
        IpAddr::V6(dst_ip),
        next_hdr,
        IpMetadata {
            dscp,
            ecn,
            ttl,
            flow_label: Some(flow_label),
            ..Default::default()
        },
    ))
}

fn parse_udp_ports(data: &[u8], offset: usize) -> Result<(u16, u16), ParseError> {
    if data.len() < offset + 4 {
        return Err(ParseError::TooShort);
    }
    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    Ok((src_port, dst_port))
}

fn parse_tcp_ports(data: &[u8], offset: usize) -> Result<(u16, u16), ParseError> {
    if data.len() < offset + 4 {
        return Err(ParseError::TooShort);
    }
    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    Ok((src_port, dst_port))
}

fn parse_icmp_type_code(data: &[u8], offset: usize) -> Result<(u16, u16), ParseError> {
    if data.len() < offset + 2 {
        return Err(ParseError::TooShort);
    }
    let icmp_type = data[offset] as u16;
    let icmp_code = data[offset + 1] as u16;
    // Encode as port field: (type << 8 | code)
    let type_code_port = (icmp_type << 8) | icmp_code;
    Ok((type_code_port, 0))
}

#[allow(clippy::too_many_arguments)]
fn parse_vxlan(
    data: &[u8],
    offset: &mut usize,
    outer_src_ip: IpAddr,
    outer_dst_ip: IpAddr,
    outer_src_port: u16,
    outer_dst_port: u16,
    outer_src_mac: [u8; 6],
    outer_dst_mac: [u8; 6],
) -> Result<ParsedPacket, ParseError> {
    // Skip UDP header (8 bytes)
    *offset += 8;

    // VXLAN header (8 bytes): flags(1) + reserved(3) + VNI(3) + reserved(1)
    if data.len() < *offset + 8 {
        return Err(ParseError::TooShort);
    }

    let vni = u32::from_be_bytes([0, data[*offset + 4], data[*offset + 5], data[*offset + 6]]);
    *offset += 8;

    // Parse inner Ethernet
    let (inner_src_mac, inner_dst_mac, inner_ether_type) = parse_ethernet(data, offset)?;

    // Parse inner IP
    let (inner_src_ip, inner_dst_ip, inner_protocol, _) = match inner_ether_type {
        EtherType::Ipv4 => parse_ipv4(data, offset)?,
        EtherType::Ipv6 => parse_ipv6(data, offset)?,
        _ => return Err(ParseError::UnsupportedEtherType),
    };

    // Parse inner L4 ports
    let (inner_src_port, inner_dst_port) = match inner_protocol {
        IpProto::Tcp | IpProto::Udp => parse_tcp_ports(data, *offset)?,
        IpProto::Icmp => parse_icmp_type_code(data, *offset)?,
        _ => (0, 0),
    };

    Ok(ParsedPacket::Tunneled {
        outer: OuterHeaders {
            five_tuple: FiveTuple {
                src_ip: outer_src_ip,
                dst_ip: outer_dst_ip,
                src_port: outer_src_port,
                dst_port: outer_dst_port,
                protocol: IpProto::Udp,
                ip_version: if outer_src_ip.is_ipv4() { 4 } else { 6 },
            },
            src_mac: outer_src_mac,
            dst_mac: outer_dst_mac,
        },
        inner: InnerHeaders {
            src_ip: inner_src_ip,
            dst_ip: inner_dst_ip,
            src_port: inner_src_port,
            dst_port: inner_dst_port,
            protocol: inner_protocol,
            src_mac: inner_src_mac,
            dst_mac: inner_dst_mac,
        },
        tunnel_info: TunnelInfo {
            tunnel_type: TunnelType::Vxlan,
            vni,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_geneve(
    data: &[u8],
    offset: &mut usize,
    outer_src_ip: IpAddr,
    outer_dst_ip: IpAddr,
    outer_src_port: u16,
    outer_dst_port: u16,
    outer_src_mac: [u8; 6],
    outer_dst_mac: [u8; 6],
) -> Result<ParsedPacket, ParseError> {
    // Skip UDP header (8 bytes)
    *offset += 8;

    // Geneve header (8+ bytes): ver/opt_len(1) + flags(1) + protocol(2) + VNI(3) + reserved(1)
    if data.len() < *offset + 8 {
        return Err(ParseError::TooShort);
    }

    let opt_len = (data[*offset] & 0x3F) as usize * 4; // Options length in bytes
    let vni = u32::from_be_bytes([0, data[*offset + 4], data[*offset + 5], data[*offset + 6]]);
    *offset += 8 + opt_len; // Skip base header + options

    // Parse inner Ethernet
    let (inner_src_mac, inner_dst_mac, inner_ether_type) = parse_ethernet(data, offset)?;

    // Parse inner IP
    let (inner_src_ip, inner_dst_ip, inner_protocol, _) = match inner_ether_type {
        EtherType::Ipv4 => parse_ipv4(data, offset)?,
        EtherType::Ipv6 => parse_ipv6(data, offset)?,
        _ => return Err(ParseError::UnsupportedEtherType),
    };

    // Parse inner L4 ports
    let (inner_src_port, inner_dst_port) = match inner_protocol {
        IpProto::Tcp | IpProto::Udp => parse_tcp_ports(data, *offset)?,
        IpProto::Icmp => parse_icmp_type_code(data, *offset)?,
        _ => (0, 0),
    };

    Ok(ParsedPacket::Tunneled {
        outer: OuterHeaders {
            five_tuple: FiveTuple {
                src_ip: outer_src_ip,
                dst_ip: outer_dst_ip,
                src_port: outer_src_port,
                dst_port: outer_dst_port,
                protocol: IpProto::Udp,
                ip_version: if outer_src_ip.is_ipv4() { 4 } else { 6 },
            },
            src_mac: outer_src_mac,
            dst_mac: outer_dst_mac,
        },
        inner: InnerHeaders {
            src_ip: inner_src_ip,
            dst_ip: inner_dst_ip,
            src_port: inner_src_port,
            dst_port: inner_dst_port,
            protocol: inner_protocol,
            src_mac: inner_src_mac,
            dst_mac: inner_dst_mac,
        },
        tunnel_info: TunnelInfo {
            tunnel_type: TunnelType::Geneve,
            vni,
        },
    })
}
