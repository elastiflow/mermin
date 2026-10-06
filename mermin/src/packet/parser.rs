//! Deep packet parser for extracting innermost 5-tuples and tunnel metadata.
//!
//! Handles VXLAN (port 4789), Geneve (port 6081), GRE (proto 47), and plain packets.
//!
//! The parser extracts:
//! 1. Innermost 5-tuple (for correct Community ID calculation)
//! 2. Outermost headers (tunnel transport)
//! 3. Tunnel metadata (VNI, type, etc.)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mermin_common::{FlowKey, TunnelType, eth::EtherType, geneve, ip::IpProto, vxlan};

use crate::{
    ip,
    packet::types::{
        FiveTuple, InnerHeaders, IpMetadata, OuterHeaders, ParseError, ParsedPacket, TunnelInfo,
    },
};

/// Returns true if the flow is likely tunneled. Fast check to avoid deep parsing for plain traffic.
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
        IpProto::Gre => true,
        _ => false,
    }
}

/// Parse tunnel UDP payload from eBPF `FlowEvent.packet_data` (VXLAN/Geneve + inner frame).
pub fn parse_packet_from_offset(
    data: &[u8],
    flow_key: &FlowKey,
    outer_src_mac: [u8; 6],
    outer_dst_mac: [u8; 6],
    vxlan_port: u16,
    geneve_port: u16,
) -> Result<ParsedPacket, ParseError> {
    let (outer_src_ip, outer_dst_ip) =
        ip::flow_key_to_ip_addrs(flow_key).map_err(|_| ParseError::InvalidHeader)?;
    let outer_src_port = flow_key.src_port;
    let outer_dst_port = flow_key.dst_port;

    let mut offset = 0;
    if outer_src_port == vxlan_port || outer_dst_port == vxlan_port {
        return parse_vxlan_payload(
            data,
            &mut offset,
            outer_src_ip,
            outer_dst_ip,
            outer_src_port,
            outer_dst_port,
            outer_src_mac,
            outer_dst_mac,
        );
    }
    if outer_src_port == geneve_port || outer_dst_port == geneve_port {
        return parse_geneve_payload(
            data,
            &mut offset,
            outer_src_ip,
            outer_dst_ip,
            outer_src_port,
            outer_dst_port,
            outer_src_mac,
            outer_dst_mac,
        );
    }

    Err(ParseError::UnsupportedProtocol)
}

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
    // EtherType::try_from expects the same encoding used by the enum repr (see mermin-common eth tests).
    let ether_type = EtherType::try_from(ether_type_raw.to_be()).unwrap_or(EtherType::Reserved);

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
    let ttl = data[*offset + 7];
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

fn parse_l4_ports(data: &[u8], offset: usize) -> Result<(u16, u16), ParseError> {
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
fn parse_vxlan_payload(
    data: &[u8],
    offset: &mut usize,
    outer_src_ip: IpAddr,
    outer_dst_ip: IpAddr,
    outer_src_port: u16,
    outer_dst_port: u16,
    outer_src_mac: [u8; 6],
    outer_dst_mac: [u8; 6],
) -> Result<ParsedPacket, ParseError> {
    if data.len() < *offset + vxlan::VXLAN_LEN {
        return Err(ParseError::TooShort);
    }

    let vni_bytes: vxlan::Vni = [data[*offset + 4], data[*offset + 5], data[*offset + 6]];
    let vni = vxlan::vni(vni_bytes);
    *offset += vxlan::VXLAN_LEN;

    let (inner_src_mac, inner_dst_mac, inner_ether_type) = parse_ethernet(data, offset)?;

    let (inner_src_ip, inner_dst_ip, inner_protocol, _) = match inner_ether_type {
        EtherType::Ipv4 => parse_ipv4(data, offset)?,
        EtherType::Ipv6 => parse_ipv6(data, offset)?,
        _ => return Err(ParseError::UnsupportedEtherType),
    };

    let (inner_src_port, inner_dst_port) = match inner_protocol {
        IpProto::Tcp | IpProto::Udp => parse_l4_ports(data, *offset)?,
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
fn parse_geneve_payload(
    data: &[u8],
    offset: &mut usize,
    outer_src_ip: IpAddr,
    outer_dst_ip: IpAddr,
    outer_src_port: u16,
    outer_dst_port: u16,
    outer_src_mac: [u8; 6],
    outer_dst_mac: [u8; 6],
) -> Result<ParsedPacket, ParseError> {
    if data.len() <= *offset {
        return Err(ParseError::TooShort);
    }

    let hdr_len = geneve::total_hdr_len(data[*offset]);
    if data.len() < *offset + hdr_len {
        return Err(ParseError::TooShort);
    }

    let vni_bytes: geneve::Vni = [data[*offset + 4], data[*offset + 5], data[*offset + 6]];
    let vni = geneve::vni(vni_bytes);
    *offset += hdr_len;

    let (inner_src_mac, inner_dst_mac, inner_ether_type) = parse_ethernet(data, offset)?;

    let (inner_src_ip, inner_dst_ip, inner_protocol, _) = match inner_ether_type {
        EtherType::Ipv4 => parse_ipv4(data, offset)?,
        EtherType::Ipv6 => parse_ipv6(data, offset)?,
        _ => return Err(ParseError::UnsupportedEtherType),
    };

    let (inner_src_port, inner_dst_port) = match inner_protocol {
        IpProto::Tcp | IpProto::Udp => parse_l4_ports(data, *offset)?,
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use mermin_common::{FlowKey, IpVersion, ip::IpProto};

    use super::*;

    fn outer_flow_key(src_port: u16, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_port,
            dst_port,
            ip_version: IpVersion::V4,
            protocol: IpProto::Udp,
        }
    }

    fn build_vxlan_icmp_payload(vni: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        // VXLAN header
        pkt.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
        pkt.push(((vni >> 16) & 0xFF) as u8);
        pkt.push(((vni >> 8) & 0xFF) as u8);
        pkt.push((vni & 0xFF) as u8);
        pkt.push(0x00);
        // Inner Ethernet
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // dst
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
        // Inner IPv4: 10.244.1.1 -> 10.244.2.2, ICMP
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0xf4,
            0x01, 0x01, 0x0a, 0xf4, 0x02, 0x02,
        ]);
        // Inner ICMP echo request (type 8, code 0)
        pkt.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
        pkt
    }

    fn build_geneve_payload(vni: u32, opt_len_quads: u8) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(opt_len_quads);
        pkt.extend_from_slice(&[0x00, 0x08, 0x00]); // flags + IPv4 ethertype
        pkt.push(((vni >> 16) & 0xFF) as u8);
        pkt.push(((vni >> 8) & 0xFF) as u8);
        pkt.push((vni & 0xFF) as u8);
        pkt.push(0x00);
        for i in 0..(opt_len_quads as usize * 4) {
            pkt.push(i as u8);
        }
        // Inner Ethernet + IPv4 UDP
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0xf4,
            0x01, 0x01, 0x0a, 0xf4, 0x02, 0x02,
        ]);
        pkt.extend_from_slice(&[0x30, 0x39, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00]); // UDP 12345->80
        pkt
    }

    #[test]
    fn test_parse_vxlan_icmp_from_udp_payload() {
        let payload = build_vxlan_icmp_payload(0x123456);
        let flow_key = outer_flow_key(54321, 4789);
        let parsed = parse_packet_from_offset(&payload, &flow_key, [0; 6], [0; 6], 4789, 6081)
            .expect("parse vxlan");

        match parsed {
            ParsedPacket::Tunneled {
                inner, tunnel_info, ..
            } => {
                assert_eq!(tunnel_info.tunnel_type, TunnelType::Vxlan);
                assert_eq!(tunnel_info.vni, 0x123456);
                assert_eq!(inner.src_ip, IpAddr::V4(Ipv4Addr::new(10, 244, 1, 1)));
                assert_eq!(inner.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 244, 2, 2)));
                assert_eq!(inner.protocol, IpProto::Icmp);
                assert_eq!(inner.src_port, (8 << 8) | 0);
            }
            ParsedPacket::Direct { .. } => panic!("expected tunneled packet"),
        }
    }

    #[test]
    fn test_parse_vxlan_non_default_port() {
        let payload = build_vxlan_icmp_payload(42);
        let flow_key = outer_flow_key(12345, 8472);
        let parsed = parse_packet_from_offset(&payload, &flow_key, [0; 6], [0; 6], 8472, 6081)
            .expect("parse flannel vxlan");

        match parsed {
            ParsedPacket::Tunneled { tunnel_info, .. } => {
                assert_eq!(tunnel_info.tunnel_type, TunnelType::Vxlan);
                assert_eq!(tunnel_info.vni, 42);
            }
            ParsedPacket::Direct { .. } => panic!("expected tunneled packet"),
        }
    }

    #[test]
    fn test_parse_geneve_default_options() {
        let payload = build_geneve_payload(0x00ABCD, 0);
        let flow_key = outer_flow_key(54321, 6081);
        let parsed = parse_packet_from_offset(&payload, &flow_key, [0; 6], [0; 6], 4789, 6081)
            .expect("parse geneve");

        match parsed {
            ParsedPacket::Tunneled {
                inner, tunnel_info, ..
            } => {
                assert_eq!(tunnel_info.tunnel_type, TunnelType::Geneve);
                assert_eq!(tunnel_info.vni, 0x00ABCD);
                assert_eq!(inner.protocol, IpProto::Udp);
                assert_eq!(inner.src_port, 12345);
                assert_eq!(inner.dst_port, 80);
            }
            ParsedPacket::Direct { .. } => panic!("expected tunneled packet"),
        }
    }

    #[test]
    fn test_parse_geneve_with_options() {
        let payload = build_geneve_payload(99, 1);
        let flow_key = outer_flow_key(6081, 54321);
        let parsed = parse_packet_from_offset(&payload, &flow_key, [0; 6], [0; 6], 4789, 6081)
            .expect("parse geneve with options");

        match parsed {
            ParsedPacket::Tunneled { tunnel_info, .. } => {
                assert_eq!(tunnel_info.tunnel_type, TunnelType::Geneve);
                assert_eq!(tunnel_info.vni, 99);
            }
            ParsedPacket::Direct { .. } => panic!("expected tunneled packet"),
        }
    }

    #[test]
    fn test_parse_truncated_payload() {
        let payload = vec![0x08, 0x00, 0x00, 0x00];
        let flow_key = outer_flow_key(54321, 4789);
        let err =
            parse_packet_from_offset(&payload, &flow_key, [0; 6], [0; 6], 4789, 6081).unwrap_err();
        assert_eq!(err, ParseError::TooShort);
    }

    #[test]
    fn test_is_tunnel_port_match() {
        let flow_key = outer_flow_key(8472, 54321);
        assert!(is_tunnel(&flow_key, 8472, 6081, 51820));
        let direct = FlowKey {
            src_port: 12345,
            dst_port: 80,
            protocol: IpProto::Udp,
            ..outer_flow_key(0, 0)
        };
        assert!(!is_tunnel(&direct, 4789, 6081, 51820));
    }
}
