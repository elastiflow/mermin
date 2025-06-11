#![no_std]
#![no_main]

use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::EbpfContext;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::{debug, info};
use mergent_common::{CReprIpAddr, FlowRecord};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};

// Defines what kind of header we expect to process in the current iteration.
enum HeaderType {
    Ethernet,
    Ipv4,
    Ipv6,
    Proto(IpProto),
    StopProcessing, // Indicates parsing should terminate for flow key purposes
    ErrorOccurred,  // Indicates an error stopped parsing
}

struct Parser {
    // Current read offset from the start of the packet
    offset: usize,
    // The header-type to parse next at 'offset'
    next_hdr: HeaderType,

    // --- Information for building the FlowKey (prioritizes innermost headers) ---
    // These fields will be updated as we parse deeper or encounter encapsulations.
    flow_src_ip_addr: Option<CReprIpAddr>,
    flow_dst_ip_addr: Option<CReprIpAddr>,
    flow_src_port: Option<u16>,
    flow_dst_port: Option<u16>,
    flow_protocol: Option<u8>, // The final L4 protocol number (e.g., 6 for TCP)

    // --- Optional: Context from outer layers (e.g. for tunnel endpoints) ---
    outer_src_ip_addr: Option<CReprIpAddr>,
    outer_dst_ip_addr: Option<CReprIpAddr>,
    outer_src_port: Option<u16>,
    outer_dst_port: Option<u16>,
    outer_protocol: Option<u8>,
    // tunnel_id: Option<u64>, // e.g., VNI for VXLAN, SPI for ESP

    // --- Packet length, might be needed for some integrity checks or payload calcs ---
    // total_packet_len: usize, // This would be ctx.pkt_len() or similar

    // flow_record: Option<FlowRecord>,
}

impl Parser {
    fn new() -> Self {
        Parser {
            offset: 0,
            next_hdr: HeaderType::Ethernet,
            flow_src_ip_addr: None,
            flow_dst_ip_addr: None,
            flow_src_port: None,
            flow_dst_port: None,
            flow_protocol: None,
            outer_src_ip_addr: None,
            outer_dst_ip_addr: None,
            outer_src_port: None,
            outer_dst_port: None,
            outer_protocol: None,
        }
    }
}

const MAX_HEADER_PARSE_DEPTH: usize = 16;

#[classifier]
pub fn mergent(ctx: TcContext) -> i32 {
    try_mergent(ctx).unwrap_or_else(|_| TC_ACT_PIPE)
}

fn try_mergent(ctx: TcContext) -> Result<i32, ()> {
    let mut parser = Parser::new();

    for i in 0..MAX_HEADER_PARSE_DEPTH {
        let result: Result<(), ()> = match parser.next_hdr {
            HeaderType::Ethernet => parse_ethernet_header(&ctx, &mut parser),
            HeaderType::Ipv4 => parse_ipv4_header(&ctx, &mut parser),
            HeaderType::Ipv6 => parse_ipv6_header(&ctx, &mut parser),
            HeaderType::Proto(_) => parse_proto_header(&ctx, &mut parser),
            HeaderType::StopProcessing => break, // Graceful stop
            HeaderType::ErrorOccurred => return Ok(TC_ACT_PIPE), // Error, pass packet
        };

        if result.is_err() {
            debug!(&ctx, "parser failed at offset {}", parser.offset);
            parser.next_hdr = HeaderType::ErrorOccurred; // Mark error
        }

        // If a parser explicitly set StopProcessing or ErrorOccurred, the loop condition will handle it.
    }

    Ok(TC_ACT_PIPE)
}

/// Parses the next header in the packet and updates the parser state accordingly.
/// Returns an error if the header is not supported.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     destination_mac_addr                      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | destination_mac_addr (con't)  |        source_mac_addr        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                    source_mac_addr (con't)                    |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |           eth_type            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
fn parse_ethernet_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let eth_hdr: EthHdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += EthHdr::LEN;
    
    // todo: Extract eth_hdr.src_addr and eth_hdr.dst_addr into src_mac_addr and dst_mac_addr fields

    match eth_hdr.ether_type {
        EtherType::Ipv4 => parser.next_hdr = HeaderType::Ipv4,
        EtherType::Ipv6 => parser.next_hdr = HeaderType::Ipv6,
        _ => {
            debug!(ctx, "ethernet header contains unsupported ether type: {}", eth_hdr.ether_type as u16);
            parser.next_hdr = HeaderType::StopProcessing;
            return Err(());
        }
    }
    Ok(())
}

fn parse_ipv4_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let ipv4_hdr: Ipv4Hdr = ctx.load(parser.offset).map_err(|_| ())?;
    let h_len = ipv4_hdr.ihl() as usize * 4;
    if h_len < Ipv4Hdr::LEN {
        // basic sanity check
        return Err(());
    }
    parser.offset += h_len;
    
    // todo: Extract additional fields from ipv4_hdr

    let next_hdr = ipv4_hdr.proto;
    match next_hdr {
        IpProto:: Icmp | IpProto::Igmp | IpProto::Tcp | IpProto::Udp | IpProto::Ospfigp | IpProto::Sctp | IpProto::UdpLite => {
            // payload headers
            // policy: innermost IP header determines the flow IPs
            parser.flow_src_ip_addr = Some(CReprIpAddr::new_v4(u32::from_be_bytes(ipv4_hdr.src_addr)));
            parser.flow_dst_ip_addr = Some(CReprIpAddr::new_v4(u32::from_be_bytes(ipv4_hdr.dst_addr)));
            parser.flow_protocol = Some(next_hdr as u8);
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        IpProto::Ipv4 | IpProto::Ipv6 | IpProto::Gre | IpProto::Esp | IpProto::Ah | IpProto::Ipip => {
            // encapsulation headers
            // if the outer IP header is not already known, then we know this outermost IP header
            if parser.outer_src_ip_addr.is_none() {
                parser.outer_src_ip_addr = Some(CReprIpAddr::new_v4(u32::from_be_bytes(ipv4_hdr.src_addr)));
            }
            if parser.outer_dst_ip_addr.is_none() {
                parser.outer_dst_ip_addr = Some(CReprIpAddr::new_v4(u32::from_be_bytes(ipv4_hdr.dst_addr)));
            }
            if parser.outer_protocol.is_none() {
                parser.outer_protocol = Some(next_hdr as u8);
            }
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        _ => {
            debug!(ctx, "ipv4 header contains unsupported protocol: {}", next_hdr as u8);
            parser.next_hdr = HeaderType::StopProcessing;
            return Err(());
        }
    }
    Ok(())
}

fn parse_ipv6_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let ipv6_hdr: Ipv6Hdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += Ipv6Hdr::LEN;

    let next_hdr = ipv6_hdr.next_hdr;
    match next_hdr {
        IpProto:: Ipv6Icmp | IpProto::Igmp | IpProto::Tcp | IpProto::Udp | IpProto::Ospfigp | IpProto::Sctp | IpProto::UdpLite => {
            // payload headers
            // policy: innermost IP header determines the flow IPs
            parser.flow_src_ip_addr = Some(CReprIpAddr::new_v6(ipv6_hdr.src_addr));
            parser.flow_dst_ip_addr = Some(CReprIpAddr::new_v6(ipv6_hdr.dst_addr));
            parser.flow_protocol = Some(next_hdr as u8);
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        IpProto::HopOpt | IpProto::Ipv6Route | IpProto::Ipv6Frag | IpProto::Ipv6Opts | IpProto::MobilityHeader | IpProto::Hip | IpProto::Shim6 => {
            // ipv6 extension headers
            parser.flow_src_ip_addr = Some(CReprIpAddr::new_v6(ipv6_hdr.src_addr));
            parser.flow_dst_ip_addr = Some(CReprIpAddr::new_v6(ipv6_hdr.dst_addr));
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        IpProto::Ipv6NoNxt => {
            // ipv6 no next header
            parser.next_hdr = HeaderType::StopProcessing;
            parser.flow_protocol = Some(next_hdr as u8);
        }
        IpProto::Ipv4 | IpProto::Ipv6 | IpProto::Gre | IpProto::Esp | IpProto::Ah | IpProto::Ipip => {
            // encapsulation headers
            // if the outer IP header is not already known, then we know this outermost IP header
            if parser.outer_src_ip_addr.is_none() {
                parser.outer_src_ip_addr = Some(CReprIpAddr::new_v6(ipv6_hdr.src_addr));
            }
            if parser.outer_dst_ip_addr.is_none() {
                parser.outer_dst_ip_addr = Some(CReprIpAddr::new_v6(ipv6_hdr.dst_addr));
            }
            if parser.outer_protocol.is_none() {
                parser.outer_protocol = Some(next_hdr as u8);
            }
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        _ => {
            debug!(ctx, "ipv6 header contains unsupported next header type: {}", next_hdr as u8);
            parser.next_hdr = HeaderType::StopProcessing;
            return Err(());
        }
    }
    Ok(())
}

fn parse_proto_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    Ok(())
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 6] = *b"GPLv2\0"; // Corrected license string length and array size
