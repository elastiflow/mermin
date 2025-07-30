#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, warn};
use mermin_common::{PacketMeta};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

// todo: verify buffer size
#[map]
static mut PACKETS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

// Defines what kind of header we expect to process in the current iteration.
#[derive(Debug)]
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

    // Information for building the FlowKey (prioritizes innermost headers)
    // These fields will be updated as we parse deeper or encounter encapsulations.
    packet_meta: PacketMeta,
}

impl Parser {
    // todo(eng-18): consider using default trait instead of new
    fn new() -> Self {
        Parser {
            offset: 0,
            next_hdr: HeaderType::Ethernet,
            packet_meta: PacketMeta::default(),
        }
    }

    // Calculate the L3 octet count (from current offset to end of packet)
    // This should be called at the start of L3 (IP) header parsing
    fn calculate_l3_octet_count(&mut self, ctx: &TcContext) {
        self.packet_meta.l3_octet_count = ctx.len() - self.offset as u32;
    }
}

const MAX_HEADER_PARSE_DEPTH: usize = 16;

#[classifier]
pub fn mermin(ctx: TcContext) -> i32 {
    try_mermin(ctx).unwrap_or_else(|_| TC_ACT_PIPE)
}

fn try_mermin(ctx: TcContext) -> Result<i32, ()> {
    let mut parser = Parser::new();

    debug!(&ctx, "mermin: parsing packet");

    for _ in 0..MAX_HEADER_PARSE_DEPTH {
        let result: Result<(), ()> = match parser.next_hdr {
            HeaderType::Ethernet => parse_ethernet_header(&ctx, &mut parser),
            HeaderType::Ipv4 => parse_ipv4_header(&ctx, &mut parser),
            HeaderType::Ipv6 => parse_ipv6_header(&ctx, &mut parser),
            HeaderType::Proto(IpProto::Tcp) => parse_tcp_header(&ctx, &mut parser),
            HeaderType::Proto(IpProto::Udp) => parse_udp_header(&ctx, &mut parser),
            HeaderType::Proto(proto) => {
                debug!(
                    &ctx,
                    "mermin: skipped parsing of unsupported protocol {}", proto as u8
                );
                break;
            }
            HeaderType::StopProcessing => break, // Graceful stop
            HeaderType::ErrorOccurred => return Ok(TC_ACT_PIPE), // Error, pass packet
        };

        if result.is_err() {
            error!(&ctx, "mermin: parser failed at offset {}", parser.offset);
            parser.next_hdr = HeaderType::ErrorOccurred; // Mark error
        }
    }

    unsafe {
        #[allow(static_mut_refs)]
        let result = PACKETS.output(&parser.packet_meta, 0);
        if result.is_err() {
            error!(&ctx, "mermin: failed to write packet to ring buffer");
        }
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

    match eth_hdr.ether_type() {
        Ok(EtherType::Ipv4) => parser.next_hdr = HeaderType::Ipv4,
        Ok(EtherType::Ipv6) => parser.next_hdr = HeaderType::Ipv6,
        _ => {
            warn!(
                ctx,
                "ethernet header contains unsupported ether type: {}", eth_hdr.ether_type
            );
            parser.next_hdr = HeaderType::StopProcessing;
            return Ok(());
        }
    }
    Ok(())
}

/// Parses the IPv4 header in the packet and updates the parser state accordingly.
/// Returns an error if the header cannot be loaded or is malformed.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |ip_ver | h_len |  ip_dscp  |ecn|        ip_total_length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       ip_identification       |flags|   ip_fragment_offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    ip_ttl     |  ip_protocol  |          ip_checksum          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         source_ipaddr                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      destination_ipaddr                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          ip_options                           |
/// /                              ...                              /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
fn parse_ipv4_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let ipv4_hdr: Ipv4Hdr = ctx.load(parser.offset).map_err(|_| ())?;
    let h_len = ipv4_hdr.ihl() as usize * 4;
    if h_len < Ipv4Hdr::LEN {
        // basic sanity check
        return Err(());
    }
    parser.calculate_l3_octet_count(ctx);
    parser.offset += h_len;

    // todo: Extract additional fields from ipv4_hdr

    let next_hdr = ipv4_hdr.proto;
    match next_hdr {
        IpProto::Tcp | IpProto::Udp => {
            // payload headers
            // policy: innermost IP header determines the flow IPs
            parser.packet_meta.src_ipv4_addr = ipv4_hdr.src_addr;
            parser.packet_meta.dst_ipv4_addr = ipv4_hdr.dst_addr;
            parser.packet_meta.proto = next_hdr as u8;
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        _ => {
            warn!(
                ctx,
                "ipv4 header contains unsupported protocol: {}", next_hdr as u8
            );
            parser.next_hdr = HeaderType::StopProcessing;
            return Ok(());
        }
    }
    Ok(())
}

/// Parses the IPv6 header in the packet and updates the parser state accordingly.
/// Returns an error if the header cannot be loaded or is malformed.
///
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |ip_ver |  ip_dscp  |ecn|             ip_flow_label             |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |       ip_payload_length       |ip_next_header | ip_hop_limit  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         source_ipaddr                         |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     source_ipaddr (con't)                     |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     source_ipaddr (con't)                     |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     source_ipaddr (con't)                     |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                      destination_ipaddr                       |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                  destination_ipaddr (con't)                   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                  destination_ipaddr (con't)                   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                  destination_ipaddr (con't)                   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
fn parse_ipv6_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let ipv6_hdr: Ipv6Hdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.calculate_l3_octet_count(ctx);
    parser.offset += Ipv6Hdr::LEN;

    let next_hdr = ipv6_hdr.next_hdr;
    match next_hdr {
        IpProto::Tcp | IpProto::Udp => {
            // payload headers
            // policy: innermost IP header determines the flow IPs
            parser.packet_meta.src_ipv6_addr = ipv6_hdr.src_addr;
            parser.packet_meta.dst_ipv6_addr = ipv6_hdr.dst_addr;
            parser.packet_meta.proto = next_hdr as u8;
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        IpProto::HopOpt
        | IpProto::Ipv6Route
        | IpProto::Ipv6Frag
        | IpProto::Ipv6Opts
        | IpProto::MobilityHeader
        | IpProto::Hip
        | IpProto::Shim6 => {
            // ipv6 extension headers
            parser.packet_meta.src_ipv6_addr = ipv6_hdr.src_addr;
            parser.packet_meta.dst_ipv6_addr = ipv6_hdr.dst_addr;
            parser.next_hdr = HeaderType::Proto(next_hdr);
        }
        IpProto::Ipv6NoNxt => {
            // ipv6 no next header
            parser.next_hdr = HeaderType::StopProcessing;
            parser.packet_meta.proto = next_hdr as u8;
        }
        _ => {
            warn!(
                ctx,
                "ipv6 header contains unsupported next header type: {}", next_hdr as u8
            );
            parser.next_hdr = HeaderType::StopProcessing;
            return Ok(());
        }
    }
    Ok(())
}

/// Parses the TCP header in the packet and updates the parser state accordingly.
/// Returns an error if the header cannot be loaded.
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          Source Port          |       Destination Port        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Sequence Number                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Acknowledgment Number                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  Data |     |N|C|E|U|A|P|R|S|F|                               |
///   | Offset| Rsrv|S|R|C|R|C|S|S|Y|I|            Window             |
///   |       |     | |W|E|G|K|H|T|N|N|                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |           Checksum            |         Urgent Pointer        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                            Options                            |
///   /                              ...                              /
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                            Padding                            |
///   /                              ...                              /
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                             data                              |
///   /                              ...                              /
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
fn parse_tcp_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let tcp_hdr: TcpHdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += TcpHdr::LEN;

    parser.packet_meta.src_port = tcp_hdr.src;
    parser.packet_meta.dst_port = tcp_hdr.dst;
    // TODO: extract and assign additional tcp fields

    Ok(())
}

/// Parses the UDP header in the packet and updates the parser state accordingly.
/// Returns an error if the header cannot be loaded.
///
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          Source Port          |       Destination Port        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          PDU Length           |           Checksum            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                             data                              |
///  /                              ...                              /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
fn parse_udp_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let udp_hdr: UdpHdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += UdpHdr::LEN;

    parser.packet_meta.src_port = udp_hdr.src;
    parser.packet_meta.dst_port = udp_hdr.dst;
    // TODO: extract and assign additional tcp fields

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 6] = *b"GPLv2\0"; // Corrected license string length and array size
