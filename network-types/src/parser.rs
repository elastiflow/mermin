
// eBPF-only imports
#[cfg(target_arch = "bpf")]
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
#[cfg(target_arch = "bpf")]
use aya_log_ebpf::{debug, error, warn};

// Host test shim: provide TcContext and no-op log macros when testing on host
#[cfg(all(test, not(target_arch = "bpf")))]
mod host_shim {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::mem;

    pub struct TcContext {
        data: Vec<u8>,
    }
    impl TcContext {
        pub fn new(data: Vec<u8>) -> Self { Self { data } }
        pub fn len(&self) -> u32 { self.data.len() as u32 }
        pub fn load<T>(&self, offset: usize) -> Result<T, ()>
        where
            T: Copy,
        {
            if offset + mem::size_of::<T>() > self.data.len() {
                return Err(());
            }
            // Safety: we just checked bounds and T: Copy so reading bytes into T is allowed
            let ptr = unsafe { self.data.as_ptr().add(offset) as *const T };
            let value = unsafe { *ptr };
            Ok(value)
        }
    }
}

// no-op logging macros to satisfy calls in parsing code (host tests only)
#[cfg(all(test, not(target_arch = "bpf")))]
macro_rules! warn { ($($tt:tt)*) => { { let _ = ($($tt)*); } }; }
#[cfg(all(test, not(target_arch = "bpf")))]
macro_rules! debug { ($($tt:tt)*) => { { let _ = ($($tt)*); } }; }
#[cfg(all(test, not(target_arch = "bpf")))]
macro_rules! error { ($($tt:tt)*) => { { let _ = ($($tt)*); } }; }

#[cfg(all(test, not(target_arch = "bpf")))]
use host_shim::TcContext;

use mermin_common::PacketMeta;
use crate::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// eBPF-only map definition
#[cfg(target_arch = "bpf")]
#[map]
pub static mut PACKETS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

// Defines what kind of header we expect to process in the current iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderType {
    Ethernet,
    Ipv4,
    Ipv6,
    Proto(IpProto),
    StopProcessing, // Indicates parsing should terminate for flow key purposes
    ErrorOccurred,  // Indicates an error stopped parsing
}

pub struct Parser {
    // Current read offset from the start of the packet
    pub offset: usize,
    // The header-type to parse next at 'offset'
    pub next_hdr: HeaderType,

    // Information for building flow records (prioritizes innermost headers).
    // These fields will be updated as we parse deeper or encounter encapsulations.
    pub packet_meta: PacketMeta,
}

impl Parser {
    // todo(eng-18): consider using default trait instead of new
    pub fn new() -> Self {
        Parser {
            offset: 0,
            next_hdr: HeaderType::Ethernet,
            packet_meta: PacketMeta::default(),
        }
    }

    // Calculate the L3 octet count (from current offset to end of packet)
    // This should be called at the start of L3 (IP) header parsing
    fn calc_l3_octet_count(&mut self, packet_len: u32) {
        self.packet_meta.l3_octet_count = packet_len - self.offset as u32;
    }
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
pub fn parse_ethernet_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
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
pub fn parse_ipv4_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let ipv4_hdr: Ipv4Hdr = ctx.load(parser.offset).map_err(|_| ())?;
    let h_len = ipv4_hdr.ihl() as usize;
    if h_len < Ipv4Hdr::LEN {
        // basic sanity check
        return Err(());
    }
    parser.calc_l3_octet_count(ctx.len());
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
pub fn parse_ipv6_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let ipv6_hdr: Ipv6Hdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.calc_l3_octet_count(ctx.len());
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
pub fn parse_tcp_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let tcp_hdr: TcpHdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += TcpHdr::LEN;

    parser.packet_meta.src_port = tcp_hdr.src;
    parser.packet_meta.dst_port = tcp_hdr.dst;
    // TODO: extract and assign additional tcp fields
    parser.next_hdr = HeaderType::StopProcessing;
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
pub fn parse_udp_header(ctx: &TcContext, parser: &mut Parser) -> Result<(), ()> {
    let udp_hdr: UdpHdr = ctx.load(parser.offset).map_err(|_| ())?;
    parser.offset += UdpHdr::LEN;

    parser.packet_meta.src_port = udp_hdr.src;
    parser.packet_meta.dst_port = udp_hdr.dst;
    // TODO: extract and assign additional tcp fields
    parser.next_hdr = HeaderType::StopProcessing;
    Ok(())
}

#[cfg(all(target_arch = "bpf", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(target_arch = "bpf")]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0"; // Corrected license string length and array size

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;


    // Helper function to create an Ethernet header test packet
    fn create_eth_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Destination MAC (ff:ff:ff:ff:ff:ff)
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC (00:11:22:33:44:55)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType (0x0800, big-endian for IPv4)
        packet.extend_from_slice(&[0x08, 0x00]);

        packet
    }

    // Helper function to create an IPv4 header test packet
    fn create_ipv4_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (4) and IHL (5) = 0x45
        packet.push(0x45);
        // DSCP and ECN
        packet.push(0x00);
        // Total Length (20 bytes for header)
        packet.extend_from_slice(&[0x00, 0x14]);
        // Identification
        packet.extend_from_slice(&[0x00, 0x00]);
        // Flags and Fragment Offset
        packet.extend_from_slice(&[0x00, 0x00]);
        // TTL
        packet.push(0x40);
        // Protocol (TCP = 6)
        packet.push(0x06);
        // Header Checksum
        packet.extend_from_slice(&[0x00, 0x00]);
        // Source IP (192.168.1.1)
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        // Destination IP (192.168.1.2)
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]);

        packet
    }

    // Helper function to create an IPv6 header test packet
    fn create_ipv6_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (6), Traffic Class, Flow Label
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        // Payload Length
        packet.extend_from_slice(&[0x00, 0x00]);
        // Next Header (TCP = 6)
        packet.push(0x06);
        // Hop Limit
        packet.push(0x40);
        // Source IP (2001:db8::1)
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Destination IP (2001:db8::2)
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        packet
    }

    // Helper function to create a TCP header test packet
    fn create_tcp_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source Port (12345)
        packet.extend_from_slice(&[0x30, 0x39]);
        // Destination Port (80)
        packet.extend_from_slice(&[0x00, 0x50]);
        // Sequence Number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Acknowledgment Number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Data Offset (5), Reserved, Flags (SYN)
        packet.extend_from_slice(&[0x50, 0x02]);
        // Window Size
        packet.extend_from_slice(&[0x20, 0x00]);
        // Checksum
        packet.extend_from_slice(&[0x00, 0x00]);
        // Urgent Pointer
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    // Helper function to create a UDP header test packet
    fn create_udp_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source Port (12345)
        packet.extend_from_slice(&[0x30, 0x39]);
        // Destination Port (53)
        packet.extend_from_slice(&[0x00, 0x35]);
        // Length (8 bytes for header)
        packet.extend_from_slice(&[0x00, 0x08]);
        // Checksum
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    // #[test]
    // fn test_my_tc_program() {
    //     let mock_packet_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    //     let ctx = MockTcContext::new(mock_packet_data);
    //
    //     // Call your eBPF program's main function with the mock context
    //     let result = mermin(&ctx as *const _ as *mut _);
    //
    //     // Assert on the expected outcome of the program
    //     assert_eq!(result, 0); // Or whatever your program should return
    // }

    // Test Parser initialization
    #[test]
    fn test_parser_initialization() {
        let parser = Parser::new();

        assert_eq!(parser.offset, 0);
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));

        // Check that packet_meta is initialized with default values
        let packet_meta = parser.packet_meta;
        assert_eq!(packet_meta.src_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.dst_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.src_port, [0, 0]);
        assert_eq!(packet_meta.dst_port, [0, 0]);
    }

    #[test]
    fn test_parser_calculate_l3_octet_count() {
        let mut parser = Parser::new();

        parser.offset = 32;
        parser.calc_l3_octet_count(256);

        assert_eq!(parser.packet_meta.l3_octet_count, 224);
    }

    // Test parse_ethernet_header function
    #[test]
    fn test_parse_ethernet_header() {
        let mut parser = Parser::new();
        let packet = create_eth_test_packet();
        let ctx = TcContext::new(packet);

        let result = parse_ethernet_header(&ctx, &mut parser);

        assert!(result.is_ok());
        assert_eq!(parser.offset, EthHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    // Test parse_ipv4_header function
    #[test]
    fn test_parse_ipv4_header() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Ipv4;
        let packet = create_ipv4_test_packet();
        let ctx = TcContext::new(packet);

        let result = parse_ipv4_header(&ctx, &mut parser);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 20); // IPv4 header length (5 * 4 bytes)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
        assert_eq!(parser.packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]); // 192.168.1.1
        assert_eq!(parser.packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]); // 192.168.1.2
        assert_eq!(parser.packet_meta.proto, 6); // TCP
    }

    // Test parse_ipv4_header function with invalid header length
    #[test]
    fn test_parse_ipv4_header_invalid_length() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Ipv4;
        let mut packet = create_ipv4_test_packet();
        // Change IHL to invalid value (0)
        packet[0] = 0x40; // Version 4, IHL 0
        let ctx = TcContext::new(packet);

        let result = parse_ipv4_header(&ctx, &mut parser);

        assert!(result.is_err());
    }

    // Test parse_ipv6_header function
    #[test]
    fn test_parse_ipv6_header() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Ipv6;
        let packet = create_ipv6_test_packet();
        let ctx = TcContext::new(packet);

        let result = parse_ipv6_header(&ctx, &mut parser);

        assert!(result.is_ok());
        assert_eq!(parser.offset, Ipv6Hdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
        assert_eq!(
            parser.packet_meta.src_ipv6_addr,
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ]
        ); // 2001:db8::1
        assert_eq!(
            parser.packet_meta.dst_ipv6_addr,
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02
            ]
        ); // 2001:db8::2
        assert_eq!(parser.packet_meta.proto, 6); // TCP
    }

    // Test parse_tcp_header function
    #[test]
    fn test_parse_tcp_header() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Tcp);
        let packet = create_tcp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parse_tcp_header(&ctx, &mut parser);

        assert!(result.is_ok());
        assert_eq!(parser.offset, TcpHdr::LEN);
        assert_eq!(parser.packet_meta.src_port, [0x30, 0x39]); // 12345
        assert_eq!(parser.packet_meta.dst_port, [0x00, 0x50]); // 80
    }

    // Test parse_udp_header function
    #[test]
    fn test_parse_udp_header() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Udp);
        let packet = create_udp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parse_udp_header(&ctx, &mut parser);

        assert!(result.is_ok());
        assert_eq!(parser.offset, UdpHdr::LEN);
        assert_eq!(parser.packet_meta.src_port, [0x30, 0x39]); // 12345
        assert_eq!(parser.packet_meta.dst_port, [0x00, 0x35]); // 53
    }
}