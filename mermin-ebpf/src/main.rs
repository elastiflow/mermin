#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
#[cfg(not(test))]
use aya_log_ebpf::{debug, error, warn};
use mermin_common::PacketMeta;
use network_types::{
    ah::AuthHdr,
    esp::Esp,
    eth::{EthHdr, EtherType},
    geneve::GeneveHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// todo: verify buffer size
#[cfg(not(test))]
#[map]
static mut PACKETS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

// Defines what kind of header we expect to process in the current iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderType {
    Ethernet,
    Ipv4,
    Ipv6,
    Geneve,
    Proto(IpProto),
    StopProcessing, // Indicates parsing should terminate for flow key purposes
    #[cfg(not(test))]
    ErrorOccurred, // Indicates an error stopped parsing
}

struct Parser {
    // Current read offset from the start of the packet
    offset: usize,
    // The header-type to parse next at 'offset'
    next_hdr: HeaderType,

    // Information for building flow records (prioritizes innermost headers).
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
    fn calc_l3_octet_count(&mut self, packet_len: u32) {
        self.packet_meta.l3_octet_count = packet_len - self.offset as u32;
    }

    /// Parses the next header in the packet and updates the parser state accordingly.
    /// Returns an error if the header is not supported.
    fn parse_ethernet_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let eth_hdr: EthHdr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.offset += EthHdr::LEN;

        // todo: Extract eth_hdr.src_addr and eth_hdr.dst_addr into src_mac_addr and dst_mac_addr fields

        match eth_hdr.ether_type() {
            Ok(EtherType::Ipv4) => self.next_hdr = HeaderType::Ipv4,
            Ok(EtherType::Ipv6) => self.next_hdr = HeaderType::Ipv6,
            _ => {
                warn!(
                    ctx,
                    "ethernet header contains unsupported ether type: {}", eth_hdr.ether_type
                );
                self.next_hdr = HeaderType::StopProcessing;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Parses the IPv4 header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_ipv4_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let ipv4_hdr: Ipv4Hdr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        let h_len = ipv4_hdr.ihl() as usize;
        if h_len < Ipv4Hdr::LEN {
            // basic sanity check
            return Err(Error::MalformedHeader);
        }
        self.calc_l3_octet_count(ctx.len());
        self.offset += h_len;

        // todo: Extract additional fields from ipv4_hdr

        let next_hdr = ipv4_hdr.proto;
        match next_hdr {
            IpProto::Tcp | IpProto::Udp => {
                // payload headers
                // policy: innermost IP header determines the flow IPs
                self.packet_meta.src_ipv4_addr = ipv4_hdr.src_addr;
                self.packet_meta.dst_ipv4_addr = ipv4_hdr.dst_addr;
                self.packet_meta.proto = next_hdr as u8;
                self.next_hdr = HeaderType::Proto(next_hdr);
            }
            _ => {
                warn!(
                    ctx,
                    "ipv4 header contains unsupported protocol: {}", next_hdr as u8
                );
                self.next_hdr = HeaderType::StopProcessing;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Parses the IPv6 header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_ipv6_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let ipv6_hdr: Ipv6Hdr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.calc_l3_octet_count(ctx.len());
        self.offset += Ipv6Hdr::LEN;

        let next_hdr = ipv6_hdr.next_hdr;
        match next_hdr {
            IpProto::Tcp | IpProto::Udp => {
                // payload headers
                // policy: innermost IP header determines the flow IPs
                self.packet_meta.src_ipv6_addr = ipv6_hdr.src_addr;
                self.packet_meta.dst_ipv6_addr = ipv6_hdr.dst_addr;
                self.packet_meta.proto = next_hdr as u8;
                self.next_hdr = HeaderType::Proto(next_hdr);
            }
            IpProto::HopOpt
            | IpProto::Ipv6Route
            | IpProto::Ipv6Frag
            | IpProto::Ipv6Opts
            | IpProto::MobilityHeader
            | IpProto::Hip
            | IpProto::Shim6 => {
                // ipv6 extension headers
                self.packet_meta.src_ipv6_addr = ipv6_hdr.src_addr;
                self.packet_meta.dst_ipv6_addr = ipv6_hdr.dst_addr;
                self.next_hdr = HeaderType::Proto(next_hdr);
            }
            IpProto::Ipv6NoNxt => {
                // ipv6 no next header
                self.next_hdr = HeaderType::StopProcessing;
                self.packet_meta.proto = next_hdr as u8;
            }
            _ => {
                warn!(
                    ctx,
                    "ipv6 header contains unsupported next header type: {}", next_hdr as u8
                );
                self.next_hdr = HeaderType::StopProcessing;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Parses the TCP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    fn parse_tcp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let tcp_hdr: TcpHdr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.offset += TcpHdr::LEN;

        self.packet_meta.src_port = tcp_hdr.src;
        self.packet_meta.dst_port = tcp_hdr.dst;
        // TODO: extract and assign additional tcp fields
        self.next_hdr = HeaderType::StopProcessing;
        Ok(())
    }

    /// Parses the UDP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    fn parse_udp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let udp_hdr: UdpHdr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.offset += UdpHdr::LEN;

        self.packet_meta.src_port = udp_hdr.src;
        self.packet_meta.dst_port = udp_hdr.dst;

        // IANA has assigned port 6081 as the fixed well-known destination port for Geneve.
        // Although the well-known value should be used by default, it is RECOMMENDED that implementations make this configurable.
        // TODO: include a configuration option read the Geneve port
        if udp_hdr.dst_port() == 6081 {
            debug!(
                ctx,
                "UDP packet with destination port 6081 (Geneve) detected"
            );
            self.next_hdr = HeaderType::Geneve;
        } else {
            // TODO: extract and assign additional udp fields
            self.next_hdr = HeaderType::StopProcessing;
        }

        Ok(())
    }

    /// Parses the AH IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_ah_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let ah_hdr: AuthHdr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.offset += AuthHdr::total_hdr_len(&ah_hdr);
        // TODO: Extract and set other AH fields
        self.next_hdr = HeaderType::Proto(ah_hdr.next_hdr());
        Ok(())
    }

    /// Parses the ESP IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_esp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let _esp_hdr: Esp = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.offset += Esp::LEN; // Move offset to start of encrypted ESP payload
        // TODO: Extract and set SPI and Sequence number
        self.next_hdr = HeaderType::StopProcessing; //ESP signals end of parsing headers
        Ok(())
    }

    /// Parses the Geneve header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_geneve_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let geneve_hdr: GeneveHdr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.offset += GeneveHdr::LEN;

        // Current version is 0. Packets with unknown version must be dropped
        let version = geneve_hdr.ver();
        if version != 0 {
            warn!(
                ctx,
                "geneve header contains unknown version: {}, dropping packet", version
            );
            self.next_hdr = HeaderType::StopProcessing;
            return Ok(());
        }

        let opt_len = geneve_hdr.opt_len() as usize * 4;
        self.offset += opt_len;

        let protocol_type = geneve_hdr.protocol_type();
        match protocol_type {
            0x0800 => self.next_hdr = HeaderType::Ipv4,
            0x86DD => self.next_hdr = HeaderType::Ipv6,
            0x6558 => self.next_hdr = HeaderType::Ethernet,
            _ => {
                warn!(
                    ctx,
                    "geneve header contains unsupported protocol type: {}", protocol_type
                );
                self.next_hdr = HeaderType::StopProcessing;
                return Ok(());
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutOfBounds,
    MalformedHeader,
    Unsupported,
}

#[cfg(not(test))]
const MAX_HEADER_PARSE_DEPTH: usize = 16;

#[cfg(not(test))]
#[classifier]
pub fn mermin(ctx: TcContext) -> i32 {
    try_mermin(ctx).unwrap_or(TC_ACT_PIPE)
}

#[cfg(not(test))]
fn try_mermin(ctx: TcContext) -> Result<i32, ()> {
    let mut parser = Parser::new();

    debug!(&ctx, "mermin: parsing packet");

    for _ in 0..MAX_HEADER_PARSE_DEPTH {
        let result: Result<(), Error> = match parser.next_hdr {
            HeaderType::Ethernet => parser.parse_ethernet_header(&ctx),
            HeaderType::Ipv4 => parser.parse_ipv4_header(&ctx),
            HeaderType::Ipv6 => parser.parse_ipv6_header(&ctx),
            HeaderType::Geneve => parser.parse_geneve_header(&ctx),
            HeaderType::Proto(IpProto::Tcp) => parser.parse_tcp_header(&ctx),
            HeaderType::Proto(IpProto::Udp) => parser.parse_udp_header(&ctx),
            HeaderType::Proto(IpProto::Ah) => parser.parse_ah_header(&ctx),
            HeaderType::Proto(IpProto::Esp) => parser.parse_esp_header(&ctx),
            HeaderType::Proto(IpProto::Ipv6NoNxt) => break,
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
        debug!(
            &ctx,
            "mermin: writing to packet output with proto {:x}", parser.packet_meta.proto
        );
        #[allow(static_mut_refs)]
        let result = PACKETS.output(&parser.packet_meta, 0);
        if result.is_err() {
            error!(&ctx, "mermin: failed to write packet to ring buffer");
        }
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(test))]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0"; // Corrected license string length and array size

#[cfg(test)]
mod host_test_shim {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::mem;

    use crate::Error;

    // A minimal stand-in for aya_ebpf::programs::TcContext used by parser functions
    pub struct TcContext {
        data: Vec<u8>,
    }
    impl TcContext {
        pub fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
        pub fn len(&self) -> u32 {
            self.data.len() as u32
        }
        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }
        pub fn load<T: Copy>(&self, offset: usize) -> Result<T, Error> {
            if offset + mem::size_of::<T>() > self.data.len() {
                return Err(Error::OutOfBounds);
            }
            let ptr = unsafe { self.data.as_ptr().add(offset) as *const T };
            let value = unsafe { *ptr };
            Ok(value)
        }
    }

    // No-op logging macros to satisfy calls in parsing code
    #[macro_export]
    macro_rules! debug {
        ($($tt:tt)*) => {};
    }
    #[macro_export]
    macro_rules! error {
        ($($tt:tt)*) => {};
    }
    #[macro_export]
    macro_rules! warn {
        ($($tt:tt)*) => {};
    }
}

#[cfg(test)]
pub use host_test_shim::TcContext;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

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

    // Helper function to create a UDP header test packet with Geneve port (6081)
    fn create_udp_geneve_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source Port (12345)
        packet.extend_from_slice(&[0x30, 0x39]);
        // Destination Port (6081 - Geneve)
        packet.extend_from_slice(&[0x17, 0xC1]); // 6081 in big-endian
        // Length (8 bytes for header)
        packet.extend_from_slice(&[0x00, 0x08]);
        // Checksum
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    // Helper function to create a Geneve header test packet
    fn create_geneve_test_packet(protocol_type: u16, opt_len: u8) -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (0) and Option Length (opt_len)
        packet.push(opt_len & 0x3F); // Version 0, Option Length as specified
        // OAM (0), Critical (0), Reserved (0)
        packet.push(0x00);
        // Protocol Type (e.g., 0x0800 for IPv4, 0x86DD for IPv6, 0x6558 for Ethernet)
        packet.extend_from_slice(&protocol_type.to_be_bytes());
        // VNI (0x123456)
        packet.extend_from_slice(&[0x12, 0x34, 0x56]);
        // Reserved
        packet.push(0x00);

        // Add option bytes if opt_len > 0
        for _ in 0..(opt_len as usize * 4) {
            packet.push(0x00);
        }

        packet
    }

    // Helper function to create an AH (Authentication Header) test packet
    // The AH fixed header is 12 bytes; to keep it minimal we set payload_len = 1, so total is 12 bytes
    fn create_ah_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::with_capacity(AuthHdr::LEN);
        // Next Header
        packet.push(next as u8);
        // Payload Len (in 4-octet units minus 2); 1 -> (1+2)*4 = 12 total bytes
        packet.push(1);
        // Reserved (2 bytes)
        packet.extend_from_slice(&[0x00, 0x00]);
        // SPI (4 bytes)
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        // Sequence Number (4 bytes)
        packet.extend_from_slice(&[0x9a, 0xbc, 0xde, 0xf0]);
        packet
    }

    // Helper function to create an ESP (Encapsulating Security Payload) test packet
    // The ESP header is 8 bytes (SPI + Sequence Number)
    fn create_esp_test_packet() -> Vec<u8> {
        let mut packet = Vec::with_capacity(Esp::LEN);
        // SPI (4 bytes)
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        // Sequence Number (4 bytes)
        packet.extend_from_slice(&[0x9a, 0xbc, 0xde, 0xf0]);
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

        let result = parser.parse_ethernet_header(&ctx);

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

        let result = parser.parse_ipv4_header(&ctx);

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

        let result = parser.parse_ipv4_header(&ctx);

        assert!(result.is_err());
    }

    // Test parse_ipv6_header function
    #[test]
    fn test_parse_ipv6_header() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Ipv6;
        let packet = create_ipv6_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv6_header(&ctx);

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

        let result = parser.parse_tcp_header(&ctx);

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

        let result = parser.parse_udp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, UdpHdr::LEN);
        assert_eq!(parser.packet_meta.src_port, [0x30, 0x39]); // 12345
        assert_eq!(parser.packet_meta.dst_port, [0x00, 0x35]); // 53
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    // Test parse_udp_header function with Geneve port
    #[test]
    fn test_parse_udp_header_geneve() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Udp);
        let packet = create_udp_geneve_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_udp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, UdpHdr::LEN);
        assert_eq!(parser.packet_meta.src_port, [0x30, 0x39]); // 12345
        assert_eq!(parser.packet_meta.dst_port, [0x17, 0xC1]); // 6081 (Geneve)
        assert!(matches!(parser.next_hdr, HeaderType::Geneve));
    }

    // Test parse_ah_header function mapping to TCP
    #[test]
    fn test_parse_ah_header_tcp() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        let packet = create_ah_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, AuthHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_ah_header function mapping to UDP
    #[test]
    fn test_parse_ah_header_udp() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        let packet = create_ah_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, AuthHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_ah_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_ah_header_out_of_bounds() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        // Provide fewer than 12 bytes
        let packet = vec![0x06, 0x01, 0x00, 0x00, 0x12, 0x34];
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test parse_esp_header function
    #[test]
    fn test_parse_esp_header() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Esp);
        let packet = create_esp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_esp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, Esp::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    // Test parse_esp_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_esp_header_out_of_bounds() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Proto(IpProto::Esp);
        // Provide fewer than 8 bytes
        let packet = vec![0x12, 0x34, 0x56, 0x78];
        let ctx = TcContext::new(packet);

        let result = parser.parse_esp_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test parse_geneve_header function with IPv4 protocol type
    #[test]
    fn test_parse_geneve_header_ipv4() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x0800, 0); // IPv4 protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    // Test parse_geneve_header function with IPv6 protocol type
    #[test]
    fn test_parse_geneve_header_ipv6() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x86DD, 0); // IPv6 protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ipv6));
    }

    // Test parse_geneve_header function with Ethernet protocol type
    #[test]
    fn test_parse_geneve_header_ethernet() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x6558, 0); // Ethernet protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));
    }

    // Test parse_geneve_header function with options
    #[test]
    fn test_parse_geneve_header_with_options() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x0800, 2); // IPv4 protocol type, 2 option units (8 bytes)
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GeneveHdr::LEN + 8); // Header length + 8 bytes of options
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    // Test parse_geneve_header function with unsupported protocol type
    #[test]
    fn test_parse_geneve_header_unsupported_protocol() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x1234, 0); // Unsupported protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    // Test parse_geneve_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_geneve_header_out_of_bounds() {
        let mut parser = Parser::new();
        parser.next_hdr = HeaderType::Geneve;
        // Provide fewer than 8 bytes (Geneve header length)
        let packet = vec![0x00, 0x00, 0x08, 0x00, 0x12, 0x34];
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }
}
