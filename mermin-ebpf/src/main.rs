#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{PerCpuArray, ProgramArray, RingBuf},
    programs::TcContext,
};
#[cfg(not(test))]
use aya_log_ebpf::{debug, error, warn};
use mermin_common::{IpAddrType, PacketMeta};
use network_types::{
    ah::AuthHdr,
    esp::Esp,
    eth::{EthHdr, EtherType},
    geneve::GeneveHdr,
    hop::HopOptHdr,
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    route::{
        CrhHeader, GenericRoute, RoutingHeaderType, RplSourceRouteHeader, SegmentRoutingHeader,
        Type2RoutingHeader,
    },
    tcp::TcpHdr,
    udp::UdpHdr,
};

// todo: verify buffer size
#[cfg(not(test))]
#[map]
static mut PACKETS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

const MAX_VAR_BUF_SIZE: usize = 256;
const MAX_SIZE_MASK: usize = 255;

// State struct that will be passed between tail call functions
#[allow(private_interfaces)]
#[derive(Clone, Copy)]
pub struct TailCallState {
    pub parser: Parser,
    pub buffer: [u8; MAX_VAR_BUF_SIZE],
    pub var_len_to_read: usize,
    pub var_offset: usize,
    pub var_bytes_read: usize,
}

impl Default for TailCallState {
    fn default() -> Self {
        Self {
            parser: Parser::default(),
            buffer: [0; MAX_VAR_BUF_SIZE],
            var_len_to_read: 0,
            var_offset: 0,
            var_bytes_read: 0,
        }
    }
}

// Map to store state between tail calls
#[cfg(not(test))]
#[map]
static mut TAIL_CALL_STATE: PerCpuArray<TailCallState> = PerCpuArray::with_max_entries(1, 0);

// Program array for tail calls can be extended to hold up to 31 entries
#[cfg(not(test))]
#[map]
static mut PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(4, 0);

// Indexes for the program array
const PROG_IDX_PARSER: u32 = 0;
const PROG_IDX_READ_VAR_BUF_ALIGN: u32 = 1;
const PROG_IDX_READ_VAR_BUF_CHUNKED: u32 = 2;
const PROG_IDX_READ_VAR_BUF_REMAINDER: u32 = 3;

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

#[derive(Debug, Clone, Copy)]
struct ParserOptions {
    /// The port number to use for Geneve tunnel detection
    /// Default is 6081 as per IANA assignment
    geneve_port: u16,

    /// Current read offset from the start of the packet
    offset: usize,
}

impl Default for ParserOptions {
    fn default() -> Self {
        ParserOptions {
            geneve_port: 6081,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]

struct Parser {
    // The header-type to parse next at 'offset'
    next_hdr: HeaderType,
    // Flag to indicate a two-step read for variable-length data
    is_reading_var_buf: bool,
    // Configuration options for the parser
    options: ParserOptions,
    // Information for building flow records (prioritizes innermost headers).
    // These fields will be updated as we parse deeper or encounter encapsulations.
    packet_meta: PacketMeta,
}

impl Parser {
    fn default() -> Self {
        Parser {
            next_hdr: HeaderType::Ethernet,
            is_reading_var_buf: false,
            options: ParserOptions::default(),
            packet_meta: PacketMeta::default(),
        }
    }

    #[allow(dead_code)]
    fn with_options(options: ParserOptions) -> Self {
        Parser {
            next_hdr: HeaderType::Ethernet,
            is_reading_var_buf: false,
            options,
            packet_meta: PacketMeta::default(),
        }
    }

    // Calculate the L3 octet count (from current offset to end of packet)
    // This should be called at the start of L3 (IP) header parsing
    fn calc_l3_octet_count(&mut self, packet_len: u32) {
        self.packet_meta.l3_octet_count = packet_len - self.options.offset as u32;
    }

    /// Parses the next header in the packet and updates the parser state accordingly.
    /// Returns an error if the header is not supported.
    fn parse_ethernet_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let eth_hdr: EthHdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.options.offset += EthHdr::LEN;

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
        let ipv4_hdr: Ipv4Hdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        let h_len = ipv4_hdr.ihl() as usize;
        if h_len < Ipv4Hdr::LEN {
            // basic sanity check
            return Err(Error::MalformedHeader);
        }
        self.calc_l3_octet_count(ctx.len());
        self.options.offset += h_len;

        // policy: innermost IP header determines the flow IPs
        self.packet_meta.src_ipv4_addr = ipv4_hdr.src_addr;
        self.packet_meta.dst_ipv4_addr = ipv4_hdr.dst_addr;
        self.packet_meta.ip_addr_type = IpAddrType::Ipv4;
        // todo: Extract additional fields from ipv4_hdr

        let next_hdr = ipv4_hdr.proto;
        match next_hdr {
            IpProto::Tcp | IpProto::Udp | IpProto::Icmp => {
                self.packet_meta.proto = next_hdr;
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
        let ipv6_hdr: Ipv6Hdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.calc_l3_octet_count(ctx.len());
        self.options.offset += Ipv6Hdr::LEN;

        // policy: innermost IP header determines the flow IPs
        self.packet_meta.src_ipv6_addr = ipv6_hdr.src_addr;
        self.packet_meta.dst_ipv6_addr = ipv6_hdr.dst_addr;
        self.packet_meta.ip_addr_type = IpAddrType::Ipv6;
        let next_hdr = ipv6_hdr.next_hdr;
        // todo: Extract additional fields from ipv6_hdr

        match next_hdr {
            IpProto::Tcp | IpProto::Udp | IpProto::Ipv6Icmp => {
                self.packet_meta.proto = next_hdr;
                self.next_hdr = HeaderType::Proto(next_hdr);
            }
            IpProto::HopOpt
            | IpProto::Ipv6Route
            | IpProto::Ipv6Frag
            | IpProto::Ipv6Opts
            | IpProto::MobilityHeader
            | IpProto::Hip
            | IpProto::Shim6 => {
                self.next_hdr = HeaderType::Proto(next_hdr);
            }
            IpProto::Ipv6NoNxt => {
                self.next_hdr = HeaderType::StopProcessing;
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
        let tcp_hdr: TcpHdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.options.offset += TcpHdr::LEN;

        self.packet_meta.src_port = tcp_hdr.src;
        self.packet_meta.dst_port = tcp_hdr.dst;
        // TODO: extract and assign additional tcp fields
        self.next_hdr = HeaderType::StopProcessing;
        Ok(())
    }

    /// Parses the UDP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    fn parse_udp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let udp_hdr: UdpHdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.options.offset += UdpHdr::LEN;

        self.packet_meta.src_port = udp_hdr.src;
        self.packet_meta.dst_port = udp_hdr.dst;

        // IANA has assigned port 6081 as the fixed well-known destination port for Geneve.
        // Although the well-known value should be used by default, it is RECOMMENDED that implementations make this configurable.
        if udp_hdr.dst_port() == self.options.geneve_port {
            debug!(
                ctx,
                "UDP packet with destination port {} (Geneve) detected", self.options.geneve_port
            );
            self.next_hdr = HeaderType::Geneve;
        } else {
            // TODO: extract and assign additional udp fields
            self.next_hdr = HeaderType::StopProcessing;
        }

        Ok(())
    }

    /// Parses the ICMP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    /// Note: ICMP does not use ports, so src_port and dst_port remain zero.
    fn parse_icmp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let _icmp_hdr: IcmpHdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.options.offset += IcmpHdr::LEN;

        // ICMP does not use ports, so we leave src_port and dst_port as zero
        // TODO: extract and assign additional ICMP fields if needed (type, code, etc.)
        self.next_hdr = HeaderType::StopProcessing;
        Ok(())
    }

    /// Parses the AH IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_ah_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let ah_hdr: AuthHdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.options.offset += AuthHdr::total_hdr_len(&ah_hdr);
        // TODO: Extract and set other AH fields
        self.next_hdr = HeaderType::Proto(ah_hdr.next_hdr());
        Ok(())
    }

    /// Parses the ESP IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_esp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let _esp_hdr: Esp = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.options.offset += Esp::LEN; // Move offset to start of encrypted ESP payload
        // TODO: Extract and set SPI and Sequence number
        self.next_hdr = HeaderType::StopProcessing; //ESP signals end of parsing headers
        Ok(())
    }

    /// Parses the Hop-by-Hop IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_hop_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let hop_hdr: HopOptHdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        self.options.offset += hop_hdr.total_hdr_len(); // Move offset to start of next header
        self.next_hdr = HeaderType::Proto(hop_hdr.next_hdr);

        if hop_hdr.hdr_ext_len != 0 {
            warn!(ctx, "Unsupported HOP extension: {}", hop_hdr.hdr_ext_len);
            return Ok(());
        }
        Ok(())
    }

    /// Parses the Geneve header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_geneve_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        let geneve_hdr: GeneveHdr = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;

        // Current version is 0. Packets with unknown version must be skipped
        let version = geneve_hdr.ver();
        if version != 0 {
            warn!(
                ctx,
                "geneve header contains unknown version: {}, skipping packet", version
            );
            self.next_hdr = HeaderType::StopProcessing;
            return Ok(());
        }

        self.options.offset += geneve_hdr.total_hdr_len();

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

    /// Parses the IPv6 routing header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_routing_header(
        &mut self,
        ctx: &TcContext,
        buffer: &[u8; MAX_VAR_BUF_SIZE],
    ) -> Result<Option<(usize, usize)>, Error> {
        let gen_hdr: GenericRoute = ctx
            .load(self.options.offset)
            .map_err(|_| Error::OutOfBounds)?;
        let routing_type: RoutingHeaderType = RoutingHeaderType::from_u8(gen_hdr.type_);

        match routing_type {
            RoutingHeaderType::RplSourceRoute => {
                let rpl_hdr: RplSourceRouteHeader = ctx
                    .load(self.options.offset)
                    .map_err(|_| Error::OutOfBounds)?;
                let var_size = rpl_hdr.gen_route.total_hdr_len().saturating_sub(8) & MAX_SIZE_MASK; // Subtract 8 for fixed RPL header
                if self.is_reading_var_buf {
                    debug!(ctx, "reading variable part of RPL routing header");

                    let _addrs = &buffer[..var_size];
                    // TODO process variable length part of RPL routing header from segments buffer
                    // Could also process directly from buffer

                    // Advance the offset past the entire header
                    self.options.offset += rpl_hdr.total_hdr_len();
                    // Reset the flag and set next header type
                    self.is_reading_var_buf = false;
                    self.next_hdr = HeaderType::Proto(rpl_hdr.gen_route.next_hdr());
                    return Ok(None);
                } else if var_size > 0 {
                    // Set flag and instruct caller to perform a tail call.
                    self.is_reading_var_buf = true;
                    // The offset passed to the reader program should be after the fixed header.
                    return Ok(Some((
                        self.options.offset + RplSourceRouteHeader::LEN,
                        var_size,
                    )));
                }
                // No variable part, just advance offset and continue.
                self.options.offset += RplSourceRouteHeader::LEN;
                self.next_hdr = HeaderType::Proto(rpl_hdr.gen_route.next_hdr());
            }
            RoutingHeaderType::Type2 => {
                let type2_hdr: Type2RoutingHeader = ctx
                    .load(self.options.offset)
                    .map_err(|_| Error::OutOfBounds)?;
                self.options.offset += Type2RoutingHeader::LEN;

                // TODO parse out and use addresses and other type2 fields
                self.next_hdr = HeaderType::Proto(type2_hdr.gen_route.next_hdr());
            }
            RoutingHeaderType::SegmentRoutingHeader => {
                let segment_hdr: SegmentRoutingHeader = ctx
                    .load(self.options.offset)
                    .map_err(|_| Error::OutOfBounds)?;
                let var_size = segment_hdr.segments_and_tlvs_len() & MAX_SIZE_MASK;
                if self.is_reading_var_buf {
                    debug!(ctx, "reading variable part of segment routing header");

                    let _segments = &buffer[..var_size];
                    // TODO process variable length part of segment routing header

                    // Advance the offset past the entire header
                    self.options.offset += segment_hdr.total_hdr_len();
                    // Reset the flag and set next header type
                    self.is_reading_var_buf = false;
                    self.next_hdr = HeaderType::Proto(segment_hdr.gen_route.next_hdr());
                    return Ok(None);
                } else if var_size > 0 {
                    // Set flag and instruct caller to perform a tail call.
                    self.is_reading_var_buf = true;
                    // The offset passed to the reader program should be after the fixed header.
                    return Ok(Some((
                        self.options.offset + SegmentRoutingHeader::LEN,
                        var_size,
                    )));
                }
                // No variable part, just advance offset and continue.
                self.options.offset += SegmentRoutingHeader::LEN;
                self.next_hdr = HeaderType::Proto(segment_hdr.gen_route.next_hdr());
            }
            RoutingHeaderType::Crh16 | RoutingHeaderType::Crh32 => {
                let crh_hdr: CrhHeader = ctx
                    .load(self.options.offset)
                    .map_err(|_| Error::OutOfBounds)?;
                let mut var_size = crh_hdr.sid_list_len() & MAX_SIZE_MASK;
                if crh_hdr.gen_route.hdr_ext_len == 0 {
                    var_size = 0;
                }
                if self.is_reading_var_buf {
                    debug!(ctx, "reading variable part of CRH routing header");

                    let _sids = &buffer[..var_size];
                    // TODO process variable length part of CRH routing header

                    // Advance the offset past the entire header
                    self.options.offset += crh_hdr.total_hdr_len();
                    // Reset the flag and set next header type
                    self.is_reading_var_buf = false;
                    self.next_hdr = HeaderType::Proto(crh_hdr.gen_route.next_hdr());
                    return Ok(None);
                } else if var_size > 0 {
                    // Set flag and instruct caller to perform a tail call.
                    self.is_reading_var_buf = true;
                    // The offset passed to the reader program should be after the fixed header.
                    return Ok(Some((self.options.offset + CrhHeader::LEN, var_size)));
                }
                // No variable part, just advance by LEN and continue.
                self.options.offset += CrhHeader::LEN + 4; // + 4 padding bytes to account for 8-byte boundary
                self.next_hdr = HeaderType::Proto(crh_hdr.gen_route.next_hdr());
            }
            RoutingHeaderType::Experiment1
            | RoutingHeaderType::Experiment2
            | RoutingHeaderType::Reserved => {
                self.next_hdr = HeaderType::Proto(gen_hdr.next_hdr);
                self.options.offset += gen_hdr.total_hdr_len();
            }
            _ => {
                self.next_hdr = HeaderType::StopProcessing;
            }
        }

        Ok(None)
    }

    fn read_single_byte(
        ctx: &TcContext,
        buf: &mut [u8; MAX_VAR_BUF_SIZE],
        len: usize,
        bytes_read_total: &mut usize,
        offset: &mut usize,
    ) -> Result<bool, Error> {
        if *bytes_read_total >= len || (*bytes_read_total + 1) > MAX_VAR_BUF_SIZE {
            return Ok(false);
        }

        match ctx.load::<u8>(*offset) {
            Ok(byte) => {
                buf[*bytes_read_total] = byte;
                *bytes_read_total += 1;
                *offset += 1;
                Ok(true)
            }
            Err(_) => Err(Error::OutOfBounds),
        }
    }

    fn read_sixteen_byte_chunk(
        ctx: &TcContext,
        buf: &mut [u8; MAX_VAR_BUF_SIZE],
        len: usize,
        bytes_read_total: &mut usize,
        offset: &mut usize,
    ) -> Result<bool, Error> {
        if *bytes_read_total >= len
            || (len.saturating_sub(*bytes_read_total)) < 16
            || (*bytes_read_total + 16) > MAX_VAR_BUF_SIZE
        {
            return Ok(false);
        }

        match ctx.load::<u128>(*offset) {
            Ok(bytes) => {
                buf[*bytes_read_total..*bytes_read_total + 16]
                    .copy_from_slice(&bytes.to_ne_bytes());
                *bytes_read_total += 16;
                *offset += 16;
                Ok(true)
            }
            Err(_) => Err(Error::OutOfBounds),
        }
    }
    #[cfg(not(test))]
    pub fn read_var_buf_align(ctx: &TcContext) -> i32 {
        let key: u32 = 0;
        #[allow(static_mut_refs)]
        let state_ptr = unsafe { TAIL_CALL_STATE.get_ptr_mut(key) };

        if let Some(state_ptr) = state_ptr {
            let state = unsafe { &mut *state_ptr };

            //Clamp to help the verifier prove we won't go out of bounds
            state.var_bytes_read &= MAX_SIZE_MASK;

            // Align to 16-byte boundary.
            for _ in 0..15 {
                if state.var_offset % 16 == 0 {
                    break;
                }
                match Self::read_single_byte(
                    ctx,
                    &mut state.buffer,
                    state.var_len_to_read,
                    &mut state.var_bytes_read,
                    &mut state.var_offset,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        // Not enough data to read, break and go to next stage.
                        break;
                    }
                    Err(_) => {
                        state.parser.next_hdr = HeaderType::ErrorOccurred;
                        #[allow(static_mut_refs)]
                        unsafe {
                            let _ = PROG_ARRAY.tail_call(ctx, PROG_IDX_PARSER);
                        };
                        return TC_ACT_PIPE;
                    }
                }
            }
            #[allow(static_mut_refs)]
            unsafe {
                let _ = PROG_ARRAY.tail_call(ctx, PROG_IDX_READ_VAR_BUF_CHUNKED);
            };
        }

        TC_ACT_PIPE
    }

    #[cfg(not(test))]
    pub fn read_var_buf_chunked(ctx: &TcContext) -> i32 {
        let key: u32 = 0;
        #[allow(static_mut_refs)]
        let state_ptr = unsafe { TAIL_CALL_STATE.get_ptr_mut(key) };

        if let Some(state_ptr) = state_ptr {
            let state = unsafe { &mut *state_ptr };

            //Clamp to help the verifier prove we won't go out of bounds
            state.var_bytes_read &= MAX_SIZE_MASK;

            // Unroll a few reads to reduce tail call overhead.
            // Breaks at 7 loops
            for _ in 0..6 {
                if state.var_len_to_read.saturating_sub(state.var_bytes_read) < 16 {
                    #[allow(static_mut_refs)]
                    unsafe {
                        let _ = PROG_ARRAY.tail_call(ctx, PROG_IDX_READ_VAR_BUF_REMAINDER);
                    };
                    return TC_ACT_PIPE;
                }

                match Self::read_sixteen_byte_chunk(
                    ctx,
                    &mut state.buffer,
                    state.var_len_to_read,
                    &mut state.var_bytes_read,
                    &mut state.var_offset,
                ) {
                    Ok(true) => {}
                    Ok(false) => break, // Not enough data for a full chunk.
                    Err(_) => {
                        state.parser.next_hdr = HeaderType::ErrorOccurred;
                        #[allow(static_mut_refs)]
                        unsafe {
                            let _ = PROG_ARRAY.tail_call(ctx, PROG_IDX_PARSER);
                        };
                        return TC_ACT_PIPE;
                    }
                }
            }

            if state.var_len_to_read.saturating_sub(state.var_bytes_read) > 0 {
                // If there's more to read, tail call recursively to handle more chunks.
                #[allow(static_mut_refs)]
                unsafe {
                    let _ = PROG_ARRAY.tail_call(ctx, PROG_IDX_READ_VAR_BUF_CHUNKED);
                };
            } else {
                // Finished reading, go back to parser.
                #[allow(static_mut_refs)]
                unsafe {
                    let _ = PROG_ARRAY.tail_call(ctx, PROG_IDX_PARSER);
                };
            }
        }

        TC_ACT_PIPE
    }

    #[cfg(not(test))]
    pub fn read_var_buf_remainder(ctx: &TcContext) -> i32 {
        let key: u32 = 0;
        #[allow(static_mut_refs)]
        let state_ptr = unsafe { TAIL_CALL_STATE.get_ptr_mut(key) };

        if let Some(state_ptr) = state_ptr {
            let state = unsafe { &mut *state_ptr };

            //Clamp to help the verifier prove we won't go out of bounds
            state.var_bytes_read &= MAX_SIZE_MASK;

            // Read remaining bytes (at most 15).
            for _ in 0..15 {
                match Self::read_single_byte(
                    ctx,
                    &mut state.buffer,
                    state.var_len_to_read,
                    &mut state.var_bytes_read,
                    &mut state.var_offset,
                ) {
                    Ok(true) => {}
                    Ok(false) => break, // No more bytes to read.
                    Err(_) => {
                        state.parser.next_hdr = HeaderType::ErrorOccurred;
                        break;
                    }
                }
            }

            // Reading is done, tail call back to the main parser.
            #[allow(static_mut_refs)]
            unsafe {
                let _ = PROG_ARRAY.tail_call(ctx, PROG_IDX_PARSER);
            };
        }

        TC_ACT_PIPE
    }

    #[cfg(test)]
    fn read_var_buf_harness(
        ctx: &TcContext,
        offset: usize,
        len: usize,
        buf: &mut [u8; MAX_VAR_BUF_SIZE],
    ) -> Result<usize, Error> {
        let mut var_offset = offset;
        let mut var_bytes_read = 0;
        let var_len_to_read = core::cmp::min(len, MAX_VAR_BUF_SIZE);

        // 1. Align to 16-byte boundary (simulate read_var_buf_align)
        for _ in 0..15 {
            if var_offset % 16 == 0 {
                break;
            }
            match Self::read_single_byte(
                ctx,
                buf,
                var_len_to_read,
                &mut var_bytes_read,
                &mut var_offset,
            ) {
                Ok(true) => {}
                Ok(false) => return Ok(var_bytes_read), // Finished reading
                Err(e) => return Err(e),
            }
        }

        // 2. Read 16-byte chunks (simulate read_var_buf_chunked)
        while var_len_to_read.saturating_sub(var_bytes_read) >= 16 {
            match Self::read_sixteen_byte_chunk(
                ctx,
                buf,
                var_len_to_read,
                &mut var_bytes_read,
                &mut var_offset,
            ) {
                Ok(true) => {}
                Ok(false) => break, // Not enough data for a full chunk
                Err(e) => return Err(e),
            }
        }

        // 3. Read the remainder (simulate read_var_buf_remainder)
        for _ in 0..15 {
            match Self::read_single_byte(
                ctx,
                buf,
                var_len_to_read,
                &mut var_bytes_read,
                &mut var_offset,
            ) {
                Ok(true) => {}
                Ok(false) => break, // Finished reading
                Err(e) => return Err(e),
            }
        }

        Ok(var_bytes_read)
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
    let key: u32 = 0;
    let state = TailCallState::default();

    unsafe {
        // Initialize state for this packet using get_ptr_mut.
        #[allow(static_mut_refs)]
        let state_ptr = TAIL_CALL_STATE.get_ptr_mut(key);
        if let Some(state_ptr) = state_ptr {
            *state_ptr = state;
        } else {
            return TC_ACT_PIPE;
        }

        // Jump to the main parser program.
        #[allow(static_mut_refs)]
        let _ = PROG_ARRAY.tail_call(&ctx, PROG_IDX_PARSER);
    }

    // This is the fallback if the tail call fails.
    TC_ACT_PIPE
}

#[cfg(not(test))]
fn try_mermin(ctx: TcContext) -> i32 {
    let key: u32 = 0;
    #[allow(static_mut_refs)]
    let state_ptr = unsafe { TAIL_CALL_STATE.get_ptr_mut(key) };
    if state_ptr.is_none() {
        return TC_ACT_PIPE;
    }

    let state = unsafe { &mut *state_ptr.unwrap() };
    let parser = &mut state.parser;

    debug!(&ctx, "mermin: parsing packet");

    for _ in 0..MAX_HEADER_PARSE_DEPTH {
        let result: Result<(), Error> = match parser.next_hdr {
            HeaderType::Ethernet => parser.parse_ethernet_header(&ctx),
            HeaderType::Ipv4 => parser.parse_ipv4_header(&ctx),
            HeaderType::Ipv6 => parser.parse_ipv6_header(&ctx),
            HeaderType::Geneve => parser.parse_geneve_header(&ctx),
            HeaderType::Proto(IpProto::Tcp) => parser.parse_tcp_header(&ctx),
            HeaderType::Proto(IpProto::Udp) => parser.parse_udp_header(&ctx),
            HeaderType::Proto(IpProto::HopOpt) => parser.parse_hop_header(&ctx),
            HeaderType::Proto(IpProto::Icmp) => parser.parse_icmp_header(&ctx),
            HeaderType::Proto(IpProto::Ipv6Icmp) => parser.parse_icmp_header(&ctx),
            HeaderType::Proto(IpProto::Ah) => parser.parse_ah_header(&ctx),
            HeaderType::Proto(IpProto::Esp) => parser.parse_esp_header(&ctx),
            HeaderType::Proto(IpProto::Ipv6Route) => {
                match parser.parse_routing_header(&ctx, &state.buffer) {
                    Ok(Some((read_offset, read_len))) => {
                        // Repurpose state fields to pass arguments to the reader program
                        state.var_offset = read_offset;
                        state.var_len_to_read = read_len;
                        state.var_bytes_read = 0;

                        #[allow(static_mut_refs)]
                        unsafe {
                            let _ = PROG_ARRAY.tail_call(&ctx, PROG_IDX_READ_VAR_BUF_ALIGN);
                        }
                        // This part is unreachable, but the compiler needs to know
                        // the function exits. A tail call is effectively an exit.
                        return TC_ACT_PIPE;
                    }

                    // Ok(Some((read_offset, read_len))) => {
                    //     // Repurpose state fields to pass arguments to the reader program
                    //     state.var_offset = read_offset;
                    //     state.var_len_to_read = read_len;
                    //
                    //     #[allow(static_mut_refs)]
                    //     unsafe {
                    //         let _ = PROG_ARRAY.tail_call(&ctx, PROG_IDX_READ_VAR_BUF);
                    //     }
                    //     // This part is unreachable, but the compiler needs to know
                    //     // the function exits. A tail call is effectively an exit.
                    //     return TC_ACT_PIPE;
                    // }
                    Ok(None) => Ok(()), // Continue parsing
                    Err(e) => Err(e),
                }
            }
            HeaderType::Proto(IpProto::Ipv6NoNxt) => break,
            HeaderType::Proto(proto) => {
                debug!(
                    &ctx,
                    "mermin: skipped parsing of unsupported protocol {}", proto as u8
                );
                break;
            }
            HeaderType::StopProcessing => break, // Graceful stop
            HeaderType::ErrorOccurred => return TC_ACT_PIPE, // Error, pass packet
        };

        if result.is_err() {
            error!(
                &ctx,
                "mermin: parser failed at offset {}", parser.options.offset
            );
            parser.next_hdr = HeaderType::ErrorOccurred; // Mark error
        }
    }

    unsafe {
        debug!(
            &ctx,
            "mermin: writing to packet output with proto {}", parser.packet_meta.proto as u8
        );
        #[allow(static_mut_refs)]
        let result = PACKETS.output(&parser.packet_meta, 0);
        if result.is_err() {
            error!(&ctx, "mermin: failed to write packet to ring buffer");
        }
    }
    TC_ACT_PIPE
}

#[cfg(not(test))]
#[classifier]
pub fn parser(ctx: TcContext) -> i32 {
    // Tail-call entrypoint wrapper for try_mermin
    try_mermin(ctx)
}

#[cfg(not(test))]
#[classifier]
pub fn read_var_buf_align_prog(ctx: TcContext) -> i32 {
    // Tail-call entrypoint wrapper for Parser::read_var_buf_align
    Parser::read_var_buf_align(&ctx)
}

#[cfg(not(test))]
#[classifier]
pub fn read_var_buf_chunked_prog(ctx: TcContext) -> i32 {
    // Tail-call entrypoint wrapper for Parser::read_var_buf_chunked
    Parser::read_var_buf_chunked(&ctx)
}

#[cfg(not(test))]
#[classifier]
pub fn read_var_buf_remainder_prog(ctx: TcContext) -> i32 {
    // Tail-call entrypoint wrapper for Parser::read_var_buf_remainder
    Parser::read_var_buf_remainder(&ctx)
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
use host_test_shim::TcContext;

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

    // Helper function to create a Hop-by-Hop Options header test packet
    // The HopOptHdr is 8 bytes (next_hdr, hdr_ext_len, and 6 bytes of opt_data)
    fn create_hop_test_packet(next: IpProto, hdr_ext_len: u8) -> Vec<u8> {
        let mut packet = Vec::with_capacity(HopOptHdr::LEN);
        // Next Header
        packet.push(next as u8);
        // Header Extension Length
        packet.push(hdr_ext_len);
        // Options Data (6 bytes)
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        packet
    }

    // Helper function to create an ICMP header test packet (Echo Request)
    fn create_icmp_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Type (8 = Echo Request)
        packet.push(0x08);
        // Code (0)
        packet.push(0x00);
        // Checksum (2 bytes)
        packet.extend_from_slice(&[0x12, 0x34]);
        // Identifier (2 bytes)
        packet.extend_from_slice(&[0x56, 0x78]);
        // Sequence Number (2 bytes)
        packet.extend_from_slice(&[0x9a, 0xbc]);

        packet
    }

    // Helper function to create a Type2 routing header test packet
    // Type2 routing header is 24 bytes total (4 bytes generic + 20 bytes fixed)
    fn create_type2_routing_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::with_capacity(24);

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(2); // Hdr Ext Len (2 * 8 = 16 bytes after first 8, total 24)
        packet.push(2); // Routing Type (Type2)
        packet.push(1); // Segments Left (always 1 for Type2)

        // Type2 fixed header (20 bytes)
        // Reserved (4 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Home Address (16 bytes) - 2001:db8::dead:beef
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad,
            0xbe, 0xef,
        ]);

        packet
    }

    // Helper function to create an RPL Source Route header test packet
    // This creates a minimal RPL header with 2 addresses
    fn create_rpl_source_route_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(4); // Hdr Ext Len (4 * 8 = 32 bytes after first 8, total 40)
        packet.push(3); // Routing Type (RplSourceRoute)
        packet.push(2); // Segments Left

        // RPL Source fixed header (4 bytes)
        packet.push(0x24); // CmprI = 2, CmprE = 4 (0x24)
        packet.push(0x60); // Pad = 6 (0x60), Reserved bits = 0
        packet.extend_from_slice(&[0x00, 0x00]); // Reserved (remaining 2 bytes)

        // Address data (32 bytes total to match hdr_ext_len)
        // First address (14 bytes, compressed by CmprI=2)
        packet.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        ]);
        // Last address (12 bytes, compressed by CmprE=4)
        packet.extend_from_slice(&[
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        ]);
        // Padding (6 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        packet
    }

    // Helper function to create a Segment Routing Header test packet
    // This creates a minimal SRH with 2 segments based on RFC 8754 structure
    fn create_segment_routing_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(4); // Hdr Ext Len (4 * 8 = 32 bytes after first 8, total 40)
        packet.push(4); // Routing Type (SegmentRoutingHeader)
        packet.push(1); // Segments Left (index of current active segment)

        // Segment Routing fixed header (4 bytes)
        packet.push(1); // Last Entry (index of last entry, 0-based, so 1 means 2 segments)
        packet.push(0x00); // Flags (8 bits)
        packet.extend_from_slice(&[0x12, 0x34]); // Tag (16 bits)

        // Segment List: 2 IPv6 addresses (16 bytes each = 32 bytes total)
        // First segment (Segment List[0])
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ]);
        // Second segment (Segment List[1])
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x01, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x35,
        ]);

        packet
    }

    // Helper function to create a minimal Segment Routing Header test packet (1 segment)
    fn create_segment_routing_min_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(2); // Hdr Ext Len (2 * 8 = 16 bytes after first 8, total 24)
        packet.push(4); // Routing Type (SegmentRoutingHeader)
        packet.push(0); // Segments Left

        // Segment Routing fixed header (4 bytes)
        packet.push(0); // Last Entry (0 means 1 segment)
        packet.push(0xFF); // Flags (all set)
        packet.extend_from_slice(&[0xAB, 0xCD]); // Tag

        // Single segment (16 bytes)
        packet.extend_from_slice(&[
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x5e, 0xff, 0xfe, 0x00,
            0x53, 0xaf,
        ]);

        packet
    }

    // Helper function to create a CRH-16 test packet with 16-bit SIDs
    // This creates a CRH-16 header with 2 SIDs (total packet: 4 + 4 = 8 bytes)
    fn create_crh16_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(0); // Hdr Ext Len (0 * 8 = 0 bytes after first 8, total 8 bytes - only fixed header)
        packet.push(5); // Routing Type (Crh16)
        packet.push(1); // Segments Left

        // Reserved bytes to make the header 8 bytes long (minimum IPv6 extension header size)
        packet.extend_from_slice(&[0; 4]);

        packet
    }

    // Helper function to create a CRH-16 test packet with SIDs
    // This creates a CRH-16 header with 2 SIDs (total packet: 4 + 4 = 8 bytes)
    fn create_crh16_with_sids_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(1); // Hdr Ext Len (1 * 8 = 8 bytes after first 8, total 16 bytes)
        packet.push(5); // Routing Type (Crh16)
        packet.push(1); // Segments Left

        // SID List: 4 16-bit SIDs (8 bytes total)
        packet.extend_from_slice(&[0x12, 0x34]); // SID[0] = 0x1234
        packet.extend_from_slice(&[0x56, 0x78]); // SID[1] = 0x5678
        packet.extend_from_slice(&[0x9A, 0xBC]); // SID[2] = 0x9ABC
        packet.extend_from_slice(&[0xDE, 0xF0]); // SID[3] = 0xDEF0

        // Reserved bytes to make the header a multiple of 8 bytes long
        packet.extend_from_slice(&[0; 4]);

        packet
    }

    // Helper function to create a CRH-32 test packet
    // This creates a CRH-32 header with no SIDs (minimum size)
    fn create_crh32_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(0); // Hdr Ext Len (0 * 8 = 0 bytes after first 8, total 8 bytes - only fixed header)
        packet.push(6); // Routing Type (Crh32)
        packet.push(0); // Segments Left

        // Reserved bytes to make the header 8 bytes long (minimum IPv6 extension header size)
        packet.extend_from_slice(&[0; 4]);

        packet
    }

    // Helper function to create a CRH-32 test packet with SIDs
    // This creates a CRH-32 header with 2 SIDs (total packet: 4 + 8 = 12 bytes)
    fn create_crh32_with_sids_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(1); // Hdr Ext Len (1 * 8 = 8 bytes after first 8, total 16 bytes)
        packet.push(6); // Routing Type (Crh32)
        packet.push(1); // Segments Left

        // SID List: 2 32-bit SIDs (8 bytes total)
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // SID[0] = 0x12345678
        packet.extend_from_slice(&[0x9A, 0xBC, 0xDE, 0xF0]); // SID[1] = 0x9ABCDEF0

        // Reserved bytes to make the header a multiple of 8 bytes long
        packet.extend_from_slice(&[0; 4]);

        packet
    }

    // Helper to call parse_routing_header possibly twice when variable-length data is present
    fn parse_rh_with_tailcall(
        parser: &mut Parser,
        ctx: &TcContext,
        packet: &Vec<u8>,
    ) -> Result<(), Error> {
        let mut buf = [0u8; MAX_VAR_BUF_SIZE];
        let res = parser.parse_routing_header(ctx, &buf)?;
        if let Some((start, len)) = res {
            // Simulate ProgramArray var-buf read by filling buffer from packet
            buf[..len].copy_from_slice(&packet[start..start + len]);
            parser.is_reading_var_buf = true;
            let _ = parser.parse_routing_header(ctx, &buf)?;
        }
        Ok(())
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
        let parser = Parser::default();

        assert_eq!(parser.options.offset, 0);
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));

        // Check that packet_meta is initialized with default values
        let packet_meta = parser.packet_meta;
        assert_eq!(packet_meta.src_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.dst_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.src_port, [0, 0]);
        assert_eq!(packet_meta.dst_port, [0, 0]);
    }

    // Test Parser with_options constructor
    #[test]
    fn test_parser_with_options() {
        let custom_options = ParserOptions {
            geneve_port: 8080,
            offset: 0,
        };
        let parser = Parser::with_options(custom_options.clone());

        // Verify custom options are set
        assert_eq!(parser.options.geneve_port, 8080);

        // Verify other fields have default values
        assert_eq!(parser.options.offset, 0);
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));

        // Check that packet_meta is initialized with default values
        let packet_meta = parser.packet_meta;
        assert_eq!(packet_meta.src_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.dst_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.src_port, [0, 0]);
        assert_eq!(packet_meta.dst_port, [0, 0]);

        // Test with default port as well
        let default_options = ParserOptions::default();
        let parser_default = Parser::with_options(default_options);
        assert_eq!(parser_default.options.geneve_port, 6081);
    }

    #[test]
    fn test_parser_calculate_l3_octet_count() {
        let mut parser = Parser::default();

        parser.options.offset = 32;
        parser.calc_l3_octet_count(256);

        assert_eq!(parser.packet_meta.l3_octet_count, 224);
    }

    // Test parse_ethernet_header function
    #[test]
    fn test_parse_ethernet_header() {
        let mut parser = Parser::default();
        let packet = create_eth_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ethernet_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, EthHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    // Test parse_ipv4_header function
    #[test]
    fn test_parse_ipv4_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv4;
        let packet = create_ipv4_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv4_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 20); // IPv4 header length (5 * 4 bytes)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
        assert_eq!(parser.packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]); // 192.168.1.1
        assert_eq!(parser.packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]); // 192.168.1.2
        assert_eq!(parser.packet_meta.proto, IpProto::Tcp); // TCP
    }

    // Test parse_ipv4_header function with invalid header length
    #[test]
    fn test_parse_ipv4_header_invalid_length() {
        let mut parser = Parser::default();
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
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv6;
        let packet = create_ipv6_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv6_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, Ipv6Hdr::LEN);
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
        assert_eq!(parser.packet_meta.proto, IpProto::Tcp); // TCP
    }

    // Test parse_tcp_header function
    #[test]
    fn test_parse_tcp_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Tcp);
        let packet = create_tcp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_tcp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, TcpHdr::LEN);
        assert_eq!(parser.packet_meta.src_port, [0x30, 0x39]); // 12345
        assert_eq!(parser.packet_meta.dst_port, [0x00, 0x50]); // 80
    }

    // Test parse_udp_header function
    #[test]
    fn test_parse_udp_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Udp);
        let packet = create_udp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_udp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, UdpHdr::LEN);
        assert_eq!(parser.packet_meta.src_port, [0x30, 0x39]); // 12345
        assert_eq!(parser.packet_meta.dst_port, [0x00, 0x35]); // 53
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    // Test parse_udp_header function with Geneve port
    #[test]
    fn test_parse_udp_header_geneve() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Udp);
        let packet = create_udp_geneve_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_udp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, UdpHdr::LEN);
        assert_eq!(parser.packet_meta.src_port, [0x30, 0x39]); // 12345
        assert_eq!(parser.packet_meta.dst_port, [0x17, 0xC1]); // 6081 (Geneve)
        assert!(matches!(parser.next_hdr, HeaderType::Geneve));
    }

    // Test parse_ah_header function mapping to TCP
    #[test]
    fn test_parse_ah_header_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        let packet = create_ah_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, AuthHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_ah_header function mapping to UDP
    #[test]
    fn test_parse_ah_header_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        let packet = create_ah_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, AuthHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_ah_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_ah_header_out_of_bounds() {
        let mut parser = Parser::default();
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
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Esp);
        let packet = create_esp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_esp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, Esp::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    // Test parse_esp_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_esp_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Esp);
        // Provide fewer than 8 bytes
        let packet = vec![0x12, 0x34, 0x56, 0x78];
        let ctx = TcContext::new(packet);

        let result = parser.parse_esp_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test parse_hop_header function mapping to TCP
    #[test]
    fn test_parse_hop_header_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        let packet = create_hop_test_packet(IpProto::Tcp, 0);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hop_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, HopOptHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_hop_header function mapping to UDP
    #[test]
    fn test_parse_hop_header_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        let packet = create_hop_test_packet(IpProto::Udp, 0);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hop_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, HopOptHdr::LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_hop_header with non-zero hdr_ext_len
    #[test]
    fn test_parse_hop_header_with_extension() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        let packet = create_hop_test_packet(IpProto::Tcp, 1);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hop_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 16); // 8 bytes base + 8 bytes extension (1 * 8)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_hop_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_hop_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        // Provide fewer than 8 bytes
        let packet = vec![0x06, 0x00, 0x01, 0x02];
        let ctx = TcContext::new(packet);

        let result = parser.parse_hop_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test parse_geneve_header function with IPv4 protocol type
    #[test]
    fn test_parse_geneve_header_ipv4() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x0800, 0); // IPv4 protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    // Test parse_geneve_header function with IPv6 protocol type
    #[test]
    fn test_parse_geneve_header_ipv6() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x86DD, 0); // IPv6 protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ipv6));
    }

    // Test parse_geneve_header function with Ethernet protocol type
    #[test]
    fn test_parse_geneve_header_ethernet() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x6558, 0); // Ethernet protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));
    }

    // Test parse_geneve_header function with options
    #[test]
    fn test_parse_geneve_header_with_options() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x0800, 2); // IPv4 protocol type, 2 option units (8 bytes)
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, GeneveHdr::LEN + 8); // Header length + 8 bytes of options
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    // Test parse_geneve_header function with unsupported protocol type
    #[test]
    fn test_parse_geneve_header_unsupported_protocol() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x1234, 0); // Unsupported protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, GeneveHdr::LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    // Test parse_geneve_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_geneve_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        // Provide fewer than 8 bytes (Geneve header length)
        let packet = vec![0x00, 0x00, 0x08, 0x00, 0x12, 0x34];
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test parse_icmp_header function
    #[test]
    fn test_parse_icmp_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Icmp);
        let packet = create_icmp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_icmp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, IcmpHdr::LEN);
        // ICMP doesn't use ports, so they should remain zero
        assert_eq!(parser.packet_meta.src_port, [0, 0]);
        assert_eq!(parser.packet_meta.dst_port, [0, 0]);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    // Test parse_icmp_header with insufficient buffer (out of bounds)
    #[test]
    fn test_parse_icmp_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Icmp);
        // Provide fewer than 8 bytes (ICMP header length)
        let packet = vec![0x08, 0x00, 0x12, 0x34];
        let ctx = TcContext::new(packet);

        let result = parser.parse_icmp_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test IPv4 header parsing with ICMP protocol
    #[test]
    fn test_parse_ipv4_header_with_icmp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv4;
        let mut packet = create_ipv4_test_packet();
        // Change protocol from TCP (6) to ICMP (1)
        packet[9] = 0x01; // Protocol field in IPv4 header
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv4_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 20); // IPv4 header length (5 * 4 bytes)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Icmp)));
        assert_eq!(parser.packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]); // 192.168.1.1
        assert_eq!(parser.packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]); // 192.168.1.2
        assert_eq!(parser.packet_meta.proto, IpProto::Icmp); // ICMP
    }

    // Test IPv6 header parsing with ICMPv6 protocol
    #[test]
    fn test_parse_ipv6_header_with_icmpv6() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv6;
        let mut packet = create_ipv6_test_packet();
        // Change next header from TCP (6) to ICMPv6 (58)
        packet[6] = 58; // Next Header field in IPv6 header
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv6_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, Ipv6Hdr::LEN);
        assert!(matches!(
            parser.next_hdr,
            HeaderType::Proto(IpProto::Ipv6Icmp)
        ));
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
        assert_eq!(parser.packet_meta.proto, IpProto::Ipv6Icmp); // ICMPv6
    }

    // Test parse_routing_header function with Type2 routing header
    #[test]
    fn test_parse_routing_header_type2_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_type2_routing_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 24); // Type2 routing header length
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with Type2 routing header mapping to UDP
    #[test]
    fn test_parse_routing_header_type2_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_type2_routing_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet);

        let mut buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 24); // Type2 routing header length
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_routing_header function with Type2 routing header with insufficient buffer
    #[test]
    fn test_parse_routing_header_type2_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        // Provide fewer than 24 bytes (incomplete Type2 header)
        let packet = vec![0x06, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00];
        let ctx = TcContext::new(packet);

        let buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test parse_routing_header function with RPL Source Route header
    #[test]
    fn test_parse_routing_header_rpl_source_route_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_rpl_source_route_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet.clone());

        let mut buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);
        assert!(result.is_ok());
        let (start, len) = result.unwrap().expect("expected var read");
        buf[..len].copy_from_slice(&packet[start..start + len]);
        let result2 = parser.parse_routing_header(&ctx, &buf);
        assert!(result2.is_ok());
        assert_eq!(parser.options.offset, 40); // RPL Source Route header length (8 + 32)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with RPL Source Route header mapping to UDP
    #[test]
    fn test_parse_routing_header_rpl_source_route_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_rpl_source_route_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 40); // RPL Source Route header length (8 + 32)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_routing_header function with RPL Source Route header with insufficient buffer
    #[test]
    fn test_parse_routing_header_rpl_source_route_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        // Provide fewer bytes than required for RPL header
        let packet = vec![0x06, 0x04, 0x03, 0x02, 0x24, 0x60];
        let ctx = TcContext::new(packet);

        let buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test parse_routing_header function with Segment Routing Header mapping to TCP
    #[test]
    fn test_parse_routing_header_segment_routing_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_segment_routing_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 40); // Segment Routing header length (8 + 32)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with Segment Routing Header mapping to UDP
    #[test]
    fn test_parse_routing_header_segment_routing_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_segment_routing_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 40); // Segment Routing header length (8 + 32)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_routing_header function with minimum valid Segment Routing Header
    #[test]
    fn test_parse_routing_header_segment_routing_min() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_segment_routing_min_test_packet(IpProto::Ipv6);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 24); // Minimum Segment Routing header length (8 + 16)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Ipv6)));
    }

    // Test parse_routing_header function with Segment Routing Header with insufficient buffer
    #[test]
    fn test_parse_routing_header_segment_routing_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        // Provide fewer bytes than required for Segment Routing header
        let packet = vec![0x06, 0x04, 0x04, 0x01, 0x01, 0x00]; // Only 6 bytes
        let ctx = TcContext::new(packet);

        let buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test Segment Routing Header edge case with maximum segments left
    #[test]
    fn test_parse_routing_header_segment_routing_max_segments_left() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let mut packet = create_segment_routing_test_packet(IpProto::Tcp);
        // Set segments left to maximum value
        packet[4] = 255;
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 40);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test Segment Routing Header with different flag values
    #[test]
    fn test_parse_routing_header_segment_routing_flags() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let mut packet = create_segment_routing_test_packet(IpProto::Udp);
        // Set all flags
        packet[6] = 0xFF;
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 40);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test Segment Routing Header with zero segments (edge case)
    #[test]
    fn test_parse_routing_header_segment_routing_zero_hdr_ext_len() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);

        // Create a packet with zero hdr_ext_len (only fixed header)
        let mut packet = Vec::new();
        packet.push(IpProto::Tcp as u8); // Next Header
        packet.push(0); // Hdr Ext Len = 0 (total 8 bytes)
        packet.push(4); // Routing Type (SegmentRoutingHeader)
        packet.push(0); // Segments Left
        packet.push(0); // Last Entry
        packet.push(0x00); // Flags
        packet.extend_from_slice(&[0x00, 0x00]); // Tag

        let ctx = TcContext::new(packet);

        let buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 8); // Only fixed header
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with CRH-16 header mapping to TCP
    #[test]
    fn test_parse_routing_header_crh16_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh16_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 8); // CRH header length (8 bytes minimum, no SIDs)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with CRH-16 header mapping to UDP
    #[test]
    fn test_parse_routing_header_crh16_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh16_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 8); // CRH header length (8 bytes minimum, no SIDs)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_routing_header function with CRH-16 header with SIDs
    #[test]
    fn test_parse_routing_header_crh16_with_sids() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh16_with_sids_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 16); // CRH header length (4 + 8 bytes SIDs + 4 bytes padding)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with CRH-16 header with insufficient buffer
    #[test]
    fn test_parse_routing_header_crh16_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        // Provide fewer bytes than required for CRH-16 header
        let packet = vec![0x06, 0x01]; // Only 2 bytes
        let ctx = TcContext::new(packet);

        let buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test CRH-16 Header edge case with maximum segments left
    #[test]
    fn test_parse_routing_header_crh16_max_segments_left() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let mut packet = create_crh16_with_sids_test_packet(IpProto::Tcp);
        // Set segments left to maximum value
        packet[3] = 255;
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 16); // CRH header length (4 + 8 bytes SIDs + 4 bytes padding)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with CRH-32 header mapping to TCP
    #[test]
    fn test_parse_routing_header_crh32_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh32_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 8); // CRH header length (8 bytes minimum, no SIDs)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with CRH-32 header mapping to UDP
    #[test]
    fn test_parse_routing_header_crh32_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh32_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 8); // CRH header length (8 bytes minimum, no SIDs)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test parse_routing_header function with CRH-32 header with SIDs
    #[test]
    fn test_parse_routing_header_crh32_with_sids() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh32_with_sids_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 16); // CRH header length (4 + 8 bytes SIDs + 4 bytes padding)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test parse_routing_header function with CRH-32 header with insufficient buffer
    #[test]
    fn test_parse_routing_header_crh32_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        // Provide fewer bytes than required for CRH-32 header
        let packet = vec![0x06, 0x01]; // Only 2 bytes
        let ctx = TcContext::new(packet);

        let buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    // Test CRH-32 Header edge case with maximum segments left
    #[test]
    fn test_parse_routing_header_crh32_max_segments_left() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let mut packet = create_crh32_with_sids_test_packet(IpProto::Udp);
        // Set segments left to maximum value
        packet[3] = 255;
        let ctx = TcContext::new(packet.clone());

        let result = parse_rh_with_tailcall(&mut parser, &ctx, &packet);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 16);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Test CRH-16 with zero hdr_ext_len (minimum valid header)
    #[test]
    fn test_parse_routing_header_crh16_zero_hdr_ext_len() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);

        // Create a packet with zero hdr_ext_len (only fixed header)
        let mut packet = Vec::new();
        packet.push(IpProto::Tcp as u8); // Next Header
        packet.push(0); // Hdr Ext Len = 0 (total 4 bytes)
        packet.push(5); // Routing Type (Crh16)
        packet.push(0); // Segments Left

        // Reserved bytes to make the header a multiple of 8 bytes long
        packet.extend_from_slice(&[0; 4]);

        let ctx = TcContext::new(packet);

        let mut buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 8); // Only fixed header and padding
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    // Test CRH-32 with zero hdr_ext_len (minimum valid header)
    #[test]
    fn test_parse_routing_header_crh32_zero_hdr_ext_len() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);

        // Create a packet with zero hdr_ext_len (only fixed header)
        let mut packet = Vec::new();
        packet.push(IpProto::Udp as u8); // Next Header
        packet.push(0); // Hdr Ext Len = 0 (total 4 bytes)
        packet.push(6); // Routing Type (Crh32)
        packet.push(0); // Segments Left

        // Reserved bytes to make the header a multiple of 8 bytes long
        packet.extend_from_slice(&[0; 4]);

        let ctx = TcContext::new(packet);

        let mut buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = parser.parse_routing_header(&ctx, &buf);

        assert!(result.is_ok());
        assert_eq!(parser.options.offset, 8); // Only fixed header and padding
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    // Helper function to create network-like test data with big endian patterns
    fn create_network_test_data(size: usize) -> Vec<u8> {
        let mut data = Vec::new();
        let mut value = 0x0102030405060708u64;

        for i in (0..size).step_by(8) {
            let bytes = value.to_be_bytes(); // Network byte order
            let remaining = size - i;
            let chunk_size = core::cmp::min(8, remaining);
            data.extend_from_slice(&bytes[0..chunk_size]);
            value = value.wrapping_add(0x0101010101010101); // Increment pattern
        }
        data
    }

    // Test read_var_buf logic with various odd lengths
    #[test]
    fn test_read_var_buf_odd_lengths() {
        let test_lengths = [
            1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 31, 33, 63, 65, 127, 129,
        ];

        for &len in &test_lengths {
            let test_data = create_network_test_data(len + 10); // Extra data to ensure we can read
            let ctx = TcContext::new(test_data.clone());
            let mut buf = [0u8; MAX_VAR_BUF_SIZE];

            let result = Parser::read_var_buf_harness(&ctx, 0, len, &mut buf);

            assert!(result.is_ok(), "Failed for length {}", len);
            assert_eq!(result.unwrap(), len, "Wrong bytes read for length {}", len);
            assert_eq!(
                &buf[0..len],
                &test_data[0..len],
                "Data mismatch for length {}",
                len
            );

            // Verify rest of buffer is unchanged
            for i in len..MAX_VAR_BUF_SIZE {
                assert_eq!(
                    buf[i], 0,
                    "Buffer corruption at index {} for length {}",
                    i, len
                );
            }
        }
    }

    // Test big endian conversion correctness for network data
    #[test]
    fn test_read_var_buf_big_endian_validation() {
        // Create test data with known big endian patterns
        let original_values = [0x01020304u32, 0x05060708u32, 0x090a0b0cu32, 0x0d0e0f10u32];

        let mut test_data = Vec::new();
        for &val in &original_values {
            test_data.extend_from_slice(&val.to_be_bytes());
        }

        let ctx = TcContext::new(test_data);
        let mut buf = [0u8; MAX_VAR_BUF_SIZE];

        let read_len = 16;
        let result = Parser::read_var_buf_harness(&ctx, 0, read_len, &mut buf);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), read_len);

        // Verify the data is correctly stored in big endian format
        for (i, &expected_val) in original_values.iter().enumerate() {
            let start_idx = i * 4;
            let actual_bytes = [
                buf[start_idx],
                buf[start_idx + 1],
                buf[start_idx + 2],
                buf[start_idx + 3],
            ];
            let actual_val = u32::from_be_bytes(actual_bytes);
            assert_eq!(
                actual_val, expected_val,
                "Big endian mismatch at position {}",
                i
            );
        }
    }

    // Test network protocol headers with realistic data patterns
    #[test]
    fn test_read_var_buf_network_headers() {
        // Simulate reading various network headers with odd sizes
        let base_size = 20;
        let option_sizes = [1, 3, 7, 11, 15];

        for &opt_size in &option_sizes {
            let total_size = base_size + opt_size;
            let test_data = create_network_test_data(total_size);
            let ctx = TcContext::new(test_data.clone());
            let mut buf = [0u8; MAX_VAR_BUF_SIZE];

            let result = Parser::read_var_buf_harness(&ctx, 0, total_size, &mut buf);

            assert!(result.is_ok(), "Failed for size {}", total_size);
            assert_eq!(result.unwrap(), total_size);
            assert_eq!(&buf[0..total_size], &test_data[0..total_size]);
        }
    }

    // Test multi-byte value reading across chunk boundaries
    #[test]
    fn test_read_var_buf_chunk_boundary_values() {
        // Test reading values that span 16-byte chunk boundaries
        let test_lengths = [15, 16, 17, 31, 32, 33];
        let test_offsets = [0, 1, 7]; // Test aligned and unaligned starts

        for &len in &test_lengths {
            for &offset in &test_offsets {
                let test_data = create_network_test_data(offset + len + 8); // Ensure enough data
                let ctx = TcContext::new(test_data.clone());
                let mut buf = [0u8; MAX_VAR_BUF_SIZE];

                let result = Parser::read_var_buf_harness(&ctx, offset, len, &mut buf);

                assert!(
                    result.is_ok(),
                    "Failed for length {} at offset {}",
                    len,
                    offset
                );
                assert_eq!(result.unwrap(), len);
                assert_eq!(
                    &buf[0..len],
                    &test_data[offset..offset + len],
                    "Data mismatch for length {} at offset {}",
                    len,
                    offset
                );
            }
        }
    }

    // Test reading with a length greater than the buffer size
    #[test]
    fn test_read_var_buf_buffer_constraints() {
        let test_data = create_network_test_data(MAX_VAR_BUF_SIZE + 20);
        let ctx = TcContext::new(test_data.clone());

        // Try to read more than MAX_VAR_BUF_SIZE
        let mut buf = [0u8; MAX_VAR_BUF_SIZE];
        let result = Parser::read_var_buf_harness(&ctx, 0, MAX_VAR_BUF_SIZE + 10, &mut buf);

        assert!(result.is_ok());
        // Should read only what fits in the buffer
        let bytes_read = result.unwrap();
        assert_eq!(
            bytes_read, MAX_VAR_BUF_SIZE,
            "Should only read up to buffer size"
        );
        assert_eq!(&buf[0..bytes_read], &test_data[0..bytes_read]);
    }
}
