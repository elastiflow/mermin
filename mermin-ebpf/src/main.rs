#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier},
    programs::TcContext,
};
use aya_log_ebpf::{debug, error};
use network_types::{
    ip::{IpProto},
    parser::{
        HeaderType, PACKETS, Parser, parse_ethernet_header, parse_ipv4_header, parse_ipv6_header,
        parse_tcp_header, parse_udp_header,
    },
};

const MAX_HEADER_PARSE_DEPTH: usize = 16;

#[classifier]
pub fn mermin(ctx: TcContext) -> i32 {
    try_mermin(ctx).unwrap_or(TC_ACT_PIPE)
}

fn try_mermin(ctx: TcContext) -> Result<i32, ()> {
    let mut parser = Parser::new();

    debug!(&ctx, "mermin: parsing packet");

    for _ in 0..MAX_HEADER_PARSE_DEPTH {
        let result = match parser.next_hdr {
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
