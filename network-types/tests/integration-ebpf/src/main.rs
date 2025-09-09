#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use aya_log_ebpf::{Level, log};
use integration_common::{HeaderUnion, PacketType, ParsedHeader};
use network_types::{
    ah::AuthHdr,
    destopts::DestOptsHdr,
    esp::Esp,
    eth::EthHdr,
    fragment::Fragment,
    geneve::GeneveHdr,
    hop::HopOptHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    route::{
        CrhHeader, RoutingHeaderType, RplSourceRouteHeader, SegmentRoutingHeader,
        Type2RoutingHeader,
    },
    tcp::TcpHdr,
    udp::UdpHdr,
    vxlan::VxlanHdr,
};

pub const MAX_RPL_ADDR_STORAGE: usize = 128;
pub const MAX_SEGMENT_STORAGE: usize = 128; // 256 Broke the stack :(
pub const MAX_CRH_SID_STORAGE: usize = 128;
pub const MAX_SIZE_MASK: usize = 255;

#[map(name = "OUT_DATA")]
static mut OUT_DATA: PerfEventArray<ParsedHeader> = PerfEventArray::new(0);

fn u8_to_packet_type(val: u8) -> Option<PacketType> {
    match val {
        1 => Some(PacketType::Eth),
        2 => Some(PacketType::Ipv4),
        3 => Some(PacketType::Ipv6),
        4 => Some(PacketType::Tcp),
        5 => Some(PacketType::Udp),
        6 => Some(PacketType::Ah),
        7 => Some(PacketType::Esp),
        8 => Some(PacketType::Hop),
        9 => Some(PacketType::Geneve),
        10 => Some(PacketType::RplSourceRoute),
        11 => Some(PacketType::Type2),
        12 => Some(PacketType::SegmentRouting),
        13 => Some(PacketType::Crh16),
        14 => Some(PacketType::Crh32),
        15 => Some(PacketType::Fragment),
        16 => Some(PacketType::DestOpts),
        17 => Some(PacketType::Vxlan),
        _ => None,
    }
}

#[classifier]
pub fn integration_test(ctx: TcContext) -> i32 {
    match try_integration_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_integration_test(ctx: TcContext) -> Result<i32, i32> {
    log!(&ctx, Level::Info, "TC program triggered");

    // In our specific test case (UDP packet on loopback), we can assume a fixed header size.
    // Ethernet Header (14 bytes) + IPv4 Header (20 bytes) + UDP Header (8 bytes) = 42 bytes.
    const PAYLOAD_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;

    let packet_type_byte: u8 = ctx.load(PAYLOAD_OFFSET).map_err(|_| TC_ACT_SHOT)?;
    let data_offset = PAYLOAD_OFFSET + 1;

    let packet_type = match u8_to_packet_type(packet_type_byte) {
        Some(pt) => pt,
        None => {
            log!(
                &ctx,
                Level::Warn,
                "Unknown packet type in payload: {}",
                packet_type_byte
            );
            return Ok(TC_ACT_OK);
        }
    };

    let response = match packet_type {
        PacketType::Eth => {
            let header: EthHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Eth,
                data: HeaderUnion { eth: header },
            }
        }
        PacketType::Ipv4 => {
            let header: Ipv4Hdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Ipv4,
                data: HeaderUnion { ipv4: header },
            }
        }
        PacketType::Ipv6 => {
            let header: Ipv6Hdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Ipv6,
                data: HeaderUnion { ipv6: header },
            }
        }
        PacketType::Tcp => {
            let header: TcpHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Tcp,
                data: HeaderUnion { tcp: header },
            }
        }
        PacketType::Udp => {
            let header: UdpHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Udp,
                data: HeaderUnion { udp: header },
            }
        }
        PacketType::Ah => {
            let header: AuthHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Ah,
                data: HeaderUnion { ah: header },
            }
        }
        PacketType::Esp => {
            let header: Esp = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Esp,
                data: HeaderUnion { esp: header },
            }
        }
        PacketType::Hop => {
            let header: HopOptHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Hop,
                data: HeaderUnion { hop: header },
            }
        }
        PacketType::Geneve => {
            let header: GeneveHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Geneve,
                data: HeaderUnion { geneve: header },
            }
        }
        PacketType::Fragment => {
            let header: Fragment = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Fragment,
                data: HeaderUnion { fragment: header },
            }
        }
        PacketType::DestOpts => {
            let header: DestOptsHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::DestOpts,
                data: HeaderUnion { destopts: header },
            }
        }
        PacketType::Type2 => {
            let type2_hdr: Type2RoutingHeader = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;

            ParsedHeader {
                type_: PacketType::Type2,
                data: HeaderUnion { type2: type2_hdr },
            }
        }
        PacketType::RplSourceRoute => {
            let offset = data_offset;
            let rpl_header: RplSourceRouteHeader = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

            if rpl_header.gen_route.type_ != RoutingHeaderType::RplSourceRoute.as_u8() {
                return Err(TC_ACT_SHOT);
            }

            ParsedHeader {
                type_: PacketType::RplSourceRoute,
                data: HeaderUnion { rpl: rpl_header },
            }
        }
        PacketType::SegmentRouting => {
            let offset = data_offset;
            let segment_hdr: SegmentRoutingHeader = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

            if segment_hdr.gen_route.type_ != RoutingHeaderType::SegmentRoutingHeader.as_u8() {
                return Err(TC_ACT_SHOT);
            }

            ParsedHeader {
                type_: PacketType::SegmentRouting,
                data: HeaderUnion {
                    segment_routing: segment_hdr,
                },
            }
        }
        PacketType::Crh16 | PacketType::Crh32 => {
            let offset = data_offset;
            let crh_header: CrhHeader = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

            // Verify routing type matches expected CRH type
            let expected_type = match packet_type {
                PacketType::Crh16 => RoutingHeaderType::Crh16.as_u8(),
                PacketType::Crh32 => RoutingHeaderType::Crh32.as_u8(),
                _ => return Err(TC_ACT_SHOT),
            };

            if crh_header.gen_route.type_ != expected_type {
                return Err(TC_ACT_SHOT);
            }

            match packet_type {
                PacketType::Crh16 => ParsedHeader {
                    type_: PacketType::Crh16,
                    data: HeaderUnion { crh16: crh_header },
                },
                PacketType::Crh32 => ParsedHeader {
                    type_: PacketType::Crh32,
                    data: HeaderUnion { crh32: crh_header },
                },
                _ => return Err(TC_ACT_SHOT),
            }
        }
        PacketType::Vxlan => {
            let header: VxlanHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            ParsedHeader {
                type_: PacketType::Vxlan,
                data: HeaderUnion { vxlan: header },
            }
        }
    };

    #[allow(static_mut_refs)]
    unsafe {
        OUT_DATA.output(&ctx, &response, 0)
    };
    log!(&ctx, Level::Info, "Successfully processed packet payload");

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
