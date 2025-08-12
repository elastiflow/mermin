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
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

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
