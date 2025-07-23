#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{map, classifier},
    maps::PerfEventArray,
    programs::TcContext,
};
use aya_log_ebpf::{log, Level};
use core::mem;
use integration_common::{EthHdr as PodEthHdr, EthHdr, HeaderUnion, Ipv4Hdr as PodIpv4Hdr, Ipv6Hdr as PodIpv6Hdr, PacketType, ParsedHeader, TcpHdr as PodTcpHdr, UdpHdr as PodUdpHdr};
use integration_common::PacketType::Ipv4;
use network_types::{
    eth::{EthHdr as NetEthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr as NetIpv4Hdr, Ipv6Hdr as NetIpv6Hdr},
    tcp::TcpHdr as NetTcpHdr,
    udp::UdpHdr as NetUdpHdr,
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
    const PAYLOAD_OFFSET: usize = NetEthHdr::LEN + NetIpv4Hdr::LEN + NetUdpHdr::LEN;
    
    let packet_type_byte: u8 = ctx.load(PAYLOAD_OFFSET).map_err(|_| TC_ACT_SHOT as i32)?;
    let data_offset = PAYLOAD_OFFSET + 1;
    
    let packet_type = match u8_to_packet_type(packet_type_byte) {
        Some(pt) => pt,
        None => {
            log!(&ctx, Level::Warn, "Unknown packet type in payload: {}", packet_type_byte);
            return Ok(TC_ACT_OK as i32);
        }
    };

    let response = match packet_type {
        PacketType::Eth => {
            let header: NetEthHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT as i32)?;
            ParsedHeader {
                ty: PacketType::Eth,
                data: HeaderUnion { eth: PodEthHdr(header) },
            }
        }
        PacketType::Ipv4 => {
            let header: NetIpv4Hdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT as i32)?;
            ParsedHeader {
                ty: PacketType::Ipv4,
                data: HeaderUnion { ipv4: PodIpv4Hdr(header) },
            }
        }
        PacketType::Ipv6 => {
            let header: NetIpv6Hdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT as i32)?;
            ParsedHeader {
                ty: PacketType::Ipv6,
                data: HeaderUnion { ipv6: PodIpv6Hdr(header) },
            }
        }
        PacketType::Tcp => {
            let header: NetTcpHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT as i32)?;
            ParsedHeader {
                ty: PacketType::Tcp,
                data: HeaderUnion { tcp: PodTcpHdr(header) },
            }
        }
        PacketType::Udp => {
            let header: NetUdpHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT as i32)?;
            ParsedHeader {
                ty: PacketType::Udp,
                data: HeaderUnion { udp: PodUdpHdr(header) },
            }
        }
    };
    
    unsafe { OUT_DATA.output(&ctx, &response, 0) };
    log!(&ctx, Level::Info, "Successfully processed packet payload");

    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}