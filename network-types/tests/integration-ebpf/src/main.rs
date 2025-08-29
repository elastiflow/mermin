#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use aya_log_ebpf::{Level, log};
use integration_common::{HeaderUnion, PacketType, ParsedHeader, RplSourceRouteParsed};
use network_types::{
    ah::AuthHdr,
    esp::Esp,
    eth::EthHdr,
    geneve::GeneveHdr,
    hop::HopOptHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    route::{RoutingHeaderType, RplSourceRouteHeader, Type2RoutingHeader},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub const MAX_RPL_ADDR_STORAGE: usize = 128;
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
        PacketType::Type2 => {
            let type2_hdr: Type2RoutingHeader = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;

            ParsedHeader {
                type_: PacketType::Type2,
                data: HeaderUnion { type2: type2_hdr },
            }
        }
        PacketType::RplSourceRoute => {
            let mut offset = data_offset;
            let rpl_header: RplSourceRouteHeader = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

            if rpl_header.gen_route.type_ != RoutingHeaderType::RplSourceRoute.as_u8() {
                return Err(TC_ACT_SHOT);
            }

            offset += RplSourceRouteHeader::LEN;

            // Calculate the total length of all addresses
            let temp_total_addr_len = rpl_header.gen_route.total_hdr_len() - 8usize;

            // Clamp the value using a bitwise AND.
            // No matter what total_addr_len was before, after this operation,
            // its maximum possible value is 255.
            let total_addr_len = temp_total_addr_len & MAX_SIZE_MASK;

            if total_addr_len > MAX_RPL_ADDR_STORAGE {
                return Err(TC_ACT_SHOT);
            }

            let mut addresses_buf = [0u8; MAX_RPL_ADDR_STORAGE];

            // Prepare the parsed data to be sent back
            let mut parsed_data = RplSourceRouteParsed {
                header: rpl_header,
                addresses: [0u8; MAX_RPL_ADDR_STORAGE],
                addresses_len: total_addr_len as u8,
            };

            let mut bytes_read_total = 0;
            // Before we go to read 16 bytes at a time, we need to ensure the offset is alligned to a 16 byte interval
            // Given we don't necessarily know where in offset we are before this, do modular math and read in individual bytes until we are alligned
            let mut allignment = offset % 16;
            for _ in 0..16 {
                const CHUNK_SIZE: usize = 1;
                if allignment == 16 {
                    break;
                }
                //if we have read up to len or 1 is too much to read, finish reading bytes
                if bytes_read_total >= total_addr_len
                    || (total_addr_len - bytes_read_total) < CHUNK_SIZE
                {
                    break;
                }
                if bytes_read_total + CHUNK_SIZE > MAX_RPL_ADDR_STORAGE {
                    break;
                }

                let bytes: u8 = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

                //copy bytes into buf at location bytes_read_total, take care to use big endian conversion
                addresses_buf[bytes_read_total] = bytes;
                //advance bytes_read_total by 1, and self.offset by 1
                bytes_read_total += CHUNK_SIZE;
                offset += CHUNK_SIZE;
                allignment += CHUNK_SIZE;
            }
            // Loop to read 16 bytes at a time => 16*16 = 256 bytes total
            for _ in 0..16 {
                const CHUNK_SIZE: usize = 16;
                //if we have read up to len or 16 is too much to read, move onto reading u64
                if bytes_read_total >= total_addr_len
                    || (total_addr_len.saturating_sub(bytes_read_total)) < CHUNK_SIZE
                {
                    break;
                }
                if bytes_read_total + CHUNK_SIZE > MAX_RPL_ADDR_STORAGE {
                    break;
                }

                let bytes: u128 = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

                //copy bytes into buf at location bytes_read_total, take care to use big endian conversion
                addresses_buf[bytes_read_total..bytes_read_total + CHUNK_SIZE]
                    .copy_from_slice(&bytes.to_ne_bytes());
                //advance bytes_read_total by 16, and self.offset by 16
                bytes_read_total += CHUNK_SIZE;
                offset += CHUNK_SIZE;
            }
            // Loop to read 1 byte at a time => 16 + 1252 from prior loops = 1268 bytes total
            for _ in 0..16 {
                const CHUNK_SIZE: usize = 1;
                //if we have read up to len or 1 is too much to read, finish reading bytes
                if bytes_read_total >= total_addr_len
                    || (total_addr_len - bytes_read_total) < CHUNK_SIZE
                {
                    break;
                }
                if bytes_read_total + CHUNK_SIZE > MAX_RPL_ADDR_STORAGE {
                    break;
                }

                let bytes: u8 = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

                //copy bytes into buf at location bytes_read_total, take care to use big endian conversion
                addresses_buf[bytes_read_total] = bytes;
                //advance bytes_read_total by 1, and self.offset by 1
                bytes_read_total += CHUNK_SIZE;
                offset += CHUNK_SIZE;
            }

            parsed_data.addresses[..total_addr_len]
                .copy_from_slice(&addresses_buf[..total_addr_len]);

            ParsedHeader {
                type_: PacketType::RplSourceRoute,
                data: HeaderUnion { rpl: parsed_data },
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
