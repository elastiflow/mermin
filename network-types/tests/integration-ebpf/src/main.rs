#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::TcContext,
};
use aya_log_ebpf::{Level, log};
use integration_common::{HeaderUnion, PacketType, ParsedHeader};
use network_types::{
    ah::AuthHdr,
    destopts::DestOptsHdr,
    esp::Esp,
    eth::EthHdr,
    fragment::FragmentHdr,
    geneve::GeneveHdr,
    gre::GreHdr,
    hop::HopOptHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    mobility::MobilityHdr,
    route::{
        CrhHeader, RoutingHeaderType, RplSourceRouteHeader, SegmentRoutingHeader,
        Type2RoutingHeader,
    },
    shim6::Shim6Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
    vxlan::VxlanHdr,
};

pub const MAX_RPL_ADDR_STORAGE: usize = 128;
pub const MAX_SEGMENT_STORAGE: usize = 128; // 256 Broke the stack :(
pub const MAX_CRH_SID_STORAGE: usize = 128;
pub const MAX_SIZE_MASK: usize = 255;

/// Test data structure to store parsed header information in PerCpuArray
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TestData {
    pub packet_type: PacketType,
    pub first_header_byte: u8, // First byte of the parsed header from ctx.load
    pub parsed_successfully: u8,
    pub reserved: [u8; 2], // Padding to ensure proper alignment
}

/// PerCpuArray to store test data for verification
#[map(name = "TEST_DATA_STORAGE")]
static mut TEST_DATA_STORAGE: PerCpuArray<TestData> = PerCpuArray::with_max_entries(1, 0);

/// Original PerfEventArray for output
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
        18 => Some(PacketType::Mobility),
        19 => Some(PacketType::Shim6),
        20 => Some(PacketType::Hip),
        21 => Some(PacketType::Gre),
        22 => Some(PacketType::WireGuard),
        _ => None,
    }
}

/// Store test data in PerCpuArray and verify it can be retrieved
fn store_and_verify_test_data(
    ctx: &TcContext,
    packet_type: PacketType,
    first_header_byte: u8,
) -> Result<(), i32> {
    // Store in PerCpuArray
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(ptr) = TEST_DATA_STORAGE.get_ptr_mut(0) {
            // Write to PerCpuArray like we would in try_mermin
            (*ptr).packet_type = packet_type;
            (*ptr).first_header_byte = first_header_byte;
            (*ptr).parsed_successfully = 1;
            (*ptr).reserved = [0; 2];
        } else {
            log!(ctx, Level::Error, "Failed to get PerCpuArray pointer");
            return Err(TC_ACT_SHOT);
        }
    }

    // Immediately retrieve and verify
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(stored_data) = TEST_DATA_STORAGE.get(0) {
            if stored_data.packet_type != packet_type {
                log!(ctx, Level::Error, "Packet type verification failed");
                return Err(TC_ACT_SHOT);
            }
            if stored_data.first_header_byte != first_header_byte {
                log!(ctx, Level::Error, "First header byte verification failed");
                return Err(TC_ACT_SHOT);
            }
            if stored_data.parsed_successfully != 1 {
                log!(ctx, Level::Error, "Parse success flag verification failed");
                return Err(TC_ACT_SHOT);
            }
        } else {
            log!(
                ctx,
                Level::Error,
                "Failed to retrieve data from PerCpuArray"
            );
            return Err(TC_ACT_SHOT);
        }
    }

    log!(
        ctx,
        Level::Info,
        "PerCpuArray storage and verification successful"
    );
    Ok(())
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

    let (response, header_size) = match packet_type {
        PacketType::Eth => {
            let header: EthHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.dst_addr[0]; // First byte of destination MAC
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Eth,
                    data: HeaderUnion { eth: header },
                },
                EthHdr::LEN as u32,
            )
        }
        PacketType::Ipv4 => {
            let header: Ipv4Hdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.vihl; // First byte contains version and IHL
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Ipv4,
                    data: HeaderUnion { ipv4: header },
                },
                Ipv4Hdr::LEN as u32,
            )
        }
        PacketType::Ipv6 => {
            let header: Ipv6Hdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.vcf[0]; // First byte contains version and traffic class
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Ipv6,
                    data: HeaderUnion { ipv6: header },
                },
                Ipv6Hdr::LEN as u32,
            )
        }
        PacketType::Tcp => {
            let header: TcpHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.src[0]; // First byte of source port
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Tcp,
                    data: HeaderUnion { tcp: header },
                },
                TcpHdr::LEN as u32,
            )
        }
        PacketType::Udp => {
            let header: UdpHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.src[0]; // First byte of source port
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Udp,
                    data: HeaderUnion { udp: header },
                },
                UdpHdr::LEN as u32,
            )
        }
        PacketType::Ah => {
            let header: AuthHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Ah,
                    data: HeaderUnion { ah: header },
                },
                AuthHdr::LEN as u32,
            )
        }
        PacketType::Esp => {
            let header: Esp = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.spi[0]; // First byte of SPI
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Esp,
                    data: HeaderUnion { esp: header },
                },
                Esp::LEN as u32,
            )
        }
        PacketType::Hop => {
            let header: HopOptHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Hop,
                    data: HeaderUnion { hop: header },
                },
                HopOptHdr::LEN as u32,
            )
        }
        PacketType::Geneve => {
            let header: GeneveHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.ver_opt_len; // First byte contains version and option length
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Geneve,
                    data: HeaderUnion { geneve: header },
                },
                GeneveHdr::LEN as u32,
            )
        }
        PacketType::Fragment => {
            let header: FragmentHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Fragment,
                    data: HeaderUnion { fragment: header },
                },
                FragmentHdr::LEN as u32,
            )
        }
        PacketType::DestOpts => {
            let header: DestOptsHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::DestOpts,
                    data: HeaderUnion { destopts: header },
                },
                DestOptsHdr::LEN as u32,
            )
        }
        PacketType::Mobility => {
            let header: MobilityHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Mobility,
                    data: HeaderUnion { mobility: header },
                },
                MobilityHdr::LEN as u32,
            )
        }
        PacketType::Type2 => {
            let type2_hdr: Type2RoutingHeader = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = type2_hdr.generic_route.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            (
                ParsedHeader {
                    type_: PacketType::Type2,
                    data: HeaderUnion { type2: type2_hdr },
                },
                Type2RoutingHeader::LEN as u32,
            )
        }
        PacketType::RplSourceRoute => {
            let offset = data_offset;
            let rpl_header: RplSourceRouteHeader = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

            if rpl_header.generic_route.type_ != RoutingHeaderType::RplSourceRoute {
                return Err(TC_ACT_SHOT);
            }

            let first_byte = rpl_header.generic_route.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            (
                ParsedHeader {
                    type_: PacketType::RplSourceRoute,
                    data: HeaderUnion { rpl: rpl_header },
                },
                RplSourceRouteHeader::LEN as u32,
            )
        }
        PacketType::SegmentRouting => {
            let offset = data_offset;
            let segment_hdr: SegmentRoutingHeader = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

            if segment_hdr.generic_route.type_ != RoutingHeaderType::SegmentRoutingHeader {
                return Err(TC_ACT_SHOT);
            }

            let first_byte = segment_hdr.generic_route.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            (
                ParsedHeader {
                    type_: PacketType::SegmentRouting,
                    data: HeaderUnion {
                        segment_routing: segment_hdr,
                    },
                },
                SegmentRoutingHeader::LEN as u32,
            )
        }
        PacketType::Shim6 => {
            let header: Shim6Hdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Shim6,
                    data: HeaderUnion { shim6: header },
                },
                Shim6Hdr::LEN as u32,
            )
        }
        PacketType::Crh16 | PacketType::Crh32 => {
            let offset = data_offset;
            let crh_header: CrhHeader = ctx.load(offset).map_err(|_| TC_ACT_SHOT)?;

            // Verify routing type matches expected CRH type
            let expected_type = match packet_type {
                PacketType::Crh16 => RoutingHeaderType::Crh16,
                PacketType::Crh32 => RoutingHeaderType::Crh32,
                _ => return Err(TC_ACT_SHOT),
            };

            if crh_header.generic_route.type_ != expected_type {
                return Err(TC_ACT_SHOT);
            }

            let first_byte = crh_header.generic_route.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            match packet_type {
                PacketType::Crh16 => (
                    ParsedHeader {
                        type_: PacketType::Crh16,
                        data: HeaderUnion { crh16: crh_header },
                    },
                    CrhHeader::LEN as u32,
                ),
                PacketType::Crh32 => (
                    ParsedHeader {
                        type_: PacketType::Crh32,
                        data: HeaderUnion { crh32: crh_header },
                    },
                    CrhHeader::LEN as u32,
                ),
                _ => return Err(TC_ACT_SHOT),
            }
        }
        PacketType::Vxlan => {
            let header: VxlanHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.flags; // First byte contains flags
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Vxlan,
                    data: HeaderUnion { vxlan: header },
                },
                VxlanHdr::LEN as u32,
            )
        }
        PacketType::Hip => {
            let header: network_types::hip::HipHdr =
                ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.next_hdr as u8; // First byte is next header
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Hip,
                    data: HeaderUnion { hip: header },
                },
                network_types::hip::HipHdr::LEN as u32,
            )
        }
        PacketType::Gre => {
            let header: GreHdr = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.flgs_res0_ver[0]; // First byte contains flags
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::Gre,
                    data: HeaderUnion { gre: header },
                },
                GreHdr::LEN as u32,
            )
        }
        PacketType::WireGuard => {
            let header: integration_common::WireGuardMinimalHeader =
                ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let first_byte = header.type_ as u8; // First byte is the message type
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            (
                ParsedHeader {
                    type_: PacketType::WireGuard,
                    data: HeaderUnion { wireguard: header },
                },
                integration_common::WireGuardMinimalHeader::LEN as u32,
            )
        }
    };

    // Output the parsed header to the PerfEventArray
    #[allow(static_mut_refs)]
    unsafe {
        OUT_DATA.output(&ctx, &response, 0)
    };

    log!(
        &ctx,
        Level::Info,
        "Successfully processed packet payload with PerCpuArray verification"
    );
    log!(&ctx, Level::Info, "Header size: {}", header_size);

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
