#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::TcContext,
};
use integration_common::{
    AhTestData, DestOptsTestData, EspTestData, EthernetTestData, FragmentTestData,
    GenericRouteTestData, GeneveTestData, GreTestData, HeaderUnion, HipTestData, HopOptTestData,
    Ipv4TestData, Ipv6TestData, MobilityTestData, PacketType, ParsedHeader, Shim6TestData,
    TcpTestData, UdpTestData, VxlanTestData, WireGuardCookieReplyTestData, WireGuardInitTestData,
    WireGuardResponseTestData, WireGuardTransportDataTestData,
};
use network_types::{
    ah::AH_LEN,
    destopts::DEST_OPTS_LEN,
    esp::ESP_LEN,
    eth::{ETH_LEN, EtherType},
    fragment::FRAGMENT_LEN,
    geneve::GENEVE_LEN,
    gre::GRE_LEN,
    hip::HIP_LEN,
    hop::HOP_OPT_LEN,
    ip::{ipv4::IPV4_LEN, ipv6::IPV6_LEN},
    mobility::MOBILITY_LEN,
    shim6::SHIM6_LEN,
    tcp::TCP_LEN,
    udp::UDP_LEN,
    vxlan::VXLAN_LEN,
    wireguard::WireGuardType,
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
        // Leaving room for the specific routing header types if we want to reintroduce them
        10 => Some(PacketType::GenericRoute),
        15 => Some(PacketType::Fragment),
        16 => Some(PacketType::DestOpts),
        17 => Some(PacketType::Vxlan),
        18 => Some(PacketType::Mobility),
        19 => Some(PacketType::Shim6),
        20 => Some(PacketType::Hip),
        21 => Some(PacketType::Gre),
        22 => Some(PacketType::WireGuardInit),
        23 => Some(PacketType::WireGuardResponse),
        24 => Some(PacketType::WireGuardCookieReply),
        25 => Some(PacketType::WireGuardTransportData),
        _ => None,
    }
}

/// Store test data in PerCpuArray and verify it can be retrieved
fn store_and_verify_test_data(
    _ctx: &TcContext,
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
            return Err(TC_ACT_SHOT);
        }
    }

    // Immediately retrieve and verify
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(stored_data) = TEST_DATA_STORAGE.get(0) {
            if stored_data.packet_type != packet_type {
                return Err(TC_ACT_SHOT);
            }
            if stored_data.first_header_byte != first_header_byte {
                return Err(TC_ACT_SHOT);
            }
            if stored_data.parsed_successfully != 1 {
                return Err(TC_ACT_SHOT);
            }
        } else {
            return Err(TC_ACT_SHOT);
        }
    }

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
    // In our specific test case (UDP packet on loopback), we can assume a fixed header size.
    // Ethernet Header (14 bytes) + IPv4 Header (20 bytes) + UDP Header (8 bytes) = 42 bytes.
    const PAYLOAD_OFFSET: usize = ETH_LEN + IPV4_LEN + UDP_LEN;

    // Bounds check for packet type byte
    if PAYLOAD_OFFSET + 1 > ctx.len() as usize {
        return Err(TC_ACT_SHOT);
    }

    let packet_type_byte: u8 = ctx.load(PAYLOAD_OFFSET).map_err(|_| TC_ACT_SHOT)?;
    let data_offset = PAYLOAD_OFFSET + 1;

    let packet_type = match u8_to_packet_type(packet_type_byte) {
        Some(pt) => pt,
        None => {
            return Ok(TC_ACT_OK);
        }
    };

    let response = match packet_type {
        PacketType::Eth => {
            if data_offset + ETH_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Ethernet header fields individually (matching mermin-ebpf methodology)
            let mac_addr: [u8; 6] = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let ether_type: EtherType = ctx.load(data_offset + 12).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = mac_addr[0]; // First byte of MAC address
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Eth,
                data: HeaderUnion {
                    eth: EthernetTestData {
                        mac_addr: mac_addr,
                        ether_type: ether_type,
                    },
                },
            }
            // return Ok(TC_ACT_OK)
        }
        PacketType::Ipv4 => {
            if data_offset + IPV4_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse IPv4 header fields individually (matching mermin-ebpf methodology)
            let dscp_ecn: u8 = ctx.load(data_offset + 1).map_err(|_| TC_ACT_SHOT)?;
            let ttl: u8 = ctx.load(data_offset + 8).map_err(|_| TC_ACT_SHOT)?;
            let proto: u8 = ctx.load(data_offset + 9).map_err(|_| TC_ACT_SHOT)?;
            let src_addr: [u8; 4] = ctx.load(data_offset + 12).map_err(|_| TC_ACT_SHOT)?;
            let dst_addr: [u8; 4] = ctx.load(data_offset + 16).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = dscp_ecn; // Use dscp_ecn as the first parsed byte for verification
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;
            ParsedHeader {
                type_: PacketType::Ipv4,
                data: HeaderUnion {
                    ipv4: Ipv4TestData {
                        dscp_ecn,
                        ttl,
                        proto,
                        src_addr,
                        dst_addr,
                    },
                },
            }
        }
        PacketType::Ipv6 => {
            if data_offset + IPV6_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse IPv6 header fields individually (matching mermin-ebpf methodology)
            let vcf: [u8; 4] = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let proto: u8 = ctx.load(data_offset + 6).map_err(|_| TC_ACT_SHOT)?;
            let hop_limit: u8 = ctx.load(data_offset + 7).map_err(|_| TC_ACT_SHOT)?;
            let src_addr: [u8; 16] = ctx.load(data_offset + 8).map_err(|_| TC_ACT_SHOT)?;
            let dst_addr: [u8; 16] = ctx.load(data_offset + 24).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = vcf[0]; // Use first byte of VCF for verification
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Ipv6,
                data: HeaderUnion {
                    ipv6: Ipv6TestData {
                        vcf,
                        proto,
                        hop_limit,
                        src_addr,
                        dst_addr,
                    },
                },
            }
        }
        PacketType::Tcp => {
            if data_offset + TCP_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse TCP header fields individually (matching mermin-ebpf methodology)
            let src_port: [u8; 2] = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let dst_port: [u8; 2] = ctx.load(data_offset + 2).map_err(|_| TC_ACT_SHOT)?;
            let tcp_flags: u8 = ctx.load(data_offset + 13).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = src_port[0];
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Tcp,
                data: HeaderUnion {
                    tcp: TcpTestData {
                        src_port,
                        dst_port,
                        tcp_flags,
                    },
                },
            }
        }
        PacketType::Udp => {
            if data_offset + UDP_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse UDP header fields individually (matching mermin-ebpf methodology)
            let src_port: [u8; 2] = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let dst_port: [u8; 2] = ctx.load(data_offset + 2).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = src_port[0]; // First byte of source port
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Udp,
                data: HeaderUnion {
                    udp: UdpTestData { src_port, dst_port },
                },
            }
        }
        PacketType::Ah => {
            if data_offset + AH_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse AH header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let spi: [u8; 4] = ctx.load(data_offset + 4).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Ah,
                data: HeaderUnion {
                    ah: AhTestData { next_hdr, spi },
                },
            }
        }
        PacketType::Esp => {
            if data_offset + ESP_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse ESP header fields individually (matching mermin-ebpf methodology)
            let spi: [u8; 4] = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = spi[0]; // Use first byte of SPI as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Esp,
                data: HeaderUnion {
                    esp: EspTestData { spi },
                },
            }
        }
        PacketType::Hop => {
            if data_offset + HOP_OPT_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Hop-by-Hop Options header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let hdr_ext_len: u8 = ctx.load(data_offset + 1).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Hop,
                data: HeaderUnion {
                    hop: HopOptTestData {
                        next_hdr,
                        hdr_ext_len,
                    },
                },
            }
        }
        PacketType::Fragment => {
            if data_offset + FRAGMENT_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Fragment header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Fragment,
                data: HeaderUnion {
                    fragment: FragmentTestData { next_hdr },
                },
            }
        }
        PacketType::DestOpts => {
            if data_offset + DEST_OPTS_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Dest Options header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let hdr_ext_len: u8 = ctx.load(data_offset + 1).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::DestOpts,
                data: HeaderUnion {
                    destopts: DestOptsTestData {
                        next_hdr,
                        hdr_ext_len,
                    },
                },
            }
        }
        PacketType::Mobility => {
            if data_offset + MOBILITY_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Mobility header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let hdr_ext_len: u8 = ctx.load(data_offset + 1).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Mobility,
                data: HeaderUnion {
                    mobility: MobilityTestData {
                        next_hdr,
                        hdr_ext_len,
                    },
                },
            }
        }
        PacketType::Shim6 => {
            if data_offset + SHIM6_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Shim6 header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let hdr_ext_len: u8 = ctx.load(data_offset + 1).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Shim6,
                data: HeaderUnion {
                    shim6: Shim6TestData {
                        next_hdr,
                        hdr_ext_len,
                    },
                },
            }
        }
        PacketType::Geneve => {
            if data_offset + GENEVE_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Geneve header fields individually (matching mermin-ebpf methodology)
            let ver_opt_len: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let tunnel_ether_type: [u8; 2] = ctx.load(data_offset + 2).map_err(|_| TC_ACT_SHOT)?;
            let vni: [u8; 3] = ctx.load(data_offset + 4).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = ver_opt_len; // Use ver_opt_len as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Geneve,
                data: HeaderUnion {
                    geneve: GeneveTestData {
                        ver_opt_len,
                        tunnel_ether_type,
                        vni,
                    },
                },
            }
        }
        PacketType::GenericRoute => {
            const GENERIC_ROUTE_LEN: usize = 4;
            if data_offset + GENERIC_ROUTE_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse Generic Route header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let hdr_ext_len: u8 = ctx.load(data_offset + 1).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::GenericRoute,
                data: HeaderUnion {
                    generic_route: GenericRouteTestData {
                        next_hdr,
                        hdr_ext_len,
                    },
                },
            }
        }
        PacketType::Vxlan => {
            if data_offset + VXLAN_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse VXLAN header fields individually (matching mermin-ebpf methodology)
            let flags: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let vni: [u8; 3] = ctx.load(data_offset + 4).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = flags; // Use flags as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Vxlan,
                data: HeaderUnion {
                    vxlan: VxlanTestData { flags, vni },
                },
            }
        }
        PacketType::Hip => {
            if data_offset + HIP_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse HIP header fields individually (matching mermin-ebpf methodology)
            let next_hdr: u8 = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let hdr_ext_len: u8 = ctx.load(data_offset + 1).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = next_hdr; // Use next_hdr as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Hip,
                data: HeaderUnion {
                    hip: HipTestData {
                        next_hdr,
                        hdr_ext_len,
                    },
                },
            }
        }
        PacketType::Gre => {
            if data_offset + GRE_LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse GRE header fields individually (matching mermin-ebpf methodology)
            let flag_res: [u8; 2] = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let ether_type: [u8; 2] = ctx.load(data_offset + 2).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = flag_res[0]; // Use first byte of flag_res as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::Gre,
                data: HeaderUnion {
                    gre: GreTestData {
                        flag_res,
                        ether_type,
                    },
                },
            }
        }
        PacketType::WireGuardInit => {
            if data_offset + WireGuardInitTestData::LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse WireGuard Init header fields individually (matching mermin-ebpf methodology)
            let type_: WireGuardType = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let sender_ind: [u8; 4] = ctx.load(data_offset + 4).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = type_ as u8; // Use message type as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::WireGuardInit,
                data: HeaderUnion {
                    wireguard_init: WireGuardInitTestData { type_, sender_ind },
                },
            }
        }
        PacketType::WireGuardResponse => {
            if data_offset + WireGuardResponseTestData::LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse WireGuard Response header fields individually (matching mermin-ebpf methodology)
            let type_: WireGuardType = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let sender_ind: [u8; 4] = ctx.load(data_offset + 4).map_err(|_| TC_ACT_SHOT)?;
            let receiver_ind: [u8; 4] = ctx.load(data_offset + 8).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = type_ as u8; // Use message type as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::WireGuardResponse,
                data: HeaderUnion {
                    wireguard_response: WireGuardResponseTestData {
                        type_,
                        sender_ind,
                        receiver_ind,
                    },
                },
            }
        }
        PacketType::WireGuardCookieReply => {
            if data_offset + WireGuardCookieReplyTestData::LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse WireGuard Cookie Reply header fields individually (matching mermin-ebpf methodology)
            let type_: WireGuardType = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let receiver_ind: [u8; 4] = ctx.load(data_offset + 4).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = type_ as u8; // Use message type as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::WireGuardCookieReply,
                data: HeaderUnion {
                    wireguard_cookie_reply: WireGuardCookieReplyTestData {
                        type_,
                        receiver_ind,
                    },
                },
            }
        }
        PacketType::WireGuardTransportData => {
            if data_offset + WireGuardTransportDataTestData::LEN > ctx.len() as usize {
                return Err(TC_ACT_SHOT);
            }

            // Parse WireGuard Transport Data header fields individually (matching mermin-ebpf methodology)
            let type_: WireGuardType = ctx.load(data_offset).map_err(|_| TC_ACT_SHOT)?;
            let receiver_ind: [u8; 4] = ctx.load(data_offset + 4).map_err(|_| TC_ACT_SHOT)?;

            let first_byte = type_ as u8; // Use message type as the first parsed byte
            store_and_verify_test_data(&ctx, packet_type, first_byte)?;

            ParsedHeader {
                type_: PacketType::WireGuardTransportData,
                data: HeaderUnion {
                    wireguard_transport_data: WireGuardTransportDataTestData {
                        type_,
                        receiver_ind,
                    },
                },
            }
        }
    };

    // Output the parsed header to the PerfEventArray
    #[allow(static_mut_refs)]
    unsafe {
        OUT_DATA.output(&ctx, &response, 0)
    };

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
