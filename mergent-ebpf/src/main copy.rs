#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::{HashMap, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::info;
use mergent_common::{CReprIpAddr, FlowRecord, IPV4_TAG, IPV6_TAG};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// Define a struct for the 5-tuple flow key
#[repr(C)]
struct FlowKey {
    src_addr: CReprIpAddr,
    dst_addr: CReprIpAddr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

// Minimal struct to read Next Header and Header Extension Length for IPv6 Ext Hdrs
#[repr(C)]
struct Ipv6ExtHdrBase {
    next_hdr: u8,
    hdr_ext_len: u8,
}

// Define a max number of extension headers to parse to ensure termination
const MAX_IPV6_EXT_HEADERS: usize = 11;

#[map]
static mut FLOWS: HashMap<FlowKey, FlowRecord> =
    HashMap::<FlowKey, FlowRecord>::with_max_entries(10240, 0);

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB ring buffer

#[classifier]
pub fn mergent(ctx: TcContext) -> i32 {
    match try_mergent(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_mergent(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    let eth_type = ethhdr.ether_type;
    match eth_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
        }
        EtherType::Ipv6 => {
            let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
        }
        _ => {
            info!(&ctx, "Non-IPv4/IPv6 packet");
            return Ok(TC_ACT_PIPE);
        }
    }

    Ok(TC_ACT_PIPE)
}

/// ---
/// config:
///   layout: dagre
///   theme: neo
///   look: classic
/// ---
/// flowchart TD
///     ETH["ETH"] --> IP["IP"]
///     IP --> ENCAP["ENCAP"] & SEC:Trans["SEC:Trans"] & SEC:Tun["SEC:Tun"] & EXT["EXT"] & PAYLOAD["PAYLOAD"]
///     ENCAP --> IP
///     SEC:Trans --> PAYLOAD
///     SEC:Tun --> IP
///     EXT --> EXT & ENCAP & SEC:Trans & SEC:Tun & PAYLOAD
///     PAYLOAD --> UDP:Tun{{"UDP:Tun"}}
///     UDP:Tun --> INNER_PAYLOAD[["INNER_PAYLOAD"]]
///     INNER_PAYLOAD -.->|VXLAN| ETH
///     linkStyle 0 stroke:#D50000,fill:none
///     linkStyle 1 stroke:#D50000,fill:none
///     linkStyle 2 stroke:#D50000,fill:none
///     linkStyle 3 stroke:#D50000,fill:none
///     linkStyle 4 stroke:#D50000,fill:none
///     linkStyle 5 stroke:#D50000,fill:none
///     linkStyle 6 stroke:#2962FF,fill:none
///     linkStyle 7 stroke:#D50000,fill:none
///     linkStyle 8 stroke:#2962FF,fill:none
///     linkStyle 9 stroke:#2962FF,fill:none
///     linkStyle 10 stroke:#D50000,fill:none
///     linkStyle 11 stroke:#D50000,fill:none
///     linkStyle 12 stroke:#D50000,fill:none
///     linkStyle 13 stroke:#D50000,fill:none
///     linkStyle 14 stroke:#D50000,fill:none
///     linkStyle 15 stroke:#D50000,fill:none
///     linkStyle 16 stroke:#2962FF,fill:none
fn parse_eth(ctx: TcContext) -> (Result<i32, ()>, EthHdr, IpHdr) {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
        }
        EtherType::Ipv6 => {
            let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
        }
        _ => {
            info!(&ctx, "Non-IPv4/IPv6 packet");
            return (Ok(TC_ACT_PIPE), ethhdr, IpHdr::default());
        }
    }
    (Ok(TC_ACT_PIPE), ethhdr, IpHdr::default())
}

// fn try_mergent(ctx: TcContext) -> Result<i32, ()> {
//     info!(&ctx, "received a packet");

//     // Parse Ethernet Header
//     //   0                   1                   2                   3
//     //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |                     destination_mac_addr                      |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  | destination_mac_addr (con't)  |        source_mac_addr        |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |                    source_mac_addr (con't)                    |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |           eth_type            |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
//     let src_mac = ethhdr.src_addr;
//     let dst_mac = ethhdr.dst_addr;

//     // Initialize variables for the flow key
//     let src_addr_repr: CReprIpAddr;
//     let dst_addr_repr: CReprIpAddr;
//     let mut src_port: u16 = 0;
//     let mut dst_port: u16 = 0;
//     let mut proto;

//     // Based on the Ethernet type, parse the appropriate IP header
//     // Extract the source and destination addresses, ports, and protocol
//     match ethhdr.ether_type {
//         EtherType::Ipv4 => {
//             let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
//             src_addr_repr = CReprIpAddr::new_v4(u32::from_be_bytes(ipv4hdr.src_addr));
//             dst_addr_repr = CReprIpAddr::new_v4(u32::from_be_bytes(ipv4hdr.dst_addr));
//             proto = ipv4hdr.proto;

//             // Calculate header length for offset calculation
//             let ip_header_len = ipv4hdr.ihl() as usize * 4;
//             let transport_offset = EthHdr::LEN + ip_header_len;

//             // Parse ports based on protocol
//             match proto {
//                 IpProto::Tcp => {
//                     let tcphdr: TcpHdr = ctx.load(transport_offset).map_err(|_| ())?;
//                     src_port = tcphdr.source;
//                     dst_port = tcphdr.dest;
//                 }
//                 IpProto::Udp => {
//                     let udphdr: UdpHdr = ctx.load(transport_offset).map_err(|_| ())?;
//                     src_port = u16::from_be_bytes(udphdr.source);
//                     dst_port = u16::from_be_bytes(udphdr.dest);
//                 }
//                 IpProto::Icmp => {
//                     let icmp_hdr: IcmpHdr = ctx.load(transport_offset).map_err(|_| ())?;
//                     // Map ICMP type to src_port and code to dst_port
//                     src_port = icmp_hdr.type_ as u16;
//                     dst_port = icmp_hdr.code as u16;
//                 }
//                 _ => {
//                     // Protocol not TCP or UDP, keep ports as 0
//                     // Or potentially return Ok(TC_ACT_PIPE) if we only care about TCP/UDP flows
//                     info!(&ctx, "Non-TCP/UDP protocol: {}", proto as u8);
//                     return Ok(TC_ACT_PIPE);
//                 }
//             }
//         }
//         EtherType::Ipv6 => {
//             let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
//             src_addr_repr = CReprIpAddr::new_v6(ipv6hdr.src_addr);
//             dst_addr_repr = CReprIpAddr::new_v6(ipv6hdr.dst_addr);
//             proto = ipv6hdr.next_hdr;

//             // Initialize offset and next header variable for loop
//             let mut current_next_hdr = proto; // proto was assigned ipv6hdr.next_hdr
//             let mut transport_offset = EthHdr::LEN + Ipv6Hdr::LEN;
//             // Define packet_len here for IPv6
//             let mut packet_len = u16::from_be_bytes(ipv6hdr.payload_len) as usize + Ipv6Hdr::LEN;

//             // Loop through extension headers
//             for _ in 0..MAX_IPV6_EXT_HEADERS {
//                 match current_next_hdr {
//                     // Check for known Extension Header types
//                     // Note: IpProto::Ipv6Dest renamed to Ipv6DestOpt based on potential network-types definition
//                     IpProto::HopOpt
//                     | IpProto::Ipv6Route
//                     | IpProto::Ipv6Frag
//                     | IpProto::Esp
//                     | IpProto::Ah
//                     | IpProto::Ipv6Opts
//                     | IpProto::MobilityHeader
//                     | IpProto::Hip
//                     | IpProto::Shim6
//                     | IpProto::Test1
//                     | IpProto::Test2 => {
//                         // Load base extension header to get next header and length
//                         let ext_hdr: Ipv6ExtHdrBase = ctx.load(transport_offset).map_err(|_| ())?;
//                         current_next_hdr = IpProto::from(ext_hdr.next_hdr);
//                         // Calculate length: (hdr_ext_len + 1) * 8 bytes for most headers
//                         // Note: ESP has variable length, AH length depends on Authentication Data length.
//                         // This basic calculation might be inaccurate for ESP/AH.
//                         // For simplicity here, we use the common formula.
//                         let ext_hdr_len_bytes = (ext_hdr.hdr_ext_len as usize + 1) * 8;
//                         transport_offset += ext_hdr_len_bytes;
//                     }
//                     // Not an extension header, break the loop
//                     _ => break,
//                 }
//             }

//             // // Assign the final protocol after iterating through extension headers
//             // proto = current_next_hdr;

//             // // Parse ports using the final transport_offset and proto
//             // match proto {
//             //     IpProto::Tcp => {
//             //         let tcphdr: TcpHdr = ctx.load(transport_offset).map_err(|_| ())?;
//             //         src_port = tcphdr.source; // Assuming u16 based on user edits
//             //         dst_port = tcphdr.dest;   // Assuming u16 based on user edits
//             //     }
//             //     IpProto::Udp => {
//             //         let udphdr: UdpHdr = ctx.load(transport_offset).map_err(|_| ())?;\
//             //         // Assuming [u8; 2] based on user edits/errors
//             //         src_port = u16::from_be_bytes(udphdr.source);
//             //         dst_port = u16::from_be_bytes(udphdr.dest);
//             //     }
//             //     _ => {
//             //         // Protocol not TCP or UDP after potentially skipping extension headers
//             //         info!(&ctx, "Non-TCP/UDP protocol after IPv6 Ext Hdrs: {}", proto as u8);
//             //         return Ok(TC_ACT_PIPE); // Exit if not TCP/UDP
//             //     }
//             // }
//         }
//         _ => return Ok(TC_ACT_PIPE),
//     }

//     // 3. Create Flow Key
//     let flow_key = FlowKey {
//         src_addr: src_addr_repr,
//         dst_addr: dst_addr_repr,
//         src_port: src_port,
//         dst_port: dst_port,
//         proto: proto as u8,
//     };
//     let flow_record = unsafe { FLOWS.get(&flow_key) };
//     if flow_record.is_some() {
//         info!(&ctx, "Flow record found");
//     } else {
//         info!(&ctx, "Flow record not found");
//     }

//     // Parse IP Header
//     //   0                   1                   2                   3
//     //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |ip_ver | h_len |  ip_dscp  |ecn|        ip_total_length        |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |       ip_identification       |flags|   ip_fragment_offset    |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |    ip_ttl     |  ip_protocol  |          ip_checksum          |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |                         source_ipaddr                         |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |                      destination_ipaddr                       |
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //  |                          ip_options                           |
//     //  /                              ...                              /
//     //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     //   ip_ver -> ip_version
//     //    h_len -> ip_header_length (multiple raw value by 4 for true length)
//     //      ecn -> ip_ecn
//     //    flags -> ip_flags
//     let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
//     let ip_version = ipv4hdr.version();
//     let ip_header_len = ipv4hdr.ihl() as usize * 4;
//     let tos = ipv4hdr.tos;
//     let ip_dscp = tos >> 2;
//     let ip_ecn = tos & 0x03;
//     let ip_packet_size = u16::from_be_bytes(ipv4hdr.tot_len) as usize;
//     let ip_payload_len = u16::from_be_bytes(ipv4hdr.tot_len) as usize - ip_header_len;
//     let frag_id = ipv4hdr.id;
//     let tmp_flags_offset = u16::from_be_bytes(ipv4hdr.frag_off);
//     let frag_flags = tmp_flags_offset >> 13;
//     let frag_offset = tmp_flags_offset & 0x1FFF;
//     let ip_ttl = ipv4hdr.ttl;
//     let ipv4_checksum = ipv4hdr.check;

//     // // 4. Flow Table Lookup & Update/Create
//     // let current_time_ns = unsafe { bpf_ktime_get_ns() };
//     // let current_time_sec = (current_time_ns / 1_000_000_000) as u32; // Convert ns to s

//     // // Revert to get() + insert() logic
//     // let flow_record_option = unsafe { FLOWS.get(&flow_key) };

//     // let final_record_for_event = match flow_record_option {
//     //     Some(mut record) => {
//     //         // Get an owned copy to modify
//     //         // Existing flow: Update counters and timestamp
//     //         record.packet_total_count += 1;
//     //         record.octet_total_count += packet_len as u64;
//     //         record.packet_delta_count = 1; // Simple delta for this packet
//     //         record.octet_delta_count = packet_len as u64;
//     //         record.flow_end_seconds = current_time_sec;

//     //         // Update the map with the modified record
//     //         if unsafe { FLOWS.insert(&flow_key, &record, 0) }.is_err() {
//     //             info!(&ctx, "Failed to update flow in map");
//     //             return Err(TC_ACT_PIPE); // Exit if update fails
//     //         }
//     //         record // Return the updated record for the event buffer
//     //     }
//     //     None => {
//     //         // New flow: Create record
//     //         let new_record = FlowRecord {
//     //             packet_total_count: 1,
//     //             octet_total_count: packet_len as u64,
//     //             packet_delta_count: 1,
//     //             octet_delta_count: packet_len as u64,
//     //             flow_start_seconds: current_time_sec,
//     //             flow_end_seconds: current_time_sec,
//     //             src_ip: flow_key.src_ip,
//     //             dst_ip: flow_key.dst_ip,
//     //             src_port: flow_key.src_port,
//     //             dst_port: flow_key.dst_port,
//     //             protocol: flow_key.protocol,
//     //             flow_end_reason: 0, // 0 might indicate 'active' or 'not ended'
//     //         };
//     //         // Insert the new record into the map
//     //         if unsafe { FLOWS.insert(&flow_key, &new_record, 0) }.is_err() {
//     //             info!(&ctx, "Failed to insert new flow into map");
//     //             return Err(TC_ACT_PIPE); // Exit if insert fails
//     //         }
//     //         new_record // Return the new record for the event buffer
//     //     }
//     // };

//     // // 5. Add FlowRecord to Ring Buffer
//     // if unsafe { EVENTS.output(&final_record_for_event, 0) }.is_err() {
//     //     info!(&ctx, "Failed to output record to ring buffer");
//     //     // Ring buffer might be full, decide how critical this is.
//     // }

//     Ok(TC_ACT_PIPE) // Always let the packet continue
// }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 6] = *b"GPLv2\0"; // Corrected license string length and array size

/// ETH -> IPv6 -> IPv6 Ext -> GRE -> IPv4 -> ESP -> IPv6 -> TCP
///        Outer                                     Inner
///        flow.outer.src_ip_addr                    flow.src_ip_addr