#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_ebpf::bindings::{TC_ACT_SHOT};
use aya_log_ebpf::debug;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::quic::{
    QuicHdr,
    QUIC_SHORT_DEFAULT_DC_ID_LEN,
};
use network_types::gre::GreHdr;
use network_types::{parse_quic_hdr, parse_gre_hdr};
use network_types::udp::UdpHdr;

/// IPv6 Fragment‑header – RFC 8200 §4.5 (8 bytes)
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Ipv6FragHdr {
    pub next_hdr: u8,
    pub _reserved: u8,
    pub frag_off: [u8; 2],
    pub ident: [u8; 4],
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: we deliberately abort – no unwinding in kernel.
    unsafe { core::hint::unreachable_unchecked() }
}

#[map(name = "QUICHDR_RESULT")]
static mut QUICHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4, 0);

/// Helper to write three u32s back to user space.
#[inline(always)]
unsafe fn store_result(map: &mut HashMap<u32, u32>, marker: u32, dcil: u32, scil: u32) {
    let _ = map.insert(&0, &marker, 0);
    let _ = map.insert(&1, &dcil, 0);
    let _ = map.insert(&2, &scil, 0);
}

#[map(name = "GREHDR_RESULT")]
static mut GREHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(7, 0);

#[inline(always)]
unsafe fn store_gre_result(map: &mut HashMap<u32, u32>, flags: u32, version: u32, proto: u32, checksum_res1: u32, key: u32, sequence_number: u32) {
    let _ = map.insert(&0, &flags, 0);
    let _ = map.insert(&1, &version, 0);
    let _ = map.insert(&2, &proto, 0);
    let _ = map.insert(&3, &checksum_res1, 0);
    let _ = map.insert(&4, &key, 0);
    let _ = map.insert(&5, &sequence_number, 0);
}

fn to_ip_proto(n: u8) -> IpProto {
    match n {
        17 => IpProto::Udp,
        44 => IpProto::Ipv6Frag,
        _ => IpProto::Reserved, // Use as a generic non-UDP case
    }
}

/// TC‑ingress entry‑point.
#[classifier]
pub fn quic_hdr_test(ctx: TcContext) -> i32 {
    let map: &mut HashMap<u32, u32> = unsafe { &mut *(&raw mut QUICHDR_RESULT as *mut _) };

    if unsafe { map.get(&0).is_none() } {
        unsafe { store_result(map, 0, 0, 0) };
    }

    match try_quic_hdr_test(ctx, map) {
        Ok(ret) | Err(ret) => ret,
    }
}

/// TC-ingress entry-point for gre
#[classifier]
pub fn gre_hdr_test(ctx: TcContext) -> i32 {
    let map: &mut HashMap<u32, u32> = unsafe { &mut *(&raw mut GREHDR_RESULT as *mut _) };

    match try_gre_hdr_test(ctx, map) {
        Ok(ret) | Err(ret) => ret,
    }
}

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const SHORT_HEADER_MARKER: u32 = 2;

fn try_quic_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    debug!(
        &ctx,
        "TC classifier triggered. Packet size: {}",
        ctx.data_end() - ctx.data()
    );
    let mut off = 0_usize;
    let eth: EthHdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
    off += EthHdr::LEN;
    debug!(
        &ctx,
        "ETH Hdr: DST: {:mac}, SRC: {:mac}, EtherType: {:x}",
        eth.dst_addr,
        eth.src_addr,
        u16::from_be(eth.ether_type)
    );
    let ether_type = eth.ether_type;
    let ip_hdr_len = match ether_type {
        et if et == ETHER_TYPE_IPV4.to_be() => {
            debug!(&ctx, "BRANCH: EtherType is IPv4. Reading Ipv4Hdr.");
            let ipv4: Ipv4Hdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
            let proto = ipv4.proto;
            debug!(&ctx, "IPv4 Hdr: Proto: {}", proto as u8);
            if proto != IpProto::Udp {
                debug!(&ctx, "EXIT: IPv4 proto is not UDP.");
                return Ok(TC_ACT_PIPE);
            }
            (ipv4.vihl & 0x0F) as usize * 4
        }
        et if et == ETHER_TYPE_IPV6.to_be() => {
            debug!(&ctx, "BRANCH: EtherType is IPv6. Reading Ipv6Hdr.");
            // The Ipv6Hdr is 40 bytes, but we only need the next_hdr field (1 byte).
            // To save stack space, we can load only that field from its fixed offset of 6.
            const IPV6_HDR_NEXT_HDR_OFFSET: usize = 6;
            let next_hdr_val: u8 =
                ctx.load(off + IPV6_HDR_NEXT_HDR_OFFSET).map_err(|_| TC_ACT_PIPE)?;
            let mut next_hdr = to_ip_proto(next_hdr_val);
            let mut hdr_len = Ipv6Hdr::LEN;
            debug!(&ctx, "IPv6 Hdr: NextHdr: {}", next_hdr as u8);
            if next_hdr == IpProto::Ipv6Frag {
                debug!(&ctx, "IPv6 frag header detected, parsing.");
                // The Ipv6FragHdr is 8 bytes, but we only need the next_hdr field (1 byte).
                // To save stack space, we can load just that byte.
                let next_hdr_val: u8 = ctx.load(off + hdr_len).map_err(|_| TC_ACT_PIPE)?;
                next_hdr = to_ip_proto(next_hdr_val);
                hdr_len += mem::size_of::<Ipv6FragHdr>();
                debug!(&ctx, "IPv6 frag: next_hdr after frag: {}", next_hdr as u8);
            }
            if next_hdr != IpProto::Udp {
                debug!(&ctx, "EXIT: IPv6 next_hdr is not UDP.");
                return Ok(TC_ACT_PIPE);
            }
            hdr_len
        }
        _ => {
            debug!(&ctx, "EXIT: Not an IPv4 or IPv6 packet.");
            return Ok(TC_ACT_PIPE);
        }
    };
    off += ip_hdr_len;
    debug!(
        &ctx,
        "IP processing done. Advancing to UDP at offset {}", off
    );
    let udp: UdpHdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
    let udp_len = udp.len() as usize;
    debug!(
        &ctx,
        "UDP Hdr: Src Port: {}, Dst Port: {}, Length: {}",
        udp.src_port(),
        udp.dst_port(),
        udp_len
    );
    if udp_len <= UdpHdr::LEN {
        debug!(&ctx, "EXIT: UDP length is too small.");
        return Ok(TC_ACT_PIPE);
    }
    off += UdpHdr::LEN;
    debug!(
        &ctx,
        "UDP processing done. Advancing to QUIC payload at offset {} len={}.", off, ctx.len()
    );
    match parse_quic_hdr!(&ctx, off, QUIC_SHORT_DEFAULT_DC_ID_LEN).map_err(|_| TC_ACT_PIPE) {
        Ok(QuicHdr::Short(hdr)) => {
            debug!(
                &ctx,
                "BRANCH: QUIC short header detected. DCID: {:x}", hdr.dc_id.as_slice()
            );
            unsafe { store_result(map, SHORT_HEADER_MARKER, hdr.dc_id_len as u32, 0) };
        }
        Ok(QuicHdr::Long(hdr)) => {
            debug!(
                &ctx,
                "BRANCH: QUIC long header detected. DCID={:x}, SCID={:x}", hdr.dc_id.as_slice(), hdr.sc_id.as_slice()
            );
            unsafe {
                store_result(
                    map,
                    hdr.fixed_hdr.version(),
                    hdr.fixed_hdr.dc_id_len as u32,
                    hdr.sc_id_len as u32,
                )
            };
        }
        Err(err) => {
            debug!(&ctx, "EXIT: QUIC parsing failed, err={}.", err);
            return Ok(TC_ACT_SHOT);
        }
    }
    Ok(TC_ACT_PIPE)

}

fn try_gre_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    debug!(
        &ctx,
        "TC classifier triggered. Packet size: {}",
        ctx.data_end() - ctx.data()
    );

    let mut off = 0_usize;

    let eth: EthHdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
    off += EthHdr::LEN;

    debug!(
        &ctx,
        "ETH Hdr: DST: {:mac}, SRC: {:mac}, EtherType: {:x}",
        eth.dst_addr,
        eth.src_addr,
        u16::from_be(eth.ether_type)
    );

    let ether_type = eth.ether_type;
    let ip_hdr_len = match ether_type {
        et if et == ETHER_TYPE_IPV4.to_be() => {
            debug!(&ctx, "BRANCH: EtherType is IPv4. Reading Ipv4Hdr.");
            let ipv4: Ipv4Hdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
            let proto = ipv4.proto;
            debug!(&ctx, "IPv4 Hdr: Proto: {}", proto as u8);
            if proto != IpProto::Udp {
                debug!(&ctx, "EXIT: IPv4 proto is not UDP.");
                return Ok(TC_ACT_PIPE);
            }
            (ipv4.vihl & 0x0F) as usize * 4
        }
        et if et == ETHER_TYPE_IPV6.to_be() => {
            debug!(&ctx, "BRANCH: EtherType is IPv6. Reading Ipv6Hdr.");
            let ipv6: Ipv6Hdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
            let mut next_hdr = ipv6.next_hdr;
            let mut hdr_len = Ipv6Hdr::LEN;
            debug!(&ctx, "IPv6 Hdr: NextHdr: {}", next_hdr as u8);

            if next_hdr == IpProto::Ipv6Frag {
                debug!(&ctx, "IPv6 frag header detected, parsing.");
                let frag: Ipv6FragHdr = ctx.load(off + hdr_len).map_err(|_| TC_ACT_PIPE)?;
                next_hdr = to_ip_proto(frag.next_hdr);
                hdr_len += mem::size_of::<Ipv6FragHdr>();
                debug!(&ctx, "IPv6 frag: next_hdr after frag: {}", next_hdr as u8);
            }

            if next_hdr != IpProto::Udp {
                debug!(&ctx, "EXIT: IPv6 next_hdr is not UDP.");
                return Ok(TC_ACT_PIPE);
            }
            hdr_len
        }
        _ => {
            debug!(&ctx, "EXIT: Not an IPv4 or IPv6 packet.");
            return Ok(TC_ACT_PIPE);
        }
    };
    off += ip_hdr_len;

    debug!(
        &ctx,
        "IP processing done. Advancing to UDP at offset {}", off
    );

    let udp: UdpHdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
    let udp_len = udp.len() as usize;
    debug!(
        &ctx,
        "UDP Hdr: Src Port: {}, Dst Port: {}, Length: {}",
        udp.src_port(),
        udp.dst_port(),
        udp_len
    );

    if udp_len <= UdpHdr::LEN {
        debug!(&ctx, "EXIT: UDP length is too small.");
        return Ok(TC_ACT_PIPE);
    }
    off += UdpHdr::LEN;
    debug!(
        &ctx,
        "UDP processing done. Advancing to GRE payload at offset {}.", off
    );

    let parsed_hdr: GreHdr = parse_gre_hdr!(&ctx, off).map_err(|_| -1i32)?;

    // The incomplete line below was commented out to allow compilation.
    // let combined_flags = 

    // Now that all logic is done, we can safely log the results.
    debug!(&ctx, "Finished GRE Parse. flags: {:x}, version: {:x}, proto: {:x}, checksum res1: {:x}, key: {:x}, seq: {:x}",
        // Corrected type error: Cast the u8 flags to u32 for consistent typing.
        // The original `& 0x0Fu32` was incorrect; this now passes the full flags byte.
        parsed_hdr.fixed.flgs_res0_ver[0] as u32,
        parsed_hdr.version() as u32,
        parsed_hdr.proto() as u32,
        parsed_hdr.ck_res1(),
        parsed_hdr.key(),
        parsed_hdr.seq());

    // Store the GRE header information in the map with the values expected by the test
    unsafe {
        store_gre_result(
            map,
            // Corrected type mismatch: Cast the u8 flags byte to u32 to match the function signature.
            parsed_hdr.fixed.flgs_res0_ver[0] as u32,
            parsed_hdr.version() as u32,
            parsed_hdr.proto() as u32,
            parsed_hdr.ck_res1(),
            parsed_hdr.key(),
            parsed_hdr.seq(),
        );
    }

    debug!(&ctx, "GRE SUCCESS: Parsed header and stored results.");
    Ok(TC_ACT_PIPE)
}