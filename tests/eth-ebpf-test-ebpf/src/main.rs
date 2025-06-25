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
use network_types::{eth::EthHdr, ip::{IpProto, Ipv4Hdr, Ipv6Hdr}, quic_v2, quic_v2::{QuicFixedHdr, QuicFixedLongHdr}, udp::UdpHdr};
use network_types::quic_v2::{QuicLongHdr, QuicShortHdr, QUIC_MAX_CID_LEN, QUIC_SHORT_DEFAULT_DC_ID_LEN};
use network_types::read_var_buf;

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
        "UDP processing done. Advancing to QUIC payload at offset {}.", off
    );
    // Load the raw QUIC header data directly into the wire-format struct.
    // ctx.load will ensure there are at least QuicHdr::LEN bytes available.
    let quic_fixed_hdr: QuicFixedHdr = match ctx.load(off) {
        Ok(hdr) => hdr,
        Err(err) => {
            debug!(
                &ctx,
                "QUIC EXIT: Failed to load QuicHdr (packet too short). {}", err
            );
            return Err(TC_ACT_PIPE);
        }
    };
    off += QuicFixedHdr::LEN;
    let quic_hdr: quic_v2::QuicHdr = match quic_fixed_hdr.is_long_header() {
        true => {
            let quic_fixed_long_hdr: QuicFixedLongHdr = match ctx.load(off) {
                Ok(hdr) => hdr,
                Err(err) => {
                    debug!(
                        &ctx,
                        "QUIC EXIT: Failed to load QuicHdr (packet too short). {}", err
                    );
                    return Err(TC_ACT_PIPE);
                }
            };
            off += QuicFixedLongHdr::LEN;
            let mut quic_long_hdr = QuicLongHdr::new(quic_fixed_hdr, quic_fixed_long_hdr);
            debug!(
                &ctx,
                "QUIC CHECK: dc_len={} off_len={}", quic_long_hdr.fixed_hdr.dc_id_len, ctx.len() - off as u32
            );
            read_var_buf!(ctx, off, quic_long_hdr.dc_id, quic_long_hdr.fixed_hdr.dc_id_len, QUIC_MAX_CID_LEN);
            debug!(
                &ctx,
                "QUIC CHECK: quic_long_hdr.dc_id={:x}", quic_long_hdr.dc_id.as_slice()
            );
            /*
            // TODO: CHECK FOR OPTIMIZATION POTENTIAL
            if (ctx.len() - off as u32) < QUIC_MAX_CID_LEN as u32 {
                let mut idx = 0;
                'outer: for _i in 0..5 {
                    for _j in 0..4 {
                        let bytes: u8 = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
                        quic_long_hdr.dc_id[idx] = bytes;
                        idx += 1;
                        if quic_long_hdr.fixed_hdr.dc_id_len == idx as u8 {
                            break 'outer;
                        }
                        off += 1;
                    }
                }
            }
            */
            // off += quic_long_hdr.fixed_hdr.dc_id_len as usize;
            quic_long_hdr.sc_id_len = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
            debug!(
                &ctx,
                "QUIC CHECK: Long Header SC ID Len. {}", quic_long_hdr.sc_id_len
            );
            off += 1;
            read_var_buf!(ctx, off, quic_long_hdr.sc_id, quic_long_hdr.sc_id_len, QUIC_MAX_CID_LEN);
            debug!(
                &ctx,
                "QUIC: Long Header SC ID. {:x}", quic_long_hdr.sc_id.as_slice()
            );
            quic_v2::QuicHdr::Long(quic_long_hdr)
        }
        false => {
            let mut quic_short_hdr = QuicShortHdr::new(QUIC_SHORT_DEFAULT_DC_ID_LEN, quic_fixed_hdr);
            read_var_buf!(ctx, off, quic_short_hdr.dc_id, quic_short_hdr.dc_id_len, QUIC_MAX_CID_LEN);
            quic_v2::QuicHdr::Short(quic_short_hdr)
        }
    };
    match quic_hdr {
        quic_v2::QuicHdr::Short(hdr) => {
            unsafe { store_result(map, SHORT_HEADER_MARKER, hdr.dc_id_len as u32, 0) };
        },
        quic_v2::QuicHdr::Long(hdr) => {
            unsafe { store_result(map, hdr.fixed_hdr.version(), hdr.fixed_hdr.dc_id_len as u32, hdr.sc_id_len as u32) };
        }
    }
    Ok(TC_ACT_PIPE)
}
