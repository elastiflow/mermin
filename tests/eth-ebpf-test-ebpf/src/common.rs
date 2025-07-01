use core::mem;
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    programs::TcContext,
};
use aya_log_ebpf::debug;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::udp::UdpHdr;

/// IPv6 Fragment‑header – RFC 8200 §4.5 (8 bytes)
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Ipv6FragHdr {
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

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;
pub const SHORT_HEADER_MARKER: u32 = 2; // Used for QUIC short headers

/// Converts a raw u8 IP protocol number to `IpProto` enum.
#[inline(always)]
pub fn to_ip_proto(n: u8) -> IpProto {
    match n {
        17 => IpProto::Udp,
        44 => IpProto::Ipv6Frag,
        _ => IpProto::Reserved, // Use as a generic non-UDP case
    }
}

/// Parses Ethernet, IP (v4 or v6, including fragments), and UDP headers.
///
/// Returns the offset after the UDP header and the UdpHdr itself on success,
/// or an eBPF action code on failure.
#[inline(always)]
pub fn parse_ether_ip_udp(ctx: &TcContext) -> Result<(usize, UdpHdr), i32> {
    debug!(
        ctx,
        "TC classifier triggered. Packet size: {}",
        ctx.data_end() - ctx.data()
    );

    let mut off = 0_usize;
    let eth: EthHdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
    off += EthHdr::LEN;

    debug!(
        ctx,
        "ETH Hdr: DST: {:mac}, SRC: {:mac}, EtherType: {:x}",
        eth.dst_addr,
        eth.src_addr,
        u16::from_be(eth.ether_type)
    );

    let ether_type = eth.ether_type;
    let ip_hdr_len = match ether_type {
        et if et == ETHER_TYPE_IPV4.to_be() => {
            debug!(ctx, "BRANCH: EtherType is IPv4. Reading Ipv4Hdr.");
            let ipv4: Ipv4Hdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
            let proto = ipv4.proto;
            debug!(ctx, "IPv4 Hdr: Proto: {}", proto as u8);
            if proto != IpProto::Udp {
                debug!(ctx, "EXIT: IPv4 proto is not UDP.");
                return Err(TC_ACT_PIPE);
            }
            (ipv4.vihl & 0x0F) as usize * 4
        }
        et if et == ETHER_TYPE_IPV6.to_be() => {
            debug!(ctx, "BRANCH: EtherType is IPv6. Reading Ipv6Hdr.");
            // We can load just the next_hdr byte to save stack space initially
            const IPV6_HDR_NEXT_HDR_OFFSET: usize = 6;
            let next_hdr_val: u8 =
                ctx.load(off + IPV6_HDR_NEXT_HDR_OFFSET).map_err(|_| TC_ACT_PIPE)?;
            let mut next_hdr = to_ip_proto(next_hdr_val);
            let mut hdr_len = Ipv6Hdr::LEN;

            debug!(ctx, "IPv6 Hdr: NextHdr: {}", next_hdr as u8);

            if next_hdr == IpProto::Ipv6Frag {
                debug!(ctx, "IPv6 frag header detected, parsing.");
                // Load the next_hdr from the fragment header
                let frag_next_hdr_val: u8 =
                    ctx.load(off + hdr_len).map_err(|_| TC_ACT_PIPE)?;
                next_hdr = to_ip_proto(frag_next_hdr_val);
                hdr_len += mem::size_of::<Ipv6FragHdr>();
                debug!(ctx, "IPv6 frag: next_hdr after frag: {}", next_hdr as u8);
            }

            if next_hdr != IpProto::Udp {
                debug!(ctx, "EXIT: IPv6 next_hdr is not UDP.");
                return Err(TC_ACT_PIPE);
            }
            hdr_len
        }
        _ => {
            debug!(ctx, "EXIT: Not an IPv4 or IPv6 packet.");
            return Err(TC_ACT_PIPE);
        }
    };
    off += ip_hdr_len;

    debug!(
        ctx,
        "IP processing done. Advancing to UDP at offset {}", off
    );

    let udp: UdpHdr = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
    let udp_len = udp.len() as usize;

    debug!(
        ctx,
        "UDP Hdr: Src Port: {}, Dst Port: {}, Length: {}",
        udp.src_port(),
        udp.dst_port(),
        udp_len
    );

    if udp_len < UdpHdr::LEN { // Should be `udp_len <= UdpHdr::LEN` if `udp_len` is just the payload length
        debug!(ctx, "EXIT: UDP length is too small.");
        return Err(TC_ACT_PIPE);
    }
    off += UdpHdr::LEN;

    Ok((off, udp))
}