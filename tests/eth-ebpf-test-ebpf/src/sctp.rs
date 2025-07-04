use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    maps::HashMap,
    programs::TcContext,
    macros::map,
};
use aya_log_ebpf::debug;
use network_types::{
    sctp::SctpHdr,
    udp::UdpHdr,
};

use crate::common::parse_ether_ip_udp;

#[map(name = "SCTPHDR_RESULT")]
pub static mut SCTPHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(9, 0);

/// Helper to write SCTP header parsing results back to user space.
#[inline(always)]
pub unsafe fn store_result(
    map: &mut HashMap<u32, u32>,
    src: u32,
    dst: u32,
    ver_tag: u32,
    checksum: u32,
) {
    let _ = map.insert(&0, &src, 0);
    let _ = map.insert(&1, &dst, 0);
    let _ = map.insert(&2, &ver_tag, 0);
    let _ = map.insert(&3, &checksum, 0);
}

/// Tries to parse an OSPF header from the packet context.
pub fn try_sctp_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    let (mut off, _udp_hdr) = parse_ether_ip_udp(&ctx)?;
    let payload_len = _udp_hdr.len() as usize - UdpHdr::LEN;
    debug!(&ctx, "UDP processing done. Advancing to SCTP payload at offset {}.", off );

    let mut sctp_hdr: SctpHdr = match ctx.load(off) {
        Ok(hdr) => hdr,
        Err(err) => {
            debug!(
                &ctx,
                "EXIT: Failed to load SctpHdr (packet too short). {}", err
            );
            return Err(TC_ACT_PIPE);
        }
    };

    debug!(
        &ctx,
        "SCTP SUCCESS. src_port={}, dst_port={}, ver_tag={}, checksum={}",
        sctp_hdr.src_port(),
        sctp_hdr.dst_port(),
        sctp_hdr.verification_tag(),
        sctp_hdr.checksum()
    );
    unsafe {
        store_result(
            map,
            sctp_hdr.src_port() as u32,
            sctp_hdr.dst_port() as u32,
            sctp_hdr.verification_tag(),
            sctp_hdr.checksum(),
        )
    };

    debug!(&ctx, "SCTP SUCCESS: Parsed header and stored results.");
    Ok(TC_ACT_PIPE)
}