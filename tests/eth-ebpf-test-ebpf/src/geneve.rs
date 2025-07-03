use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    maps::HashMap,
    programs::TcContext,
    macros::map,
};
use aya_log_ebpf::debug;

use network_types::{
    geneve::GeneveHdr,
    udp::UdpHdr,
};

use crate::common::parse_ether_ip_udp;

#[map(name = "GENEVEHDR_RESULT")]
pub static mut GENEVEHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(9, 0);

/// Helper to write GENEVE header parsing results back to user space.
#[inline(always)]
pub unsafe fn store_result(
    map: &mut HashMap<u32, u32>,
    version: u32,
    opt_len: u32,
    o_flag: u32,
    c_flag: u32,
    protocol_type: u32,
    vni: u32,
) {
    let _ = map.insert(&0, &version, 0);
    let _ = map.insert(&1, &opt_len, 0);
    let _ = map.insert(&2, &o_flag, 0);
    let _ = map.insert(&3, &c_flag, 0);
    let _ = map.insert(&4, &protocol_type, 0);
    let _ = map.insert(&5, &vni, 0);
}


/// Tries to parse a GENEVE header from the packet context.
pub fn try_geneve_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    let (mut off, _udp_hdr) = parse_ether_ip_udp(&ctx)?;
    debug!(&ctx, "UDP processing done. Advancing to GENEVE payload at offset {}.", off );

    let mut geneve_hdr: GeneveHdr = match ctx.load(off) {
        Ok(hdr) => hdr,
        Err(err) => {
            debug!(
                &ctx,
                "EXIT: Failed to load GeneveHdr (packet too short). {}", err
            );
            return Err(TC_ACT_PIPE);
        }
    };

    debug!(
        &ctx,
        "GENEVE SUCCESS. ver={}, opt_len={}, o_flag={}, c_flag={}, protocol_type={}, vni={:x}",
        geneve_hdr.ver(),
        geneve_hdr.opt_len(),
        geneve_hdr.o_flag(),
        geneve_hdr.c_flag(),
        geneve_hdr.protocol_type(),
        geneve_hdr.vni()
    );
    unsafe {
        store_result(
            map,
            geneve_hdr.ver() as u32,
            geneve_hdr.opt_len() as u32,
            geneve_hdr.o_flag() as u32,
            geneve_hdr.c_flag() as u32,
            geneve_hdr.protocol_type() as u32,
            geneve_hdr.vni()
        )
    };

    debug!(&ctx, "GENEVE SUCCESS: Parsed header and stored results.");
    Ok(TC_ACT_PIPE)
}