use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    maps::HashMap,
    programs::TcContext,
    macros::map,
};
use aya_log_ebpf::debug;
use network_types::gre::GreHdr;
use network_types::parse_gre_hdr;

use crate::common::parse_ether_ip_udp;

#[map(name = "GREHDR_RESULT")]
pub static mut GREHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(7, 0);

/// Helper to write GRE header parsing results back to user space.
#[inline(always)]
pub unsafe fn store_result(
    map: &mut HashMap<u32, u32>,
    flags: u32,
    version: u32,
    proto: u32,
    checksum_res1: u32,
    key: u32,
    sequence_number: u32,
) {
    let _ = map.insert(&0, &flags, 0);
    let _ = map.insert(&1, &version, 0);
    let _ = map.insert(&2, &proto, 0);
    let _ = map.insert(&3, &checksum_res1, 0);
    let _ = map.insert(&4, &key, 0);
    let _ = map.insert(&5, &sequence_number, 0);
}

/// Tries to parse a GRE header from the packet context.
pub fn try_gre_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    let (mut off, _udp_hdr) = parse_ether_ip_udp(&ctx)?;

    debug!(
        &ctx,
        "UDP processing done. Advancing to GRE payload at offset {}.", off
    );

    let parsed_hdr: GreHdr = parse_gre_hdr!(&ctx, off).map_err(|_| -1i32)?;

    debug!(&ctx, "Finished GRE Parse. flags: {:x}, version: {:x}, proto: {:x}, checksum res1: {:x}, key: {:x}, seq: {:x}",
        parsed_hdr.fixed.flgs_res0_ver[0] as u32,
        parsed_hdr.version() as u32,
        parsed_hdr.proto() as u32,
        parsed_hdr.ck_res1(),
        parsed_hdr.key(),
        parsed_hdr.seq());

    unsafe {
        store_result(
            map,
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