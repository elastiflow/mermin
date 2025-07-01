use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    maps::HashMap,
    programs::TcContext,
    macros::map,
};
use aya_log_ebpf::debug;
use network_types::quic::{QuicHdr, QUIC_SHORT_DEFAULT_DC_ID_LEN};
use network_types::parse_quic_hdr;

use crate::common::{parse_ether_ip_udp, SHORT_HEADER_MARKER};

#[map(name = "QUICHDR_RESULT")]
pub static mut QUICHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4, 0);

/// Helper to write three u32s back to user space for QUIC results.
#[inline(always)]
pub unsafe fn store_result(map: &mut HashMap<u32, u32>, marker: u32, dcil: u32, scil: u32) {
    let _ = map.insert(&0, &marker, 0);
    let _ = map.insert(&1, &dcil, 0);
    let _ = map.insert(&2, &scil, 0);
}

/// Tries to parse a QUIC header from the packet context.
pub fn try_quic_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    let (mut off, _udp_hdr) = parse_ether_ip_udp(&ctx)?;

    debug!(
        &ctx,
        "UDP processing done. Advancing to QUIC payload at offset {} len={}.", off, ctx.len()
    );

    match parse_quic_hdr!(&ctx, off, QUIC_SHORT_DEFAULT_DC_ID_LEN).map_err(|_| TC_ACT_SHOT) {
        Ok(QuicHdr::Short(hdr)) => {
            debug!(
                &ctx,
                "BRANCH: QUIC short header detected. DCID: {:x}", hdr.dc_id.as_slice()
            );
            unsafe {
                store_result(
                    map,
                    SHORT_HEADER_MARKER,
                    hdr.dc_id_len as u32,
                    0,
                )
            };
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
            return Err(TC_ACT_SHOT);
        }
    }
    Ok(TC_ACT_PIPE)
}