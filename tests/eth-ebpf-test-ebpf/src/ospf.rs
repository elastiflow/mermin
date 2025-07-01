use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    maps::HashMap,
    programs::TcContext,
    macros::map,
};
use aya_log_ebpf::debug;
use network_types::{
    ospf::{OspfV2Hdr, OspfV3Hdr},
    udp::UdpHdr,
};

use crate::common::parse_ether_ip_udp;

#[map(name = "OSPFHDR_RESULT")]
pub static mut OSPFHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(9, 0);

/// Helper to write OSPF header parsing results back to user space.
#[inline(always)]
pub unsafe fn store_result(
    map: &mut HashMap<u32, u32>,
    version: u32,
    packet_type: u32,
    length: u32,
    router_id: u32,
    area_id: u32,
    checksum: u32,
    custom1: u32,
    custom2: u32,
) {
    let _ = map.insert(&0, &version, 0);
    let _ = map.insert(&1, &packet_type, 0);
    let _ = map.insert(&2, &length, 0);
    let _ = map.insert(&3, &router_id, 0);
    let _ = map.insert(&4, &area_id, 0);
    let _ = map.insert(&5, &checksum, 0);
    let _ = map.insert(&6, &custom1, 0);
    let _ = map.insert(&7, &custom2, 0);
}

/// Tries to parse a OSPD header from the packet context.
pub fn try_ospf_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    let (mut off, _udp_hdr) = parse_ether_ip_udp(&ctx)?;
    let payload_len = _udp_hdr.len() as usize - UdpHdr::LEN;
    debug!(&ctx, "UDP processing done. Advancing to OSPF payload at offset {}.", off );

    match payload_len {
        len if len == OspfV2Hdr::LEN => {
            let mut ospfv2_hdr: OspfV2Hdr = match ctx.load(off) {
                Ok(hdr) => hdr,
                Err(err) => {
                    debug!(&ctx, "EXIT: Failed to load OspfV2Hdr (packet too short). {}", err);
                    return Err(TC_ACT_PIPE);
                }
            };

            let authentication = ospfv2_hdr.authentication();
            debug!(
                &ctx, 
                "OSPF V2 SUCCESS. version={} type={} length={} router={} area={} checksum={} auth type={} auth={:x}", 
                ospfv2_hdr.version(), 
                ospfv2_hdr.type_(), 
                ospfv2_hdr.len(),
                ospfv2_hdr.router_id(), 
                ospfv2_hdr.area_id(),
                ospfv2_hdr.checksum(), 
                ospfv2_hdr.au_type(), 
                authentication.as_slice()
            );

            /// Authentication param not sent back to user space as it is too long for logging as u32
            unsafe { 
                store_result(
                    map,
                    ospfv2_hdr.version() as u32,
                    ospfv2_hdr.type_() as u32,
                    ospfv2_hdr.len() as u32,
                    ospfv2_hdr.router_id(),
                    ospfv2_hdr.area_id(),
                    ospfv2_hdr.checksum() as u32,
                    ospfv2_hdr.au_type() as u32,
                    0
                ) 
            };
        }
        len if len == OspfV3Hdr::LEN => {
            let mut ospfv3_hdr: OspfV3Hdr = match ctx.load(off) {
                Ok(hdr) => hdr,
                Err(err) => {
                    debug!(&ctx, "EXIT: Failed to load OspfV3Hdr (packet too short). {}", err);
                    return Err(TC_ACT_PIPE);
                }
            };

            debug!(
                &ctx, 
                "OSPF V3 SUCCESS. version={} type={} length={} router={} area={} checksum={} instance={} res={}", 
                ospfv3_hdr.version(), 
                ospfv3_hdr.type_(), 
                ospfv3_hdr.len(),
                ospfv3_hdr.router_id(), 
                ospfv3_hdr.area_id(),
                ospfv3_hdr.checksum(),
                ospfv3_hdr.instance_id(),
                ospfv3_hdr.reserved
            );

            unsafe { 
                store_result(
                    map,
                    ospfv3_hdr.version() as u32,
                    ospfv3_hdr.type_() as u32,
                    ospfv3_hdr.len() as u32,
                    ospfv3_hdr.router_id(),
                    ospfv3_hdr.area_id(),
                    ospfv3_hdr.checksum() as u32,
                    ospfv3_hdr.instance_id() as u32,
                    ospfv3_hdr.reserved as u32
                ) 
            };
        }
        _ => {
            debug!(&ctx, "OSPF FAILURE: Payload length {} is not supported.", payload_len);
            return Err(TC_ACT_PIPE);
        }
    }

    debug!(&ctx, "OSPF SUCCESS: Parsed header and stored results.");
    Ok(TC_ACT_PIPE)
}