use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    maps::HashMap,
    programs::TcContext,
    macros::map,
};
use aya_log_ebpf::debug;
use network_types::{bgp::BgpHdr, parse_bgp_hdr, udp::UdpHdr};

use crate::common::parse_ether_ip_udp;

#[map(name = "BGPHDR_RESULT")]
pub static mut BGPHDR_RESULT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(9, 0);

/// Helper to write BGP header parsing results back to user space.
#[inline(always)]
pub unsafe fn store_result(
    map: &mut HashMap<u32, u32>,
    marker: u32,
    length: u32,
    msg_type: u32,
    custom1: u32,
    custom2: u32,
    custom3: u32,
    custom4: u32,
    custom5: u32,
) {
    let _ = map.insert(&0, &marker, 0);
    let _ = map.insert(&1, &length, 0);
    let _ = map.insert(&2, &msg_type, 0);
    let _ = map.insert(&3, &custom1, 0);
    let _ = map.insert(&4, &custom2, 0);
    let _ = map.insert(&5, &custom3, 0);
    let _ = map.insert(&6, &custom4, 0);
    let _ = map.insert(&7, &custom5, 0);
}

/// Tries to parse a BGP header from the packet context.
pub fn try_bgp_hdr_test(ctx: TcContext, map: &mut HashMap<u32, u32>) -> Result<i32, i32> {
    let (mut off, _udp_hdr) = parse_ether_ip_udp(&ctx)?;
    debug!(&ctx, "UDP processing done. Advancing to BGP payload at offset {}.", off );

    match parse_bgp_hdr!(&ctx, off).map_err(|_| TC_ACT_PIPE) {
            Ok(BgpHdr::Open(hdr)) => {
                debug!(
                    &ctx, 
                    "BRANCH: BGP Open header parsed. Marker: {}, Length: {}, MsgType: {}, Version: {}, MyAS: {}, HoldTime: {}, BGPID: {}, OptParamLen: {}", 
                    hdr.fixed_hdr.marker[0],
                    hdr.length(),
                    hdr.msg_type_raw(), 
                    hdr.version(),
                    hdr.my_as(),
                    hdr.hold_time(),
                    hdr.bgp_id(),
                    hdr.opt_parm_len()
                );
                unsafe {
                    store_result(
                        map,
                        hdr.fixed_hdr.marker[0] as u32,
                        hdr.length() as u32,
                        hdr.msg_type_raw() as u32,
                        hdr.version() as u32,
                        hdr.my_as() as u32, 
                        hdr.hold_time() as u32, 
                        hdr.bgp_id(),
                        hdr.opt_parm_len() as u32
                    ) 
                };
        }
        Ok(BgpHdr::Update(hdr)) => {
            debug!(
                &ctx,
                "BRANCH: BGP Update header parsed. Marker: {}, Length: {}, MsgType: {}, WdrwRtLen: {}, PathAttrLen: {}", 
                hdr.fixed_hdr.marker[0],
                hdr.length(),
                hdr.msg_type_raw(),
                hdr.withdrawn_routes_length(),
                hdr.path_attr_length()
            );
            unsafe {
                store_result(
                    map,
                    hdr.fixed_hdr.marker[0] as u32,
                    hdr.length() as u32,
                    hdr.msg_type_raw() as u32,
                    hdr.withdrawn_routes_length() as u32,
                    hdr.path_attr_length() as u32,
                    0,
                    0,
                    0,
                )
            }
        }
        Ok(BgpHdr::Notification(hdr)) => {
            debug!(
                &ctx,
                "BRANCH: BGP Notification header parsed. Marker: {}, Length: {}, MsgType: {}, ErrorCode: {}, ErrorSubCode: {}", 
                hdr.fixed_hdr.marker[0],
                hdr.length(),
                hdr.msg_type_raw(),
                hdr.error_code(),
                hdr.error_subcode()
            );
            unsafe {
                store_result(
                    map,
                    hdr.fixed_hdr.marker[0] as u32,
                    hdr.length() as u32,
                    hdr.msg_type_raw() as u32,
                    hdr.error_code() as u32,
                    hdr.error_subcode() as u32,
                    0,
                    0,
                    0,
                )
            }
        }
        Ok(BgpHdr::KeepAlive(hdr)) => {
            debug!(
                &ctx,
                "BRANCH: BGP Keep Alive header parsed. Marker: {}, Length: {}, MsgType: {}", 
                hdr.fixed_hdr.marker[0],
                hdr.length(),
                hdr.msg_type_raw()
            );
            unsafe {
                store_result(
                    map,
                    hdr.fixed_hdr.marker[0] as u32,
                    hdr.length() as u32,
                    hdr.msg_type_raw() as u32,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            }
        }
        Ok(BgpHdr::RouteRefresh(hdr)) => {
            debug!(
                &ctx,
                "BRANCH: BGP Route Refresh header parsed. Marker: {}, Length: {}, MsgType: {}, AFI: {}, SAFI: {:x}", 
                hdr.fixed_hdr.marker[0],
                hdr.length(),
                hdr.msg_type_raw(),
                hdr.afi(),
                hdr.safi()
            );
            unsafe {
                store_result(
                    map,
                    hdr.fixed_hdr.marker[0] as u32,
                    hdr.length() as u32,
                    hdr.msg_type_raw() as u32,
                    hdr.afi() as u32,
                    hdr.safi() as u32,
                    0,
                    0,
                    0,
                )
            }
        }
        Err(err) => {
            debug!(&ctx, "EXIT: BGP parsing failed, err={}.", err);
            return Err(TC_ACT_PIPE);
        }
    }

    debug!(&ctx, "BGP SUCCESS: Parsed header and stored results.");
    Ok(TC_ACT_PIPE)
}

