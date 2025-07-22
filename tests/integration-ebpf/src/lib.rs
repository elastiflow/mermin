#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::KProbeContext,
    helpers::bpf_get_current_pid_tgid,
};
use aya_log_ebpf::info;

// Import our test's shared structs
use integration_common::{HeaderUnion, ParsedRequest, PacketType, ParsedHeader, REQUEST_DATA_SIZE};
use network_types::{
    eth::{EthHdr, EtherType},
};

// Map for receiving raw data from the user-space test runner. Keyed by PID.
#[map]
static IN_DATA: HashMap<u32, [u8; REQUEST_DATA_SIZE]> = HashMap::new(1024, 0);

// Map for sending the parsed result back to the test runner.
#[map]
static OUT_DATA: PerfEventArray<ParsedRequest> = PerfEventArray::new(0);

// This program is the eBPF part of our integration test.
#[kprobe]
pub fn integration_test(ctx: KProbeContext) -> u32 {
    match try_integration_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_integration_test(ctx: KProbeContext) -> Result<u32, u32> {
    let pid = bpf_get_current_pid_tgid() as u32;

    let raw_data = match unsafe { IN_DATA.get(&pid) } {
        Some(data) => data,
        None => return Ok(0),
    };

    let packet_type = raw_data[0];
    let payload_bytes = &raw_data[1..];

    // Match on the packet type to execute the correct parsing logic.
    match packet_type {
        t if t == PacketType::Eth as u8 => {
            info!(&ctx, "Manually parsing Ethernet header");

            if payload_bytes.len() < EthHdr::LEN {
                return Err(1);
            }

            let dst_addr: [u8; 6] = payload_bytes[0..6].try_into().unwrap();
            let src_addr: [u8; 6] = payload_bytes[6..12].try_into().unwrap();

            let eth_type_bytes: [u8; 2] = payload_bytes[12..14].try_into().unwrap();
            let eth_type_u16 = u16::from_be_bytes(eth_type_bytes);
            let eth_type_enum = EtherType::try_from(eth_type_u16).unwrap();

            let header = EthHdr::new(dst_addr, src_addr, eth_type_enum);

            let response = ParsedHeader {
                ty: PacketType::Eth,
                data: HeaderUnion { eth: header },
            };
            OUT_DATA.output(&ctx, &response, 0);
        }
        _ => {
            info!(&ctx, "Received unknown packet type: {}", packet_type);
        }
    }

    // Clean up the map after processing.
    unsafe { IN_DATA.delete(&pid) };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}