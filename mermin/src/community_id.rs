use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use network_types::ip::IpProto;
use sha1::{Digest, Sha1};

/// Community ID generator with configurable seed
#[derive(Debug)]
pub struct CommunityIdGenerator {
    seed: u16,
}

impl CommunityIdGenerator {
    /// Create a new Community ID generator with the specified seed
    pub fn new(seed: u16) -> Self {
        Self { seed }
    }

    /// Create a new Community ID generator with default seed (0)
    #[allow(dead_code)]
    pub fn default() -> Self {
        Self { seed: 0 }
    }

    /// Generate Community ID for any flow based on protocol type
    /// This is the main entry point that handles all protocol types
    pub fn generate(
        &self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        src_port: u16,
        dst_port: u16,
        proto: IpProto,
    ) -> String {
        match proto {
            IpProto::Tcp | IpProto::Udp | IpProto::Sctp => {
                self.community_id_v1(src_addr, dst_addr, src_port, dst_port, proto as u8)
            }
            IpProto::Icmp => {
                // For ICMP, map type/code to port-like values
                let (sport, dport) = map_icmp_to_ports(src_port, dst_port);
                self.community_id_v1(src_addr, dst_addr, sport, dport, proto as u8)
            }
            IpProto::Ipv6Icmp => {
                // For ICMPv6, map type/code to port-like values
                let (sport, dport) = map_icmp_to_ports(src_port, dst_port);
                self.community_id_v1(src_addr, dst_addr, sport, dport, proto as u8)
            }
            _ => {
                // For other protocols without ports
                self.community_id_v1(src_addr, dst_addr, 0, 0, proto as u8)
            }
        }
    }

    /// Core Community ID v1 implementation
    fn community_id_v1(
        &self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> String {
        // Convert addresses to network byte order
        let src_addr_bytes = self.ip_addr_to_bytes(src_addr);
        let dst_addr_bytes = self.ip_addr_to_bytes(dst_addr);

        // Convert ports to network byte order
        let src_port_bytes = src_port.to_be_bytes();
        let dst_port_bytes = dst_port.to_be_bytes();

        // Convert seed to network byte order
        let seed_bytes = self.seed.to_be_bytes();

        // Order endpoints so smaller IP:port comes first
        let (first_addr, second_addr, first_port, second_port) = self.order_endpoints(
            src_addr_bytes,
            dst_addr_bytes,
            src_port_bytes,
            dst_port_bytes,
        );

        // Build hash input: seed + first_addr + second_addr + proto + 0 + first_port + second_port
        let mut hasher = Sha1::new();
        hasher.update(seed_bytes);
        hasher.update(&first_addr);
        hasher.update(&second_addr);
        hasher.update([proto, 0]); // proto + padding byte
        hasher.update(first_port);
        hasher.update(second_port);

        let digest = hasher.finalize();

        // Return version + base64 encoded digest
        format!("1:{}", BASE64.encode(digest))
    }

    /// Convert IP address to network byte order bytes
    fn ip_addr_to_bytes(&self, addr: IpAddr) -> Vec<u8> {
        match addr {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        }
    }

    /// Order endpoints so the smaller IP:port tuple comes first
    /// This implements lexicographic comparison of the entire IP:port tuple
    fn order_endpoints(
        &self,
        src_addr: Vec<u8>,
        dst_addr: Vec<u8>,
        src_port: [u8; 2],
        dst_port: [u8; 2],
    ) -> (Vec<u8>, Vec<u8>, [u8; 2], [u8; 2]) {
        match src_addr.cmp(&dst_addr) {
            std::cmp::Ordering::Less => (src_addr, dst_addr, src_port, dst_port),
            std::cmp::Ordering::Greater => (dst_addr, src_addr, dst_port, src_port),
            std::cmp::Ordering::Equal => match src_port.cmp(&dst_port) {
                std::cmp::Ordering::Less => (src_addr, dst_addr, src_port, dst_port),
                std::cmp::Ordering::Equal => (src_addr, dst_addr, src_port, dst_port),
                std::cmp::Ordering::Greater => (dst_addr, src_addr, dst_port, src_port),
            },
        }
    }
}

/// Map ICMP type and code to port-like values for Community ID calculation
/// This mapping is based on Zeek's implementation as referenced in the spec
/// See: https://github.com/corelight/pycommunityid/blob/master/communityid/icmp.py
///
/// For ICMP flows, the src_port parameter should contain the ICMP type,
/// and the dst_port parameter should contain the ICMP code.
fn map_icmp_to_ports(_type: u16, counter_type: u16) -> (u16, u16) {
    // Map ICMP types to their corresponding reply types for proper flow identification
    // This ensures that echo/echo_reply, timestamp/timestamp_reply, etc. are treated as the same flow
    let counter_type = match _type {
        // IPv4 ICMP types
        0 => 8,   // ECHO_REPLY -> ECHO
        8 => 0,   // ECHO -> ECHO_REPLY
        9 => 10,  // RTR_ADVERT -> RTR_SOLICIT
        10 => 9,  // RTR_SOLICIT -> RTR_ADVERT
        13 => 14, // TSTAMP -> TSTAMP_REPLY
        14 => 13, // TSTAMP_REPLY -> TSTAMP
        15 => 16, // INFO -> INFO_REPLY
        16 => 15, // INFO_REPLY -> INFO
        17 => 18, // MASK -> MASK_REPLY
        18 => 17, // MASK_REPLY -> MASK

        // ICMPv6 types (RFC 4443)
        128 => 129,        // ICMPv6 ECHO_REQUEST -> ICMPv6 ECHO_REPLY
        129 => 128,        // ICMPv6 ECHO_REPLY -> ICMPv6 ECHO_REQUEST
        130 => 131,        // ICMPv6 MLD_LISTENER_QUERY -> ICMPv6 MLD_LISTENER_REPORT
        131 => 130,        // ICMPv6 MLD_LISTENER_REPORT -> ICMPv6 MLD_LISTENER_QUERY
        133 => 134,        // ICMPv6 RTR_SOLICIT -> ICMPv6 RTR_ADVERT
        134 => 133,        // ICMPv6 RTR_ADVERT -> ICMPv6 RTR_SOLICIT
        135 => 136,        // ICMPv6 NEIGHBOR_SOLICIT -> ICMPv6 NEIGHBOR_ADVERT
        136 => 135,        // ICMPv6 NEIGHBOR_ADVERT -> ICMPv6 NEIGHBOR_SOLICIT
        139 => 140,        // ICMPv6 NODE_INFO_QUERY -> ICMPv6 NODE_INFO_RESPONSE
        140 => 139,        // ICMPv6 NODE_INFO_RESPONSE -> ICMPv6 NODE_INFO_QUERY
        141 => 142,        // ICMPv6 INVERSE_NEIGHBOR_SOLICIT -> ICMPv6 INVERSE_NEIGHBOR_ADVERT
        142 => 141,        // ICMPv6 INVERSE_NEIGHBOR_ADVERT -> ICMPv6 INVERSE_NEIGHBOR_SOLICIT
        144 => 145, // ICMPv6 HOME_AGENT_ADDR_DISCOVERY_REQUEST -> ICMPv6 HOME_AGENT_ADDR_DISCOVERY_REPLY
        145 => 144, // ICMPv6 HOME_AGENT_ADDR_DISCOVERY_REPLY -> ICMPv6 HOME_AGENT_ADDR_DISCOVERY_REQUEST
        146 => 147, // ICMPv6 MOBILE_PREFIX_SOLICIT -> ICMPv6 MOBILE_PREFIX_ADVERT
        147 => 146, // ICMPv6 MOBILE_PREFIX_ADVERT -> ICMPv6 MOBILE_PREFIX_SOLICIT
        148 => 149, // ICMPv6 CERTIFICATION_PATH_SOLICIT -> ICMPv6 CERTIFICATION_PATH_ADVERT
        149 => 148, // ICMPv6 CERTIFICATION_PATH_ADVERT -> ICMPv6 CERTIFICATION_PATH_SOLICIT
        151 => 152, // ICMPv6 MULTICAST_RTR_ADVERT -> ICMPv6 MULTICAST_RTR_SOLICIT
        152 => 151, // ICMPv6 MULTICAST_RTR_SOLICIT -> ICMPv6 MULTICAST_RTR_ADVERT
        160 => 161, // ICMPv6 EXTENDED_ECHO_REQUEST -> ICMPv6 EXTENDED_ECHO_REPLY
        161 => 160, // ICMPv6 EXTENDED_ECHO_REPLY -> ICMPv6 EXTENDED_ECHO_REQUEST
        _ => counter_type, // For unmapped types, use the same type for both ports
    };

    (_type, counter_type)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_community_id_generation() {
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let community_id = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);

        assert!(community_id.starts_with("1:"));
        assert_eq!(community_id.len(), 30); // 1: + 20 bytes base64 encoded (with padding)
    }

    #[test]
    fn test_bidirectional_flow_consistency() {
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        // Forward flow
        let forward = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);
        // Reverse flow
        let reverse = generator.generate(dst_addr, src_addr, 3344, 1122, IpProto::Tcp);

        // Both should generate the same Community ID
        assert_eq!(forward, reverse);
    }

    #[test]
    fn test_seed_configuration() {
        let generator_default = CommunityIdGenerator::default();
        let generator_seed1 = CommunityIdGenerator::new(1);
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let id_default = generator_default.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);
        let id_seed1 = generator_seed1.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);

        // Different seeds should produce different IDs
        assert_ne!(id_default, id_seed1);
    }

    #[test]
    fn test_baseline_data_tcp() {
        // Test case from baseline data: TCP 1.2.3.4:1122 -> 5.6.7.8:3344
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let community_id = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);
        let community_id_reverse = generator.generate(dst_addr, src_addr, 3344, 1122, IpProto::Tcp);

        assert_eq!(community_id, "1:wCb3OG7yAFWelaUydu0D+125CLM=");
        assert_eq!(community_id_reverse, "1:wCb3OG7yAFWelaUydu0D+125CLM=");
    }

    #[test]
    fn test_baseline_data_udp() {
        // Test case from baseline data: UDP 1.2.3.4:1122 -> 5.6.7.8:3344
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let community_id = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Udp);
        let community_id_reverse = generator.generate(dst_addr, src_addr, 3344, 1122, IpProto::Udp);

        assert_eq!(community_id, "1:0Mu9InQx6z4ZiCZM/7HXi2WMhOg=");
        assert_eq!(community_id_reverse, "1:0Mu9InQx6z4ZiCZM/7HXi2WMhOg=");
    }

    #[test]
    fn test_baseline_data_sctp() {
        // Test case from baseline data: SCTP 1.2.3.4:1122 -> 5.6.7.8:3344
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let community_id = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Sctp);
        let community_id_reverse =
            generator.generate(dst_addr, src_addr, 3344, 1122, IpProto::Sctp);

        assert_eq!(community_id, "1:EKt4MsxuyaE6mL+hmrEkQ9csDD8=");
        assert_eq!(community_id_reverse, "1:EKt4MsxuyaE6mL+hmrEkQ9csDD8=");
    }

    #[test]
    fn test_baseline_data_icmp() {
        // Test case from baseline data: ICMP echo request 1.2.3.4 -> 5.6.7.8
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let community_id = generator.generate(src_addr, dst_addr, 8, 0, IpProto::Icmp);
        let community_id_reverse = generator.generate(dst_addr, src_addr, 0, 0, IpProto::Icmp);
        let community_id_unidir = generator.generate(src_addr, dst_addr, 11, 0, IpProto::Icmp);

        assert_eq!(community_id, "1:crodRHL2FEsHjbv3UkRrfbs4bZ0=");
        assert_eq!(community_id_reverse, "1:crodRHL2FEsHjbv3UkRrfbs4bZ0=");
        assert_eq!(community_id_unidir, "1:f/YiSyWqczrTgfUCZlBUnvHRcPk=");
    }

    #[test]
    fn test_baseline_data_icmpv6() {
        // Test case from baseline data: ICMPv6 echo request
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0A0B, 0x0C0D,
        ));
        let dst_addr = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x1011, 0x1213, 0x1415, 0x1617, 0x1819, 0x1A1B, 0x1C1D,
        ));

        let community_id = generator.generate(src_addr, dst_addr, 128, 0, IpProto::Ipv6Icmp);
        let community_id_reverse =
            generator.generate(dst_addr, src_addr, 129, 0, IpProto::Ipv6Icmp);
        let community_id_unidir = generator.generate(src_addr, dst_addr, 155, 0, IpProto::Ipv6Icmp);
        let community_id_unidir_reverse =
            generator.generate(dst_addr, src_addr, 155, 0, IpProto::Ipv6Icmp);

        assert_eq!(community_id, "1:0bf7hyMJUwt3fMED7z8LIfRpBeo=");
        assert_eq!(community_id_reverse, "1:0bf7hyMJUwt3fMED7z8LIfRpBeo=");
        assert_eq!(community_id_unidir, "1:EvBBWYT0zEU0Gg9GDmH7rd7Mxk0=");
        assert_eq!(
            community_id_unidir_reverse,
            "1:Zb019rYpqfcZisDbVT+l16mxt+Y="
        );
    }

    #[test]
    fn test_baseline_data_rsvp() {
        // Test case from baseline data: RSVP 1.2.3.4 -> 5.6.7.8
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let src_addr_v6 = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0A0B, 0x0C0D,
        ));
        let dst_addr_v6 = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x1011, 0x1213, 0x1415, 0x1617, 0x1819, 0x1A1B, 0x1C1D,
        ));

        let community_id = generator.generate(src_addr, dst_addr, 0, 0, IpProto::Rsvp);
        let community_id_reverse = generator.generate(dst_addr, src_addr, 0, 0, IpProto::Rsvp);
        let community_id_v6 = generator.generate(src_addr_v6, dst_addr_v6, 0, 0, IpProto::Rsvp);
        let community_id_v6_reverse =
            generator.generate(dst_addr_v6, src_addr_v6, 0, 0, IpProto::Rsvp);

        assert_eq!(community_id, community_id_reverse);
        assert_eq!(community_id, "1:hZHQjvhiT2t0BQWM3zNp/Kq7jHw=");
        assert_eq!(community_id_reverse, "1:hZHQjvhiT2t0BQWM3zNp/Kq7jHw=");
        assert_eq!(community_id_v6, "1:oYO4dR7oS+6Hep4XUZjUlYLWEJo=");
        assert_eq!(community_id_v6_reverse, "1:oYO4dR7oS+6Hep4XUZjUlYLWEJo=");
    }

    #[test]
    fn test_seed_1_baseline_data() {
        // Test case from baseline data with seed=1: TCP 1.2.3.4:1122 -> 5.6.7.8:3344
        let generator = CommunityIdGenerator::new(1);
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let community_id = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);

        assert_eq!(community_id, "1:HhA1B+6CoLbiKPEs5nhNYN4XWfk=");
    }

    #[test]
    fn test_ipv6_bidirectional_flow() {
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0A0B, 0x0C0D,
        ));
        let dst_addr = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x1011, 0x1213, 0x1415, 0x1617, 0x1819, 0x1A1B, 0x1C1D,
        ));

        let forward = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);
        let reverse = generator.generate(dst_addr, src_addr, 3344, 1122, IpProto::Tcp);

        assert_eq!(forward, reverse);
    }

    #[test]
    fn test_mixed_ip_versions() {
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0A0B, 0x0C0D,
        ));

        let community_id = generator.generate(src_addr, dst_addr, 1122, 3344, IpProto::Tcp);

        assert!(community_id.starts_with("1:"));
        assert_eq!(community_id.len(), 30);
    }

    #[test]
    fn test_icmp_bidirectional_flow() {
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        // ICMP echo request (type 8) from src to dst
        let echo_request = generator.generate(src_addr, dst_addr, 8, 0, IpProto::Icmp);
        // ICMP echo reply (type 0) from dst to src
        let echo_reply = generator.generate(dst_addr, src_addr, 0, 0, IpProto::Icmp);

        // Both should generate the same Community ID due to proper type mapping
        assert_eq!(echo_request, echo_reply);
    }

    #[test]
    fn test_icmp_type_mapping() {
        let generator = CommunityIdGenerator::default();
        let src_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        // Test various ICMP type pairs to ensure they map correctly
        let test_cases = vec![
            (8, 0),     // ECHO -> ECHO_REPLY
            (13, 14),   // TSTAMP -> TSTAMP_REPLY
            (15, 16),   // INFO -> INFO_REPLY
            (17, 18),   // MASK -> MASK_REPLY
            (128, 129), // ICMPv6 ECHO_REQUEST -> ICMPv6 ECHO_REPLY
            (130, 131), // ICMPv6 MLD_LISTENER_QUERY -> ICMPv6 MLD_LISTENER_REPORT
            (133, 134), // ICMPv6 RTR_SOLICIT -> ICMPv6 RTR_ADVERT
            (135, 136), // ICMPv6 NEIGHBOR_SOLICIT -> ICMPv6 NEIGHBOR_ADVERT
            (139, 140), // ICMPv6 NODE_INFO_QUERY -> ICMPv6 NODE_INFO_RESPONSE
            (141, 142), // ICMPv6 INVERSE_NEIGHBOR_SOLICIT -> ICMPv6 INVERSE_NEIGHBOR_ADVERT
            (144, 145), // ICMPv6 HOME_AGENT_ADDR_DISCOVERY_REQUEST -> ICMPv6 HOME_AGENT_ADDR_DISCOVERY_REPLY
            (146, 147), // ICMPv6 MOBILE_PREFIX_SOLICIT -> ICMPv6 MOBILE_PREFIX_ADVERT
            (148, 149), // ICMPv6 CERTIFICATION_PATH_SOLICIT -> ICMPv6 CERTIFICATION_PATH_ADVERT
            (151, 152), // ICMPv6 MULTICAST_RTR_ADVERT -> ICMPv6 MULTICAST_RTR_SOLICIT
            (160, 161), // ICMPv6 EXTENDED_ECHO_REQUEST -> ICMPv6 EXTENDED_ECHO_REPLY
        ];

        for (request_type, counter_type) in test_cases {
            let request = generator.generate(src_addr, dst_addr, request_type, 0, IpProto::Icmp);
            let reply = generator.generate(dst_addr, src_addr, counter_type, 0, IpProto::Icmp);

            // Each request/reply pair should generate the same Community ID
            assert_eq!(
                request, reply,
                "Failed for types {} -> {}",
                request_type, counter_type
            );
        }
    }
}
