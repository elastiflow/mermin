use std::{collections::HashSet, net::IpAddr, str::FromStr};

use globset::{Glob, GlobSet, GlobSetBuilder};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use mermin_common::PacketMeta;
use network_types::{
    icmp,
    ip::{IpDscp, IpEcn, IpProto},
};
use num_iter::range_inclusive;
use num_traits::PrimInt;
use pnet::datalink::MacAddr;
use tracing::warn;

use crate::{
    ip::{Error as IpError, resolve_addrs},
    runtime::conf::{Conf, FilteringOptions, FilteringPair},
    span::tcp::{ConnectionState, TcpFlags},
};

/// Contains a pre-compiled set of rules for a single filter dimension (e.g., "source", "network").
#[derive(Default)]
struct CompiledRules {
    address: Option<CompiledRuleSet<IpNetworkTable<()>>>,
    port: Option<CompiledRuleSet<HashSet<u16>>>,
    transport: Option<CompiledRuleSet<GlobSet>>,
    type_: Option<CompiledRuleSet<GlobSet>>,
    interface_name: Option<CompiledRuleSet<GlobSet>>,
    interface_index: Option<CompiledRuleSet<HashSet<u32>>>,
    interface_mac: Option<CompiledRuleSet<GlobSet>>,
    connection_state: Option<CompiledRuleSet<GlobSet>>,
    end_reason: Option<CompiledRuleSet<GlobSet>>,
    ip_dscp_name: Option<CompiledRuleSet<GlobSet>>,
    ip_ecn_name: Option<CompiledRuleSet<GlobSet>>,
    ip_ttl: Option<CompiledRuleSet<HashSet<u8>>>,
    ip_flow_label: Option<CompiledRuleSet<HashSet<u32>>>,
    icmp_type_name: Option<CompiledRuleSet<GlobSet>>,
    icmp_code_name: Option<CompiledRuleSet<GlobSet>>,
    tcp_flags: Option<CompiledRuleSet<GlobSet>>,
}

/// A generic, pre-compiled set of rules for any filterable type.
#[derive(Debug, Clone)]
struct CompiledRuleSet<T> {
    match_rules: T,
    not_match_rules: T,
}

impl CompiledRules {
    fn new(opts: Option<&FilteringOptions>) -> Self {
        let Some(opts) = opts else {
            return Self::default();
        };

        let build_glob_set = |pair: &FilteringPair| -> CompiledRuleSet<GlobSet> {
            let build = |s: &str| -> GlobSet {
                if s.is_empty() {
                    return GlobSetBuilder::new().build().unwrap();
                }
                let mut builder = GlobSetBuilder::new();
                for part in s.split(',') {
                    match Glob::new(part.trim()) {
                        Ok(glob) => {
                            builder.add(glob);
                        }
                        Err(e) => warn!(
                            event_name = "filter.glob_parse_failed",
                            pattern = %part,
                            error.message = %e,
                            "Invalid glob pattern in filter config, skipping."
                        ),
                    }
                }
                builder.build().unwrap()
            };

            CompiledRuleSet {
                match_rules: build(&pair.match_glob),
                not_match_rules: build(&pair.not_match_glob),
            }
        };

        fn build_numeric_pair<T>(pair: &FilteringPair) -> CompiledRuleSet<HashSet<T>>
        where
            T: PrimInt + FromStr,
            <T as FromStr>::Err: std::fmt::Debug,
        {
            CompiledRuleSet {
                match_rules: build_numeric_set::<T>(&pair.match_glob),
                not_match_rules: build_numeric_set::<T>(&pair.not_match_glob),
            }
        }

        Self {
            address: opts.address.as_ref().map(|pair| CompiledRuleSet {
                match_rules: build_ip_network_table(&pair.match_glob),
                not_match_rules: build_ip_network_table(&pair.not_match_glob),
            }),
            port: opts.port.as_ref().map(build_numeric_pair::<u16>),
            transport: opts.transport.as_ref().map(build_glob_set),
            type_: opts.type_.as_ref().map(build_glob_set),
            interface_name: opts.interface_name.as_ref().map(build_glob_set),
            interface_index: opts.interface_index.as_ref().map(build_numeric_pair::<u32>),
            interface_mac: opts.interface_mac.as_ref().map(build_glob_set),
            connection_state: opts.connection_state.as_ref().map(build_glob_set),
            end_reason: opts.end_reason.as_ref().map(build_glob_set),
            ip_dscp_name: opts.ip_dscp_name.as_ref().map(build_glob_set),
            ip_ecn_name: opts.ip_ecn_name.as_ref().map(build_glob_set),
            ip_ttl: opts.ip_ttl.as_ref().map(build_numeric_pair::<u8>),
            ip_flow_label: opts.ip_flow_label.as_ref().map(build_numeric_pair::<u32>),
            icmp_type_name: opts.icmp_type_name.as_ref().map(build_glob_set),
            icmp_code_name: opts.icmp_code_name.as_ref().map(build_glob_set),
            tcp_flags: opts.tcp_flags.as_ref().map(build_glob_set),
        }
    }
}

/// Parses a comma-separated string of CIDRs into an IpNetworkTable.
fn build_ip_network_table(s: &str) -> IpNetworkTable<()> {
    let mut table = IpNetworkTable::new();
    if s.is_empty() {
        return table;
    }
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Ok(net) = part.parse::<IpNetwork>() {
            table.insert(net, ());
        } else {
            warn!(
                event_name = "filter.cidr_parse_failed",
                cidr = %part,
                "Invalid CIDR in filter config, skipping."
            );
        }
    }
    table
}

/// Parses a comma-separated string of numbers and ranges into a HashSet.
/// e.g., "80, 443, 8000-8002" -> {80, 443, 8000, 8001, 8002}
fn build_numeric_set<T>(s: &str) -> HashSet<T>
where
    T: PrimInt + FromStr,
    <T as FromStr>::Err: std::fmt::Debug,
{
    let mut set = HashSet::new();
    if s.is_empty() {
        return set;
    }

    for part in s.split(',') {
        let part = part.trim();
        if let Some((start_str, end_str)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_str.parse::<T>(), end_str.parse::<T>()) {
                if start > end {
                    warn!(
                        event_name = "filter.range_invalid",
                        range = %part,
                        "Invalid numeric range (start > end) in filter config, skipping."
                    );
                    continue;
                }
                for i in range_inclusive(start, end) {
                    set.insert(i);
                }
            } else {
                warn!(
                    event_name = "filter.range_parse_failed",
                    range = %part,
                    "Invalid numeric range in filter config, skipping."
                );
            }
        } else if let Ok(val) = part.parse::<T>() {
            set.insert(val);
        } else {
            warn!(
                event_name = "filter.value_parse_failed",
                value = %part,
                "Invalid numeric value in filter config, skipping."
            );
        }
    }
    set
}

/// A helper trait for collections that can check if a value is allowed.
trait IsAllowed<T: ?Sized> {
    fn is_allowed(&self, value: &T) -> bool;
}

impl<T, C> IsAllowed<T> for CompiledRuleSet<C>
where
    T: ?Sized,
    C: RuleCollection<T>,
{
    fn is_allowed(&self, value: &T) -> bool {
        if self.not_match_rules.matches(value) {
            return false;
        }
        if !self.match_rules.is_empty() && !self.match_rules.matches(value) {
            return false;
        }
        true
    }
}

/// A trait that abstracts over the different collection types
trait RuleCollection<T: ?Sized> {
    fn matches(&self, value: &T) -> bool;
    fn is_empty(&self) -> bool;
}

impl RuleCollection<IpAddr> for IpNetworkTable<()> {
    fn matches(&self, value: &IpAddr) -> bool {
        self.longest_match(*value).is_some()
    }
    fn is_empty(&self) -> bool {
        IpNetworkTable::is_empty(self)
    }
}

impl<T: std::hash::Hash + Eq> RuleCollection<T> for HashSet<T> {
    fn matches(&self, value: &T) -> bool {
        self.contains(value)
    }
    fn is_empty(&self) -> bool {
        HashSet::is_empty(self)
    }
}

impl RuleCollection<str> for GlobSet {
    fn matches(&self, value: &str) -> bool {
        self.is_match(&value.to_lowercase())
    }
    fn is_empty(&self) -> bool {
        GlobSet::is_empty(self)
    }
}

/// A pre-compiled filter that holds all filtering rules from the configuration.
#[derive(Default)]
pub struct PacketFilter {
    source: CompiledRules,
    destination: CompiledRules,
    network: CompiledRules,
    flow: CompiledRules,
}

impl PacketFilter {
    pub fn new(conf: &Conf) -> Self {
        let get_filter = |name: &str| -> Option<&FilteringOptions> {
            conf.filter.as_ref().and_then(|map| map.get(name))
        };

        Self {
            source: CompiledRules::new(get_filter("source")),
            destination: CompiledRules::new(get_filter("destination")),
            network: CompiledRules::new(get_filter("network")),
            flow: CompiledRules::new(get_filter("flow")),
        }
    }

    pub fn should_process(&self, packet: &PacketMeta) -> Result<bool, IpError> {
        if let Some(rules) = &self.network.transport
            && !rules.is_allowed(&packet.proto.to_string())
        {
            return Ok(false);
        }
        if let Some(rules) = &self.network.type_
            && !rules.is_allowed(packet.ether_type.as_str())
        {
            return Ok(false);
        }
        if let Some(rules) = &self.network.interface_index
            && !rules.is_allowed(&packet.ifindex)
        {
            return Ok(false);
        }
        if let Some(rules) = &self.network.interface_mac {
            let mac = MacAddr::new(
                packet.src_mac_addr[0],
                packet.src_mac_addr[1],
                packet.src_mac_addr[2],
                packet.src_mac_addr[3],
                packet.src_mac_addr[4],
                packet.src_mac_addr[5],
            );
            if !rules.is_allowed(&mac.to_string()) {
                return Ok(false);
            }
        }

        if let Some(rules) = &self.flow.connection_state {
            if packet.proto == IpProto::Tcp {
                if let Some(state) = ConnectionState::from_packet(packet) {
                    if !rules.is_allowed(state.as_str()) {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            } else if !rules.match_rules.is_empty() {
                return Ok(false);
            }
        }
        if let Some(rules) = &self.flow.ip_dscp_name {
            let name = IpDscp::try_from_u8(packet.ip_dscp_id)
                .unwrap_or_default()
                .as_str();
            if !rules.is_allowed(name) {
                return Ok(false);
            }
        }
        if let Some(rules) = &self.flow.ip_ecn_name {
            let name = IpEcn::try_from_u8(packet.ip_ecn_id)
                .unwrap_or_default()
                .as_str();
            if !rules.is_allowed(name) {
                return Ok(false);
            }
        }
        if let Some(rules) = &self.flow.ip_ttl
            && !rules.is_allowed(&packet.ip_ttl)
        {
            return Ok(false);
        }
        if let Some(rules) = &self.flow.ip_flow_label
            && !rules.is_allowed(&packet.ip_flow_label)
        {
            return Ok(false);
        }

        if packet.proto == IpProto::Icmp || packet.proto == IpProto::Ipv6Icmp {
            if let Some(rules) = &self.flow.icmp_type_name {
                let name = if packet.proto == IpProto::Icmp {
                    icmp::get_icmpv4_type_name(packet.icmp_type_id)
                } else {
                    icmp::get_icmpv6_type_name(packet.icmp_type_id)
                };
                if !rules.is_allowed(name.unwrap_or_default()) {
                    return Ok(false);
                }
            }
            if let Some(rules) = &self.flow.icmp_code_name {
                let name = if packet.proto == IpProto::Icmp {
                    icmp::get_icmpv4_code_name(packet.icmp_type_id, packet.icmp_code_id)
                } else {
                    icmp::get_icmpv6_code_name(packet.icmp_type_id, packet.icmp_code_id)
                };
                if !rules.is_allowed(name.unwrap_or_default()) {
                    return Ok(false);
                }
            }
        }

        if packet.proto == IpProto::Tcp {
            if let Some(rules) = &self.flow.tcp_flags {
                let tags = TcpFlags::from_packet(packet).active_flags();
                if tags
                    .iter()
                    .any(|tag| rules.not_match_rules.is_match(tag.as_str()))
                {
                    return Ok(false);
                }
                if !rules.match_rules.is_empty()
                    && !tags
                        .iter()
                        .any(|tag| rules.match_rules.is_match(tag.as_str()))
                {
                    return Ok(false);
                }
            }
        }

        let (src_ip, dst_ip) = resolve_addrs(
            packet.ip_addr_type,
            packet.src_ipv4_addr,
            packet.dst_ipv4_addr,
            packet.src_ipv6_addr,
            packet.dst_ipv6_addr,
        )?;
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();

        if let Some(rules) = &self.source.address
            && !rules.is_allowed(&src_ip)
        {
            return Ok(false);
        }
        if let Some(rules) = &self.source.port
            && !rules.is_allowed(&src_port)
        {
            return Ok(false);
        }
        if let Some(rules) = &self.destination.address
            && !rules.is_allowed(&dst_ip)
        {
            return Ok(false);
        }
        if let Some(rules) = &self.destination.port
            && !rules.is_allowed(&dst_port)
        {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
    };

    use mermin_common::{IpAddrType, PacketMeta};
    use network_types::{eth::EtherType, ip::IpProto};

    use super::*;
    use crate::runtime::conf::{Conf, FilteringOptions, FilteringPair};

    fn mock_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        proto: IpProto,
    ) -> PacketMeta {
        let mut packet = PacketMeta::default();
        packet.ip_addr_type = IpAddrType::Ipv4;
        packet.src_ipv4_addr = src_ip.octets();
        packet.dst_ipv4_addr = dst_ip.octets();
        packet.src_port = src_port.to_be_bytes();
        packet.dst_port = dst_port.to_be_bytes();
        packet.proto = proto;
        packet.ether_type = EtherType::Ipv4;
        packet
    }

    #[test]
    fn test_parse_ports() {
        let hash_set = build_numeric_set::<u16>("80, 443, 8000-8002");
        assert!(hash_set.contains(&80));
        assert!(hash_set.contains(&443));
        assert!(hash_set.contains(&8000));
        assert!(hash_set.contains(&8001));
        assert!(hash_set.contains(&8002));
        assert!(!hash_set.contains(&8003));
        assert_eq!(hash_set.len(), 5);
    }

    #[test]
    fn test_parse_cidrs() {
        let table = build_ip_network_table("192.168.1.0/24, 10.0.0.1/32");
        assert!(
            table
                .longest_match("192.168.1.50".parse::<IpAddr>().unwrap())
                .is_some()
        );
        assert!(
            table
                .longest_match("10.0.0.1".parse::<IpAddr>().unwrap())
                .is_some()
        );
        assert!(
            table
                .longest_match("10.0.0.2".parse::<IpAddr>().unwrap())
                .is_none()
        );
    }

    #[test]
    fn test_parse_string_globset() {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new("tcp").unwrap());
        builder.add(Glob::new("ud*").unwrap());
        let glob_set = builder.build().unwrap();

        assert_eq!(glob_set.len(), 2);
        assert!(glob_set.is_match("tcp"));
        assert!(glob_set.is_match("udp"));
        assert!(!glob_set.is_match("icmp"));
    }

    fn build_filter(filters: HashMap<String, FilteringOptions>) -> PacketFilter {
        let mut conf = Conf::default();
        conf.filter = Some(filters);
        PacketFilter::new(&conf)
    }

    #[test]
    fn test_filter_allows_by_default() {
        let filter = PacketFilter::default();
        let packet = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        assert!(filter.should_process(&packet).unwrap());
    }

    #[test]
    fn test_filter_destination_port() {
        let filter = build_filter(HashMap::from([(
            "destination".to_string(),
            FilteringOptions {
                port: Some(FilteringPair {
                    match_glob: "80,443".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let packet_ok = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        let packet_bad = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            8080,
            IpProto::Tcp,
        );

        assert!(filter.should_process(&packet_ok).unwrap());
        assert!(!filter.should_process(&packet_bad).unwrap());
    }

    #[test]
    fn test_filter_source_address_exclude() {
        let filter = build_filter(HashMap::from([(
            "source".to_string(),
            FilteringOptions {
                address: Some(FilteringPair {
                    not_match_glob: "10.0.0.0/8".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let packet_ok = mock_packet(
            "192.168.1.1".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Udp,
        );
        let packet_bad = mock_packet(
            "10.1.2.3".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Udp,
        );

        assert!(filter.should_process(&packet_ok).unwrap());
        assert!(!filter.should_process(&packet_bad).unwrap());
    }

    #[test]
    fn test_filter_ip_ttl() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                ip_ttl: Some(FilteringPair {
                    match_glob: "64".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let mut packet_ok = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_ok.ip_ttl = 64;

        let mut packet_bad = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_bad.ip_ttl = 128;

        assert!(filter.should_process(&packet_ok).unwrap());
        assert!(!filter.should_process(&packet_bad).unwrap());
    }

    #[test]
    fn test_filter_dscp_name() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                ip_dscp_name: Some(FilteringPair {
                    match_glob: "ef".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let mut packet_ok = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_ok.ip_dscp_id = 46; // EF (Expedited Forwarding)

        let mut packet_bad = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_bad.ip_dscp_id = 0; // DF (Default)

        assert!(filter.should_process(&packet_ok).unwrap());
        assert!(!filter.should_process(&packet_bad).unwrap());
    }

    #[test]
    fn test_filter_interface_mac() {
        let filter = build_filter(HashMap::from([(
            "network".to_string(),
            FilteringOptions {
                interface_mac: Some(FilteringPair {
                    match_glob: "aa:bb:cc:*:ee:ff".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let mut packet_ok = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_ok.src_mac_addr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let mut packet_bad = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_bad.src_mac_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        assert!(filter.should_process(&packet_ok).unwrap());
        assert!(!filter.should_process(&packet_bad).unwrap());
    }

    #[test]
    fn test_filter_icmp_type_name() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                icmp_type_name: Some(FilteringPair {
                    match_glob: "echo_request".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let mut packet_ok = mock_packet(
            "1.1.1.1".parse().unwrap(),
            0,
            "2.2.2.2".parse().unwrap(),
            0,
            IpProto::Icmp,
        );
        packet_ok.icmp_type_id = 8; // Echo Request

        let mut packet_bad = mock_packet(
            "1.1.1.1".parse().unwrap(),
            0,
            "2.2.2.2".parse().unwrap(),
            0,
            IpProto::Icmp,
        );
        packet_bad.icmp_type_id = 3; // Destination Unreachable

        let packet_irrelevant = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );

        assert!(filter.should_process(&packet_ok).unwrap());
        assert!(!filter.should_process(&packet_bad).unwrap());
        assert!(filter.should_process(&packet_irrelevant).unwrap());
    }

    #[test]
    fn test_filter_tcp_flags() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                tcp_flags: Some(FilteringPair {
                    match_glob: "syn,ack".to_string(),
                    not_match_glob: "rst".to_string(),
                }),
                ..Default::default()
            },
        )]));

        let mut packet_syn_ack = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_syn_ack.tcp_flags = 0x12; // SYN+ACK

        let mut packet_ack = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_ack.tcp_flags = 0x10; // ACK only

        let mut packet_rst = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_rst.tcp_flags = 0x04; // RST

        let mut packet_syn_rst = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_syn_rst.tcp_flags = 0x06; // SYN+RST

        assert!(filter.should_process(&packet_syn_ack).unwrap()); // Has ACK, no RST
        assert!(filter.should_process(&packet_ack).unwrap()); // Has ACK, no RST
        assert!(!filter.should_process(&packet_rst).unwrap()); // Has RST
        assert!(!filter.should_process(&packet_syn_rst).unwrap()); // Has RST
    }
}
