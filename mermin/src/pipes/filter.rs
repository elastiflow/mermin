use std::{collections::HashSet, net::IpAddr};

use glob::Pattern as GlobPattern;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use log::warn;
use mermin_common::PacketMeta;
use network_types::ip::IpProto;

use crate::{
    ip::{Error as IpError, resolve_addrs},
    runtime::conf::{Conf, FilteringOptions, FilteringPair},
    span::tcp::ConnectionState,
};

/// Contains a pre-compiled set of rules for a single filter dimension (e.g., "source", "network").
#[derive(Default)]
struct CompiledRules {
    address: Option<CompiledRuleSet<IpNetworkTable<()>>>,
    port: Option<CompiledRuleSet<HashSet<u16>>>,
    transport: Option<CompiledRuleSet<Vec<GlobPattern>>>,
    type_: Option<CompiledRuleSet<Vec<GlobPattern>>>,
    connection: Option<CompiledRuleSet<Vec<GlobPattern>>>,
}

/// A generic, pre-compiled set of rules for any filterable type.
/// It holds a collection of `match` rules and `not_match` rules.
#[derive(Debug, Clone)]
struct CompiledRuleSet<T> {
    match_rules: T,
    not_match_rules: T,
}

impl<T: FromGlobStr> From<&FilteringPair> for CompiledRuleSet<T> {
    fn from(pair: &FilteringPair) -> Self {
        Self {
            match_rules: T::from_glob_str(&pair.match_glob),
            not_match_rules: T::from_glob_str(&pair.not_match_glob),
        }
    }
}

impl CompiledRules {
    fn new(opts: Option<&FilteringOptions>) -> Self {
        match opts {
            Some(opts) => Self {
                address: opts.address.as_ref().map(|p| p.into()),
                port: opts.port.as_ref().map(|p| p.into()),
                transport: opts.transport.as_ref().map(|p| p.into()),
                type_: opts.type_.as_ref().map(|p| p.into()),
                connection: opts.connection.as_ref().map(|c| (&c.state).into()),
            },
            None => Self::default(),
        }
    }
}

/// A helper trait for types that can be parsed from a comma-separated string.
trait FromGlobStr: Sized {
    fn from_glob_str(s: &str) -> Self;
}

// For IP Addresses
impl FromGlobStr for IpNetworkTable<()> {
    fn from_glob_str(s: &str) -> Self {
        let mut table = IpNetworkTable::new();
        if s.is_empty() {
            return table;
        }
        for part in s.split(',') {
            if let Ok(net) = part.trim().parse::<IpNetwork>() {
                match net {
                    IpNetwork::V4(n) => table.insert(n, ()),
                    IpNetwork::V6(n) => table.insert(n, ()),
                };
            } else {
                warn!("invalid cidr '{part}' in filter config, skipping.");
            }
        }
        table
    }
}

// For Ports
impl FromGlobStr for HashSet<u16> {
    fn from_glob_str(s: &str) -> Self {
        let mut set = HashSet::new();
        if s.is_empty() {
            return set;
        }
        for part in s.split(',') {
            let part = part.trim();
            if let Some((start, end)) = part.split_once('-') {
                if let (Ok(start_port), Ok(end_port)) = (start.parse::<u16>(), end.parse::<u16>()) {
                    set.extend(start_port..=end_port);
                } else {
                    warn!("invalid port range '{part}' in filter config, skipping.");
                }
            } else if let Ok(port) = part.parse() {
                set.insert(port);
            } else {
                warn!("invalid port '{part}' in filter config, skipping.");
            }
        }
        set
    }
}

// For String Globs
impl FromGlobStr for Vec<GlobPattern> {
    fn from_glob_str(s: &str) -> Self {
        if s.is_empty() {
            return Vec::new();
        }
        s.split(',')
            .filter_map(|p| match GlobPattern::new(p.trim()) {
                Ok(pat) => Some(pat),
                Err(e) => {
                    warn!("invalid glob pattern '{p}' in filter config, skipping: {e}");
                    None
                }
            })
            .collect()
    }
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

/// A trait that abstracts over the different collection types (`HashSet`, `IpNetworkTable`, etc.)
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

impl RuleCollection<u16> for HashSet<u16> {
    fn matches(&self, value: &u16) -> bool {
        self.contains(value)
    }
    fn is_empty(&self) -> bool {
        HashSet::is_empty(self)
    }
}

impl RuleCollection<str> for Vec<GlobPattern> {
    fn matches(&self, value: &str) -> bool {
        self.iter().any(|p| p.matches(&value.to_lowercase()))
    }
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
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
    /// Creates a new `PacketFilter` by compiling all rules from the `Conf` struct.
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

    /// Determines if a packet should be processed based on all filtering rules.
    /// Returns `true` if the packet should be kept, `false` if it should be skipped.
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

        if let Some(rules) = &self.flow.connection {
            if packet.proto == IpProto::Tcp {
                if let Some(initial_state) = ConnectionState::from_packet(packet) {
                    if !rules.is_allowed(initial_state.as_str()) {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            } else if !rules.match_rules.is_empty() {
                return Ok(false);
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

        // If all checks passed, the packet is allowed.
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
    use crate::runtime::conf::{ConnectionOptions, FilteringOptions, FilteringPair};

    // --- Helper function to create a test PacketMeta ---
    fn mock_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        proto: IpProto,
        eth_type: EtherType,
        tcp_flags: u8,
    ) -> PacketMeta {
        let mut packet = PacketMeta::default();
        packet.ip_addr_type = IpAddrType::Ipv4;
        packet.src_ipv4_addr = src_ip.octets();
        packet.dst_ipv4_addr = dst_ip.octets();
        packet.src_port = src_port.to_be_bytes();
        packet.dst_port = dst_port.to_be_bytes();
        packet.proto = proto;
        packet.ether_type = eth_type;
        packet.tcp_flags = tcp_flags;
        packet
    }

    #[test]
    fn test_parse_ports() {
        let hash_set: HashSet<u16> = HashSet::from_glob_str("80, 443, 8000-8002");
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
        let table: IpNetworkTable<()> =
            IpNetworkTable::from_glob_str("192.168.1.0/24, 10.0.0.1/32");
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
        assert!(!table.is_empty());
    }

    #[test]
    fn test_parse_string_globs() {
        let globs: Vec<GlobPattern> = Vec::from_glob_str("tcp, ud*");
        assert_eq!(globs.len(), 2);
        assert!(globs[0].matches("tcp"));
        assert!(globs[1].matches("udp"));
        assert!(!globs[0].matches("udp"));
    }

    #[test]
    fn test_is_allowed_logic() {
        // Create a rule set for ports: include 80, 443; exclude 8080
        let pair = FilteringPair {
            match_glob: "80, 443".to_string(),
            not_match_glob: "8080".to_string(),
        };
        let rules: CompiledRuleSet<HashSet<u16>> = (&pair).into();

        // Test inclusion
        assert!(rules.is_allowed(&80));
        assert!(rules.is_allowed(&443));

        // Test exclusion
        assert!(!rules.is_allowed(&8080));

        // Test not in include list
        assert!(!rules.is_allowed(&9000));
    }

    #[test]
    fn test_is_allowed_logic_empty_include() {
        // Create a rule set: include is empty; exclude 8080
        let pair = FilteringPair {
            match_glob: "".to_string(), // Empty include means "allow all"
            not_match_glob: "8080".to_string(),
        };
        let rules: CompiledRuleSet<HashSet<u16>> = (&pair).into();

        assert!(rules.is_allowed(&80));
        assert!(rules.is_allowed(&443));
        assert!(!rules.is_allowed(&8080));
    }

    #[test]
    fn test_packet_filter_allows_by_default() {
        // An empty config should result in a filter that allows everything.
        let conf = Conf::default();
        let filter = PacketFilter::new(&conf);
        let packet = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
            EtherType::Ipv4,
            0x02,
        );

        assert!(filter.should_process(&packet).unwrap());
    }

    #[test]
    fn test_packet_filter_destination_port_include() {
        // Filter that ONLY allows destination port 80.
        let mut conf = Conf::default();
        let mut filters = HashMap::new();
        filters.insert(
            "destination".to_string(),
            FilteringOptions {
                port: Some(FilteringPair {
                    match_glob: "80".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        conf.filter = Some(filters);

        let filter = PacketFilter::new(&conf);

        let packet_ok = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
            EtherType::Ipv4,
            0x02,
        );
        assert!(filter.should_process(&packet_ok).unwrap());

        let packet_bad = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            443,
            IpProto::Tcp,
            EtherType::Ipv4,
            0x02,
        );
        assert!(!filter.should_process(&packet_bad).unwrap());
    }

    #[test]
    fn test_packet_filter_source_ip_exclude() {
        // Filter that excludes the entire 10.0.0.0/8 range.
        let mut conf = Conf::default();
        let mut filters = HashMap::new();
        filters.insert(
            "source".to_string(),
            FilteringOptions {
                address: Some(FilteringPair {
                    not_match_glob: "10.0.0.0/8".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        conf.filter = Some(filters);

        let filter = PacketFilter::new(&conf);

        let packet_ok = mock_packet(
            "192.168.1.1".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Udp,
            EtherType::Ipv4,
            0,
        );
        assert!(filter.should_process(&packet_ok).unwrap());

        // This packet should be DROPPED
        let packet_bad = mock_packet(
            "10.1.2.3".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Udp,
            EtherType::Ipv4,
            0,
        );
        assert!(!filter.should_process(&packet_bad).unwrap());
    }

    #[test]
    fn test_packet_filter_transport_and_connection_state() {
        let mut conf = Conf::default();
        let mut filters = HashMap::new();
        filters.insert(
            "network".to_string(),
            FilteringOptions {
                transport: Some(FilteringPair {
                    match_glob: "tcp".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        filters.insert(
            "flow".to_string(),
            FilteringOptions {
                connection: Some(ConnectionOptions {
                    state: FilteringPair {
                        match_glob: "syn_sent".to_string(),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
        );
        conf.filter = Some(filters);

        let filter = PacketFilter::new(&conf);

        // This packet should be ALLOWED (TCP SYN)
        let packet_ok = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
            EtherType::Ipv4,
            0x02, // SYN flag
        );
        assert!(filter.should_process(&packet_ok).unwrap());

        // This packet should be DROPPED (UDP)
        let packet_bad_proto = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            53,
            IpProto::Udp,
            EtherType::Ipv4,
            0,
        );
        assert!(!filter.should_process(&packet_bad_proto).unwrap());

        // This packet should be DROPPED (TCP but not SYN)
        let packet_bad_state = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
            EtherType::Ipv4,
            0x10, // ACK flag
        );
        assert!(!filter.should_process(&packet_bad_state).unwrap());
    }
}
