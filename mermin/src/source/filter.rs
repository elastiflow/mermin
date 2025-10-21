//! Packet filtering based on user-configured rules.
//!
//! This module provides high-performance packet filtering capabilities by pre-compiling
//! filter rules at initialization time. Rules are organized into four dimensions:
//! - `source`: Source IP address and port filtering
//! - `destination`: Destination IP address and port filtering
//! - `network`: Network-level filtering (transport protocol, interface, MAC address)
//! - `flow`: Flow-level filtering (TCP state, DSCP, ECN, TTL, ICMP types, TCP flags)
//!
//! # Performance
//!
//! Filter rules are pre-compiled into efficient data structures:
//! - IP addresses/CIDRs use trie-based `IpNetworkTable` for O(log n) lookups
//! - Port numbers and numeric values use `HashSet` for O(1) lookups
//! - String patterns use `GlobSet` for efficient pattern matching
//!
//! # Example
//!
//! ```ignore
//! use mermin::source::filter::PacketFilter;
//! use mermin::runtime::conf::Conf;
//!
//! let conf = Conf::load_from_file("config.hcl")?;
//! let filter = PacketFilter::new(&conf, iface_map);
//!
//! if filter.should_process(&packet)? {
//!     // Process the packet
//! }
//! ```

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    str::FromStr,
};

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
use tracing::{error, warn};

use crate::{
    ip::{Error as IpError, resolve_addrs},
    runtime::conf::{Conf, FilteringOptions, FilteringPair},
    span::tcp::{ConnectionState, TcpFlags},
};

/// Helper macro to check if a packet passes a filter rule.
///
/// Returns early with `Ok(false)` if the filter exists and the value is not allowed.
/// This reduces boilerplate in the `should_process` method.
macro_rules! check_filter {
    ($rules:expr, $value:expr) => {
        if let Some(rules) = $rules {
            if !rules.is_allowed($value) {
                return Ok(false);
            }
        }
    };
}

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
                    // Empty builder can never fail
                    return GlobSetBuilder::new()
                        .build()
                        .expect("empty globset build should never fail");
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
                            "invalid glob pattern in filter config, skipping."
                        ),
                    }
                }
                // GlobSetBuilder::build only fails if the builder is misconfigured,
                // which cannot happen with the simple add() calls above
                builder.build().unwrap_or_else(|e| {
                    error!(
                        event_name = "filter.globset_build_failed",
                        error.message = %e,
                        "failed to build globset, using empty set as fallback"
                    );
                    GlobSetBuilder::new()
                        .build()
                        .expect("empty globset build should never fail")
                })
            };

            CompiledRuleSet {
                match_rules: build(&pair.match_glob),
                not_match_rules: build(&pair.not_match_glob),
            }
        };

        fn build_numeric_pair<T>(pair: &FilteringPair) -> CompiledRuleSet<HashSet<T>>
        where
            T: PrimInt + FromStr + std::hash::Hash + Eq,
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
                "nvalid cidr in filter config, skipping."
            );
        }
    }
    table
}

/// Parses a comma-separated string of numbers and ranges into a HashSet.
/// e.g., "80, 443, 8000-8002" -> {80, 443, 8000, 8001, 8002}
fn build_numeric_set<T>(s: &str) -> HashSet<T>
where
    T: PrimInt + FromStr + std::hash::Hash + Eq,
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
                        "invalid numeric range (start > end) in filter config, skipping."
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
                    "invalid numeric range in filter config, skipping."
                );
            }
        } else if let Ok(val) = part.parse::<T>() {
            set.insert(val);
        } else {
            warn!(
                event_name = "filter.value_parse_failed",
                value = %part,
                "invalid numeric value in filter config, skipping."
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
    /// Performs case-insensitive glob pattern matching.
    ///
    /// # Case Sensitivity
    ///
    /// This implementation normalizes the input value to lowercase before matching.
    /// This is appropriate for protocol names (e.g., "TCP", "UDP"), connection states,
    /// and other string-based filters where case-insensitive matching is desired.
    ///
    /// Examples that match:
    /// - Pattern "tcp" matches: "TCP", "tcp", "Tcp"
    /// - Pattern "syn" matches: "SYN", "syn", "Syn"
    fn matches(&self, value: &str) -> bool {
        self.is_match(value.to_lowercase())
    }

    fn is_empty(&self) -> bool {
        GlobSet::is_empty(self)
    }
}

/// A pre-compiled filter that holds all filtering rules from the configuration.
///
/// This struct pre-compiles all filter rules at initialization time for efficient
/// runtime packet filtering. Filters are organized into four dimensions:
/// - `source`: Source IP address and port
/// - `destination`: Destination IP address and port
/// - `network`: Network-level attributes (protocol, interface, MAC)
/// - `flow`: Flow-level attributes (TCP state, DSCP, ECN, TTL, etc.)
///
/// # Performance
///
/// Pre-compilation ensures that packet filtering has minimal overhead:
/// - IP lookups: O(log n) via trie-based `IpNetworkTable`
/// - Port/numeric lookups: O(1) via `HashSet`
/// - Pattern matching: Optimized via compiled `GlobSet`
#[derive(Default)]
pub struct PacketFilter {
    source: CompiledRules,
    destination: CompiledRules,
    network: CompiledRules,
    flow: CompiledRules,
    iface_map: HashMap<u32, String>,
}

impl PacketFilter {
    /// Creates a new `PacketFilter` from configuration.
    pub fn new(conf: &Conf, iface_map: HashMap<u32, String>) -> Self {
        let get_filter = |name: &str| -> Option<&FilteringOptions> {
            conf.filter.as_ref().and_then(|map| map.get(name))
        };

        Self {
            source: CompiledRules::new(get_filter("source")),
            destination: CompiledRules::new(get_filter("destination")),
            network: CompiledRules::new(get_filter("network")),
            flow: CompiledRules::new(get_filter("flow")),
            iface_map,
        }
    }

    /// Determines if a packet should be processed based on configured filter rules.
    ///
    /// This is the core filtering method called for every packet in the hot path.
    /// Filters are evaluated in a specific order to optimize for early rejection
    /// of unwanted packets.
    ///
    /// # Arguments
    ///
    /// - `packet` - The packet metadata to evaluate against filter rules
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - Packet matches all applicable filters and should be processed
    /// - `Ok(false)` - Packet does not match filter criteria and should be dropped
    /// - `Err(IpError)` - Failed to parse IP addresses from packet metadata
    ///
    /// # Filter Evaluation Order
    ///
    /// Filters are evaluated in the following order for optimal performance
    /// (evaluation short-circuits on the first mismatch):
    ///
    /// 1. **Network filters** (cheap to evaluate, high rejection rate):
    ///    - Transport protocol (TCP, UDP, ICMP, etc.)
    ///    - Network type (IPv4, IPv6)
    ///    - Interface index, name, MAC address
    ///
    /// 2. **Flow filters** (protocol-specific, moderate cost):
    ///    - TCP connection state (for TCP packets only)
    ///    - IP DSCP and ECN values
    ///    - IP TTL and flow label
    ///    - ICMP type/code (for ICMP packets only)
    ///    - TCP flags (for TCP packets only)
    ///
    /// 3. **Address/Port filters** (requires IP parsing, evaluated last):
    ///    - Source IP address and port
    ///    - Destination IP address and port
    ///
    /// # Performance
    ///
    /// This method is highly optimized for the hot path:
    /// - Pre-compiled filter rules enable O(1) or O(log n) lookups
    /// - Early short-circuit evaluation minimizes unnecessary checks
    /// - IP address parsing only occurs after cheaper filters pass
    ///
    /// # Filter Semantics
    ///
    /// Each filter dimension supports both positive (`match`) and negative (`not_match`) rules:
    /// - If `not_match` rules are present and match: packet is **rejected**
    /// - If `match` rules are present and don't match: packet is **rejected**
    /// - If neither set of rules is present for a filter: packet **passes** that filter
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Filter configuration allows only TCP traffic on port 443
    /// if filter.should_process(&packet)? {
    ///     process_packet(packet);
    /// } else {
    ///     // Packet filtered out - no processing needed
    /// }
    /// ```
    pub fn should_process(&self, packet: &PacketMeta) -> Result<bool, IpError> {
        // Network-level filters (cheap checks first)
        check_filter!(&self.network.transport, &packet.proto.to_string());
        check_filter!(&self.network.type_, packet.ether_type.as_str());
        check_filter!(&self.network.interface_index, &packet.ifindex);
        if let Some(rules) = &self.network.interface_name {
            if let Some(iface_name) = self.iface_map.get(&packet.ifindex) {
                if !rules.is_allowed(iface_name) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
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
        check_filter!(&self.flow.ip_ttl, &packet.ip_ttl);
        check_filter!(&self.flow.ip_flow_label, &packet.ip_flow_label);

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

        if packet.proto == IpProto::Tcp
            && let Some(rules) = &self.flow.tcp_flags
        {
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

        // Address/port filters (requires IP parsing, evaluated last)
        let (src_ip, dst_ip) = resolve_addrs(
            packet.ip_addr_type,
            packet.src_ipv4_addr,
            packet.dst_ipv4_addr,
            packet.src_ipv6_addr,
            packet.dst_ipv6_addr,
        )?;
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();

        check_filter!(&self.source.address, &src_ip);
        check_filter!(&self.source.port, &src_port);
        check_filter!(&self.destination.address, &dst_ip);
        check_filter!(&self.destination.port, &dst_port);

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

    // TCP flag constants for test clarity
    const TCP_FLAG_SYN: u8 = 0x02;
    const TCP_FLAG_RST: u8 = 0x04;
    const TCP_FLAG_ACK: u8 = 0x10;

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
        let iface_map: HashMap<u32, String> = HashMap::from([
            (1, "eth0".to_string()),
            (2, "lo".to_string()),
            (3, "docker0".to_string()),
        ]);
        PacketFilter::new(&conf, iface_map)
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
        packet_syn_ack.tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

        let mut packet_ack = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_ack.tcp_flags = TCP_FLAG_ACK;

        let mut packet_rst = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_rst.tcp_flags = TCP_FLAG_RST;

        let mut packet_syn_rst = mock_packet(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        packet_syn_rst.tcp_flags = TCP_FLAG_SYN | TCP_FLAG_RST;

        assert!(filter.should_process(&packet_syn_ack).unwrap()); // Has ACK, no RST
        assert!(filter.should_process(&packet_ack).unwrap()); // Has ACK, no RST
        assert!(!filter.should_process(&packet_rst).unwrap()); // Has RST
        assert!(!filter.should_process(&packet_syn_rst).unwrap()); // Has RST
    }

    #[test]
    fn test_invalid_cidr_handling() {
        // Test that invalid CIDRs are gracefully skipped with warnings
        let filter = build_filter(HashMap::from([(
            "source".to_string(),
            FilteringOptions {
                address: Some(FilteringPair {
                    match_glob: "192.168.1.0/24, invalid-cidr, 10.0.0.0/8".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        // Valid CIDR should still work
        let packet_in_range = mock_packet(
            "192.168.1.50".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Tcp,
        );
        assert!(filter.should_process(&packet_in_range).unwrap());

        // invalid CIDR shouldn't cause panic or stop processing
        let packet_out_range = mock_packet(
            "172.16.0.1".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Tcp,
        );
        assert!(!filter.should_process(&packet_out_range).unwrap());
    }

    #[test]
    fn test_invalid_port_range_handling() {
        // Test that invalid port ranges (start > end) are gracefully skipped
        let filter = build_filter(HashMap::from([(
            "destination".to_string(),
            FilteringOptions {
                port: Some(FilteringPair {
                    match_glob: "80, 9000-8000, 443".to_string(), // invalid range
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        // Valid ports should still work
        let packet_80 = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        assert!(filter.should_process(&packet_80).unwrap());

        // Port in invalid range should not match
        let packet_8500 = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            8500,
            IpProto::Tcp,
        );
        assert!(!filter.should_process(&packet_8500).unwrap());
    }

    #[test]
    fn test_empty_filter_configuration() {
        // Test that empty/missing filter configuration allows all packets
        let filter = build_filter(HashMap::new());

        let packet = mock_packet(
            "1.2.3.4".parse().unwrap(),
            1234,
            "5.6.7.8".parse().unwrap(),
            80,
            IpProto::Tcp,
        );

        assert!(filter.should_process(&packet).unwrap());
    }

    #[test]
    fn test_malformed_numeric_values() {
        // Test handling of non-numeric values in numeric fields
        let filter = build_filter(HashMap::from([(
            "destination".to_string(),
            FilteringOptions {
                port: Some(FilteringPair {
                    match_glob: "80, abc, 443, xyz-999".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        // Valid numeric ports should still work
        let packet = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            443,
            IpProto::Tcp,
        );
        assert!(filter.should_process(&packet).unwrap());
    }

    #[test]
    fn test_invalid_glob_patterns() {
        // Test that invalid glob patterns are gracefully skipped
        let filter = build_filter(HashMap::from([(
            "network".to_string(),
            FilteringOptions {
                transport: Some(FilteringPair {
                    match_glob: "tcp, [invalid-glob, udp".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        // Valid patterns should still work
        let mut packet = mock_packet(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );

        assert!(filter.should_process(&packet).unwrap());

        packet.proto = IpProto::Udp;
        assert!(filter.should_process(&packet).unwrap());
    }
}
