//! Filtering infrastructure with pre-compiled rules for efficient lookups.
//!
//! Provides IP tables, port sets, and glob matching for flow filtering.
//! Rules are organized by source, destination, network, and flow dimensions.

use std::{collections::HashSet, net::IpAddr, str::FromStr, sync::Arc};

use dashmap::DashMap;
use globset::{Glob, GlobSet, GlobSetBuilder};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use network_types::ip::IpProto;
use num_iter::range_inclusive;
use num_traits::PrimInt;
use pnet::datalink::MacAddr;
use tracing::{error, warn};

use crate::{
    filter::opts::{FilteringOptions, FilteringPair},
    ip::{Error as IpError, resolve_addrs},
    runtime::conf::Conf,
    span::tcp::TcpFlags,
};

/// Helper macro to check if a packet/flow passes a filter rule.
///
/// Returns early with `Ok(false)` if the filter exists and the value is not allowed.
/// This reduces boilerplate in filtering methods.
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
    tcp_flags_tags: Option<CompiledRuleSet<GlobSet>>,
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
            let build = |list: &[String]| -> GlobSet {
                let mut builder = GlobSetBuilder::new();
                for part in list {
                    let normalized_part = part.trim().to_lowercase();
                    match Glob::new(&normalized_part) {
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
                match_rules: build(&pair.match_list),
                not_match_rules: build(&pair.not_match_list),
            }
        };

        fn build_numeric_pair<T>(pair: &FilteringPair) -> CompiledRuleSet<HashSet<T>>
        where
            T: PrimInt + FromStr + std::hash::Hash + Eq,
            <T as FromStr>::Err: std::fmt::Debug,
        {
            CompiledRuleSet {
                match_rules: build_numeric_set::<T>(&pair.match_list),
                not_match_rules: build_numeric_set::<T>(&pair.not_match_list),
            }
        }

        Self {
            address: opts.address.as_ref().map(|pair| CompiledRuleSet {
                match_rules: build_ip_network_table(&pair.match_list),
                not_match_rules: build_ip_network_table(&pair.not_match_list),
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
            tcp_flags_tags: opts.tcp_flags_tags.as_ref().map(build_glob_set),
        }
    }
}

/// Parses a comma-separated string of CIDRs or IPs into an IpNetworkTable.
/// Supports:
/// - CIDR: "192.168.1.0/24"
/// - IP: "192.168.1.1" (implies /32)
fn build_ip_network_table(list: &[String]) -> IpNetworkTable<()> {
    let mut table = IpNetworkTable::new();
    for item in list {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let network = item
            .parse::<IpNetwork>()
            .ok()
            .or_else(|| item.parse::<IpAddr>().ok().map(IpNetwork::from));

        match network {
            Some(net) => {
                table.insert(net, ());
            }
            None => {
                warn!(
                    event_name = "filter.cidr_parse_failed",
                    input = %item,
                    "invalid cidr or ip pattern in filter config, skipping."
                );
            }
        }
    }
    table
}

/// Parses a comma-separated string of numbers into a HashSet.
/// e.g., "80, 443, 8000" -> {80, 443, 8000}
fn build_numeric_set<T>(list: &[String]) -> HashSet<T>
where
    T: PrimInt + FromStr + std::hash::Hash + Eq,
    <T as FromStr>::Err: std::fmt::Debug,
{
    let mut set = HashSet::new();
    for item in list {
        let item = item.trim();
        if let Some((start_str, end_str)) = item.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_str.parse::<T>(), end_str.parse::<T>()) {
                if start > end {
                    warn!(
                        event_name = "filter.range_invalid",
                        range = %item,
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
                    range = %item,
                    "invalid numeric range in filter config, skipping."
                );
            }
        } else if let Ok(val) = item.parse::<T>() {
            set.insert(val);
        } else {
            warn!(
                event_name = "filter.value_parse_failed",
                value = %item,
                "invalid numeric value in filter config (wildcards not supported), skipping."
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
    iface_map: Arc<DashMap<u32, String>>,
}

impl PacketFilter {
    /// Creates a new `PacketFilter` from configuration.
    pub fn new(conf: &Conf, iface_map: Arc<DashMap<u32, String>>) -> Self {
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

    /// Determines if a flow should be tracked based on configured filter rules.
    ///
    /// This is an adapter method that evaluates flow-level filtering using `FlowKey` and `FlowStats`
    /// from the eBPF layer, rather than requiring full packet metadata.
    ///
    /// # Arguments
    ///
    /// - `flow_key` - The normalized flow key from eBPF
    /// - `stats` - The flow statistics from eBPF (contains MACs, DSCP, TTL, etc.)
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - Flow matches all applicable filters and should be tracked
    /// - `Ok(false)` - Flow does not match filter criteria and should be filtered out
    /// - `Err(IpError)` - Failed to parse IP addresses from flow key
    pub fn should_track_flow(
        &self,
        flow_key: &mermin_common::FlowKey,
        stats: &mermin_common::FlowStats,
    ) -> Result<bool, IpError> {
        // Network-level filters
        check_filter!(&self.network.transport, &flow_key.protocol.to_string());

        let ip_version_str = match flow_key.ip_version {
            mermin_common::IpVersion::V4 => "ipv4",
            mermin_common::IpVersion::V6 => "ipv6",
            _ => return Ok(false),
        };
        check_filter!(&self.network.type_, ip_version_str);
        check_filter!(&self.network.interface_index, &stats.ifindex);

        if let Some(rules) = &self.network.interface_name {
            if let Some(iface_name_ref) = self.iface_map.get(&stats.ifindex) {
                if !rules.is_allowed(iface_name_ref.value().as_str()) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        if let Some(rules) = &self.network.interface_mac {
            let mac = MacAddr::new(
                stats.src_mac[0],
                stats.src_mac[1],
                stats.src_mac[2],
                stats.src_mac[3],
                stats.src_mac[4],
                stats.src_mac[5],
            );
            if !rules.is_allowed(&mac.to_string()) {
                return Ok(false);
            }
        }

        // Flow-level filters
        // Use numeric DSCP/ECN values for filtering
        let dscp_str = stats.ip_dscp.to_string();
        let ecn_str = stats.ip_ecn.to_string();
        check_filter!(&self.flow.ip_dscp_name, dscp_str.as_str());
        check_filter!(&self.flow.ip_ecn_name, ecn_str.as_str());
        check_filter!(&self.flow.ip_ttl, &stats.ip_ttl);

        if flow_key.ip_version == mermin_common::IpVersion::V6 {
            check_filter!(&self.flow.ip_flow_label, &stats.ip_flow_label);
        }

        if matches!(flow_key.protocol, IpProto::Icmp | IpProto::Ipv6Icmp) {
            // Use numeric ICMP type/code for filtering since the types don't implement Display
            let icmp_type_str = stats.icmp.icmp_type.to_string();
            let icmp_code_str = stats.icmp.icmp_code.to_string();
            check_filter!(&self.flow.icmp_type_name, icmp_type_str.as_str());
            check_filter!(&self.flow.icmp_code_name, icmp_code_str.as_str());
        }

        if flow_key.protocol == IpProto::Tcp {
            if let Some(rules) = &self.flow.tcp_flags_tags {
                let flags_vec = TcpFlags::flags_from_bits(stats.tcp.tcp_flags);
                // Check each flag individually against the patterns
                // This allows patterns like "syn,ack" to match flows with any of those flags
                for flag in &flags_vec {
                    let flag_str = flag.as_str();
                    // If any flag matches the not_match rules, reject the flow
                    if RuleCollection::<str>::matches(&rules.not_match_rules, flag_str) {
                        return Ok(false);
                    }
                }
                // If match_rules is non-empty, at least one flag must match
                if !RuleCollection::<str>::is_empty(&rules.match_rules) {
                    let has_match = flags_vec.iter().any(|flag| {
                        RuleCollection::<str>::matches(&rules.match_rules, flag.as_str())
                    });
                    if !has_match {
                        return Ok(false);
                    }
                }
            }

            check_filter!(&self.flow.connection_state, stats.tcp.tcp_state.as_str());
        }

        // Source/Destination filters (requires IP parsing)
        let (src_addr, dst_addr) = resolve_addrs(
            flow_key.ip_version,
            [
                flow_key.src_ip[0],
                flow_key.src_ip[1],
                flow_key.src_ip[2],
                flow_key.src_ip[3],
            ],
            [
                flow_key.dst_ip[0],
                flow_key.dst_ip[1],
                flow_key.dst_ip[2],
                flow_key.dst_ip[3],
            ],
            flow_key.src_ip,
            flow_key.dst_ip,
        )?;

        check_filter!(&self.source.address, &src_addr);
        check_filter!(&self.source.port, &flow_key.src_port);
        check_filter!(&self.destination.address, &dst_addr);
        check_filter!(&self.destination.port, &flow_key.dst_port);

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use mermin_common::{Direction, FlowKey, FlowStats, IcmpStats, IpVersion, TcpStats};
    use network_types::{
        eth::EtherType,
        ip::IpProto,
        tcp::{TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN},
    };

    use super::*;
    use crate::runtime::conf::Conf;

    /// Helper to create a FlowKey for testing
    fn mock_flow_key(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        proto: IpProto,
    ) -> FlowKey {
        let mut src_ip_bytes = [0u8; 16];
        src_ip_bytes[0..4].copy_from_slice(&src_ip.octets());
        let mut dst_ip_bytes = [0u8; 16];
        dst_ip_bytes[0..4].copy_from_slice(&dst_ip.octets());

        FlowKey {
            src_ip: src_ip_bytes,
            dst_ip: dst_ip_bytes,
            src_port,
            dst_port,
            ip_version: IpVersion::V4,
            protocol: proto,
        }
    }

    /// Helper to create FlowStats for testing
    fn mock_flow_stats(ifindex: u32) -> FlowStats {
        FlowStats {
            first_seen_ns: 0,
            last_seen_ns: 0,
            packets: 0,
            bytes: 0,
            reverse_packets: 0,
            reverse_bytes: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_mac: [0; 6],
            ifindex,
            ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: 0,
            dst_port: 0,
            direction: Direction::Egress,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            reverse_ip_flow_label: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
            pid: 0,
            comm: [0u8; 16],
        }
    }

    /// Helper to create TcpStats for testing
    fn mock_tcp_stats() -> TcpStats {
        TcpStats {
            tcp_syn_ns: 0,
            tcp_syn_ack_ns: 0,
            tcp_last_payload_fwd_ns: 0,
            tcp_last_payload_rev_ns: 0,
            tcp_txn_sum_ns: 0,
            tcp_txn_count: 0,
            tcp_jitter_avg_ns: 0,
            tcp_flags: 0,
            tcp_state: ConnectionState::Closed,
            forward_tcp_flags: 0,
            reverse_tcp_flags: 0,
        }
    }

    /// Helper to create IcmpStats for testing
    fn mock_icmp_stats() -> IcmpStats {
        IcmpStats {
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
        }
    }

    fn build_filter(filters: HashMap<String, FilteringOptions>) -> PacketFilter {
        let mut conf = Conf::default();
        conf.filter = Some(filters);
        let iface_map = Arc::new(DashMap::from_iter([
            (1, "eth0".to_string()),
            (2, "lo".to_string()),
            (3, "docker0".to_string()),
        ]));
        PacketFilter::new(&conf, iface_map)
    }

    #[test]
    fn test_parse_ports() {
        let hash_set = build_numeric_set::<u16>(&[
            "80".to_string(),
            "443".to_string(),
            "8000-8002".to_string(),
        ]);
        assert!(hash_set.contains(&80));
        assert!(hash_set.contains(&443));
        assert!(hash_set.contains(&8000));
        assert!(hash_set.contains(&8001));
        assert!(hash_set.contains(&8002));
        assert!(!hash_set.contains(&8003));
        assert_eq!(hash_set.len(), 5);
    }

    #[test]
    fn test_parse_cidrs_and_ips() {
        let table = build_ip_network_table(&["192.168.1.0/24".to_string(), "10.0.0.1".to_string()]);
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

    #[test]
    fn test_filter_allows_by_default() {
        let filter = PacketFilter::default();
        let flow_key = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        let flow_stats = mock_flow_stats(1);
        assert!(filter.should_track_flow(&flow_key, &flow_stats).unwrap());
    }

    #[test]
    fn test_filter_destination_port() {
        let filter = build_filter(HashMap::from([(
            "destination".to_string(),
            FilteringOptions {
                port: Some(FilteringPair {
                    match_list: vec!["80".to_string(), "443".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_key_ok = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        let flow_key_bad = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            8080,
            IpProto::Tcp,
        );
        let flow_stats = mock_flow_stats(1);
        assert!(filter.should_track_flow(&flow_key_ok, &flow_stats).unwrap());
        assert!(
            !filter
                .should_track_flow(&flow_key_bad, &flow_stats)
                .unwrap()
        );
    }

    #[test]
    fn test_filter_source_address_exclude() {
        let filter = build_filter(HashMap::from([(
            "source".to_string(),
            FilteringOptions {
                address: Some(FilteringPair {
                    not_match_list: vec!["10.0.0.0/8".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_key_ok = mock_flow_key(
            "192.168.1.1".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Udp,
        );
        let flow_key_bad = mock_flow_key(
            "10.1.2.3".parse().unwrap(),
            1234,
            "8.8.8.8".parse().unwrap(),
            53,
            IpProto::Udp,
        );
        let flow_stats = mock_flow_stats(1);
        assert!(filter.should_track_flow(&flow_key_ok, &flow_stats).unwrap());
        assert!(
            !filter
                .should_track_flow(&flow_key_bad, &flow_stats)
                .unwrap()
        );
    }

    #[test]
    fn test_filter_ip_ttl() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                ip_ttl: Some(FilteringPair {
                    match_list: vec!["64".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_key = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );

        let mut flow_stats_ok = mock_flow_stats(1);
        flow_stats_ok.ip_ttl = 64;

        let mut flow_stats_bad = mock_flow_stats(1);
        flow_stats_bad.ip_ttl = 128;

        assert!(filter.should_track_flow(&flow_key, &flow_stats_ok).unwrap());
        assert!(
            !filter
                .should_track_flow(&flow_key, &flow_stats_bad)
                .unwrap()
        );
    }

    #[test]
    fn test_filter_dscp_value() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                ip_dscp_name: Some(FilteringPair {
                    match_list: vec!["46".to_string()], // EF (Expedited Forwarding)
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_key = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );

        let mut flow_stats_ok = mock_flow_stats(1);
        flow_stats_ok.ip_dscp = 46; // EF

        let mut flow_stats_bad = mock_flow_stats(1);
        flow_stats_bad.ip_dscp = 0; // DF (Default)

        assert!(filter.should_track_flow(&flow_key, &flow_stats_ok).unwrap());
        assert!(
            !filter
                .should_track_flow(&flow_key, &flow_stats_bad)
                .unwrap()
        );
    }

    #[test]
    fn test_filter_interface_mac() {
        let filter = build_filter(HashMap::from([(
            "network".to_string(),
            FilteringOptions {
                interface_mac: Some(FilteringPair {
                    match_list: vec!["aa:bb:cc:*:ee:ff".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_key = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );

        let mut flow_stats_ok = mock_flow_stats(1);
        flow_stats_ok.src_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let mut flow_stats_bad = mock_flow_stats(1);
        flow_stats_bad.src_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        assert!(filter.should_track_flow(&flow_key, &flow_stats_ok).unwrap());
        assert!(
            !filter
                .should_track_flow(&flow_key, &flow_stats_bad)
                .unwrap()
        );
    }

    #[test]
    fn test_filter_icmp_type() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                icmp_type_name: Some(FilteringPair {
                    match_list: vec!["8".to_string()], // Echo Request
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_key_ok = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            0,
            "2.2.2.2".parse().unwrap(),
            0,
            IpProto::Icmp,
        );
        let mut flow_stats_ok = mock_flow_stats(1);
        flow_stats_ok.protocol = IpProto::Icmp;
        flow_stats_ok.icmp.icmp_type = 8; // Echo Request

        assert!(
            filter
                .should_track_flow(&flow_key_ok, &flow_stats_ok)
                .unwrap()
        );

        let flow_key_bad = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            0,
            "2.2.2.2".parse().unwrap(),
            0,
            IpProto::Icmp,
        );
        let mut flow_stats_bad = mock_flow_stats(1);
        flow_stats_bad.protocol = IpProto::Icmp;
        flow_stats_bad.icmp.icmp_type = 3; // Destination Unreachable

        assert!(
            !filter
                .should_track_flow(&flow_key_bad, &flow_stats_bad)
                .unwrap()
        );

        let flow_key_irrelevant = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        let flow_stats_irrelevant = mock_flow_stats(1);

        assert!(
            filter
                .should_track_flow(&flow_key_irrelevant, &flow_stats_irrelevant)
                .unwrap()
        );
    }

    #[test]
    fn test_filter_tcp_flags_tags() {
        let filter = build_filter(HashMap::from([(
            "flow".to_string(),
            FilteringOptions {
                tcp_flags_tags: Some(FilteringPair {
                    match_list: vec!["syn".to_string(), "ack".to_string()],
                    not_match_list: vec!["rst".to_string()],
                }),
                ..Default::default()
            },
        )]));

        let flow_key = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );

        let mut flow_stats_syn_ack = mock_flow_stats(1);
        flow_stats_syn_ack.tcp.tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

        assert!(
            filter
                .should_track_flow(&flow_key, &flow_stats_syn_ack)
                .unwrap()
        ); // Has ACK, no RST

        let mut flow_stats_ack = mock_flow_stats(1);
        flow_stats_ack.tcp.tcp_flags = TCP_FLAG_ACK;

        assert!(
            filter
                .should_track_flow(&flow_key, &flow_stats_ack)
                .unwrap()
        ); // Has ACK, no RST

        let mut flow_stats_rst = mock_flow_stats(1);
        flow_stats_rst.tcp.tcp_flags = TCP_FLAG_RST;

        assert!(
            !filter
                .should_track_flow(&flow_key, &flow_stats_rst)
                .unwrap()
        ); // Has RST

        let mut flow_stats_syn_rst = mock_flow_stats(1);
        flow_stats_syn_rst.tcp.tcp_flags = TCP_FLAG_SYN | TCP_FLAG_RST;

        assert!(
            !filter
                .should_track_flow(&flow_key, &flow_stats_syn_rst)
                .unwrap()
        ); // Has RST
    }

    #[test]
    fn test_invalid_cidr_handling() {
        // Test that invalid CIDRs are gracefully skipped with warnings
        // Wildcards like "10.*" are no longer supported for IPs and should be ignored
        let filter = build_filter(HashMap::from([(
            "source".to_string(),
            FilteringOptions {
                address: Some(FilteringPair {
                    match_list: vec!["192.168.1.0/24".to_string(), "10.*".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_stats = mock_flow_stats(1);

        // Valid CIDR still matches
        let flow_key_ok = mock_flow_key(
            "192.168.1.50".parse().unwrap(),
            1,
            "8.8.8.8".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        assert!(filter.should_track_flow(&flow_key_ok, &flow_stats).unwrap());

        // Wildcard "10.*" failed to parse, so this IP (which would have matched a wildcard) now fails
        let flow_key_was_wildcard = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1,
            "8.8.8.8".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        assert!(
            !filter
                .should_track_flow(&flow_key_was_wildcard, &flow_stats)
                .unwrap()
        );
    }

    #[test]
    fn test_empty_filter_configuration() {
        // Test that empty/missing filter configuration allows all flows
        let filter = build_filter(HashMap::new());

        let flow_key = mock_flow_key(
            "1.2.3.4".parse().unwrap(),
            1234,
            "5.6.7.8".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        let flow_stats = mock_flow_stats(1);

        assert!(filter.should_track_flow(&flow_key, &flow_stats).unwrap());
    }

    #[test]
    fn test_malformed_numeric_values() {
        // Test handling of non-numeric values in numeric fields
        let filter = build_filter(HashMap::from([(
            "destination".to_string(),
            FilteringOptions {
                port: Some(FilteringPair {
                    match_list: vec![
                        "80".to_string(),
                        "abc".to_string(),
                        "443".to_string(),
                        "xyz-999".to_string(),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        // Valid numeric ports should still work
        let flow_key = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            443,
            IpProto::Tcp,
        );
        let flow_stats = mock_flow_stats(1);
        assert!(filter.should_track_flow(&flow_key, &flow_stats).unwrap());
    }

    #[test]
    fn test_invalid_glob_patterns() {
        // Test that invalid glob patterns are gracefully skipped
        let filter = build_filter(HashMap::from([(
            "network".to_string(),
            FilteringOptions {
                transport: Some(FilteringPair {
                    match_list: vec![
                        "tcp".to_string(),
                        "[invalid-glob".to_string(),
                        "udp".to_string(),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        // Valid patterns should still work
        let flow_key_tcp = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        let flow_stats = mock_flow_stats(1);
        assert!(
            filter
                .should_track_flow(&flow_key_tcp, &flow_stats)
                .unwrap()
        );

        let flow_key_udp = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Udp,
        );
        assert!(
            filter
                .should_track_flow(&flow_key_udp, &flow_stats)
                .unwrap()
        );
    }

    #[test]
    fn test_advanced_glob_matching() {
        let filter = build_filter(HashMap::from([(
            "network".to_string(),
            FilteringOptions {
                transport: Some(FilteringPair {
                    match_list: vec!["t[bc]p".to_string()], // Matches 'tcp' or 'tbp'
                    ..Default::default()
                }),
                interface_name: Some(FilteringPair {
                    match_list: vec!["eth[0-9]".to_string(), "lo".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_tcp = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Tcp,
        );
        let stats_eth0 = mock_flow_stats(1);

        assert!(
            filter.should_track_flow(&flow_tcp, &stats_eth0).unwrap(),
            "t[bc]p should match 'tcp'"
        );

        assert!(
            filter.should_track_flow(&flow_tcp, &stats_eth0).unwrap(),
            "eth0 should match eth[0-9]"
        );

        let stats_lo = mock_flow_stats(2);
        assert!(
            filter.should_track_flow(&flow_tcp, &stats_lo).unwrap(),
            "Multiple list items should act like brace expansion"
        );

        let flow_udp = mock_flow_key(
            "10.1.1.1".parse().unwrap(),
            1234,
            "10.2.2.2".parse().unwrap(),
            80,
            IpProto::Udp,
        );
        assert!(
            !filter.should_track_flow(&flow_udp, &stats_eth0).unwrap(),
            "udp should NOT match t[bc]p"
        );
    }

    #[test]
    fn test_glob_case_insensitivity() {
        let filter = build_filter(HashMap::from([(
            "network".to_string(),
            FilteringOptions {
                transport: Some(FilteringPair {
                    match_list: vec!["TCP".to_string()], // Uppercase in config
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]));

        let flow_key = mock_flow_key(
            "1.1.1.1".parse().unwrap(),
            1,
            "2.2.2.2".parse().unwrap(),
            2,
            IpProto::Tcp,
        );
        let stats = mock_flow_stats(1);

        assert!(
            filter.should_track_flow(&flow_key, &stats).unwrap(),
            "Filters should be case-insensitive (config TCP matches flow tcp)"
        );
    }
}
