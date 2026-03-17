//! Filtering infrastructure with pre-compiled rules for efficient lookups.
//!
//! Provides IP tables, port sets, and glob matching for flow filtering.
//! Rules are organized by source, destination, network, and flow dimensions.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::IpAddr,
    str::FromStr,
    sync::Arc,
};

use arc_swap::ArcSwap;
use globset::{Glob, GlobSet, GlobSetBuilder};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use mermin_common::{
    icmp::{
        get_icmpv4_code_name, get_icmpv4_type_name, get_icmpv6_code_name, get_icmpv6_type_name,
    },
    ip::{IpDscp, IpEcn, IpProto},
};
use num_iter::range_inclusive;
use num_traits::PrimInt;
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
            transport: opts.transport.as_ref().map(build_glob_rule_set),
            type_: opts.type_.as_ref().map(build_glob_rule_set),
            interface_name: opts.interface_name.as_ref().map(build_glob_rule_set),
            interface_index: opts.interface_index.as_ref().map(build_numeric_pair::<u32>),
            interface_mac: opts.interface_mac.as_ref().map(build_glob_rule_set),
            connection_state: opts.connection_state.as_ref().map(build_glob_rule_set),
            ip_dscp_name: opts.ip_dscp_name.as_ref().map(build_glob_rule_set),
            ip_ecn_name: opts.ip_ecn_name.as_ref().map(build_glob_rule_set),
            ip_ttl: opts.ip_ttl.as_ref().map(build_numeric_pair::<u8>),
            ip_flow_label: opts.ip_flow_label.as_ref().map(build_numeric_pair::<u32>),
            icmp_type_name: opts.icmp_type_name.as_ref().map(build_glob_rule_set),
            icmp_code_name: opts.icmp_code_name.as_ref().map(build_glob_rule_set),
            tcp_flags_tags: opts.tcp_flags_tags.as_ref().map(build_glob_rule_set),
        }
    }
}

fn build_glob_rule_set(pair: &FilteringPair) -> CompiledRuleSet<GlobSet> {
    CompiledRuleSet {
        match_rules: build_glob_set(&pair.match_list),
        not_match_rules: build_glob_set(&pair.not_match_list),
    }
}

/// Compiles a list of glob pattern strings into a [`GlobSet`], normalizing each
/// pattern to lowercase. Invalid patterns are skipped with a warning.
fn build_glob_set(list: &[String]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for part in list {
        let normalized_part = part.trim().to_lowercase();
        match Glob::new(&normalized_part) {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(e) => warn!(
                event_name = "filter.config_invalid",
                value = %part,
                error.message = %e,
                "invalid glob pattern in filter config, skipping"
            ),
        }
    }
    // GlobSetBuilder::build only fails if the builder is misconfigured,
    // which cannot happen with the simple add() calls above.
    builder.build().unwrap_or_else(|e| {
        error!(
            event_name = "filter.config_invalid",
            error.message = %e,
            "failed to build globset, using empty set as fallback"
        );
        GlobSetBuilder::new()
            .build()
            .expect("empty globset build should never fail")
    })
}

/// Builds an [`IpNetworkTable`] from a list of CIDR or IP strings.
/// Bare IP addresses are treated as host routes (`/32` for IPv4, `/128` for IPv6).
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
                    event_name = "filter.config_invalid",
                    value = %item,
                    "invalid cidr or ip pattern in filter config, skipping"
                );
            }
        }
    }
    table
}

/// Builds a [`HashSet`] from a list of numeric strings, supporting inclusive ranges
/// with `-` (e.g. `"8000-8002"` expands to `{8000, 8001, 8002}`).
fn build_numeric_set<T>(list: &[String]) -> HashSet<T>
where
    T: PrimInt + FromStr + std::hash::Hash + Eq,
    <T as FromStr>::Err: std::fmt::Debug,
{
    let mut set = HashSet::new();
    for item in list {
        let item = item.trim();
        // Only treat as a range if the item starts with a digit and contains '-',
        // to avoid misinterpreting non-numeric strings that happen to contain hyphens
        // (e.g. "abc-123") as intended ranges.
        let is_potential_range =
            item.bytes().next().is_some_and(|b| b.is_ascii_digit()) && item.contains('-');
        if is_potential_range {
            if let Some((start_str, end_str)) = item.split_once('-') {
                if let (Ok(start), Ok(end)) = (start_str.parse::<T>(), end_str.parse::<T>()) {
                    if start > end {
                        warn!(
                            event_name = "filter.config_invalid",
                            value = %item,
                            "invalid numeric range (start > end) in filter config, skipping"
                        );
                        continue;
                    }
                    for i in range_inclusive(start, end) {
                        set.insert(i);
                    }
                } else {
                    warn!(
                        event_name = "filter.config_invalid",
                        value = %item,
                        "invalid numeric range in filter config, skipping"
                    );
                }
            }
        } else if let Ok(val) = item.parse::<T>() {
            set.insert(val);
        } else {
            warn!(
                event_name = "filter.config_invalid",
                value = %item,
                "invalid numeric value in filter config (wildcards not supported), skipping"
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
        !self.not_match_rules.matches(value)
            && (self.match_rules.is_empty() || self.match_rules.matches(value))
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
    /// Matches `value` case-insensitively; patterns are pre-normalized to lowercase
    /// in [`build_glob_set`]. Avoids allocating when `value` is already lowercase
    /// (the common case for static protocol/flag strings from `as_str()` methods).
    fn matches(&self, value: &str) -> bool {
        if value.bytes().any(|b| b.is_ascii_uppercase()) {
            self.is_match(value.to_lowercase())
        } else {
            self.is_match(value)
        }
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
pub struct PacketFilter {
    source: CompiledRules,
    destination: CompiledRules,
    network: CompiledRules,
    flow: CompiledRules,
    iface_map: Arc<ArcSwap<HashMap<u32, String>>>,
}

impl Default for PacketFilter {
    fn default() -> Self {
        Self {
            source: CompiledRules::default(),
            destination: CompiledRules::default(),
            network: CompiledRules::default(),
            flow: CompiledRules::default(),
            iface_map: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
        }
    }
}

impl PacketFilter {
    /// Creates a new `PacketFilter` from configuration.
    pub fn new(conf: &Conf, iface_map: Arc<ArcSwap<HashMap<u32, String>>>) -> Self {
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
    /// Evaluates flow-level filtering using [`mermin_common::FlowKey`] and
    /// [`mermin_common::FlowStats`] from the eBPF layer. Returns `Ok(true)` when the
    /// flow passes all applicable filters and should be tracked, `Ok(false)` when it is
    /// filtered out, or an error if IP addresses cannot be resolved from the flow key.
    ///
    /// # Errors
    ///
    /// Returns [`IpError`] if the raw IP bytes in `flow_key` cannot be resolved into
    /// valid [`std::net::IpAddr`] values.
    #[must_use = "filtering decision must not be discarded"]
    pub fn should_track_flow(
        &self,
        flow_key: &mermin_common::FlowKey,
        stats: &mermin_common::FlowStats,
    ) -> Result<bool, IpError> {
        check_filter!(&self.network.transport, flow_key.protocol.as_str());

        let ip_version_str = match flow_key.ip_version {
            mermin_common::IpVersion::V4 => "ipv4",
            mermin_common::IpVersion::V6 => "ipv6",
            _ => return Ok(false),
        };
        check_filter!(&self.network.type_, ip_version_str);
        check_filter!(&self.network.interface_index, &stats.ifindex);

        if let Some(rules) = &self.network.interface_name {
            let guard = self.iface_map.load();
            if let Some(iface_name) = guard.get(&stats.ifindex) {
                if !rules.is_allowed(iface_name.as_str()) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        if let Some(rules) = &self.network.interface_mac {
            // Format the MAC directly as lowercase hex (e.g. "aa:bb:cc:dd:ee:ff").
            // This avoids the pnet MacAddr::to_string() heap allocation AND the
            // subsequent to_lowercase() allocation inside GlobSet::matches(), since
            // the output is already lowercase and GlobSet::matches skips lowercasing
            // when no uppercase bytes are present.
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                stats.src_mac[0],
                stats.src_mac[1],
                stats.src_mac[2],
                stats.src_mac[3],
                stats.src_mac[4],
                stats.src_mac[5],
            );
            if !rules.is_allowed(mac_str.as_str()) {
                return Ok(false);
            }
        }

        // Flow-level filters — resolve numeric DSCP/ECN values to their standard names
        // (e.g. 46 → "ef", 0 → "df") so filter patterns match what operators expect.
        // Falls back to the raw decimal string for values not in the standard registry.
        // String conversion is deferred until the filter is actually configured to avoid
        // heap allocations on every flow when these filters are absent.
        if let Some(rules) = &self.flow.ip_dscp_name {
            let dscp_str: Cow<'static, str> = IpDscp::try_from_u8(stats.ip_dscp)
                .map(|d| Cow::Borrowed(d.as_str()))
                .unwrap_or_else(|| Cow::Owned(stats.ip_dscp.to_string()));
            if !rules.is_allowed(dscp_str.as_ref()) {
                return Ok(false);
            }
        }
        if let Some(rules) = &self.flow.ip_ecn_name {
            let ecn_str: Cow<'static, str> = IpEcn::try_from_u8(stats.ip_ecn)
                .map(|e| Cow::Borrowed(e.as_str()))
                .unwrap_or_else(|| Cow::Owned(stats.ip_ecn.to_string()));
            if !rules.is_allowed(ecn_str.as_ref()) {
                return Ok(false);
            }
        }
        check_filter!(&self.flow.ip_ttl, &stats.ip_ttl);

        if flow_key.ip_version == mermin_common::IpVersion::V6 {
            check_filter!(&self.flow.ip_flow_label, &stats.ip_flow_label);
        }

        if matches!(flow_key.protocol, IpProto::Icmp | IpProto::Ipv6Icmp) {
            // Only resolve ICMP name strings if the corresponding filter is configured,
            // deferring both the lookup and any fallback to_string() allocation.
            if self.flow.icmp_type_name.is_some() || self.flow.icmp_code_name.is_some() {
                type GetTypeName = fn(u8) -> Option<&'static str>;
                type GetCodeName = fn(u8, u8) -> Option<&'static str>;
                let (get_type, get_code): (GetTypeName, GetCodeName) =
                    if flow_key.protocol == IpProto::Icmp {
                        (get_icmpv4_type_name, get_icmpv4_code_name)
                    } else {
                        (get_icmpv6_type_name, get_icmpv6_code_name)
                    };
                if let Some(rules) = &self.flow.icmp_type_name {
                    let icmp_type_str: Cow<'static, str> = get_type(stats.icmp_type)
                        .map(Cow::Borrowed)
                        .unwrap_or_else(|| Cow::Owned(stats.icmp_type.to_string()));
                    if !rules.is_allowed(icmp_type_str.as_ref()) {
                        return Ok(false);
                    }
                }
                if let Some(rules) = &self.flow.icmp_code_name {
                    let icmp_code_str: Cow<'static, str> =
                        get_code(stats.icmp_type, stats.icmp_code)
                            .map(Cow::Borrowed)
                            .unwrap_or_else(|| Cow::Owned(stats.icmp_code.to_string()));
                    if !rules.is_allowed(icmp_code_str.as_ref()) {
                        return Ok(false);
                    }
                }
            }
        }

        if flow_key.protocol == IpProto::Tcp {
            if let Some(rules) = &self.flow.tcp_flags_tags {
                // Single-pass: check not-match and match rules together, avoiding the
                // original two-pass iteration and the heap Vec allocation from flags_from_bits.
                let mut has_match = RuleCollection::<str>::is_empty(&rules.match_rules);
                for flag in TcpFlags::flags_from_bits(stats.tcp_flags) {
                    let s = flag.as_str();
                    if RuleCollection::<str>::matches(&rules.not_match_rules, s) {
                        return Ok(false);
                    }
                    if !has_match && RuleCollection::<str>::matches(&rules.match_rules, s) {
                        has_match = true;
                    }
                }
                if !has_match {
                    return Ok(false);
                }
            }

            check_filter!(&self.flow.connection_state, stats.tcp_state.as_str());
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

    use mermin_common::{
        ConnectionState, Direction, FlowKey, FlowStats, IpVersion,
        eth::EtherType,
        ip::IpProto,
        tcp::{TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN},
    };

    use super::*;
    use crate::runtime::conf::Conf;

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

    fn mock_flow_stats(ifindex: u32) -> FlowStats {
        FlowStats {
            first_seen_ns: 0,
            last_seen_ns: 0,
            packets: 0,
            bytes: 0,
            reverse_packets: 0,
            reverse_bytes: 0,
            tcp_syn_ns: 0,
            tcp_syn_ack_ns: 0,
            tcp_last_payload_fwd_ns: 0,
            tcp_last_payload_rev_ns: 0,
            tcp_txn_sum_ns: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            ifindex,
            ip_flow_label: 0,
            reverse_ip_flow_label: 0,
            tcp_txn_count: 0,
            tcp_jitter_avg_ns: 0,
            ether_type: EtherType::Ipv4,
            src_port: 0,
            dst_port: 0,
            src_mac: [0; 6],
            direction: Direction::Egress,
            ip_version: IpVersion::V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
            tcp_flags: 0,
            tcp_state: ConnectionState::Closed,
            forward_tcp_flags: 0,
            reverse_tcp_flags: 0,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            pid: 0,
            comm: [0u8; 16],
        }
    }

    fn build_filter(filters: HashMap<String, FilteringOptions>) -> PacketFilter {
        let mut conf = Conf::default();
        conf.filter = Some(filters);
        let iface_map = Arc::new(ArcSwap::new(Arc::new(HashMap::from([
            (1u32, "eth0".to_string()),
            (2u32, "lo".to_string()),
            (3u32, "docker0".to_string()),
        ]))));
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
                    match_list: vec!["ef".to_string()], // EF (Expedited Forwarding) = DSCP 46
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
                    match_list: vec!["echo_request".to_string()], // ICMPv4 type 8
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
        flow_stats_ok.icmp_type = 8; // Echo Request

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
        flow_stats_bad.icmp_type = 3; // Destination Unreachable

        assert!(
            !filter
                .should_track_flow(&flow_key_bad, &flow_stats_bad)
                .unwrap()
        );

        // ICMP type filters only apply to ICMP flows; non-ICMP flows should always pass.
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
        flow_stats_syn_ack.tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

        assert!(
            filter
                .should_track_flow(&flow_key, &flow_stats_syn_ack)
                .unwrap()
        );

        let mut flow_stats_ack = mock_flow_stats(1);
        flow_stats_ack.tcp_flags = TCP_FLAG_ACK;

        assert!(
            filter
                .should_track_flow(&flow_key, &flow_stats_ack)
                .unwrap()
        );

        let mut flow_stats_rst = mock_flow_stats(1);
        flow_stats_rst.tcp_flags = TCP_FLAG_RST;

        assert!(
            !filter
                .should_track_flow(&flow_key, &flow_stats_rst)
                .unwrap()
        );

        let mut flow_stats_syn_rst = mock_flow_stats(1);
        flow_stats_syn_rst.tcp_flags = TCP_FLAG_SYN | TCP_FLAG_RST;

        assert!(
            !filter
                .should_track_flow(&flow_key, &flow_stats_syn_rst)
                .unwrap()
        );
    }

    #[test]
    fn test_invalid_cidr_handling() {
        // Wildcards like "10.*" are not supported for IPs and should be silently skipped.
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
        let stats_eth0 = mock_flow_stats(1); // ifindex 1 → "eth0"

        assert!(
            filter.should_track_flow(&flow_tcp, &stats_eth0).unwrap(),
            "t[bc]p should match 'tcp' and eth[0-9] should match 'eth0'"
        );

        // Independently verify interface_name matching: docker0 (ifindex 3) does NOT
        // match eth[0-9], so the flow is rejected even though transport passes.
        let stats_docker0 = mock_flow_stats(3); // ifindex 3 → "docker0"
        assert!(
            !filter.should_track_flow(&flow_tcp, &stats_docker0).unwrap(),
            "docker0 should NOT match eth[0-9]"
        );

        let stats_lo = mock_flow_stats(2); // ifindex 2 → "lo"
        assert!(
            filter.should_track_flow(&flow_tcp, &stats_lo).unwrap(),
            "lo should match the literal 'lo' pattern in the interface_name list"
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
                    match_list: vec!["TCP".to_string()],
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
