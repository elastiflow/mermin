use std::{
    ffi::{CStr, CString},
    net::IpAddr,
    ptr,
    time::Duration,
};

use k8s_openapi::api::core::v1::{Namespace, Node};
use kube::{Api, Client};
use nix::{ifaddrs, net::if_::InterfaceFlags, unistd};
use opentelemetry::{Array, KeyValue, Value};
use opentelemetry_sdk::Resource;
use tracing::{debug, warn};

const K8S_DETECT_TIMEOUT: Duration = Duration::from_secs(15);
const DNS_FQDN_TIMEOUT: Duration = Duration::from_secs(2);

/// Detects the resource attributes for the observed host.
///
/// Always returns a valid `Resource`. All K8s-dependent attributes are best-effort and
/// silently omitted if detection fails or the K8s API is unavailable.
pub async fn detect_resource() -> Resource {
    let short_hostname = unistd::gethostname()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    let host_id = std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let k8s_node_name = std::env::var("POD_NODE_NAME").ok();
    let k8s_namespace = std::env::var("POD_NAMESPACE").ok();

    // Resolve the OS hostname to an FQDN via getaddrinfo(AI_CANONNAME) concurrently
    // with K8s API calls. Used when K8s does not provide an InternalDNS address.
    let dns_fqdn_task = {
        let h = short_hostname.clone();
        tokio::time::timeout(
            DNS_FQDN_TIMEOUT,
            tokio::task::spawn_blocking(move || resolve_fqdn(&h)),
        )
    };

    let (node_result, cluster_uid, dns_fqdn) = match Client::try_default().await {
        Ok(client) => {
            let (node_res, cluster_res, fqdn_res) = tokio::join!(
                tokio::time::timeout(
                    K8S_DETECT_TIMEOUT,
                    get_k8s_node(client.clone(), k8s_node_name.clone())
                ),
                tokio::time::timeout(K8S_DETECT_TIMEOUT, get_k8s_cluster_uid(client)),
                dns_fqdn_task,
            );

            let node_result = match node_res {
                Ok(v) => v,
                Err(_) => {
                    warn!(
                        event.name = "resource.k8s_node_timeout",
                        "k8s node lookup timed out after {}s",
                        K8S_DETECT_TIMEOUT.as_secs()
                    );
                    None
                }
            };

            let cluster_uid = match cluster_res {
                Ok(v) => v,
                Err(_) => {
                    warn!(
                        event.name = "resource.k8s_cluster_timeout",
                        "k8s cluster uid lookup timed out after {}s",
                        K8S_DETECT_TIMEOUT.as_secs()
                    );
                    None
                }
            };

            let dns_fqdn = fqdn_res.ok().and_then(|r| r.ok()).flatten();

            (node_result, cluster_uid, dns_fqdn)
        }
        Err(e) => {
            debug!(
                event.name = "resource.k8s_unavailable",
                error.message = %e,
                "k8s client unavailable, skipping k8s resource detection"
            );
            let dns_fqdn = dns_fqdn_task.await.ok().and_then(|r| r.ok()).flatten();
            (None, None, dns_fqdn)
        }
    };

    // host.name resolution priority:
    // 1. K8s InternalDNS (FQDN from the K8s node API, identified by containing a '.')
    // 2. getaddrinfo AI_CANONNAME (DNS-resolved FQDN for the OS hostname)
    // 3. K8s Hostname (may be a short name without a domain component)
    // 4. gethostname() (OS short hostname, last resort)
    let k8s_host = node_result.as_ref().and_then(|(_, h, _)| h.clone());
    let host_name = k8s_host
        .as_deref()
        .filter(|h| h.contains('.'))
        .map(str::to_owned)
        .or(dns_fqdn)
        .or(k8s_host)
        .unwrap_or(short_hostname);

    // host.ip: prefer InternalIP addresses from the K8s node API; fall back to
    // non-loopback, non-link-local addresses from the host's network interfaces.
    let host_ips: Vec<String> = if let Some((_, _, ref k8s_ips)) = node_result {
        k8s_ips.clone()
    } else {
        host_interface_ips()
    };

    let mut builder = Resource::builder_empty()
        .with_attribute(KeyValue::new("telemetry.distro.name", "mermin"))
        .with_attribute(KeyValue::new(
            "telemetry.distro.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_attribute(KeyValue::new("host.name", host_name.clone()));

    if !host_id.is_empty() {
        builder = builder.with_attribute(KeyValue::new("host.id", host_id.clone()));
    }
    if !host_ips.is_empty() {
        let ip_array = Value::Array(Array::String(
            host_ips.iter().cloned().map(Into::into).collect(),
        ));
        builder = builder.with_attribute(KeyValue::new("host.ip", ip_array));
    }
    if let Some(name) = &k8s_node_name {
        builder = builder.with_attribute(KeyValue::new("k8s.node.name", name.clone()));
    }
    if let Some(ns) = &k8s_namespace {
        builder = builder.with_attribute(KeyValue::new("k8s.namespace.name", ns.clone()));
    }
    if let Some((uid, _, _)) = &node_result {
        builder = builder.with_attribute(KeyValue::new("k8s.node.uid", uid.clone()));
    }
    if let Some(uid) = &cluster_uid {
        builder = builder.with_attribute(KeyValue::new("k8s.cluster.uid", uid.clone()));
    }

    debug!(
        event.name = "resource.detection_complete",
        "host.name" = %host_name,
        "host.id" = %host_id,
        "host.ip" = ?host_ips,
        "k8s.node.name" = ?k8s_node_name,
        "k8s.namespace.name" = ?k8s_namespace,
        "k8s.node.uid" = ?node_result.as_ref().map(|(uid, _, _)| uid),
        "k8s.cluster.uid" = ?cluster_uid,
        "resource detection complete"
    );

    builder.build()
}

/// Returns non-loopback, non-link-local IP addresses from the host's network interfaces.
/// Used as a fallback when K8s node API is unavailable.
fn host_interface_ips() -> Vec<String> {
    let Ok(addrs) = ifaddrs::getifaddrs() else {
        return Vec::new();
    };

    addrs
        .filter_map(|iface| {
            if iface
                .flags
                .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
                || !iface.flags.contains(InterfaceFlags::IFF_UP)
            {
                return None;
            }
            let sock_addr = iface.address?;
            let addr: IpAddr = sock_addr
                .as_sockaddr_in()
                .map(|s| IpAddr::V4(s.ip()))
                .or_else(|| sock_addr.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())))?;
            if addr.is_loopback() || is_link_local(addr) {
                return None;
            }
            Some(addr.to_string())
        })
        .collect()
}

fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Resolves `hostname` to a fully qualified domain name using `getaddrinfo(3)` with
/// `AI_CANONNAME`. Returns `None` if resolution fails or the result is not a genuine FQDN
/// (i.e. does not contain a dot or is identical to the input short name).
///
/// This is a blocking call and must be invoked via `tokio::task::spawn_blocking`.
fn resolve_fqdn(hostname: &str) -> Option<String> {
    let hostname_c = CString::new(hostname).ok()?;
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = libc::AI_CANONNAME;

    let mut res: *mut libc::addrinfo = ptr::null_mut();
    let ret = unsafe { libc::getaddrinfo(hostname_c.as_ptr(), ptr::null(), &hints, &mut res) };

    if ret != 0 || res.is_null() {
        return None;
    }

    let fqdn = unsafe {
        if (*res).ai_canonname.is_null() {
            None
        } else {
            CStr::from_ptr((*res).ai_canonname)
                .to_str()
                .ok()
                .map(str::to_owned)
        }
    };

    unsafe { libc::freeaddrinfo(res) };

    // Discard the result if it's not a genuine FQDN or just echoes the input back.
    fqdn.filter(|s| s.contains('.') && s != hostname)
}

/// Fetches node UID, hostname, and IP addresses from the K8s API for the given node name.
///
/// Returns `Some((uid, host, ips))` where:
/// - `host` is the `InternalDNS` address (preferred, an FQDN) or the `Hostname` address
/// - `ips` is the list of `InternalIP` addresses from `node.status.addresses`
///
/// Returns `None` if the node name is not provided or the API call fails.
async fn get_k8s_node(
    client: Client,
    node_name: Option<String>,
) -> Option<(String, Option<String>, Vec<String>)> {
    let node_name = node_name?;
    let api: Api<Node> = Api::all(client);

    match api.get(&node_name).await {
        Ok(node) => {
            let uid = node.metadata.uid.clone()?;
            let addresses = node.status.as_ref().and_then(|s| s.addresses.as_ref());

            let host = addresses.and_then(|addrs| {
                addrs
                    .iter()
                    .find(|a| a.type_ == "InternalDNS")
                    .or_else(|| addrs.iter().find(|a| a.type_ == "Hostname"))
                    .map(|a| a.address.clone())
            });

            let ips = addresses
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter(|a| a.type_ == "InternalIP")
                        .map(|a| a.address.clone())
                        .collect()
                })
                .unwrap_or_default();

            Some((uid, host, ips))
        }
        Err(e) => {
            warn!(
                event.name = "resource.k8s_node_failed",
                error.message = %e,
                node.name = %node_name,
                "failed to retrieve k8s node details"
            );
            None
        }
    }
}

/// Fetches the cluster UID from the `kube-system` namespace.
async fn get_k8s_cluster_uid(client: Client) -> Option<String> {
    let api: Api<Namespace> = Api::all(client);

    match api.get("kube-system").await {
        Ok(ns) => {
            let uid = ns.metadata.uid.clone()?;
            Some(uid)
        }
        Err(e) => {
            warn!(
                event.name = "resource.k8s_cluster_uid_failed",
                error.message = %e,
                "failed to retrieve k8s cluster uid"
            );
            None
        }
    }
}
