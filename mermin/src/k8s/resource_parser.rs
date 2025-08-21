use std::{
    collections::HashMap,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use async_trait::async_trait;
use k8s_openapi::api::{
    apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
    batch::v1::Job,
    discovery::v1::EndpointSlice,
    networking::v1::{Ingress, NetworkPolicy},
};
use log::info;
use mermin_common::{IpAddrType, PacketMeta};

use crate::k8s::Attributor;

/// Represents structured data extracted from a Kubernetes resource
#[derive(Debug, Default)]
pub struct ResourceData {
    /// The kind of resource (e.g., "Pod", "Service")
    #[allow(dead_code)]
    pub kind: String,
    /// The namespace of the resource
    pub namespace: String,
    /// The name of the resource
    pub name: String,
    /// Key-value pairs of resource attributes
    pub attributes: HashMap<String, String>,
    /// Nested resources or sections
    pub sections: HashMap<String, Vec<ResourceData>>,
}

pub mod helpers {
    use std::{collections::BTreeMap, sync::Arc};

    use k8s_openapi::{
        api::{core::v1::Service, networking::v1::Ingress},
        apimachinery::pkg::apis::meta::v1::ObjectMeta,
    };

    use super::*;

    /// Check if an ingress is related to any of the given services
    pub fn is_ingress_related_to_services(ingress: &Ingress, services: &[Arc<Service>]) -> bool {
        if let Some(spec) = &ingress.spec
            && let Some(rules) = &spec.rules
        {
            for rule in rules {
                if let Some(http) = &rule.http {
                    for path in &http.paths {
                        let backend = &path.backend;
                        if let Some(service) = &backend.service {
                            for pod_service in services {
                                if pod_service.metadata.name.as_deref() == Some(&service.name) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Add labels from metadata to a ResourceData object
    pub fn add_labels(resource_data: &mut ResourceData, metadata: &ObjectMeta) {
        if let Some(labels) = &metadata.labels
            && !labels.is_empty()
        {
            let mut label_data = Vec::new();
            for (key, value) in labels {
                let mut label = ResourceData::new("Label", "", key);
                label.add_attribute("value", value.to_string());
                label_data.push(label);
            }
            resource_data.add_section("Labels", label_data);
        }
    }

    /// Extract namespace and name from metadata with default values
    pub fn extract_metadata(metadata: &ObjectMeta) -> (String, String) {
        let namespace = metadata
            .namespace
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let name = metadata.name.as_deref().unwrap_or("unknown").to_string();
        (namespace, name)
    }

    /// Add match labels from a selector to a ResourceData object
    #[allow(dead_code)]
    pub fn add_match_labels(
        resource_data: &mut ResourceData,
        match_labels: &HashMap<String, String>,
        section_name: &str,
    ) {
        if !match_labels.is_empty() {
            let mut label_data = Vec::new();
            for (key, value) in match_labels {
                let mut label = ResourceData::new("Label", "", key);
                label.add_attribute("value", value.to_string());
                label_data.push(label);
            }
            resource_data.add_section(section_name, label_data);
        }
    }

    /// Add match labels from a BTreeMap selector to a ResourceData object
    pub fn add_match_labels_btree(
        resource_data: &mut ResourceData,
        match_labels: &BTreeMap<String, String>,
        section_name: &str,
    ) {
        if !match_labels.is_empty() {
            let mut label_data = Vec::new();
            for (key, value) in match_labels {
                let mut label = ResourceData::new("Label", "", key);
                label.add_attribute("value", value.to_string());
                label_data.push(label);
            }
            resource_data.add_section(section_name, label_data);
        }
    }
}

impl ResourceData {
    /// Create a new ResourceData with the given kind, namespace, and name
    pub fn new(kind: &str, namespace: &str, name: &str) -> Self {
        Self {
            kind: kind.to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
            attributes: HashMap::new(),
            sections: HashMap::new(),
        }
    }

    /// Add an attribute to the resource data
    pub fn add_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Display,
    {
        self.attributes.insert(key.into(), value.to_string());
    }

    /// Add a section to the resource data
    pub fn add_section<K>(&mut self, section_name: K, items: Vec<ResourceData>)
    where
        K: Into<String>,
    {
        if !items.is_empty() {
            self.sections.insert(section_name.into(), items);
        }
    }

    /// Print the resource data to the console
    pub fn print(&self) {
        println!("{}/{}", self.namespace, self.name);

        // Print attributes
        for (key, value) in &self.attributes {
            println!("  {key}: {value}");
        }

        // Print sections
        for (section_name, items) in &self.sections {
            if !items.is_empty() {
                println!("  {section_name}:");
                for (i, item) in items.iter().enumerate() {
                    if *section_name == "Labels" || *section_name == "Annotations" {
                        println!(
                            "    {}: {}",
                            item.name,
                            item.attributes.get("value").unwrap_or(&String::new())
                        );
                    } else {
                        println!("    Item #{}:", i + 1);
                        for (key, value) in &item.attributes {
                            println!("      {key}: {value}");
                        }
                    }
                }
            }
        }
    }
}

/// Trait for parsing Kubernetes resources into ResourceData
#[async_trait]
pub trait ResourceParser {
    /// Parse a resource and return structured data
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData>;

    /// Parse and print resource information
    async fn parse_and_print(&self, client: &Attributor, src_ipv4: Ipv4Addr) {
        info!("Parsing {} information", self.resource_type());

        let resources = self.parse(client, src_ipv4).await;

        if resources.is_empty() {
            println!("{}: none found for IP {}", self.resource_type(), src_ipv4);
            return;
        }

        println!("{}:", self.resource_type());
        for resource in resources {
            resource.print();
        }
    }

    /// Get the type of resource this parser handles
    fn resource_type(&self) -> &'static str;
}

/// Parser for Pod resources
pub struct PodParser;

#[async_trait]
impl ResourceParser for PodParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let (namespace, name) = helpers::extract_metadata(&pod.metadata);
            let mut pod_data = ResourceData::new("Pod", &namespace, &name);

            // Add pod details
            if let Some(status) = &pod.status {
                if let Some(phase) = &status.phase {
                    pod_data.add_attribute("Phase", phase.to_string());
                }
                if let Some(host_ip) = &status.host_ip {
                    pod_data.add_attribute("Host IP", host_ip.to_string());
                }
                if let Some(qos_class) = &status.qos_class {
                    pod_data.add_attribute("QoS Class", qos_class.to_string());
                }
            }

            // Add pod labels
            helpers::add_labels(&mut pod_data, &pod.metadata);

            result.push(pod_data);
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "Pod"
    }
}

/// Parser for Service resources
pub struct ServiceParser;

#[async_trait]
impl ResourceParser for ServiceParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let services = client.get_services_for_pod(&pod);

            for service in services {
                let (namespace, name) = helpers::extract_metadata(&service.metadata);
                let mut service_data = ResourceData::new("Service", &namespace, &name);

                // Service type and cluster IP
                if let Some(spec) = &service.spec {
                    if let Some(service_type) = &spec.type_ {
                        service_data.add_attribute("Type", service_type.to_string());
                    }
                    if let Some(cluster_ip) = &spec.cluster_ip {
                        service_data.add_attribute("Cluster IP", cluster_ip.to_string());
                    }

                    // Service ports
                    if let Some(ports) = &spec.ports
                        && !ports.is_empty()
                    {
                        let mut port_data = Vec::new();
                        for port in ports {
                            let port_name = port.name.as_deref().unwrap_or("unnamed");
                            let mut port_resource = ResourceData::new("Port", "", port_name);

                            port_resource.add_attribute("Port", port.port);
                            port_resource.add_attribute(
                                "Protocol",
                                port.protocol.as_deref().unwrap_or("TCP").to_string(),
                            );

                            if let Some(target_port) = &port.target_port {
                                match target_port {
                                    k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(i) => {
                                        port_resource.add_attribute("Target Port", i.to_string());
                                    },
                                    k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(s) => {
                                        port_resource.add_attribute("Target Port", s.to_string());
                                    },
                                }
                            }

                            port_data.push(port_resource);
                        }
                        service_data.add_section("Ports", port_data);
                    }
                }

                // Add service labels
                helpers::add_labels(&mut service_data, &service.metadata);

                result.push(service_data);
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "Service"
    }
}

/// Parser for Node resources
pub struct NodeParser;

#[async_trait]
impl ResourceParser for NodeParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await
            && let Some(node_name) = pod.spec.as_ref().and_then(|s| s.node_name.as_ref())
        {
            // Find the node in the store
            for node in client.resource_store.nodes.state() {
                if let Some(name) = &node.metadata.name {
                    let mut node_data = ResourceData::new("Node", "", name);

                    if *name == *node_name {
                        // Node addresses
                        if let Some(addresses) =
                            node.status.as_ref().and_then(|s| s.addresses.as_ref())
                            && !addresses.is_empty()
                        {
                            let mut address_data = Vec::new();
                            for addr in addresses {
                                let mut address = ResourceData::new("Address", "", &addr.type_);
                                address.add_attribute("value", &addr.address);
                                address_data.push(address);
                            }
                            node_data.add_section("Addresses", address_data);
                        }
                    }

                    // Node capacity
                    if let Some(capacity) = node.status.as_ref().and_then(|s| s.capacity.as_ref())
                        && !capacity.is_empty()
                    {
                        let mut capacity_data = Vec::new();
                        for (resource, quantity) in capacity {
                            let mut cap = ResourceData::new("Capacity", "", resource);
                            cap.add_attribute("value", format!("{quantity:?}"));
                            capacity_data.push(cap);
                        }
                        node_data.add_section("Capacity", capacity_data);
                    }

                    // Node labels
                    helpers::add_labels(&mut node_data, &node.metadata);

                    result.push(node_data);
                    break;
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "Node"
    }
}

/// Parser for Deployment resources
pub struct DeploymentParser;

#[async_trait]
impl ResourceParser for DeploymentParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Check for owner references to find the ReplicaSet
            if let Some(owner_refs) = &pod.metadata.owner_references {
                for owner_ref in owner_refs {
                    if owner_ref.kind == "ReplicaSet" {
                        // Get deployments in the namespace
                        let deployments = client
                            .resource_store
                            .get_by_namespace::<Deployment>(namespace);

                        for deployment in deployments {
                            // Check if this deployment manages the ReplicaSet
                            if let Some(name) = &deployment.metadata.name
                                && owner_ref.name.starts_with(name)
                            {
                                let (_, deployment_name) =
                                    helpers::extract_metadata(&deployment.metadata);
                                let mut deployment_data =
                                    ResourceData::new("Deployment", namespace, &deployment_name);

                                // Deployment details
                                if let Some(spec) = &deployment.spec {
                                    if let Some(replicas) = spec.replicas {
                                        deployment_data.add_attribute("Replicas", replicas);
                                    }
                                    if let Some(strategy) = &spec.strategy
                                        && let Some(strategy_type) = &strategy.type_
                                    {
                                        deployment_data
                                            .add_attribute("Strategy", strategy_type.to_string());
                                    }
                                }

                                // Deployment status
                                if let Some(status) = &deployment.status {
                                    if let Some(available_replicas) = status.available_replicas {
                                        deployment_data.add_attribute(
                                            "Available Replicas",
                                            available_replicas,
                                        );
                                    }
                                    if let Some(ready_replicas) = status.ready_replicas {
                                        deployment_data
                                            .add_attribute("Ready Replicas", ready_replicas);
                                    }
                                }

                                // Add deployment labels
                                helpers::add_labels(&mut deployment_data, &deployment.metadata);

                                result.push(deployment_data);
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "Deployment"
    }
}

/// Parser for ReplicaSet resources
pub struct ReplicaSetParser;

#[async_trait]
impl ResourceParser for ReplicaSetParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Check for owner references to find the ReplicaSet
            if let Some(owner_refs) = &pod.metadata.owner_references {
                for owner_ref in owner_refs {
                    if owner_ref.kind == "ReplicaSet" {
                        let rs_name = &owner_ref.name;

                        let replica_sets_in_ns = client
                            .resource_store
                            .get_by_namespace::<ReplicaSet>(namespace);

                        if let Some(rs) = replica_sets_in_ns
                            .iter()
                            .find(|rs| rs.metadata.name.as_deref() == Some(rs_name))
                        {
                            let mut rs_data = ResourceData::new("ReplicaSet", namespace, rs_name);

                            // ReplicaSet details
                            if let Some(spec) = &rs.spec {
                                if let Some(replicas) = spec.replicas {
                                    rs_data.add_attribute("Replicas", replicas);
                                }

                                // Selector
                                let selector = &spec.selector;
                                if let Some(match_labels) = &selector.match_labels {
                                    helpers::add_match_labels_btree(
                                        &mut rs_data,
                                        match_labels,
                                        "Selector",
                                    );
                                }
                            }

                            // ReplicaSet status
                            if let Some(status) = &rs.status {
                                rs_data.add_attribute("Current Replicas", status.replicas);
                                if let Some(ready_replicas) = status.ready_replicas {
                                    rs_data.add_attribute("Ready Replicas", ready_replicas);
                                }
                            }

                            // Add ReplicaSet labels
                            helpers::add_labels(&mut rs_data, &rs.metadata);

                            result.push(rs_data);
                        }
                        break;
                    }
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "ReplicaSet"
    }
}

/// Parser for StatefulSet resources
pub struct StatefulSetParser;

#[async_trait]
impl ResourceParser for StatefulSetParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Check for owner references to find the StatefulSet
            if let Some(owner_refs) = &pod.metadata.owner_references {
                for owner_ref in owner_refs {
                    if owner_ref.kind == "StatefulSet" {
                        let sts_name = &owner_ref.name;

                        let stateful_sets_in_ns = client
                            .resource_store
                            .get_by_namespace::<StatefulSet>(namespace);

                        // Find the StatefulSet in the store
                        if let Some(sts) = stateful_sets_in_ns
                            .iter()
                            .find(|s| s.metadata.name.as_deref() == Some(sts_name))
                        {
                            let mut sts_data =
                                ResourceData::new("StatefulSet", namespace, sts_name);

                            // StatefulSet details
                            if let Some(spec) = &sts.spec {
                                if let Some(replicas) = spec.replicas {
                                    sts_data.add_attribute("Replicas", replicas);
                                }
                                sts_data.add_attribute("Service Name", &spec.service_name);
                                if let Some(pod_management_policy) = &spec.pod_management_policy {
                                    sts_data.add_attribute(
                                        "Pod Management Policy",
                                        pod_management_policy,
                                    );
                                }
                            }

                            // StatefulSet status
                            if let Some(status) = &sts.status {
                                sts_data.add_attribute("Current Replicas", status.replicas);
                                if let Some(ready_replicas) = status.ready_replicas {
                                    sts_data.add_attribute("Ready Replicas", ready_replicas);
                                }
                                if let Some(current_revision) = &status.current_revision {
                                    sts_data.add_attribute("Current Revision", current_revision);
                                }
                            }

                            // Add StatefulSet labels
                            helpers::add_labels(&mut sts_data, &sts.metadata);

                            result.push(sts_data);
                        }
                        break;
                    }
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "StatefulSet"
    }
}

/// Parser for DaemonSet resources
pub struct DaemonSetParser;

#[async_trait]
impl ResourceParser for DaemonSetParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Check for owner references to find the DaemonSet
            if let Some(owner_refs) = &pod.metadata.owner_references {
                for owner_ref in owner_refs {
                    if owner_ref.kind == "DaemonSet" {
                        let ds_name = &owner_ref.name;

                        let daemon_sets_in_ns = client
                            .resource_store
                            .get_by_namespace::<DaemonSet>(namespace);

                        // Find the DaemonSet in the store
                        if let Some(ds) = daemon_sets_in_ns
                            .iter()
                            .find(|d| d.metadata.name.as_deref() == Some(ds_name))
                        {
                            let mut ds_data = ResourceData::new("DaemonSet", namespace, ds_name);

                            // DaemonSet details
                            if let Some(spec) = &ds.spec {
                                let selector = &spec.selector;
                                if let Some(match_labels) = &selector.match_labels {
                                    helpers::add_match_labels_btree(
                                        &mut ds_data,
                                        match_labels,
                                        "Selector",
                                    );
                                }
                            }

                            // DaemonSet status
                            if let Some(status) = &ds.status {
                                ds_data.add_attribute(
                                    "Current Number Scheduled",
                                    status.current_number_scheduled,
                                );
                                ds_data.add_attribute(
                                    "Desired Number Scheduled",
                                    status.desired_number_scheduled,
                                );
                                ds_data.add_attribute("Number Ready", status.number_ready);
                            }

                            // Add DaemonSet labels
                            helpers::add_labels(&mut ds_data, &ds.metadata);

                            result.push(ds_data);
                        }
                        break;
                    }
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "DaemonSet"
    }
}

/// Parser for Job resources
pub struct JobParser;

#[async_trait]
impl ResourceParser for JobParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Check for owner references to find the Job
            if let Some(owner_refs) = &pod.metadata.owner_references {
                for owner_ref in owner_refs {
                    if owner_ref.kind == "Job" {
                        let job_name = &owner_ref.name;

                        let jobs_in_ns = client.resource_store.get_by_namespace::<Job>(namespace);

                        // Find the Job in the store
                        if let Some(job) = jobs_in_ns
                            .iter()
                            .find(|j| j.metadata.name.as_deref() == Some(job_name))
                        {
                            let mut job_data = ResourceData::new("Job", namespace, job_name);

                            // Job details
                            if let Some(spec) = &job.spec {
                                if let Some(parallelism) = spec.parallelism {
                                    job_data.add_attribute("Parallelism", parallelism);
                                }
                                if let Some(completions) = spec.completions {
                                    job_data.add_attribute("Completions", completions);
                                }
                                if let Some(backoff_limit) = spec.backoff_limit {
                                    job_data.add_attribute("Backoff Limit", backoff_limit);
                                }
                            }

                            // Job status
                            if let Some(status) = &job.status {
                                if let Some(active) = status.active {
                                    job_data.add_attribute("Active", active);
                                }
                                if let Some(succeeded) = status.succeeded {
                                    job_data.add_attribute("Succeeded", succeeded);
                                }
                                if let Some(failed) = status.failed {
                                    job_data.add_attribute("Failed", failed);
                                }
                                if let Some(completion_time) = &status.completion_time {
                                    job_data.add_attribute(
                                        "Completion Time",
                                        format!("{completion_time:?}"),
                                    );
                                }
                            }

                            // Add Job labels
                            helpers::add_labels(&mut job_data, &job.metadata);

                            result.push(job_data);
                        }
                        break;
                    }
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "Job"
    }
}

/// Parser for Ingress resources
pub struct IngressParser;

#[async_trait]
impl ResourceParser for IngressParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Get services for the pod
            let services = client.get_services_for_pod(&pod);

            if !services.is_empty() {
                // Check if any ingresses reference these services
                let ingresses_in_ns = client.resource_store.get_by_namespace::<Ingress>(namespace);

                for ingress in ingresses_in_ns {
                    if helpers::is_ingress_related_to_services(&ingress, &services) {
                        let name = ingress.metadata.name.as_deref().unwrap_or("unknown");
                        let mut ingress_data = ResourceData::new("Ingress", namespace, name);

                        // Ingress details
                        if let Some(spec) = &ingress.spec {
                            // Ingress class
                            if let Some(ingress_class_name) = &spec.ingress_class_name {
                                ingress_data
                                    .add_attribute("Ingress Class", ingress_class_name.to_string());
                            }

                            // TLS
                            if let Some(tls) = &spec.tls
                                && !tls.is_empty()
                            {
                                let mut tls_data = Vec::new();
                                for (i, tls_entry) in tls.iter().enumerate() {
                                    let mut tls_item =
                                        ResourceData::new("TLS", "", &format!("Entry #{}", i + 1));

                                    if let Some(hosts) = &tls_entry.hosts {
                                        tls_item.add_attribute("Hosts", hosts.join(", "));
                                    }
                                    if let Some(secret_name) = &tls_entry.secret_name {
                                        tls_item.add_attribute("Secret", secret_name.to_string());
                                    }

                                    tls_data.push(tls_item);
                                }
                                ingress_data.add_section("TLS", tls_data);
                            }

                            // Rules
                            if let Some(rules) = &spec.rules
                                && !rules.is_empty()
                            {
                                let mut rules_data = Vec::new();
                                for (i, rule) in rules.iter().enumerate() {
                                    let mut rule_item =
                                        ResourceData::new("Rule", "", &format!("#{}", i + 1));

                                    if let Some(host) = &rule.host {
                                        rule_item.add_attribute("Host", host.to_string());
                                    }

                                    if let Some(http) = &rule.http {
                                        let mut paths_data = Vec::new();
                                        for (j, path) in http.paths.iter().enumerate() {
                                            let mut path_item = ResourceData::new(
                                                "Path",
                                                "",
                                                &format!("#{}", j + 1),
                                            );

                                            path_item.add_attribute(
                                                "Path",
                                                path.path.as_deref().unwrap_or("/"),
                                            );
                                            path_item.add_attribute("PathType", &path.path_type);

                                            let backend = &path.backend;
                                            if let Some(service) = &backend.service {
                                                path_item.add_attribute("Service", &service.name);
                                                if let Some(port) = &service.port {
                                                    match &port.number {
                                                        Some(num) => {
                                                            path_item.add_attribute(
                                                                "Port",
                                                                num.to_string(),
                                                            );
                                                        }
                                                        None => {
                                                            if let Some(name) = &port.name {
                                                                path_item.add_attribute(
                                                                    "Port Name",
                                                                    name,
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            paths_data.push(path_item);
                                        }
                                        rule_item.add_section("Paths", paths_data);
                                    }

                                    rules_data.push(rule_item);
                                }
                                ingress_data.add_section("Rules", rules_data);
                            }
                        }

                        // Ingress status
                        if let Some(status) = &ingress.status
                            && let Some(load_balancer) = &status.load_balancer
                            && let Some(ingress_points) = &load_balancer.ingress
                            && !ingress_points.is_empty()
                        {
                            let mut lb_data = Vec::new();
                            for (i, ingress_point) in ingress_points.iter().enumerate() {
                                let mut point = ResourceData::new(
                                    "LoadBalancer",
                                    "",
                                    &format!("Point #{}", i + 1),
                                );

                                if let Some(ip) = &ingress_point.ip {
                                    point.add_attribute("IP", ip);
                                }
                                if let Some(hostname) = &ingress_point.hostname {
                                    point.add_attribute("Hostname", hostname);
                                }

                                lb_data.push(point);
                            }
                            ingress_data.add_section("Load Balancer", lb_data);
                        }

                        // Add Ingress labels
                        helpers::add_labels(&mut ingress_data, &ingress.metadata);

                        result.push(ingress_data);
                    }
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "Ingress"
    }
}

/// Parser for EndpointSlice resources
pub struct EndpointSliceParser;

#[async_trait]
impl ResourceParser for EndpointSliceParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");
            let pod_ip = src_ipv4.to_string();

            let slices_in_ns = client
                .resource_store
                .get_by_namespace::<EndpointSlice>(namespace);

            // Check all endpoint slices for this pod's IP
            for slice in slices_in_ns {
                let endpoints = &slice.endpoints;
                let is_related = endpoints.iter().any(|ep| ep.addresses.contains(&pod_ip));

                if is_related {
                    let name = slice.metadata.name.as_deref().unwrap_or("unknown");
                    let mut slice_data = ResourceData::new("EndpointSlice", namespace, name);

                    // EndpointSlice details
                    slice_data.add_attribute("Address Type", &slice.address_type);

                    // Endpoints
                    let mut endpoints_data = Vec::new();
                    for (i, endpoint) in endpoints.iter().enumerate().take(3) {
                        // Limit to first 3 for brevity
                        let mut endpoint_item =
                            ResourceData::new("Endpoint", "", &format!("#{}", i + 1));

                        let addresses = &endpoint.addresses;
                        endpoint_item.add_attribute("Addresses", addresses.join(", "));

                        if let Some(hostname) = &endpoint.hostname {
                            endpoint_item.add_attribute("Hostname", hostname);
                        }
                        if let Some(node_name) = &endpoint.node_name {
                            endpoint_item.add_attribute("Node", node_name);
                        }

                        endpoints_data.push(endpoint_item);
                    }

                    if endpoints.len() > 3 {
                        let mut more = ResourceData::new("More", "", "");
                        more.add_attribute("Count", endpoints.len() - 3);
                        endpoints_data.push(more);
                    }

                    slice_data.add_section("Endpoints", endpoints_data);

                    // Ports
                    if let Some(ports) = &slice.ports
                        && !ports.is_empty()
                    {
                        let mut ports_data = Vec::new();
                        for port in ports {
                            let port_name = port.name.as_deref().unwrap_or("unnamed");
                            let mut port_item = ResourceData::new("Port", "", port_name);

                            if let Some(port_number) = port.port {
                                port_item.add_attribute("Port", port_number);
                            }

                            let protocol = port.protocol.as_deref().unwrap_or("TCP");
                            port_item.add_attribute("Protocol", protocol);

                            ports_data.push(port_item);
                        }
                        slice_data.add_section("Ports", ports_data);
                    }

                    // Add EndpointSlice labels
                    helpers::add_labels(&mut slice_data, &slice.metadata);

                    result.push(slice_data);
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "EndpointSlice"
    }
}

/// Parser for NetworkPolicy resources
pub struct NetworkPolicyParser;

#[async_trait]
impl ResourceParser for NetworkPolicyParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Get all network policies in the pod's namespace
            let relevant_policies = client
                .resource_store
                .get_by_namespace::<NetworkPolicy>(namespace);

            for policy in relevant_policies {
                let name = policy.metadata.name.as_deref().unwrap_or("unknown");
                let mut policy_data = ResourceData::new("NetworkPolicy", namespace, name);

                // Policy types (ingress/egress)
                if let Some(spec) = &policy.spec {
                    if let Some(policy_types) = &spec.policy_types {
                        policy_data.add_attribute("Types", policy_types.join(", "));
                    }

                    // Pod selector
                    let pod_selector = &spec.pod_selector;
                    if let Some(match_labels) = &pod_selector.match_labels {
                        helpers::add_match_labels_btree(
                            &mut policy_data,
                            match_labels,
                            "Pod Selector",
                        );
                    }
                }

                // Add NetworkPolicy labels
                helpers::add_labels(&mut policy_data, &policy.metadata);

                result.push(policy_data);
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "NetworkPolicy"
    }
}

/// Parser for Ingress Controller resources
pub struct IngressControllerParser;

#[async_trait]
impl ResourceParser for IngressControllerParser {
    async fn parse(&self, client: &Attributor, src_ipv4: Ipv4Addr) -> Vec<ResourceData> {
        let mut result = Vec::new();

        if let Some(pod) = client.get_pod_by_ip(src_ipv4).await {
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Get services for the pod
            let services = client.get_services_for_pod(&pod);

            if !services.is_empty() {
                // Check if any ingresses reference these services and extract controller information
                let mut controllers = std::collections::HashSet::new();
                let ingresses_in_ns = client.resource_store.get_by_namespace::<Ingress>(namespace);

                for ingress in ingresses_in_ns {
                    if helpers::is_ingress_related_to_services(&ingress, &services) {
                        // Try to identify the ingress controller
                        // First check for ingress class name
                        if let Some(spec) = &ingress.spec
                            && let Some(ingress_class_name) = &spec.ingress_class_name
                        {
                            controllers.insert(format!("Class: {ingress_class_name}"));
                        }

                        // Then check for annotations that might indicate the controller
                        if let Some(annotations) = &ingress.metadata.annotations {
                            for (key, value) in annotations {
                                if key.contains("kubernetes.io/ingress.class")
                                    || key.contains("ingress-controller")
                                    || key.contains("ingress.kubernetes.io")
                                {
                                    controllers.insert(format!("Annotation: {key} = {value}"));
                                }
                            }
                        }
                    }
                }

                if !controllers.is_empty() {
                    let mut controller_data =
                        ResourceData::new("IngressController", namespace, "detected");

                    let mut controller_items = Vec::new();
                    for (i, controller) in controllers.iter().enumerate() {
                        let mut item = ResourceData::new("Controller", "", &format!("#{}", i + 1));
                        item.add_attribute("Info", controller.to_string());
                        controller_items.push(item);
                    }

                    controller_data.add_section("Controllers", controller_items);
                    result.push(controller_data);
                }
            }
        }

        result
    }

    fn resource_type(&self) -> &'static str {
        "IngressController"
    }
}

/// Factory for creating resource parsers
pub struct ResourceParserFactory;

impl ResourceParserFactory {
    #[allow(dead_code)]
    /// Create a parser for the specified resource type
    pub fn create(resource_type: &str) -> Box<dyn ResourceParser + Send + Sync> {
        match resource_type {
            "Pod" => Box::new(PodParser),
            "Service" => Box::new(ServiceParser),
            "Node" => Box::new(NodeParser),
            "Deployment" => Box::new(DeploymentParser),
            "ReplicaSet" => Box::new(ReplicaSetParser),
            "StatefulSet" => Box::new(StatefulSetParser),
            "DaemonSet" => Box::new(DaemonSetParser),
            "Job" => Box::new(JobParser),
            "Ingress" => Box::new(IngressParser),
            "EndpointSlice" => Box::new(EndpointSliceParser),
            "NetworkPolicy" => Box::new(NetworkPolicyParser),
            "IngressController" => Box::new(IngressControllerParser),
            _ => panic!("Unsupported resource type: {resource_type}"),
        }
    }

    /// Get all available parsers
    pub fn all_parsers() -> Vec<Box<dyn ResourceParser + Send + Sync>> {
        vec![
            Box::new(PodParser),
            Box::new(ServiceParser),
            Box::new(NodeParser),
            Box::new(DeploymentParser),
            Box::new(ReplicaSetParser),
            Box::new(StatefulSetParser),
            Box::new(DaemonSetParser),
            Box::new(JobParser),
            Box::new(IngressParser),
            Box::new(EndpointSliceParser),
            Box::new(NetworkPolicyParser),
            Box::new(IngressControllerParser),
        ]
    }
}

/// Parse packet metadata and extract connection information
pub fn parse_packet_meta(event: &PacketMeta) -> (String, String) {
    // Protocol information
    let protocol = match event.proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "Other",
    };

    let connection_info = match event.ip_addr_type {
        IpAddrType::Ipv4 => {
            // Get the source and destination IPv4 addresses
            let src_ipv4 = Ipv4Addr::from(event.src_ipv4_addr);
            let dst_ipv4 = Ipv4Addr::from(event.dst_ipv4_addr);

            match event.proto {
                // For ICMP and ICMPv6, don't show ports since they don't use them
                1 | 58 => format!("Connection: {src_ipv4} -> {dst_ipv4} ({protocol})"),
                // For TCP, UDP and other protocols, show ports
                _ => {
                    let src_port = event.src_port();
                    let dst_port = event.dst_port();
                    format!(
                        "Connection: {src_ipv4}:{src_port} -> {dst_ipv4}:{dst_port} ({protocol})"
                    )
                }
            }
        }
        IpAddrType::Ipv6 => {
            // Get the source and destination IPv6 addresses
            let src_ipv6 = Ipv6Addr::from(event.src_ipv6_addr);
            let dst_ipv6 = Ipv6Addr::from(event.dst_ipv6_addr);

            match event.proto {
                // For ICMP and ICMPv6, don't show ports since they don't use them
                1 | 58 => format!("Connection: [{src_ipv6}] -> [{dst_ipv6}] ({protocol})"),
                // For TCP, UDP and other protocols, show ports
                _ => {
                    let src_port = event.src_port();
                    let dst_port = event.dst_port();
                    format!(
                        "Connection: [{src_ipv6}]:{src_port} -> [{dst_ipv6}]:{dst_port} ({protocol})"
                    )
                }
            }
        }
    };

    let packet_size_info = format!("Packet size: {} bytes", event.l3_octet_count);

    (connection_info, packet_size_info)
}
