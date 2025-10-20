use std::fmt;

use thiserror::Error;

/// Errors that can occur during Kubernetes operations
#[derive(Debug, Error)]
pub enum K8sError {
    /// Failed to create or initialize Kubernetes client
    #[error("failed to initialize Kubernetes client: {0}")]
    ClientInitialization(#[source] Box<kube::Error>),

    /// Failed to create or access resource store
    #[error("failed to create resource store for {resource}: {source}")]
    #[allow(dead_code)]
    ResourceStore {
        resource: String,
        #[source]
        source: Box<kube::Error>,
    },

    /// Failed to list Kubernetes resources
    #[error("failed to list {resource}: {source}")]
    ResourceList {
        resource: String,
        #[source]
        source: Box<kube::Error>,
    },

    /// Critical resource reflector failed to initialize
    #[error("failed to create critical reflector for {resource}: {details}")]
    CriticalReflectorFailure { resource: String, details: String },

    /// Network policy evaluation error
    #[error("failed to evaluate network policies: {0}")]
    #[allow(dead_code)]
    NetworkPolicyEvaluation(String),

    /// Label selector matching error
    #[error("label selector matching failed: {0}")]
    #[allow(dead_code)]
    LabelSelectorMatching(String),

    /// Pod lookup error
    #[error("failed to lookup pod by IP {ip}: {details}")]
    #[allow(dead_code)]
    PodLookup { ip: String, details: String },

    /// Service lookup error
    #[error("failed to lookup service by IP {ip}: {details}")]
    #[allow(dead_code)]
    ServiceLookup { ip: String, details: String },

    /// Node lookup error
    #[error("failed to lookup node by IP {ip}: {details}")]
    #[allow(dead_code)]
    NodeLookup { ip: String, details: String },

    /// Resource attribution error
    #[error("failed to attribute flow with Kubernetes metadata: {0}")]
    #[allow(dead_code)]
    Attribution(String),

    /// Flow context creation error
    #[error("failed to create flow context: {0}")]
    #[allow(dead_code)]
    FlowContext(String),
}

impl K8sError {
    /// Create a critical reflector failure error
    pub fn critical_reflector(resource: impl Into<String>, details: impl fmt::Display) -> Self {
        Self::CriticalReflectorFailure {
            resource: resource.into(),
            details: details.to_string(),
        }
    }

    /// Create a resource store error
    #[allow(dead_code)]
    pub fn resource_store(resource: impl Into<String>, source: kube::Error) -> Self {
        Self::ResourceStore {
            resource: resource.into(),
            source: Box::new(source),
        }
    }

    /// Create a resource list error
    #[allow(dead_code)]
    pub fn resource_list(resource: impl Into<String>, source: kube::Error) -> Self {
        Self::ResourceList {
            resource: resource.into(),
            source: Box::new(source),
        }
    }
}
