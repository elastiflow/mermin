use std::fmt;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum K8sError {
    #[error("failed to initialize Kubernetes client: {0}")]
    ClientInitialization(#[source] Box<kube::Error>),

    #[error("failed to list {resource}: {source}")]
    ResourceList {
        resource: String,
        #[source]
        source: Box<kube::Error>,
    },

    #[error("failed to create critical reflector for {resource}: {details}")]
    CriticalReflectorFailure { resource: String, details: String },

    #[error("failed to attribute flow with Kubernetes metadata: {0}")]
    Attribution(String),
}

impl K8sError {
    pub fn critical_reflector(resource: impl Into<String>, details: impl fmt::Display) -> Self {
        Self::CriticalReflectorFailure {
            resource: resource.into(),
            details: details.to_string(),
        }
    }
}
