use std::{error::Error, fmt};

#[derive(Debug)]
pub enum K8sError {
    ClientInitialization(Box<kube::Error>),
    ResourceList {
        resource: String,
        source: Box<kube::Error>,
    },
    CriticalReflectorFailure {
        resource: String,
        details: String,
    },
    Attribution(String),
}

impl fmt::Display for K8sError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientInitialization(e) => {
                write!(f, "failed to initialize Kubernetes client: {e}")
            }
            Self::ResourceList { resource, source } => {
                write!(f, "failed to list {resource}: {source}")
            }
            Self::CriticalReflectorFailure { resource, details } => {
                write!(
                    f,
                    "failed to create critical reflector for {resource}: {details}"
                )
            }
            Self::Attribution(msg) => {
                write!(
                    f,
                    "failed to attribute flow with Kubernetes metadata: {msg}"
                )
            }
        }
    }
}

impl Error for K8sError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ClientInitialization(e) => Some(e.as_ref()),
            Self::ResourceList { source, .. } => Some(source.as_ref()),
            Self::CriticalReflectorFailure { .. } | Self::Attribution(_) => None,
        }
    }
}

impl K8sError {
    pub fn critical_reflector(resource: impl Into<String>, details: impl fmt::Display) -> Self {
        Self::CriticalReflectorFailure {
            resource: resource.into(),
            details: details.to_string(),
        }
    }
}
