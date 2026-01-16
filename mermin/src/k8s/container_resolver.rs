//! container_resolver.rs - Container resolution logic for Kubernetes Pods
//!
//! This module provides intelligent container resolution from Kubernetes Pods
//! using port-based matching. It handles multi-container pods by matching
//! the flow port against the containerPort specifications in the Pod spec.

use k8s_openapi::api::core::v1::Pod;

/// Container information extracted from a Pod
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub name: String,
    pub image_name: String,
}

/// Resolves container from a Pod based on port matching
///
/// This function attempts to identify the correct container in a Pod by
/// matching the provided port against the containerPort specifications
/// in each container's ports array.
///
/// # Resolution Algorithm
/// 1. Extract `spec.containers` from Pod
/// 2. For each container, check `ports` array
/// 3. Match `port` parameter against `containerPort` field
/// 4. On match: extract `name` and `image` fields
/// 5. On no match: return `None`
///
/// # Edge Cases
/// - Pod with no `spec` → returns `None`
/// - Pod with no `containers` → returns `None`
/// - Container with no `ports` defined → skip container
/// - Container with no `image` field → returns `None` for that container
/// - Multiple containers with same port → returns first match
/// - No port match found → returns `None`
///
/// # Arguments
/// * `pod` - The Kubernetes Pod to search
/// * `port` - The port number to match against containerPort specifications
///
/// # Returns
/// `Some(ContainerInfo)` if a matching container is found, `None` otherwise
pub fn resolve_container_by_port(pod: &Pod, port: u16) -> Option<ContainerInfo> {
    let spec = pod.spec.as_ref()?;

    // Iterate through all containers in the pod
    for container in &spec.containers {
        // Check if this container has any ports defined
        let ports = container.ports.as_ref()?;

        // Check if any of the container's ports match the requested port
        for container_port in ports {
            if container_port.container_port as u16 == port {
                // Found a match! Extract container name and image
                let name = container.name.clone();
                let image_name = container.image.clone()?;

                return Some(ContainerInfo { name, image_name });
            }
        }
    }

    // No matching container found
    None
}

#[cfg(test)]
mod tests {
    use k8s_openapi::{
        api::core::v1::{Container, ContainerPort, PodSpec},
        apimachinery::pkg::apis::meta::v1::ObjectMeta,
    };

    use super::*;

    /// Helper to create a test container with a name, image, and ports
    fn create_container(name: &str, image: &str, ports: Vec<i32>) -> Container {
        Container {
            name: name.to_string(),
            image: Some(image.to_string()),
            ports: Some(
                ports
                    .into_iter()
                    .map(|port| ContainerPort {
                        container_port: port,
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    /// Helper to create a test Pod with given containers
    fn create_pod(containers: Vec<Container>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some("test-pod".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_single_container_with_port_match() {
        let pod = create_pod(vec![create_container("web", "nginx:1.21", vec![8080])]);

        let result = resolve_container_by_port(&pod, 8080);
        assert!(result.is_some());

        let container_info = result.unwrap();
        assert_eq!(container_info.name, "web");
        assert_eq!(container_info.image_name, "nginx:1.21");
    }

    #[test]
    fn test_multi_container_with_port_match() {
        let pod = create_pod(vec![
            create_container("frontend", "frontend:v1", vec![8080]),
            create_container("sidecar", "envoy:latest", vec![9090]),
            create_container("metrics", "prometheus:v2", vec![3000]),
        ]);

        // Test matching the middle container
        let result = resolve_container_by_port(&pod, 9090);
        assert!(result.is_some());

        let container_info = result.unwrap();
        assert_eq!(container_info.name, "sidecar");
        assert_eq!(container_info.image_name, "envoy:latest");
    }

    #[test]
    fn test_no_port_match() {
        let pod = create_pod(vec![create_container("web", "nginx:1.21", vec![8080])]);

        let result = resolve_container_by_port(&pod, 3000);
        assert!(result.is_none());
    }

    #[test]
    fn test_container_without_ports() {
        let mut container = create_container("worker", "worker:v1", vec![]);
        container.ports = None; // Explicitly set to None

        let pod = create_pod(vec![container]);

        let result = resolve_container_by_port(&pod, 8080);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_containers_array() {
        let pod = create_pod(vec![]);

        let result = resolve_container_by_port(&pod, 8080);
        assert!(result.is_none());
    }

    #[test]
    fn test_pod_without_spec() {
        let mut pod = create_pod(vec![create_container("web", "nginx:1.21", vec![8080])]);
        pod.spec = None;

        let result = resolve_container_by_port(&pod, 8080);
        assert!(result.is_none());
    }

    #[test]
    fn test_container_without_image() {
        let mut container = create_container("web", "nginx:1.21", vec![8080]);
        container.image = None;

        let pod = create_pod(vec![container]);

        let result = resolve_container_by_port(&pod, 8080);
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_ports_on_single_container() {
        let pod = create_pod(vec![create_container(
            "web",
            "nginx:1.21",
            vec![80, 443, 8080],
        )]);

        // Test matching the middle port
        let result = resolve_container_by_port(&pod, 443);
        assert!(result.is_some());

        let container_info = result.unwrap();
        assert_eq!(container_info.name, "web");
        assert_eq!(container_info.image_name, "nginx:1.21");
    }

    #[test]
    fn test_first_match_wins_with_duplicate_ports() {
        let pod = create_pod(vec![
            create_container("first", "first:v1", vec![8080]),
            create_container("second", "second:v1", vec![8080]),
        ]);

        let result = resolve_container_by_port(&pod, 8080);
        assert!(result.is_some());

        let container_info = result.unwrap();
        // Should return the first container with matching port
        assert_eq!(container_info.name, "first");
        assert_eq!(container_info.image_name, "first:v1");
    }

    #[test]
    fn test_container_with_complex_image_name() {
        let pod = create_pod(vec![create_container(
            "app",
            "registry.example.com/team/app:v1.2.3-beta",
            vec![8080],
        )]);

        let result = resolve_container_by_port(&pod, 8080);
        assert!(result.is_some());

        let container_info = result.unwrap();
        assert_eq!(container_info.name, "app");
        assert_eq!(
            container_info.image_name,
            "registry.example.com/team/app:v1.2.3-beta"
        );
    }
}
