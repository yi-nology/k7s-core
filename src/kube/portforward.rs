//! Port-forwarding a pod port to a local TCP listener (B6), and resolving a
//! Service down to one of its pods so Services can be forwarded too (B16).
//!
//! A forward binds `127.0.0.1:0` (an OS-assigned local port) and, for each
//! incoming local connection, opens a fresh `portforward` to the pod and pumps
//! bytes bidirectionally. Per-connection tasks live in a JoinSet owned by the
//! accept loop, so aborting the forward (on stop / disconnect) tears down every
//! connection with it.
//!
//! Kubernetes has no "forward to a Service" primitive — `kubectl port-forward
//! svc/x` also just picks a backing pod — so [`resolve_service`] does that pick
//! here and everything downstream is the plain pod path.

use crate::error::AppError;
use k7s_deps::k8s_openapi::api::core::v1::{Pod, Service};
use k7s_deps::k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k7s_deps::kube::api::ListParams;
use k7s_deps::kube::{Api, Client};
use k7s_deps::tokio::net::TcpListener;
use k7s_deps::tokio::sync::{mpsc, oneshot};
use k7s_deps::tokio::task::JoinSet;

/// Run a port-forward accept loop. Sends the bound local port (or an error) back
/// through `ready` once the listener is up, then serves connections until aborted.
///
/// `errors` reports per-connection failures (the pod died, connection refused) so
/// the UI can flag the forward: those happen long after `ready` has been answered,
/// and would otherwise be invisible — the local port keeps accepting either way.
///
/// `local_port` specifies the local port to bind to. If 0, the OS picks a free port.
pub async fn run_port_forward(
    client: Client,
    namespace: String,
    pod: String,
    remote_port: u16,
    local_port: u16,
    ready: oneshot::Sender<Result<u16, String>>,
    errors: mpsc::Sender<String>,
) {
    let listener = match TcpListener::bind(("127.0.0.1", local_port)).await {
        Ok(l) => l,
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };
    let local_port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };
    // Report success (with the chosen local port) before entering the accept loop.
    if ready.send(Ok(local_port)).is_err() {
        return; // caller went away
    }

    let api: Api<Pod> = Api::namespaced(client, &namespace);
    let mut conns = JoinSet::new();

    while let Ok((mut tcp, _)) = listener.accept().await {
        // Reap finished connections on every accept: without this the JoinSet
        // retains every task it has ever spawned for the forward's lifetime,
        // growing without bound on a long-lived port.
        while conns.try_join_next().is_some() {}
        let api = api.clone();
        let pod = pod.clone();
        let errors = errors.clone();
        conns.spawn(async move {
            // One portforward stream per local connection.
            match api.portforward(&pod, &[remote_port]).await {
                Ok(mut pf) => match pf.take_stream(remote_port) {
                    // Pump until either side closes.
                    Some(mut upstream) => {
                        let _ =
                            k7s_deps::tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await;
                    }
                    None => {
                        let _ = errors.try_send(format!("port {remote_port} not open on {pod}"));
                    }
                },
                Err(e) => {
                    // try_send, not send: never block the accept loop on a full
                    // error channel — one reported failure is enough to flag it.
                    let _ = errors.try_send(e.to_string());
                }
            }
        });
    }
}

/// Resolve a Service to a Ready backing pod and the container port to forward to.
///
/// `service_port` is the port as published by the Service; the returned port is
/// its `targetPort` on the pod, which is often different and may be *named* (in
/// which case it's looked up in the chosen pod's container ports).
pub async fn resolve_service(
    client: Client,
    namespace: &str,
    service: &str,
    service_port: u16,
) -> Result<(String, u16), AppError> {
    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    let svc = svc_api
        .get_opt(service)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("service {service} not found")))?;
    let spec = svc
        .spec
        .ok_or_else(|| AppError::Other(format!("service {service} has no spec")))?;

    // Selector-less Services (ExternalName, or manually-managed Endpoints) have no
    // pods of their own to forward to.
    let selector = spec.selector.unwrap_or_default();
    if selector.is_empty() {
        return Err(AppError::Other(format!(
            "service {service} has no selector, so it has no pods to forward to"
        )));
    }

    // Find the requested port's spec to learn its targetPort.
    let ports = spec.ports.unwrap_or_default();
    let port_spec = ports
        .iter()
        .find(|p| p.port == i32::from(service_port))
        .ok_or_else(|| {
            let available: Vec<String> = ports.iter().map(|p| p.port.to_string()).collect();
            AppError::Other(format!(
                "service {service} has no port {service_port} (has: {})",
                if available.is_empty() {
                    "none".into()
                } else {
                    available.join(", ")
                }
            ))
        })?;

    // Pick a Ready pod: an unready pod would accept the forward and fail the traffic.
    let label_selector = selector
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    let list = pods
        .list(&ListParams::default().labels(&label_selector))
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let pod = list.items.iter().find(|p| is_ready(p)).ok_or_else(|| {
        AppError::NotFound(format!(
            "service {service} has no ready pods ({} matched its selector)",
            list.items.len()
        ))
    })?;
    let pod_name = pod.metadata.name.clone().unwrap_or_default();

    // targetPort defaults to the service port when unset; a named one is resolved
    // against the pod we just chose.
    let target = match &port_spec.target_port {
        None => service_port,
        Some(IntOrString::Int(n)) => {
            u16::try_from(*n).map_err(|_| AppError::Other(format!("invalid targetPort {n}")))?
        }
        Some(IntOrString::String(name)) => named_container_port(pod, name).ok_or_else(|| {
            AppError::Other(format!(
                "service {service} targets port \"{name}\", which pod {pod_name} does not declare"
            ))
        })?,
    };

    Ok((pod_name, target))
}

/// True when the pod's Ready condition is True.
fn is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
        .unwrap_or(false)
}

/// Look up a named container port (e.g. targetPort: "http") in a pod's containers.
fn named_container_port(pod: &Pod, name: &str) -> Option<u16> {
    let spec = pod.spec.as_ref()?;
    for c in &spec.containers {
        for p in c.ports.iter().flatten() {
            if p.name.as_deref() == Some(name) {
                return u16::try_from(p.container_port).ok();
            }
        }
    }
    None
}

/// Ensure a pod exists (friendly error otherwise) before forwarding to it.
pub async fn ensure_pod(client: Client, namespace: &str, pod: &str) -> Result<(), AppError> {
    let api: Api<Pod> = Api::namespaced(client, namespace);
    match api.get_opt(pod).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(AppError::NotFound(format!("pod {pod} not found"))),
        Err(e) => Err(AppError::Kube(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json::json;

    /// A pod with the given Ready condition and named container ports.
    fn pod(ready: bool, ports: &[(&str, i32)]) -> Pod {
        let ports: Vec<_> = ports
            .iter()
            .map(|(n, p)| json!({ "name": n, "containerPort": p }))
            .collect();
        k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "p1", "namespace": "prod" },
            "spec": { "containers": [{ "name": "app", "ports": ports }] },
            "status": {
                "conditions": [
                    { "type": "Ready", "status": if ready { "True" } else { "False" } }
                ]
            },
        }))
        .unwrap()
    }

    /// Only pods whose Ready condition is True are forwardable: an unready pod
    /// would accept the connection and then fail the traffic.
    #[test]
    fn readiness_is_read_from_conditions() {
        assert!(is_ready(&pod(true, &[])));
        assert!(!is_ready(&pod(false, &[])));
    }

    /// A pod with no status at all (just scheduled) is not ready.
    #[test]
    fn pod_without_status_is_not_ready() {
        let p: Pod =
            k7s_deps::serde_json::from_value(json!({ "metadata": { "name": "p" } })).unwrap();
        assert!(!is_ready(&p));
    }

    /// Named targetPorts resolve to the container port that declares the name.
    #[test]
    fn resolves_named_container_port() {
        let p = pod(true, &[("http", 8080), ("metrics", 9090)]);
        assert_eq!(named_container_port(&p, "metrics"), Some(9090));
        assert_eq!(named_container_port(&p, "http"), Some(8080));
    }

    /// An unknown port name resolves to nothing (caller turns this into an error
    /// naming the pod, rather than forwarding to a wrong port).
    #[test]
    fn unknown_port_name_is_none() {
        assert_eq!(
            named_container_port(&pod(true, &[("http", 8080)]), "grpc"),
            None
        );
    }

    /// Containers without declared ports don't panic the lookup.
    #[test]
    fn pod_without_ports_is_none() {
        assert_eq!(named_container_port(&pod(true, &[]), "http"), None);
    }
}
