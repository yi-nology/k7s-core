//! Ingress route debugger: traces the full routing chain from Ingress rules
//! through Service backends to endpoint Pods, validating each hop.
//!
//! Common debugging scenario: "my Ingress returns 503" — this tool checks
//! whether the backend Service exists and has healthy endpoints, pinpointing
//! the exact break in the chain.

use crate::error::AppResult;
use k7s_deps::k8s_openapi::api::core::v1::Service;
use k7s_deps::k8s_openapi::api::discovery::v1::EndpointSlice;
use k7s_deps::k8s_openapi::api::networking::v1::Ingress;
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::Client;
use serde::Serialize;

/// One hop in the Ingress routing chain.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteHop {
    pub kind: String,
    pub name: String,
    pub namespace: String,
    /// "ok", "warning", or "error".
    pub status: String,
    pub detail: String,
}

/// A single Ingress rule path with its full routing chain.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressRoute {
    pub host: String,
    pub path: String,
    pub path_type: String,
    pub hops: Vec<RouteHop>,
    /// Worst status across all hops: "ok", "warning", or "error".
    pub overall_status: String,
}

/// Full debug result for an Ingress resource.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressDebugResult {
    pub ingress: String,
    pub namespace: String,
    pub ingress_class: Option<String>,
    pub tls: bool,
    pub routes: Vec<IngressRoute>,
}

/// Compute the overall status for a set of hops: error if any hop failed,
/// warning if any hop warned, otherwise ok.
fn overall_status(hops: &[RouteHop]) -> String {
    if hops.iter().any(|h| h.status == "error") {
        "error".into()
    } else if hops.iter().any(|h| h.status == "warning") {
        "warning".into()
    } else {
        "ok".into()
    }
}

/// Count ready endpoint addresses across EndpointSlices for a Service.
///
/// Uses EndpointSlices (the modern shape, v1.21+) rather than the legacy
/// Endpoints object, matching the rest of the codebase (see `endpoints.rs`).
fn count_ready_addresses(slices: &[EndpointSlice], service_name: &str) -> usize {
    slices
        .iter()
        .filter(|s| {
            s.metadata
                .labels
                .as_ref()
                .and_then(|m| m.get("kubernetes.io/service-name"))
                .map(|n| n == service_name)
                .unwrap_or(false)
        })
        .flat_map(|s| s.endpoints.iter().flatten())
        .filter(|ep| ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true))
        .flat_map(|ep| &ep.addresses)
        .count()
}

/// Debug an Ingress's routing chain: for every rule path, trace through the
/// backend Service to its endpoint Pods and report the health of each hop.
pub async fn debug_ingress(
    client: Client,
    namespace: &str,
    name: &str,
) -> AppResult<IngressDebugResult> {
    let ing_api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
    let ing = ing_api.get(name).await?;

    let ing_name = ing.metadata.name.clone().unwrap_or_default();
    let ing_ns = ing
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.into());
    let spec = ing.spec.clone().unwrap_or_default();

    let ing_class = spec.ingress_class_name.clone();
    let has_tls = spec.tls.as_ref().map(|t| !t.is_empty()).unwrap_or(false);

    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ing_ns);
    let ep_api: Api<EndpointSlice> = Api::namespaced(client.clone(), &ing_ns);

    // Pre-fetch all EndpointSlices in the namespace once, then filter per
    // service. An Ingress commonly points multiple paths at the same Service,
    // so one list call is cheaper than one get per path.
    let all_slices = ep_api
        .list(&ListParams::default())
        .await
        .map(|l| l.items)
        .unwrap_or_default();

    let mut routes = Vec::new();

    for rule in spec.rules.iter().flatten() {
        let host = rule
            .host
            .clone()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "*".into());

        let Some(http) = &rule.http else {
            continue;
        };

        for path in &http.paths {
            let path_str = path
                .path
                .clone()
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "/".into());
            let path_type = path.path_type.clone();

            let mut hops = Vec::new();

            // Hop 1: the Ingress itself (always ok — we fetched it successfully).
            hops.push(RouteHop {
                kind: "Ingress".into(),
                name: ing_name.clone(),
                namespace: ing_ns.clone(),
                status: "ok".into(),
                detail: format!("host={host}, path={path_str}"),
            });

            // Hop 2: the backend Service.
            let Some(svc_backend) = &path.backend.service else {
                hops.push(RouteHop {
                    kind: "Service".into(),
                    name: "(none)".into(),
                    namespace: ing_ns.clone(),
                    status: "error".into(),
                    detail: "no backend service defined".into(),
                });
                routes.push(IngressRoute {
                    host: host.clone(),
                    path: path_str,
                    path_type,
                    overall_status: overall_status(&hops),
                    hops,
                });
                continue;
            };

            let svc_name = svc_backend.name.clone();
            let port_display = super::properties::network::backend_port(svc_backend.port.as_ref());

            match svc_api.get(&svc_name).await {
                Ok(svc) => {
                    let svc_type = svc
                        .spec
                        .as_ref()
                        .and_then(|s| s.type_.clone())
                        .unwrap_or_else(|| "ClusterIP".into());
                    let cluster_ip = svc
                        .spec
                        .as_ref()
                        .and_then(|s| s.cluster_ip.clone())
                        .unwrap_or_default();

                    hops.push(RouteHop {
                        kind: "Service".into(),
                        name: svc_name.clone(),
                        namespace: ing_ns.clone(),
                        status: "ok".into(),
                        detail: format!(
                            "type={svc_type}, clusterIP={cluster_ip}, port={port_display}"
                        ),
                    });

                    // Hop 3: Endpoints — check if any Pods back this Service.
                    let addr_count = count_ready_addresses(&all_slices, &svc_name);

                    if addr_count > 0 {
                        hops.push(RouteHop {
                            kind: "Endpoints".into(),
                            name: svc_name.clone(),
                            namespace: ing_ns.clone(),
                            status: "ok".into(),
                            detail: format!("{addr_count} endpoint(s) ready"),
                        });
                    } else {
                        hops.push(RouteHop {
                            kind: "Endpoints".into(),
                            name: svc_name.clone(),
                            namespace: ing_ns.clone(),
                            status: "error".into(),
                            detail: "no endpoints — Service has no backing Pods".into(),
                        });
                    }
                }
                Err(_) => {
                    hops.push(RouteHop {
                        kind: "Service".into(),
                        name: svc_name,
                        namespace: ing_ns.clone(),
                        status: "error".into(),
                        detail: "Service not found".into(),
                    });
                }
            }

            routes.push(IngressRoute {
                host: host.clone(),
                path: path_str,
                path_type,
                overall_status: overall_status(&hops),
                hops,
            });
        }
    }

    Ok(IngressDebugResult {
        ingress: ing_name,
        namespace: ing_ns,
        ingress_class: ing_class,
        tls: has_tls,
        routes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(status: &str) -> RouteHop {
        RouteHop {
            kind: "Test".into(),
            name: "x".into(),
            namespace: "default".into(),
            status: status.into(),
            detail: String::new(),
        }
    }

    /// All hops ok => overall ok.
    #[test]
    fn overall_ok_when_all_hops_ok() {
        let hops = vec![hop("ok"), hop("ok"), hop("ok")];
        assert_eq!(overall_status(&hops), "ok");
    }

    /// Any warning => overall warning.
    #[test]
    fn overall_warning_on_any_warning() {
        let hops = vec![hop("ok"), hop("warning"), hop("ok")];
        assert_eq!(overall_status(&hops), "warning");
    }

    /// Any error => overall error, even if a warning is also present.
    #[test]
    fn overall_error_on_any_error() {
        let hops = vec![hop("ok"), hop("warning"), hop("error")];
        assert_eq!(overall_status(&hops), "error");
    }

    /// Error takes precedence over warning.
    #[test]
    fn error_beats_warning() {
        let hops = vec![hop("warning"), hop("error")];
        assert_eq!(overall_status(&hops), "error");
    }

    /// Empty hops => ok (vacuously true — no failures).
    #[test]
    fn overall_ok_for_empty_hops() {
        assert_eq!(overall_status(&[]), "ok");
    }

    /// Single error hop => error.
    #[test]
    fn single_error_hop() {
        let hops = vec![hop("error")];
        assert_eq!(overall_status(&hops), "error");
    }

    /// count_ready_addresses filters by service name label and ready condition.
    #[test]
    fn count_ready_filters_correctly() {
        use k7s_deps::k8s_openapi::api::discovery::v1::{
            Endpoint, EndpointConditions, EndpointSlice,
        };
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use std::collections::BTreeMap;

        let make_slice =
            |name: &str, svc: &str, addresses: Vec<&str>, ready: Option<bool>| -> EndpointSlice {
                let mut labels = BTreeMap::new();
                labels.insert("kubernetes.io/service-name".into(), svc.into());
                EndpointSlice {
                    metadata: ObjectMeta {
                        name: Some(name.into()),
                        namespace: Some("default".into()),
                        labels: Some(labels),
                        ..Default::default()
                    },
                    endpoints: Some(
                        addresses
                            .into_iter()
                            .map(|a| Endpoint {
                                addresses: vec![a.into()],
                                conditions: Some(EndpointConditions {
                                    ready,
                                    ..Default::default()
                                }),
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..Default::default()
                }
            };

        let slices = vec![
            make_slice("svc-a-1", "svc-a", vec!["10.0.0.1", "10.0.0.2"], Some(true)),
            make_slice("svc-a-2", "svc-a", vec!["10.0.0.3"], Some(false)),
            make_slice("svc-b-1", "svc-b", vec!["10.0.1.1"], Some(true)),
        ];

        // svc-a: 2 ready (the third is not-ready).
        assert_eq!(count_ready_addresses(&slices, "svc-a"), 2);
        // svc-b: 1 ready.
        assert_eq!(count_ready_addresses(&slices, "svc-b"), 1);
        // svc-c: not present.
        assert_eq!(count_ready_addresses(&slices, "svc-c"), 0);
    }
}
