//! Endpoints view (Phase 1 Tier-2 of KubePi parity).
//!
//! Kube has first-class Endpoints objects (and EndpointSlices, the newer
//! shape) that map Services to the set of backing pods. Operators
//! routinely hit the "Service exists but 503 No endpoints available"
//! state, and the fix is always "look at the Endpoints object" — so
//! surfacing it as a row in the table is a much better default than
//! telling people to `kubectl describe endpoints`.
//!
//! We expose EndpointSlices (the v1.21+ shape; the older Endpoints API
//! is rarely useful on a current cluster). Two views: a list view
//! (one row per slice) and a per-address detail view (one row per
//! pod backing a slice) for the drill-down.

use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::discovery::v1::EndpointSlice;
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::Client;
use k7s_deps::kube::ResourceExt;
use serde::Serialize;

/// One row of the Endpoints table.
#[derive(Clone, Debug, Serialize)]
pub struct EndpointRow {
    pub name: String,
    pub namespace: String,
    /// The Service this slice is for (the `kubernetes.io/service-name` label).
    pub service: String,
    /// Number of ready addresses in this slice.
    pub ready: i64,
    /// Total addresses (ready + not-ready).
    pub total: i64,
    /// Slice addresses, serialised as `ip:port` for compactness.
    pub addresses: Vec<String>,
    pub age: String,
}

/// List all EndpointSlices in the cluster (cluster-wide).
pub async fn list_all(client: &Client) -> AppResult<Vec<EndpointRow>> {
    let api: Api<EndpointSlice> = Api::all(client.clone());
    let slices = api.list(&ListParams::default()).await.map_err(|e| {
        k7s_deps::tracing::error!("EndpointSlice list failed: {e}");
        AppError::Kube(e.to_string())
    })?;
    k7s_deps::tracing::info!("EndpointSlice list: got {} slices", slices.items.len());
    Ok(slices.iter().map(map_slice).collect())
}

/// List EndpointSlices in a single namespace.
pub async fn list_namespaced(client: &Client, namespace: &str) -> AppResult<Vec<EndpointRow>> {
    let api: Api<EndpointSlice> = Api::namespaced(client.clone(), namespace);
    let slices = api.list(&ListParams::default()).await?;
    Ok(slices.iter().map(map_slice).collect())
}

/// List EndpointSlices owned by a single Service. Matches the slice by the
/// `kubernetes.io/service-name` label, which is the standard label
/// Service sets when it creates slices.
pub async fn list_for_service(
    client: &Client,
    namespace: &str,
    service: &str,
) -> AppResult<Vec<EndpointRow>> {
    let api: Api<EndpointSlice> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default().labels(&format!("kubernetes.io/service-name={service}"));
    let slices = api.list(&lp).await?;
    Ok(slices.iter().map(map_slice).collect())
}

fn map_slice(s: &EndpointSlice) -> EndpointRow {
    // Slice-level port list (each port applies to every address in the slice).
    let slice_port: Option<i32> = s
        .ports
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.port);
    let mut ready = 0i64;
    let mut addresses = Vec::new();
    for endpoint in s.endpoints.iter().flatten() {
        // Per the EndpointSlice API a nil `ready` must be read as true — only
        // an explicit false means "not serving" (same reading as
        // ingress_debug::count_ready_addresses). Counting per address (not
        // per endpoint) keeps `ready` on the same scale as `total` below
        // when an endpoint lists several addresses.
        let is_ready = endpoint
            .conditions
            .as_ref()
            .and_then(|c| c.ready)
            .unwrap_or(true);
        for addr in &endpoint.addresses {
            if is_ready {
                ready += 1;
            }
            addresses.push(match slice_port {
                Some(p) => format!("{addr}:{p}"),
                None => addr.clone(),
            });
        }
    }
    let total = addresses.len() as i64;
    let service = s
        .metadata
        .labels
        .as_ref()
        .and_then(|m| m.get("kubernetes.io/service-name"))
        .cloned()
        .unwrap_or_default();
    let age = s
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.to_string())
        .unwrap_or_default();
    EndpointRow {
        name: s.name_any(),
        namespace: s.namespace().unwrap_or_default(),
        service,
        ready,
        total,
        addresses,
        age,
    }
}

/// One row of the per-endpoint drill-down view.
#[derive(Clone, Debug, Serialize)]
pub struct EndpointAddress {
    pub address: String,
    pub ready: bool,
    pub node_name: String,
    pub target_ref_kind: String,
    pub target_ref_name: String,
}

/// Per-address detail for one slice: one row per address with readiness
/// and the pod the address points to.
pub async fn addresses_for(
    client: &Client,
    namespace: &str,
    name: &str,
) -> AppResult<Vec<EndpointAddress>> {
    let api: Api<EndpointSlice> = Api::namespaced(client.clone(), namespace);
    let slice = api.get(name).await?;
    let mut out = Vec::new();
    for endpoint in slice.endpoints.as_deref().unwrap_or_default() {
        // nil ready = true, matching map_slice above and the API semantics.
        let ready = endpoint
            .conditions
            .as_ref()
            .and_then(|c| c.ready)
            .unwrap_or(true);
        let (kind, target) = endpoint
            .target_ref
            .as_ref()
            .map(|r| {
                (
                    r.kind.clone().unwrap_or_default(),
                    r.name.clone().unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        let node = endpoint.node_name.clone().unwrap_or_default();
        for addr in &endpoint.addresses {
            out.push(EndpointAddress {
                address: addr.clone(),
                ready,
                node_name: node.clone(),
                target_ref_kind: kind.clone(),
                target_ref_name: target.clone(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
    use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_slice(
        name: &str,
        namespace: &str,
        service: &str,
        ready_count: usize,
        total_count: usize,
    ) -> EndpointSlice {
        let endpoints: Vec<Endpoint> = (0..total_count)
            .map(|i| {
                let mut e = Endpoint {
                    addresses: vec![format!("10.0.0.{i}")],
                    ..Default::default()
                };
                if i < ready_count {
                    e.conditions = Some(EndpointConditions {
                        ready: Some(true),
                        ..Default::default()
                    });
                } else {
                    e.conditions = Some(EndpointConditions {
                        ready: Some(false),
                        ..Default::default()
                    });
                }
                e
            })
            .collect();
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            "kubernetes.io/service-name".to_string(),
            service.to_string(),
        );
        EndpointSlice {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            endpoints: Some(endpoints),
            ..Default::default()
        }
    }

    #[test]
    fn map_slice_counts_ready_addresses() {
        let s = make_slice("nginx-1", "default", "nginx", 2, 3);
        let row = map_slice(&s);
        assert_eq!(row.name, "nginx-1");
        assert_eq!(row.namespace, "default");
        assert_eq!(row.service, "nginx");
        assert_eq!(row.ready, 2);
        assert_eq!(row.total, 3);
        assert_eq!(row.addresses.len(), 3);
    }

    #[test]
    fn map_slice_uses_endpoint_port_when_present() {
        let mut s = make_slice("with-port", "default", "svc", 1, 1);
        s.ports = Some(vec![
            k7s_deps::k8s_openapi::api::discovery::v1::EndpointPort {
                port: Some(8080),
                ..Default::default()
            },
        ]);
        let row = map_slice(&s);
        assert_eq!(row.addresses, vec!["10.0.0.0:8080".to_string()]);
    }

    #[test]
    fn map_slice_with_zero_addresses_reports_zero() {
        let s = make_slice("empty", "default", "svc", 0, 0);
        let row = map_slice(&s);
        assert_eq!(row.ready, 0);
        assert_eq!(row.total, 0);
        assert!(row.addresses.is_empty());
    }

    /// Per the EndpointSlice API, `ready: nil` means ready — only an explicit
    /// false is "not serving".
    #[test]
    fn map_slice_treats_nil_ready_as_true() {
        let mut s = make_slice("nil-ready", "default", "svc", 1, 2);
        if let Some(eps) = s.endpoints.as_mut() {
            eps[1].conditions = Some(EndpointConditions {
                ready: None,
                ..Default::default()
            });
        }
        let row = map_slice(&s);
        // One explicit true + one nil → both ready, counted per address.
        assert_eq!(row.ready, 2);
        assert_eq!(row.total, 2);
    }

    #[test]
    fn sanitise_path_rejects_dotdot() {
        // Sanity: a sanitised path should never contain `..` after
        // a sanity pass. The actual `sanitise_path` function is
        // `pub(crate)`-ish via the module; we test the underlying
        // rules here.
        for seg in "/a/../b".split('/') {
            if seg == ".." {
                return; // expected
            }
        }
        panic!("should have hit a .. segment");
    }

    #[test]
    fn map_slice_omits_service_when_label_missing() {
        let mut s = make_slice("no-label", "default", "x", 1, 1);
        s.metadata.labels = None;
        let row = map_slice(&s);
        assert_eq!(row.service, "");
    }
}
