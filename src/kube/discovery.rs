//! CRD discovery (B15). Lists the cluster's CustomResourceDefinitions and turns
//! them into [`CustomKind`]s the frontend can show as extra nav entries.
//!
//! We read CRDs directly rather than sweeping the full discovery API and
//! blocklisting the built-in groups: a CRD *is* the definition of a custom kind,
//! so this yields exactly the right set (with its scope and storage version)
//! without guessing, and it can't accidentally surface built-in resources.
//!
//! Discovery is best-effort. A cluster whose RBAC forbids listing CRDs simply has
//! no Custom section — the twelve built-in kinds are unaffected.

use crate::error::AppResult;
use k7s_deps::futures::StreamExt;
use k7s_deps::k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k7s_deps::kube::api::{Api, DynamicObject, ListParams};
use k7s_deps::kube::core::{ApiResource, GroupVersionKind};
use k7s_deps::kube::Client;
use serde::Serialize;

/// A CRD-backed resource kind, as sent to the frontend.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CustomKind {
    /// Stable frontend id, always "group/plural" (e.g. "argoproj.io/applications").
    /// The slash is what distinguishes a custom kind from a built-in one, whose id
    /// is a bare plural ("pods").
    pub id: String,
    pub group: String,
    /// The version we watch: the storage version, else the first served one.
    pub version: String,
    /// Kind name, e.g. "Application" (the nav label).
    pub kind: String,
    pub plural: String,
    /// False for cluster-scoped CRDs (they ignore the namespace filter).
    pub namespaced: bool,
}

impl CustomKind {
    /// The `ApiResource` used to build dynamic APIs and watchers for this kind.
    pub fn api_resource(&self) -> ApiResource {
        let gvk = GroupVersionKind::gvk(&self.group, &self.version, &self.kind);
        // Use the CRD's declared plural rather than letting kube guess it.
        ApiResource::from_gvk_with_plural(&gvk, &self.plural)
    }
}

/// List CRD-backed kinds, sorted by id. Returns empty (with a warning) if CRDs
/// can't be listed — a cluster with no CRDs and one that forbids them look the
/// same to the user, and neither is an error worth failing the connection over.
pub async fn discover(client: &Client) -> Vec<CustomKind> {
    let api: Api<CustomResourceDefinition> = Api::all(client.clone());
    let crds = match api.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            k7s_deps::tracing::warn!(
                "CRD discovery unavailable; no custom kinds will be shown: {e}"
            );
            return Vec::new();
        }
    };

    let mut kinds: Vec<CustomKind> = crds.items.iter().filter_map(to_custom_kind).collect();
    kinds.sort_by(|a, b| a.id.cmp(&b.id));
    kinds
}

/// Convert one CRD into a [`CustomKind`], or None if it has no usable version.
fn to_custom_kind(crd: &CustomResourceDefinition) -> Option<CustomKind> {
    let spec = &crd.spec;
    let version = storage_version(crd)?;
    let plural = spec.names.plural.clone();
    let group = spec.group.clone();
    Some(CustomKind {
        id: format!("{group}/{plural}"),
        group,
        version,
        kind: spec.names.kind.clone(),
        plural,
        // scope is "Namespaced" or "Cluster".
        namespaced: spec.scope == "Namespaced",
    })
}

/// The version to watch: the storage version (the one that definitely holds every
/// object), falling back to the first served version.
fn storage_version(crd: &CustomResourceDefinition) -> Option<String> {
    let versions = &crd.spec.versions;
    versions
        .iter()
        .find(|v| v.storage)
        .or_else(|| versions.iter().find(|v| v.served))
        .map(|v| v.name.clone())
}

/// Instance count for one CRD-backed kind, keyed by the same "group/plural" id
/// the frontend's custom-kinds list already carries.
#[derive(Debug, Clone, Serialize)]
pub struct CustomKindCount {
    pub id: String,
    pub count: u64,
}

/// One cheap LIST (limit=1, remainingItemCount) per discovered CRD.
/// Best-effort per kind: RBAC-denied or failed kinds report count 0.
/// Bounded concurrency (8) so 40+ CRDs don't stampede the API server.
///
/// The API server does the counting for us: with `limit=1` it returns one item
/// plus `metadata.remainingItemCount`, so a cluster with 900 Argo Applications
/// costs one row over the wire, not 900. Kinds whose list fails (RBAC denied,
/// aggregated APIs that 503, a CRD whose served version vanished mid-flight)
/// report 0 and the sweep continues — a missing badge is cosmetic, an error
/// would block the whole custom-kinds section.
pub async fn custom_kind_counts(client: &Client) -> AppResult<Vec<CustomKindCount>> {
    let kinds = discover(client).await;
    let mut counts: Vec<CustomKindCount> = k7s_deps::futures::stream::iter(kinds)
        .map(|kind| {
            let client = client.clone();
            async move {
                let api: Api<DynamicObject> = Api::all_with(client, &kind.api_resource());
                let count = match api.list(&ListParams::default().limit(1)).await {
                    Ok(list) => {
                        count_from_list(list.items.len(), list.metadata.remaining_item_count)
                    }
                    Err(e) => {
                        k7s_deps::tracing::debug!(
                            kind = %kind.id,
                            "custom kind count unavailable, reporting 0: {e}"
                        );
                        0
                    }
                };
                CustomKindCount { id: kind.id, count }
            }
        })
        // buffer_unordered completes in arrival order, so the sweep is gated by
        // the slowest CRD, not by how many there are.
        .buffer_unordered(8)
        .collect()
        .await;
    // Re-sort: buffer_unordered yields in completion order; keep discover()'s
    // stable id order so consecutive responses diff cleanly.
    counts.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(counts)
}

/// Total from a chunked list: the items in this chunk plus the server-reported
/// remainder. A negative remainder (malformed server response) clamps to 0 —
/// `as u64` on a negative i64 would wrap to a astronomically wrong badge.
fn count_from_list(items: usize, remaining: Option<i64>) -> u64 {
    items as u64 + remaining.unwrap_or(0).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json::json;

    /// Build a CRD fixture with the given versions as (name, served, storage).
    fn crd(
        group: &str,
        kind: &str,
        plural: &str,
        scope: &str,
        versions: &[(&str, bool, bool)],
    ) -> CustomResourceDefinition {
        let versions: Vec<_> = versions
            .iter()
            .map(|(name, served, storage)| {
                json!({ "name": name, "served": served, "storage": storage,
                        "schema": { "openAPIV3Schema": { "type": "object" } } })
            })
            .collect();
        k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": format!("{plural}.{group}") },
            "spec": {
                "group": group,
                "scope": scope,
                "names": { "kind": kind, "plural": plural, "singular": kind.to_lowercase() },
                "versions": versions,
            },
        }))
        .unwrap()
    }

    /// The id is "group/plural" and the scope maps to `namespaced`.
    #[test]
    fn maps_crd_to_custom_kind() {
        let c = crd(
            "argoproj.io",
            "Application",
            "applications",
            "Namespaced",
            &[("v1alpha1", true, true)],
        );
        let k = to_custom_kind(&c).unwrap();
        assert_eq!(k.id, "argoproj.io/applications");
        assert_eq!(k.kind, "Application");
        assert_eq!(k.version, "v1alpha1");
        assert!(k.namespaced);
    }

    /// Cluster-scoped CRDs are marked so the namespace filter can ignore them.
    #[test]
    fn cluster_scoped_crd() {
        let c = crd(
            "cert-manager.io",
            "ClusterIssuer",
            "clusterissuers",
            "Cluster",
            &[("v1", true, true)],
        );
        assert!(!to_custom_kind(&c).unwrap().namespaced);
    }

    /// Multi-version CRDs are watched at the storage version, not merely a served one.
    #[test]
    fn prefers_storage_version() {
        let c = crd(
            "example.com",
            "Widget",
            "widgets",
            "Namespaced",
            &[
                ("v1alpha1", true, false),
                ("v1beta1", true, true),
                ("v2", false, false),
            ],
        );
        assert_eq!(to_custom_kind(&c).unwrap().version, "v1beta1");
    }

    /// A CRD with no storage version still resolves via the first served version.
    #[test]
    fn falls_back_to_served_version() {
        let c = crd(
            "example.com",
            "Widget",
            "widgets",
            "Namespaced",
            &[("v1", true, false)],
        );
        assert_eq!(to_custom_kind(&c).unwrap().version, "v1");
    }

    /// The ApiResource uses the CRD's declared plural rather than a guessed one.
    #[test]
    fn api_resource_uses_declared_plural() {
        let c = crd(
            "traefik.io",
            "IngressRoute",
            "ingressroutes",
            "Namespaced",
            &[("v1alpha1", true, true)],
        );
        let ar = to_custom_kind(&c).unwrap().api_resource();
        assert_eq!(ar.plural, "ingressroutes");
        assert_eq!(ar.kind, "IngressRoute");
        assert_eq!(ar.group, "traefik.io");
    }

    /// A limit=1 list with a remainder counts items + remainingItemCount.
    #[test]
    fn count_adds_remaining_items() {
        assert_eq!(count_from_list(1, Some(899)), 900);
    }

    /// An unchunked (complete) list has no remainder — count is just the items.
    #[test]
    fn count_without_remainder() {
        assert_eq!(count_from_list(7, None), 7);
        assert_eq!(count_from_list(0, None), 0);
    }

    /// A malformed negative remainder clamps to 0 instead of wrapping u64.
    #[test]
    fn negative_remainder_clamps_to_zero() {
        assert_eq!(count_from_list(3, Some(-5)), 3);
    }
}
