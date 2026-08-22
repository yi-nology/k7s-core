//! Properties (B13, B18): the "what is this thing actually wired to" view — the
//! things you'd otherwise dig out of YAML or several kubectl commands.
//!
//! Rather than a bespoke DTO and renderer per kind, a gatherer returns a generic
//! [`Properties`] document: an ordered list of [`Section`]s, each a field grid, a
//! table, or a set of chips. The frontend renders that shape for every kind, so
//! adding a kind is one gatherer here and nothing there.
//!
//! Every lookup beyond the object itself is best-effort: a missing PVC/PV or an
//! RBAC denial degrades that row or section rather than failing the whole panel.
//!
//! Kinds with a gatherer (see [`gather`]) show the tab; the rest don't.

mod cluster;
mod config;
mod extensions;
mod helm;
pub(crate) mod network;
mod pod;
mod rbac;
mod workload;

use super::dto::{Cell, NavTarget, Tone};
use super::helm as helm_mod;
use super::ResourceKind;
use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::apps::v1::ReplicaSet;
use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k7s_deps::kube::api::Api;
use k7s_deps::kube::{Client, ResourceExt};
use serde::Serialize;
use std::collections::BTreeMap;

/// A label/annotation entry (a list keeps frontend rendering simple).
#[derive(Serialize, Clone)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

/// One row of a field grid: a label, a toned value, and an optional nav target
/// that makes the value a click-through link (B33).
#[derive(Serialize)]
pub struct Field {
    pub label: String,
    pub value: Cell,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nav: Option<NavTarget>,
}

impl Field {
    /// Attach a nav target, making this field a link (builder style).
    fn with_nav(mut self, target: NavTarget) -> Self {
        self.nav = Some(target);
        self
    }
}

/// What a section renders as. Tagged so the frontend can switch on `type`.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Body {
    /// A label/value grid (the "Overview" shape).
    Fields { fields: Vec<Field> },
    /// A table. The frontend shows the row count beside the section title.
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<Cell>>,
    },
    /// key=value chips (labels/annotations).
    Chips { chips: Vec<KeyValue> },
}

/// One section of the Properties tab.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub title: String,
    /// Shown in place of an empty table ("no taints"). Without one, an empty
    /// table section is dropped entirely (see [`Properties::push_table`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_note: Option<String>,
    pub body: Body,
}

/// The whole panel: sections in display order.
#[derive(Serialize, Default)]
pub struct Properties {
    pub sections: Vec<Section>,
}

impl Properties {
    fn push(&mut self, section: Section) {
        self.sections.push(section);
    }

    /// Add a field grid.
    fn fields(&mut self, title: &str, fields: Vec<Field>) {
        self.push(Section {
            title: title.into(),
            empty_note: None,
            body: Body::Fields { fields },
        });
    }

    /// Add a table. `empty_note` = Some means an empty table still renders (with
    /// the note); None means an empty table is omitted, so optional sections like
    /// "Other volumes" simply don't appear when there's nothing to show.
    fn push_table(
        &mut self,
        title: &str,
        empty_note: Option<&str>,
        columns: &[&str],
        rows: Vec<Vec<Cell>>,
    ) {
        if rows.is_empty() && empty_note.is_none() {
            return;
        }
        self.push(Section {
            title: title.into(),
            empty_note: empty_note.map(Into::into),
            body: Body::Table {
                columns: columns.iter().map(|c| c.to_string()).collect(),
                rows,
            },
        });
    }

    /// Add a chips section, omitted when empty.
    fn chips(&mut self, title: &str, chips: Vec<KeyValue>) {
        if chips.is_empty() {
            return;
        }
        self.push(Section {
            title: title.into(),
            empty_note: None,
            body: Body::Chips { chips },
        });
    }
}

/// Placeholder for an unset value (matches the tables' em dash).
const DASH: &str = "\u{2014}";

fn or_dash(s: Option<String>) -> String {
    s.filter(|v| !v.is_empty()).unwrap_or_else(|| DASH.into())
}

/// A plain secondary-toned cell.
fn c(text: impl Into<String>) -> Cell {
    Cell::new(text.into(), Tone::Secondary)
}

/// A name cell (primary emphasis, matching the tables' NAME column).
fn name_cell(text: impl Into<String>) -> Cell {
    Cell::new(text.into(), Tone::Primary)
}

/// A muted cell (de-emphasized detail).
fn muted(text: impl Into<String>) -> Cell {
    Cell::new(text.into(), Tone::Muted)
}

/// A field with a secondary-toned value.
fn field(label: &str, value: impl Into<String>) -> Field {
    Field {
        label: label.into(),
        value: c(value.into()),
        nav: None,
    }
}

/// A field whose value carries a tone (e.g. a status).
fn field_toned(label: &str, value: impl Into<String>, tone: Tone) -> Field {
    Field {
        label: label.into(),
        value: Cell::new(value.into(), tone),
        nav: None,
    }
}

/// A cell naming another object that may not exist: link it when it does, say so
/// when it doesn't (B42). A link to a 404 is worse than the plain text it
/// replaced, and an absent reference is usually the answer to "why isn't this
/// working" — a missing backend Service is what an Ingress 503 looks like.
fn ref_cell(name: &str, exists: bool, target: NavTarget) -> Cell {
    if name.is_empty() || name == DASH {
        c(DASH)
    } else if exists {
        Cell::link(name.to_string(), Tone::Secondary, Some(target))
    } else {
        Cell::new(format!("{name} (not found)"), Tone::Warn)
    }
}

/// A field that is a click-through link when `nav` is Some (B33).
fn nav_field(label: &str, value: impl Into<String>, nav: Option<NavTarget>) -> Field {
    let f = field(label, value);
    match nav {
        Some(target) => f.with_nav(target),
        None => f,
    }
}

/// Map a built-in Kubernetes Kind (PascalCase) to the app's nav id, for the kinds
/// we list. Returns None for kinds without a table (e.g. Endpoints, Events, Helm),
/// so an owner of that kind renders as plain text rather than a dead link (B33).
pub fn builtin_nav_id(kind: &str) -> Option<&'static str> {
    use super::ResourceKind;
    let rk = ResourceKind::from_kind_name(kind)?;
    // Exclude kinds that have no nav table in the frontend.
    match rk {
        ResourceKind::Events
        | ResourceKind::Helm
        | ResourceKind::Mutatingwebhookconfigurations
        | ResourceKind::Validatingwebhookconfigurations
        | ResourceKind::Apiservices => None,
        _ => Some(rk.id()),
    }
}

/// Resolve a pod's controller owner into a display string and, where we can
/// navigate to it, a nav target (B33).
///
/// A ReplicaSet owner is resolved *through* to its Deployment — that's the
/// workload the user thinks of as the owner, and it stays the more useful
/// destination even now that ReplicaSets are listed (B40). A bare ReplicaSet (no
/// Deployment above it, or an RBAC-denied lookup) links to the ReplicaSet itself.
pub async fn resolve_owner(
    client: &Client,
    namespace: &str,
    pod: &Pod,
) -> (String, Option<NavTarget>) {
    let refs = pod.metadata.owner_references.as_ref();
    let owner = refs.and_then(|o| {
        o.iter()
            .find(|r| r.controller == Some(true))
            .or_else(|| o.first())
    });
    let Some(owner) = owner else {
        return (DASH.into(), None);
    };

    if owner.kind == "ReplicaSet" {
        let rs_api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
        if let Ok(rs) = rs_api.get(&owner.name).await {
            if let Some(dep) = rs
                .metadata
                .owner_references
                .as_ref()
                .and_then(|o| o.iter().find(|r| r.kind == "Deployment"))
            {
                return (
                    format!("Deployment/{}", dep.name),
                    Some(NavTarget {
                        kind: "deployments".into(),
                        namespace: Some(namespace.to_string()),
                        name: dep.name.clone(),
                    }),
                );
            }
        }
        // A bare ReplicaSet (no Deployment above it, or the lookup was denied).
        // Since B40 lists ReplicaSets, this is a real destination now rather than
        // the dead end it used to be.
        return (
            format!("ReplicaSet/{}", owner.name),
            Some(NavTarget::namespaced(
                "replicasets",
                namespace,
                owner.name.clone(),
            )),
        );
    }

    let display = format!("{}/{}", owner.kind, owner.name);
    match builtin_nav_id(&owner.kind) {
        // A Node owner (static/mirror pods) is cluster-scoped; everything else
        // shares the pod's namespace.
        Some(nav) => {
            let namespace = (nav != "nodes").then(|| namespace.to_string());
            (
                display,
                Some(NavTarget {
                    kind: nav.into(),
                    namespace,
                    name: owner.name.clone(),
                }),
            )
        }
        None => (display, None),
    }
}

/// Map a BTreeMap of labels/annotations into a KeyValue list (sorted by BTreeMap).
fn to_kv(map: Option<&BTreeMap<String, String>>) -> Vec<KeyValue> {
    map.map(|m| {
        m.iter()
            .map(|(k, v)| KeyValue {
                key: k.clone(),
                value: v.clone(),
            })
            .collect()
    })
    .unwrap_or_default()
}

/// Render a selector map as `k=v,k2=v2` (the form kubectl prints and accepts).
fn selector_text(map: Option<&BTreeMap<String, String>>) -> String {
    match map {
        Some(m) if !m.is_empty() => m
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(","),
        _ => DASH.into(),
    }
}

/// A quantity as its original string ("100m", "2Gi"), or a dash.
fn qty(q: Option<&Quantity>) -> String {
    q.map(|q| q.0.clone()).unwrap_or_else(|| DASH.into())
}

/// Render an IntOrString ("25%" or "1").
pub(super) fn int_or_string(
    v: &k7s_deps::k8s_openapi::apimachinery::pkg::util::intstr::IntOrString,
) -> String {
    use k7s_deps::k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    match v {
        IntOrString::Int(i) => i.to_string(),
        IntOrString::String(s) => s.clone(),
    }
}

/// "n/total" ready-style tone: green when all ready, amber when partial, red at zero.
fn ready_tone(ready: i32, desired: i32) -> Tone {
    if desired == 0 {
        Tone::Muted
    } else if ready >= desired {
        Tone::Good
    } else if ready == 0 {
        Tone::Bad
    } else {
        Tone::Warn
    }
}

/// Tone for a condition's status.
///
/// Most conditions are "good when True" (Ready, Available), but the pressure-style
/// ones invert — a Node with MemoryPressure=True is unhealthy. Getting this wrong
/// would paint a struggling node green, so the polarity is explicit.
fn condition_tone(type_: &str, status: &str) -> Tone {
    let good_when_true = !matches!(
        type_,
        "MemoryPressure" | "DiskPressure" | "PIDPressure" | "NetworkUnavailable" | "ReplicaFailure"
    );
    match (status, good_when_true) {
        ("True", true) | ("False", false) => Tone::Good,
        ("False", true) | ("True", false) => Tone::Bad,
        // "Unknown" — the kubelet stopped reporting, or the controller hasn't yet.
        _ => Tone::Warn,
    }
}

/// One condition, flattened from the per-kind condition types (which share these
/// fields but no common trait).
struct Condition {
    type_: String,
    status: String,
    reason: String,
    message: String,
    /// RFC3339 last transition time, if reported.
    since: Option<String>,
}

/// Build the standard Conditions table.
fn conditions_section(props: &mut Properties, conds: Vec<Condition>) {
    let rows = conds
        .into_iter()
        .map(|c0| {
            vec![
                name_cell(c0.type_.clone()),
                Cell::new(c0.status.clone(), condition_tone(&c0.type_, &c0.status)),
                c(c0.reason),
                c(c0.message),
                match c0.since {
                    Some(t) => Cell::age(Some(t)),
                    None => muted(DASH),
                },
            ]
        })
        .collect();
    props.push_table(
        "Conditions",
        Some("no conditions reported"),
        &["TYPE", "STATUS", "REASON", "MESSAGE", "SINCE"],
        rows,
    );
}

/// The standard meta sections every namespaced resource gets: labels,
/// annotations, and (when present) owner references.
fn meta_sections<K: ResourceExt>(props: &mut Properties, obj: &K) {
    props.chips("Labels", to_kv(Some(obj.labels())));
    props.chips("Annotations", to_kv(Some(obj.annotations())));
}

pub async fn gather(
    client: Client,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<Properties> {
    match kind {
        "pods" => pod::gather_pod(client, namespace, name).await,
        "deployments" => workload::gather_deployment(client, namespace, name).await,
        "services" => network::gather_service(client, namespace, name).await,
        "statefulsets" => workload::gather_statefulset(client, namespace, name).await,
        "daemonsets" => workload::gather_daemonset(client, namespace, name).await,
        "replicasets" => workload::gather_replicaset(client, namespace, name).await,
        "ingresses" => network::gather_ingress(client, namespace, name).await,
        "nodes" => cluster::gather_node(client, name).await,
        "configmaps" => config::gather_configmap(client, namespace, name).await,
        "secrets" => config::gather_secret(client, namespace, name).await,
        "namespaces" => config::gather_namespace(client, name).await,
        "storageclasses" => cluster::gather_storageclass(client, name).await,
        "serviceaccounts" => cluster::gather_serviceaccount(client, namespace, name).await,
        "persistentvolumeclaims" => cluster::gather_pvc(client, namespace, name).await,
        "persistentvolumes" => cluster::gather_pv(client, name).await,
        "jobs" => workload::gather_job(client, namespace, name).await,
        "cronjobs" => workload::gather_cronjob(client, namespace, name).await,
        "horizontalpodautoscalers" => workload::gather_hpa(client, namespace, name).await,
        "networkpolicies" => network::gather_networkpolicy(client, namespace, name).await,
        "resourcequotas" => config::gather_resourcequota(client, namespace, name).await,
        "roles" => rbac::gather_role(client, namespace, name).await,
        "clusterroles" => rbac::gather_clusterrole(client, name).await,
        "rolebindings" => rbac::gather_rolebinding(client, namespace, name).await,
        "clusterrolebindings" => rbac::gather_clusterrolebinding(client, name).await,
        "helm" => helm::gather_helm(client, namespace, name).await,
        "poddisruptionbudgets" => extensions::gather_pdb(client, namespace, name).await,
        "mutatingwebhookconfigurations" => extensions::gather_webhook(client, name, true).await,
        "validatingwebhookconfigurations" => extensions::gather_webhook(client, name, false).await,
        "apiservices" => extensions::gather_api_service(client, name).await,
        other if other.contains('/') => extensions::gather_crd_detail(client, other).await,
        other => Err(AppError::Other(format!("no properties for kind {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ready/Available read green when True; the same status on a pressure
    /// condition reads red, because those inverted types mean the opposite.
    #[test]
    fn condition_polarity_is_per_type() {
        assert_eq!(condition_tone("Ready", "True"), Tone::Good);
        assert_eq!(condition_tone("Ready", "False"), Tone::Bad);
        assert_eq!(condition_tone("Available", "True"), Tone::Good);
        // A node under memory pressure is unhealthy, not healthy.
        assert_eq!(condition_tone("MemoryPressure", "True"), Tone::Bad);
        assert_eq!(condition_tone("MemoryPressure", "False"), Tone::Good);
        assert_eq!(condition_tone("DiskPressure", "True"), Tone::Bad);
        assert_eq!(condition_tone("ReplicaFailure", "True"), Tone::Bad);
    }

    /// An unreported condition ("Unknown") is a warning either way.
    #[test]
    fn unknown_condition_is_a_warning() {
        assert_eq!(condition_tone("Ready", "Unknown"), Tone::Warn);
        assert_eq!(condition_tone("MemoryPressure", "Unknown"), Tone::Warn);
    }

    /// Helm history (B35): revisions decoded in any order render newest-first,
    /// the current revision's status leads the Overview, superseded rows read
    /// muted and the current deployed row reads ok, and values are redacted.
    #[test]
    fn helm_history_orders_and_tones() {
        let rel = |revision: i64, status: &str| helm_mod::Release {
            name: "redis".into(),
            namespace: "prod".into(),
            chart: "redis-1.2.3".into(),
            app_version: "7.2".into(),
            revision,
            status: status.into(),
            updated: format!("2026-06-0{revision}T00:00:00Z"),
            first_deployed: "2026-06-01T00:00:00Z".into(),
            description: "Upgrade complete".into(),
            config: k7s_deps::serde_json::json!({ "auth": { "password": "hunter2" }, "replicas": 3 }),
            manifest: String::new(),
        };
        // Deliberately unsorted input: v1, v3, v2.
        let props = helm::build_helm_properties(vec![
            rel(1, "superseded"),
            rel(3, "deployed"),
            rel(2, "superseded"),
        ]);

        // Overview leads with the current (highest) revision.
        let overview = match &props.sections[0].body {
            Body::Fields { fields } => fields,
            _ => panic!("first section is the Overview grid"),
        };
        let status = overview.iter().find(|f| f.label == "status").unwrap();
        assert_eq!(status.value.text, "deployed");
        assert_eq!(status.value.tone, Tone::Good, "current deployed reads ok");
        let revision = overview.iter().find(|f| f.label == "revision").unwrap();
        assert_eq!(revision.value.text, "3");

        // History is newest-first, with the right per-row toning.
        let history = props
            .sections
            .iter()
            .find(|s| s.title == "History")
            .unwrap();
        let rows = match &history.body {
            Body::Table { rows, .. } => rows,
            _ => panic!("History is a table"),
        };
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0][0].text, "3");
        assert_eq!(rows[0][1].tone, Tone::Good, "current revision ok");
        assert_eq!(rows[1][0].text, "2");
        assert_eq!(rows[1][1].tone, Tone::Muted, "superseded reads muted");
        assert_eq!(rows[2][0].text, "1");

        // Values are redacted, and the password never reaches the cells.
        let values = props.sections.iter().find(|s| s.title == "Values").unwrap();
        let vrows = match &values.body {
            Body::Table { rows, .. } => rows,
            _ => panic!("Values is a table"),
        };
        let dumped = format!("{vrows:?}");
        assert!(
            !dumped.contains("hunter2"),
            "the password must never reach the payload"
        );
        assert!(vrows
            .iter()
            .any(|r| r[0].text == "auth.password" && r[1].text == "<redacted>"));
        assert!(vrows
            .iter()
            .any(|r| r[0].text == "replicas" && r[1].text == "3"));
    }

    /// An Ingress backend port is a number *or* a name; murphy-yi's only Ingress uses
    /// a name, so a number-only reading would silently show nothing.
    #[test]
    fn backend_port_takes_a_number_or_a_name() {
        let port = |v: k7s_deps::serde_json::Value| -> k7s_deps::k8s_openapi::api::networking::v1::ServiceBackendPort {
            k7s_deps::serde_json::from_value(v).unwrap()
        };
        assert_eq!(
            network::backend_port(Some(&port(k7s_deps::serde_json::json!({ "number": 8080 })))),
            "8080"
        );
        assert_eq!(
            network::backend_port(Some(&port(k7s_deps::serde_json::json!({ "name": "http" })))),
            "http"
        );
        // A number wins when both are somehow set, matching the API's precedence.
        assert_eq!(
            network::backend_port(Some(&port(
                k7s_deps::serde_json::json!({ "number": 80, "name": "http" })
            ))),
            "80"
        );
        assert_eq!(network::backend_port(None), "\u{2014}");
    }

    /// A reference that resolves becomes a link; one that doesn't says so rather
    /// than linking to a 404 (B42) — the rule the whole audit kept re-learning.
    #[test]
    fn ref_cell_links_only_what_exists() {
        let target = || NavTarget::namespaced("services", "prod", "api");

        let present = ref_cell("api", true, target());
        assert_eq!(present.text, "api");
        assert!(present.nav.is_some());
        assert_eq!(present.tone, Tone::Secondary);

        let missing = ref_cell("api", false, target());
        assert_eq!(missing.text, "api (not found)");
        assert!(
            missing.nav.is_none(),
            "never link to something that isn't there"
        );
        assert_eq!(missing.tone, Tone::Warn);

        // "nothing referenced" is not the same as "referenced but missing".
        let none = ref_cell(DASH, false, target());
        assert_eq!(none.text, DASH);
        assert!(none.nav.is_none());
        assert_eq!(none.tone, Tone::Secondary);
    }

    /// Owner-kind → nav id: kinds we list resolve; kinds we don't return None so
    /// the reference stays plain text rather than becoming a dead link (B33).
    #[test]
    fn builtin_nav_id_only_maps_listed_kinds() {
        assert_eq!(builtin_nav_id("Deployment"), Some("deployments"));
        assert_eq!(builtin_nav_id("StatefulSet"), Some("statefulsets"));
        assert_eq!(builtin_nav_id("DaemonSet"), Some("daemonsets"));
        assert_eq!(builtin_nav_id("Node"), Some("nodes"));
        // Listed as of B40 — these used to be the canonical dead ends.
        assert_eq!(builtin_nav_id("ReplicaSet"), Some("replicasets"));
        assert_eq!(builtin_nav_id("StorageClass"), Some("storageclasses"));
        assert_eq!(
            builtin_nav_id("PersistentVolumeClaim"),
            Some("persistentvolumeclaims")
        );
        assert_eq!(builtin_nav_id("ServiceAccount"), Some("serviceaccounts"));
        // Still unlisted, so still correctly None.
        assert_eq!(builtin_nav_id("Endpoints"), None);
        assert_eq!(builtin_nav_id("PriorityClass"), None);
        assert_eq!(builtin_nav_id("FooBar"), None);
    }

    /// Inline volume sources resolve to the detail that identifies them: a
    /// ConfigMap links through, while a host path / NFS export / CSI driver is
    /// plain text (they aren't cluster objects to navigate to). Before this, every
    /// non-ConfigMap/Secret volume showed a bare em dash for its source.
    #[test]
    fn volume_source_names_inline_backings() {
        use k7s_deps::serde_json::json;
        let vol =
            |body: k7s_deps::serde_json::Value| -> k7s_deps::k8s_openapi::api::core::v1::Volume {
                k7s_deps::serde_json::from_value(body).unwrap()
            };

        let (src, nav) = pod::volume_source(
            &vol(json!({ "name": "cfg", "configMap": { "name": "app-config" } })),
            "prod",
        );
        assert_eq!(src, "app-config");
        assert!(nav.is_some(), "a ConfigMap is a listed kind, so it links");

        let (src, nav) = pod::volume_source(
            &vol(json!({ "name": "data", "hostPath": { "path": "/var/lib/data" } })),
            "prod",
        );
        assert_eq!(src, "/var/lib/data");
        assert!(nav.is_none(), "a host directory is not a cluster object");

        let (src, _) = pod::volume_source(
            &vol(
                json!({ "name": "exports", "nfs": { "server": "nfs01", "path": "/exports/prod" } }),
            ),
            "prod",
        );
        assert_eq!(src, "nfs01:/exports/prod", "shown as mount writes it");

        let (src, _) = pod::volume_source(
            &vol(json!({ "name": "vault", "csi": { "driver": "secrets-store.csi.k8s.io" } })),
            "prod",
        );
        assert_eq!(src, "secrets-store.csi.k8s.io");

        // Nothing to name (e.g. an emptyDir) still falls back to the em dash.
        let (src, nav) =
            pod::volume_source(&vol(json!({ "name": "scratch", "emptyDir": {} })), "prod");
        assert_eq!(src, DASH);
        assert!(nav.is_none());
    }

    /// Replica readiness: all → green, some → amber, none → red.
    #[test]
    fn ready_tone_reflects_shortfall() {
        assert_eq!(ready_tone(3, 3), Tone::Good);
        assert_eq!(ready_tone(1, 3), Tone::Warn);
        assert_eq!(ready_tone(0, 3), Tone::Bad);
        // Scaled to zero deliberately — nothing is wrong.
        assert_eq!(ready_tone(0, 0), Tone::Muted);
    }

    /// Selectors render in the k=v,k2=v2 form kubectl uses.
    #[test]
    fn selector_rendering() {
        let mut m = BTreeMap::new();
        m.insert("app".to_string(), "valkyrie".to_string());
        m.insert("tier".to_string(), "api".to_string());
        assert_eq!(selector_text(Some(&m)), "app=valkyrie,tier=api");
        assert_eq!(selector_text(None), DASH);
        assert_eq!(selector_text(Some(&BTreeMap::new())), DASH);
    }

    /// An empty table with no note is dropped; with a note it's kept.
    #[test]
    fn empty_tables_are_dropped_unless_noted() {
        let mut p = Properties::default();
        p.push_table("Gone", None, &["A"], vec![]);
        assert!(
            p.sections.is_empty(),
            "an empty optional section should not render"
        );

        p.push_table("Kept", Some("nothing here"), &["A"], vec![]);
        assert_eq!(p.sections.len(), 1);
        assert_eq!(p.sections[0].title, "Kept");
    }

    /// Empty chip sections never render (a pod with no annotations shows nothing).
    #[test]
    fn empty_chips_are_dropped() {
        let mut p = Properties::default();
        p.chips("Labels", vec![]);
        assert!(p.sections.is_empty());
        p.chips(
            "Labels",
            vec![KeyValue {
                key: "a".into(),
                value: "b".into(),
            }],
        );
        assert_eq!(p.sections.len(), 1);
    }

    /// An unsupported kind errors rather than returning an empty panel, so a dead
    /// tab can't appear.
    #[k7s_deps::tokio::test]
    async fn unknown_kind_is_an_error() {
        // Install rustls crypto provider before creating kube client
        let _ = k7s_deps::rustls::crypto::ring::default_provider().install_default();

        // No client call happens for an unknown kind, so a default client is fine.
        let Ok(client) = Client::try_default().await else {
            return; // no kubeconfig in this environment; nothing to assert
        };
        assert!(gather(client, "configmaps", "default", "x").await.is_err());
    }
}
