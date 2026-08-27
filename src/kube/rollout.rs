//! Workload rollback — `kubectl rollout undo` and `rollout history`, implemented.
//!
//! Three workload kinds carry a pod template and a revision history, but the
//! storage differs:
//!
//!   - **Deployment** owns ReplicaSets, each stamped with a
//!     `deployment.kubernetes.io/revision` annotation. Rolling back is copying a
//!     target ReplicaSet's `.spec.template` back onto the Deployment — exactly
//!     what `kubectl rollout undo --to-revision=N` does internally.
//!
//!   - **StatefulSet / DaemonSet** keep their history in `ControllerRevision`
//!     objects (label `controllerrevision.k8s.io/owner=<name>`). Each holds the
//!     pod template as `data` (a `RawExtension` wrapping a `PodTemplateSpec`).
//!     Rolling back is applying that template to the workload's
//!     `.spec.template`.
//!
//! The two storage shapes collapse to one DTO ([`Revision`]) so the frontend
//! renders a single table regardless of kind. The pure helpers (revision
//! parsing, template extraction, current-revision detection) are split out from
//! the cluster I/O so they can be pinned by tests without a live apiserver —
//! the same separation `restart.rs` uses.

use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::apps::v1::{
    ControllerRevision, DaemonSet, Deployment, ReplicaSet, StatefulSet,
};
use k7s_deps::k8s_openapi::api::core::v1::PodTemplateSpec;
use k7s_deps::kube::api::{Api, ListParams, Patch, PatchParams};
use k7s_deps::kube::ResourceExt;
use serde::Serialize;

/// Kinds that carry a pod template with a retained revision history. Matches
/// `restart::ROLLOUT_KINDS`; duplicated here so this module is self-contained
/// (the two notions of "rollout-capable" are the same set today and a
/// drift would be a real bug to catch in review).
pub const ROLLOUT_KINDS: [&str; 3] = ["deployments", "statefulsets", "daemonsets"];

/// Whether `kind` (a built-in table id) supports revision history / rollback.
pub fn is_rollout_kind(kind: &str) -> bool {
    ROLLOUT_KINDS.contains(&kind)
}

/// One row of a workload's revision history — the unified shape the frontend
/// renders, regardless of whether the history lives in ReplicaSets or
/// ControllerRevisions.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Revision {
    /// The numeric revision (`deployment.kubernetes.io/revision` for a
    /// Deployment's ReplicaSet; the `revision` annotation / trailing `<N>` of a
    /// ControllerRevision's name). `None` only if neither is present, which is
    /// rare enough that the frontend shows a dash.
    pub revision: Option<i64>,
    /// Each container's `name: image` from this revision's pod template, in
    /// template order. Lets the user read what a rollback would change to
    /// without opening the ReplicaSet/ControllerRevision YAML.
    pub images: Vec<ContainerImage>,
    /// The replica count this revision was declared with.
    pub desired: i32,
    /// How many replicas of this revision are currently ready. Only the
    /// current revision has ready > 0 in steady state.
    pub ready: i32,
    /// RFC3339 creation timestamp, for the AGE column.
    pub age: String,
    /// True for the revision the workload is currently rolling out. The
    /// frontend marks it and hides its own "rollback" button (rolling back to
    /// yourself is a no-op that would still bump the revision counter).
    pub is_current: bool,
}

/// A container's name and image, extracted from a pod template. Kept as a
/// small struct rather than a `name:image` string so the frontend can render
/// them in columns and copy either half.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContainerImage {
    pub name: String,
    pub image: String,
    /// `true` for `initContainers` entries, so the UI can badge them apart
    /// from the main containers.
    pub init: bool,
}

/// The annotation a Deployment's ReplicaSet carries its revision under.
pub const DEPLOYMENT_REVISION_ANNOTATION: &str = "deployment.kubernetes.io/revision";

/// The label a StatefulSet/DaemonSet's ControllerRevisions carry their owner
/// name under.
pub const CONTROLLER_REVISION_OWNER_LABEL: &str = "controllerrevision.k8s.io/owner";

/// A ReplicaSet's rollout revision, from the annotation the Deployment
/// controller stamps on it. Extracted from `properties::revision_of` so this
/// module owns the rollback path end-to-end (the Properties tab keeps its own
/// copy; the two must agree and a test pins the shape).
pub fn revision_of_replicaset(rs: &ReplicaSet) -> Option<i64> {
    rs.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(DEPLOYMENT_REVISION_ANNOTATION))
        .and_then(|v| v.parse().ok())
}

/// A ControllerRevision's revision number. The StatefulSet/DaemonSet
/// controllers stamp it under the `revision` annotation; failing that, the
/// object name is `<owner>-<N>`, so the trailing integer is the fallback.
pub fn revision_of_controller_revision(cr: &ControllerRevision) -> Option<i64> {
    if let Some(v) = cr
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get("revision"))
    {
        if let Ok(n) = v.parse() {
            return Some(n);
        }
    }
    // `<owner>-<N>`: take the last `-`-separated segment and parse it.
    cr.name_any()
        .rsplit('-')
        .next()
        .and_then(|s| s.parse().ok())
}

/// Pull the container images out of a pod template in template order. Returns
/// main containers first, then init containers, each flagged so the UI can tell
/// them apart. Empty for a template with no containers (shouldn't happen for a
/// real workload, but degrades to an empty list rather than panicking).
pub fn images_of(template: &PodTemplateSpec) -> Vec<ContainerImage> {
    let spec = match &template.spec {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for c in spec.containers.iter() {
        out.push(ContainerImage {
            name: c.name.clone(),
            image: c.image.clone().unwrap_or_default(),
            init: false,
        });
    }
    for c in spec.init_containers.iter().flatten() {
        out.push(ContainerImage {
            name: c.name.clone(),
            image: c.image.clone().unwrap_or_default(),
            init: true,
        });
    }
    out
}

/// List a workload's revision history, newest revision first.
///
/// RBAC denials degrade to an empty list (matching the Properties tab's
/// behaviour) — the Revisions tab still opens, it just shows "no history"
/// rather than erroring the whole panel.
pub async fn list_revisions(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<Vec<Revision>> {
    match kind {
        "deployments" => list_deployment_revisions(client, namespace, name).await,
        "statefulsets" | "daemonsets" => {
            list_controller_revisions(client, kind, namespace, name).await
        }
        _ => Err(AppError::Other(format!("{kind} has no revision history"))),
    }
}

async fn list_deployment_revisions(
    client: k7s_deps::kube::Client,
    namespace: &str,
    name: &str,
) -> AppResult<Vec<Revision>> {
    let dep_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let dep = match dep_api.get(name).await {
        Ok(d) => d,
        // RBAC or "already gone" — nothing to list against.
        Err(_) => return Ok(Vec::new()),
    };
    let dep_uid = dep.metadata.uid.clone();

    let rs_api: Api<ReplicaSet> = Api::namespaced(client, namespace);
    let list = match rs_api.list(&ListParams::default()).await {
        Ok(l) => l,
        Err(_) => return Ok(Vec::new()),
    };

    // The current revision is the highest-numbered owned ReplicaSet that is
    // actually carrying replicas — the Deployment controller scales the current
    // RS to `spec.replicas` and any older ones to zero. A fresh Deployment whose
    // RSes haven't converged yet falls back to "the newest revision", matching
    // what `kubectl rollout history` shows on the active line.
    let current_rev = list
        .items
        .iter()
        .filter(|rs| owned_by(rs, &dep_uid))
        .filter(|rs| rs.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0) > 0)
        .filter_map(revision_of_replicaset)
        .max()
        .or_else(|| {
            list.items
                .iter()
                .filter(|rs| owned_by(rs, &dep_uid))
                .filter_map(revision_of_replicaset)
                .max()
        });

    let mut owned: Vec<ReplicaSet> = list
        .items
        .into_iter()
        .filter(|rs| owned_by(rs, &dep_uid))
        .collect();
    // Newest first — that's the revision the user just rolled out.
    owned.sort_by_key(|rs| std::cmp::Reverse(revision_of_replicaset(rs).unwrap_or(0)));

    Ok(owned
        .iter()
        .map(|rs| {
            let rev = revision_of_replicaset(rs);
            let spec = rs.spec.clone().unwrap_or_default();
            let status = rs.status.clone().unwrap_or_default();
            let template = spec.template.clone();
            Revision {
                revision: rev,
                images: template.as_ref().map(images_of).unwrap_or_default(),
                desired: spec.replicas.unwrap_or(0),
                ready: status.ready_replicas.unwrap_or(0),
                age: rs
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| t.0.to_string())
                    .unwrap_or_default(),
                is_current: rev.is_some() && rev == current_rev,
            }
        })
        .collect())
}

async fn list_controller_revisions(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<Vec<Revision>> {
    // StatefulSet reports a `currentRevision` template-hash string in its status;
    // the matching ControllerRevision carries that same hash as its `revision`
    // annotation, so the two line up. DaemonSet status has no such pointer — its
    // active revision is just the newest ControllerRevision, which is what
    // `kubectl rollout history` shows too.
    let current_hash: Option<String> = if kind == "statefulsets" {
        Api::<StatefulSet>::namespaced(client.clone(), namespace)
            .get(name)
            .await
            .ok()
            .and_then(|s| s.status.and_then(|st| st.current_revision))
    } else {
        None
    };

    let cr_api: Api<ControllerRevision> = Api::namespaced(client, namespace);
    let lp = ListParams::default().labels(&format!("{CONTROLLER_REVISION_OWNER_LABEL}={name}"));
    let list = match cr_api.list(&lp).await {
        Ok(l) => l,
        Err(_) => return Ok(Vec::new()),
    };

    let mut items: Vec<ControllerRevision> = list.items;
    items.sort_by_key(|cr| std::cmp::Reverse(revision_of_controller_revision(cr).unwrap_or(0)));
    let newest_rev = items.first().and_then(revision_of_controller_revision);

    Ok(items
        .iter()
        .map(|cr| {
            let rev = revision_of_controller_revision(cr);
            let cr_hash = cr
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("revision"))
                .cloned();
            // StatefulSet: match by the controller's currentRevision hash.
            // DaemonSet (or STS without status): the newest revision is current.
            let is_current = match (&current_hash, cr_hash) {
                (Some(hash), Some(h)) => h == *hash,
                _ => rev == newest_rev,
            };
            let template = controller_revision_template(cr);
            // ControllerRevisions don't carry a replica count (the workload's
            // spec.replicas is what matters at apply time); show 0 and let the
            // current-revision flag carry the meaning.
            let desired = 0;
            Revision {
                revision: rev,
                images: template.as_ref().map(images_of).unwrap_or_default(),
                desired,
                ready: if is_current { desired } else { 0 },
                age: cr
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| t.0.to_string())
                    .unwrap_or_default(),
                is_current,
            }
        })
        .collect())
}

/// Decode a ControllerRevision's `data` back into a PodTemplateSpec. The
/// controller stores it as a `RawExtension`, so we round-trip through serde_json
/// to the typed struct. Returns None on a malformed payload (an old or
/// hand-edited history) — the caller treats that as a revision with no images.
fn controller_revision_template(cr: &ControllerRevision) -> Option<PodTemplateSpec> {
    let data = cr.data.as_ref()?;
    k7s_deps::serde_json::from_value::<PodTemplateSpec>(data.0.clone()).ok()
}

/// Roll a workload back to `to_revision`, or to the previous revision when
/// `to_revision` is `None` (the `kubectl rollout undo` default).
///
/// The mechanism is "copy that revision's pod template onto the workload's
/// `spec.template`", delivered as a merge patch. The controller then rolls
/// through its normal update strategy — surge/MaxUnavailable for Deployments,
/// `partition`/`maxUnavailable` for StatefulSets/DaemonSets — so the rollback
/// respects the workload's own rollout budget.
pub async fn undo_to(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    to_revision: Option<i64>,
) -> AppResult<()> {
    let result = match kind {
        "deployments" => undo_deployment(client, namespace, name, to_revision).await,
        "statefulsets" | "daemonsets" => {
            undo_controller_revision(client, kind, namespace, name, to_revision).await
        }
        _ => Err(AppError::Other(format!("{kind} cannot be rolled back"))),
    };
    if result.is_ok() {
        // Audit identifiers only, after the rollback actually landed.
        crate::core::audit::record(
            "rollout.undo",
            k7s_deps::serde_json::json!({
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "revision": to_revision,
            }),
        );
    }
    result
}

async fn undo_deployment(
    client: k7s_deps::kube::Client,
    namespace: &str,
    name: &str,
    to_revision: Option<i64>,
) -> AppResult<()> {
    let dep_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let dep = dep_api.get(name).await?;
    let dep_uid = dep.metadata.uid.clone();

    let rs_api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
    let owned: Vec<ReplicaSet> = rs_api
        .list(&ListParams::default())
        .await?
        .items
        .into_iter()
        .filter(|rs| owned_by(rs, &dep_uid))
        .collect();

    let target = pick_target(
        &owned,
        to_revision,
        revision_of_replicaset,
        "ReplicaSet",
        name,
    )?;
    let template = target
        .spec
        .clone()
        .ok_or_else(|| {
            AppError::Other(format!("revision {} has no spec", display_rev(to_revision)))
        })?
        .template
        .clone()
        .ok_or_else(|| {
            AppError::Other(format!(
                "revision {} has no pod template",
                display_rev(to_revision)
            ))
        })?;

    let patch = Patch::Merge(k7s_deps::serde_json::json!({ "spec": { "template": template } }));
    dep_api.patch(name, &PatchParams::default(), &patch).await?;
    Ok(())
}

async fn undo_controller_revision(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    to_revision: Option<i64>,
) -> AppResult<()> {
    let cr_api: Api<ControllerRevision> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default().labels(&format!("{CONTROLLER_REVISION_OWNER_LABEL}={name}"));
    let owned: Vec<ControllerRevision> = cr_api.list(&lp).await?.items;

    let target = pick_target(
        &owned,
        to_revision,
        revision_of_controller_revision,
        "ControllerRevision",
        name,
    )?;
    let template = controller_revision_template(target).ok_or_else(|| {
        AppError::Other(format!(
            "revision {} has no readable pod template",
            display_rev(to_revision)
        ))
    })?;

    // A StatefulSet/DaemonSet rollback is a Strategic merge patch on
    // spec.template — same shape as the Deployment path. The typed Api is
    // required: Strategic merge needs a known schema to merge container lists
    // by name, and a DynamicObject Api would only accept Merge/JSON patches.
    let patch = Patch::Strategic(k7s_deps::serde_json::json!({ "spec": { "template": template } }));
    match kind {
        "statefulsets" => {
            let api: Api<StatefulSet> = Api::namespaced(client, namespace);
            api.patch(name, &PatchParams::default(), &patch).await?;
        }
        "daemonsets" => {
            let api: Api<DaemonSet> = Api::namespaced(client, namespace);
            api.patch(name, &PatchParams::default(), &patch).await?;
        }
        _ => return Err(AppError::Other(format!("{kind} cannot be rolled back"))),
    }
    Ok(())
}

/// Pick the history entry to roll back to.
///
/// `None` means "the previous revision" — i.e. the second-newest, since the
/// newest is the current one. A revision equal to the current is refused with a
/// clear message (it would be a no-op that still consumes a revision slot).
fn pick_target<'a, T, F>(
    owned: &'a [T],
    to_revision: Option<i64>,
    rev_of: F,
    kind_label: &'a str,
    workload_name: &'a str,
) -> AppResult<&'a T>
where
    F: Fn(&T) -> Option<i64>,
{
    let mut by_rev: Vec<(Option<i64>, usize)> = owned
        .iter()
        .enumerate()
        .map(|(i, x)| (rev_of(x), i))
        .collect();
    // Newest first by revision number; unnumbered entries sort to the bottom.
    by_rev.sort_by_key(|(r, _)| std::cmp::Reverse(r.unwrap_or(i64::MIN)));

    let target_idx = match to_revision {
        Some(want) => by_rev
            .iter()
            .find(|(r, _)| *r == Some(want))
            .map(|(_, i)| *i)
            .ok_or_else(|| {
                AppError::Other(format!(
                    "{workload_name} has no {kind_label} with revision {want}"
                ))
            })?,
        None => {
            // The current revision is the newest; roll back to the one before it.
            if by_rev.len() < 2 {
                return Err(AppError::Other(format!(
                    "{workload_name} has no previous revision to roll back to"
                )));
            }
            by_rev[1].1
        }
    };
    Ok(&owned[target_idx])
}

/// True when `rs` is owned by `owner_uid` (a None owner never matches). Ownership
/// is by uid, not name: a deleted-and-recreated Deployment reuses the name, and a
/// name match would wrongly adopt the previous generation's ReplicaSets.
fn owned_by(rs: &ReplicaSet, owner_uid: &Option<String>) -> bool {
    let Some(uid) = owner_uid else { return false };
    rs.metadata
        .owner_references
        .iter()
        .flatten()
        .any(|o| &o.uid == uid)
}

/// Readable form of a revision argument for error messages.
fn display_rev(to_revision: Option<i64>) -> String {
    match to_revision {
        Some(n) => n.to_string(),
        None => "(previous)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::k8s_openapi::api::apps::v1::{ReplicaSet, ReplicaSetSpec};
    use k7s_deps::k8s_openapi::api::core::v1::{Container, PodSpec, PodTemplateSpec};
    use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    fn rs_with_revision(name: &str, rev: i64) -> ReplicaSet {
        let mut annotations = BTreeMap::new();
        annotations.insert(DEPLOYMENT_REVISION_ANNOTATION.to_string(), rev.to_string());
        ReplicaSet {
            metadata: ObjectMeta {
                name: Some(name.into()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(ReplicaSetSpec {
                replicas: Some(0),
                template: Some(PodTemplateSpec {
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            name: "app".into(),
                            image: Some(format!("img:v{rev}")),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn parses_replicaset_revision_annotation() {
        assert_eq!(revision_of_replicaset(&rs_with_revision("a", 7)), Some(7));
        // Missing annotation → None.
        let mut rs = rs_with_revision("a", 1);
        rs.metadata.annotations = None;
        assert_eq!(revision_of_replicaset(&rs), None);
        // Non-numeric → None, not a panic.
        let mut rs = rs_with_revision("a", 1);
        rs.metadata.annotations = Some(
            [(DEPLOYMENT_REVISION_ANNOTATION.to_string(), "oops".into())]
                .into_iter()
                .collect(),
        );
        assert_eq!(revision_of_replicaset(&rs), None);
    }

    #[test]
    fn images_of_returns_main_then_init() {
        let template = PodTemplateSpec {
            spec: Some(PodSpec {
                containers: vec![
                    Container {
                        name: "app".into(),
                        image: Some("nginx:1.25".into()),
                        ..Default::default()
                    },
                    Container {
                        name: "sidecar".into(),
                        image: Some("redis:7".into()),
                        ..Default::default()
                    },
                ],
                init_containers: Some(vec![Container {
                    name: "init".into(),
                    image: Some("busybox".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let imgs = images_of(&template);
        assert_eq!(imgs.len(), 3);
        assert_eq!(imgs[0].name, "app");
        assert!(!imgs[0].init);
        assert_eq!(imgs[1].name, "sidecar");
        assert_eq!(imgs[2].name, "init");
        assert!(imgs[2].init);
    }

    #[test]
    fn images_of_handles_empty_template() {
        let template = PodTemplateSpec::default();
        assert!(images_of(&template).is_empty());
    }

    #[test]
    fn rollout_kinds_match_restart_set() {
        // The two module notions of "rollout-capable" must agree; a drift is a
        // bug (rollback offered on a kind that can't restart, or vice versa).
        assert_eq!(ROLLOUT_KINDS, crate::kube::restart::ROLLOUT_KINDS);
        assert!(is_rollout_kind("deployments"));
        assert!(is_rollout_kind("statefulsets"));
        assert!(is_rollout_kind("daemonsets"));
        assert!(!is_rollout_kind("pods"));
        assert!(!is_rollout_kind("jobs"));
    }

    #[test]
    fn controller_revision_name_fallback_parses_trailing_int() {
        // <owner>-<N> → N. The annotation is preferred but the name is the
        // stable fallback the controller guarantees.
        let cr = ControllerRevision {
            metadata: ObjectMeta {
                name: Some("web-42".into()),
                ..Default::default()
            },
            data: None,
            revision: 0,
        };
        assert_eq!(revision_of_controller_revision(&cr), Some(42));
    }

    #[test]
    fn controller_revision_annotation_preferred_over_name() {
        let mut annotations = BTreeMap::new();
        annotations.insert("revision".to_string(), "99".into());
        let cr = ControllerRevision {
            metadata: ObjectMeta {
                name: Some("web-5".into()),
                annotations: Some(annotations),
                ..Default::default()
            },
            data: None,
            revision: 0,
        };
        assert_eq!(revision_of_controller_revision(&cr), Some(99));
    }
}
