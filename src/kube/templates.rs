//! YAML template rendering (Phase 4 of KubePi parity).
//!
//! Templates are mostly a *frontend* concern: the user picks a template
//! ("Deployment + Service"), fills in a form, and we render the result as a
//! YAML string. The backend's job is to take that rendered string and either
//! apply it (`apply_yaml`, already in commands.rs) or server-side dry-run it
//! (`dry_run_yaml`, also already there).
//!
//! What this module adds is the *structured* path: a template produces a
//! *list of manifests* (e.g. one Deployment + one Service + one Ingress),
//! each of which the API can apply independently. The front-end can preview
//! the whole bundle and apply it as a single transaction via a
//! `MultiApply` command.
//!
//! Rendering lives in TypeScript (`src/lib/templates/render.ts`) — see that
//! file for the template catalog. This file is a thin shim:
//!
//!   - Parse a list of YAML documents (a single string with `---` separators).
//!   - Apply each one through the dynamic API.
//!   - Stop at the first error, returning the per-document status so the UI
//!     can highlight which one failed.

use crate::error::{AppError, AppResult};
use crate::kube::manager::ClientManager;
use k7s_deps::kube::api::{Api, DynamicObject, Patch, PatchParams};
use k7s_deps::kube::core::{ApiResource, GroupVersionKind};
use k7s_deps::kube::ResourceExt;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ApplyResult {
    pub name: String,
    pub kind: String,
    pub namespace: String,
    pub action: &'static str, // "created" | "updated" | "unchanged" | "failed"
    pub error: Option<String>,
}

/// Apply a multi-document YAML bundle. Each doc is parsed, looked up via
/// the same dynamic-API path `apply_yaml` uses, and either created (if
/// absent) or replaced (if present). On the first error we return what
/// succeeded so the UI can show a "5 of 7 applied" status.
pub async fn multi_apply(
    yaml: &str,
    client: k7s_deps::kube::Client,
    mgr: &ClientManager,
) -> AppResult<Vec<ApplyResult>> {
    let docs = split_documents(yaml);
    if docs.is_empty() {
        return Err(AppError::Other("no documents in YAML bundle".into()));
    }
    let mut results = Vec::with_capacity(docs.len());
    let pp = PatchParams::apply("k7s");
    // One discovery pass for the whole bundle. Discovery::run() walks every
    // API group/version; running it per document (the old behaviour) made an
    // N-doc template cost N full API walks before a single apply.
    let groups = discover_groups(&client).await?;
    for doc in docs {
        let parsed: Result<DynamicObject, _> = k7s_deps::yaml_serde::from_str(&doc);
        let obj = match parsed {
            Ok(o) => o,
            Err(e) => {
                results.push(ApplyResult {
                    name: String::new(),
                    kind: String::new(),
                    namespace: String::new(),
                    action: "failed",
                    error: Some(format!("parse: {e}")),
                });
                return Ok(results);
            }
        };
        let tm = obj
            .types
            .clone()
            .ok_or_else(|| AppError::Other("document has no apiVersion/kind".into()))?;
        let gvk = GroupVersionKind::try_from(&tm)
            .map_err(|e| AppError::Other(format!("parse gvk: {e}")))?;
        let (ar, namespaced) = resolve_api_resource(&groups, &gvk)?;
        let ns = obj
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".into());
        let api: Api<DynamicObject> = if namespaced {
            Api::namespaced_with(client.clone(), &ns, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };
        let name = obj.name_any();
        let kind = gvk.kind.clone();
        // Single server-side apply per doc: create-or-update by name, so the
        // hand-rolled create-then-replace-on-409 dance is unnecessary. SSA
        // doesn't tell us create-vs-update cheaply, so we report a single
        // honest "applied" action.
        let action = match api.patch(&name, &pp, &Patch::Apply(obj)).await {
            Ok(_) => {
                // Audit identifiers only — never the manifest body. Borrowed:
                // the values move into the ApplyResult below.
                crate::core::audit::record(
                    "apply",
                    k7s_deps::serde_json::json!({
                        "kind": &kind,
                        "name": &name,
                        "namespace": &ns,
                    }),
                );
                "applied"
            }
            Err(e) => {
                results.push(ApplyResult {
                    name,
                    kind,
                    namespace: ns,
                    action: "failed",
                    error: Some(e.to_string()),
                });
                return Ok(results);
            }
        };
        results.push(ApplyResult {
            name,
            kind,
            namespace: ns,
            action,
            error: None,
        });
    }
    // Suppress unused-arg warnings on `mgr`; future: emit progress events.
    let _ = mgr;
    Ok(results)
}

/// Per-document outcome of a multi-doc dry run (the bundle equivalent of
/// `dry_run_yaml`). `proposed` is the object the server *would* store after
/// defaulting and mutating webhooks, serialized as YAML; `error` is set when
/// the dry run was rejected (the point of a dry run, not a hard failure).
#[derive(Clone, Debug, Serialize)]
pub struct DocDryRun {
    pub name: String,
    pub kind: String,
    pub namespace: String,
    pub proposed: Option<String>,
    pub error: Option<String>,
}

/// Dry-run each document in a bundle without writing anything. Mirrors
/// `multi_apply`'s parse/resolve loop but applies a server-side dry-run SSA
/// patch per doc, collecting the server-defaulted proposed YAML. Stops at the
/// first hard error (parse/resolve), but a *rejected* dry run is recorded as a
/// per-doc error and the loop continues so the caller sees every problem.
pub async fn multi_dry_run(
    yaml: &str,
    client: k7s_deps::kube::Client,
) -> AppResult<Vec<DocDryRun>> {
    let docs = split_documents(yaml);
    if docs.is_empty() {
        return Err(AppError::Other("no documents in YAML bundle".into()));
    }
    let mut results = Vec::with_capacity(docs.len());
    // Server-side-apply dry run: runs the full admission chain (validation,
    // defaulting, mutating webhooks) without persisting — same semantics as the
    // single-doc dry_run_yaml, so the bundle preview matches a real apply.
    let pp = PatchParams::apply("k7s").dry_run();
    // Shared discovery, as in `multi_apply`: one API walk for all documents.
    let groups = discover_groups(&client).await?;
    for doc in docs {
        let parsed: Result<DynamicObject, _> = k7s_deps::yaml_serde::from_str(&doc);
        let obj = match parsed {
            Ok(o) => o,
            Err(e) => {
                results.push(DocDryRun {
                    name: String::new(),
                    kind: String::new(),
                    namespace: String::new(),
                    proposed: None,
                    error: Some(format!("parse: {e}")),
                });
                return Ok(results);
            }
        };
        let tm = obj
            .types
            .clone()
            .ok_or_else(|| AppError::Other("document has no apiVersion/kind".into()))?;
        let gvk = GroupVersionKind::try_from(&tm)
            .map_err(|e| AppError::Other(format!("parse gvk: {e}")))?;
        let (ar, namespaced) = resolve_api_resource(&groups, &gvk)?;
        let ns = obj
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".into());
        let api: Api<DynamicObject> = if namespaced {
            Api::namespaced_with(client.clone(), &ns, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };
        let name = obj.name_any();
        let kind = gvk.kind.clone();
        match api.patch(&name, &pp, &Patch::Apply(obj)).await {
            Ok(mut proposed) => {
                proposed.metadata.managed_fields = None;
                results.push(DocDryRun {
                    name,
                    kind,
                    namespace: ns,
                    proposed: Some(k7s_deps::yaml_serde::to_string(&proposed)?),
                    error: None,
                });
            }
            Err(e) => {
                results.push(DocDryRun {
                    name,
                    kind,
                    namespace: ns,
                    proposed: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }
    Ok(results)
}

/// Split a multi-document YAML bundle on `---` line boundaries. The
/// well-known helm-marker / kustomize behaviour: any line that is exactly
/// `---` (no trailing content) starts a new document; otherwise the
/// separator is treated as part of the current document.
fn split_documents(yaml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for line in yaml.lines() {
        if line.trim_end() == "---" {
            let trimmed = buf.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
            buf.clear();
        } else {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    let trimmed = buf.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    out
}

/// Run one full API discovery for a bundle. The result is shared by every
/// document's `resolve_api_resource` lookup below.
async fn discover_groups(
    client: &k7s_deps::kube::Client,
) -> AppResult<k7s_deps::kube::discovery::Discovery> {
    Ok(k7s_deps::kube::discovery::Discovery::new(client.clone())
        .run()
        .await?)
}

/// Resolve one document's GVK against already-discovered groups. We need a
/// `Resource` mapping to learn plural + scope; doing this against a shared
/// discovery (instead of a fresh `Discovery::run()` per document) keeps an
/// N-doc bundle at one API walk.
fn resolve_api_resource(
    groups: &k7s_deps::kube::discovery::Discovery,
    gvk: &GroupVersionKind,
) -> AppResult<(ApiResource, bool)> {
    use k7s_deps::kube::discovery::Scope;
    for group in groups.groups() {
        if group.name() != gvk.group {
            continue;
        }
        for (ar, caps) in group.versioned_resources(&gvk.version) {
            if ar.kind == gvk.kind {
                return Ok((ar, caps.scope == Scope::Namespaced));
            }
        }
    }
    Err(AppError::NotFound(format!(
        "kind {} not discovered in this cluster",
        gvk.kind
    )))
}
