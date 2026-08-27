//! Transport-agnostic command helpers shared by the Tauri and web shells.
//!
//! Every public function in this module was previously duplicated between
//! `crate::commands` (Tauri) and `crate::web::handlers` (HTTP). Moving them
//! here eliminates the drift risk and fixes several behavioural divergences.

use crate::core::prefs;
use crate::error::{AppError, AppResult};
use crate::kube::client;
use crate::kube::exec;
use crate::kube::logs::{self, LogStreamOptions};
use crate::kube::manager::{ClientManager, ShellSession};
use crate::kube::nodeshell;
use crate::kube::ResourceKind;
use k7s_deps::k8s_openapi::api::core::v1::Secret;
use k7s_deps::kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
};
use k7s_deps::kube::config::Kubeconfig;
use k7s_deps::kube::core::GroupVersionKind;
use k7s_deps::kube::ResourceExt;
use k7s_deps::tokio::sync::mpsc;
use k7s_deps::tokio::task::JoinHandle;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Shared connection sequence
// ---------------------------------------------------------------------------

/// Result of the shared connection sequence returned to each shell so it can
/// layer its own post-connect work (watchers, pollers, knowledge sync) on top.
pub struct ConnectResult {
    pub client: k7s_deps::kube::Client,
    pub server: String,
    pub version: String,
    /// CRD-backed kinds discovered during connection. Callers that emit
    /// UI events (Tauri, web) can forward this list to the frontend.
    pub custom_kinds: Vec<crate::kube::discovery::CustomKind>,
}

/// The shared connection sequence: reset -> build client -> probe version ->
/// discover CRDs. Each entry point (Tauri, web, MCP) calls this, then spawns
/// its own watchers / pollers and calls `manager.set_connected(...)` with the
/// real watcher count.
///
/// Priority: `imported_kubeconfig` (already-parsed, from web/MCP uploads) >
/// `import_path` (file on disk) > default kubeconfig. This fixes the Tauri
/// command which previously lacked the imported-kubeconfig path entirely.
pub async fn connect_core(
    manager: &ClientManager,
    imported_kubeconfig: Option<Kubeconfig>,
    import_path: Option<String>,
    context: &str,
) -> AppResult<ConnectResult> {
    // 1. Tear down any previous connection (Story 6.1).
    manager.reset().await;

    // 2. Build client: imported kubeconfig > file > default.
    let (kube_client, server) = if let Some(kc) = imported_kubeconfig {
        client::build_client_from_kubeconfig(kc, context).await?
    } else if let Some(path) = import_path {
        client::build_client_from_file(&path, context).await?
    } else {
        client::build_client(context).await?
    };

    // 3. Probe API server version (also a reachability check).
    let version = client::probe_version(&kube_client).await?;

    // 4. CRD discovery — populates the nav with custom kinds (B15).
    let custom = crate::kube::discovery::discover(&kube_client).await;
    manager.set_custom_kinds(custom.clone()).await;

    Ok(ConnectResult {
        client: kube_client,
        server,
        version,
        custom_kinds: custom,
    })
}

// ---------------------------------------------------------------------------
// Monotonic sequence counters
// ---------------------------------------------------------------------------

/// Global monotonic counter for generating unique stream / shell / forward ids.
/// Shared across all shells to prevent id collisions when both run in the same
/// binary (unlikely today, but the architecture supports it).
pub static STREAM_SEQ: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

/// What the frontend needs to drive and clean up a node shell session.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeShellInfo {
    pub stream_id: String,
    pub namespace: String,
    /// Surfaced in the UI so the pod is never invisible: if cleanup somehow fails,
    /// the user has the exact name to delete by hand.
    pub pod: String,
}

/// What the frontend needs to drive a pod shell session.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellInfo {
    pub stream_id: String,
    pub namespace: String,
    pub pod: String,
}

/// What a proposed edit would actually do, as the *server* sees it (B36).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YamlDiff {
    /// The live object now.
    pub current: String,
    /// What would be stored if this were applied — after defaulting and any
    /// mutating webhooks.
    pub proposed: String,
}

// ---------------------------------------------------------------------------
// Kind → API mapping
// ---------------------------------------------------------------------------

/// Map a frontend kind id to its `ApiResource` and whether it is namespaced.
///
/// A custom (CRD-backed) kind id contains a slash ("group/plural", B15) and is
/// resolved from the kinds discovered on connect, so YAML/delete/events work on
/// CRDs through the same path as built-ins.
pub async fn resource_for(kind: &str, mgr: &ClientManager) -> AppResult<(ApiResource, bool)> {
    if kind.contains('/') {
        return match mgr.custom_kind(kind).await {
            Some(ck) => Ok((ck.api_resource(), ck.namespaced)),
            None => Err(AppError::Other(format!("unknown custom kind: {kind}"))),
        };
    }
    // Endpoints is not in ResourceKind (not watched) but is valid for dynamic API.
    if kind == "endpoints" {
        let gvk = GroupVersionKind::gvk("", "v1", "Endpoints");
        return Ok((ApiResource::from_gvk_with_plural(&gvk, kind), true));
    }
    let rk = ResourceKind::from_id(kind)
        .ok_or_else(|| AppError::Other(format!("unknown kind: {kind}")))?;
    let gvk = GroupVersionKind::gvk(rk.group(), rk.version(), rk.kind_name());
    Ok((
        ApiResource::from_gvk_with_plural(&gvk, kind),
        rk.is_namespaced(),
    ))
}

/// Build a dynamic API for `kind`, namespaced or cluster-scoped as appropriate.
/// Returns `(Api, is_helm)` so the caller can special-case Helm releases.
pub async fn dynamic_api(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    mgr: &ClientManager,
) -> AppResult<(Api<DynamicObject>, bool)> {
    // Helm releases aren't real API objects — return a dummy Api so the caller
    // can still call `.get()` etc. on it (it won't be used; the caller checks
    // the `is_helm` flag first).
    if kind == ResourceKind::Helm.id() {
        let gvk = GroupVersionKind::gvk("helm", "v1", "Release");
        let ar = ApiResource::from_gvk_with_plural(&gvk, "helm");
        return Ok((Api::namespaced_with(client, namespace, &ar), true));
    }
    let (ar, namespaced) = resource_for(kind, mgr).await?;
    Ok((
        if namespaced {
            Api::namespaced_with(client, namespace, &ar)
        } else {
            Api::all_with(client, &ar)
        },
        false,
    ))
}

// ---------------------------------------------------------------------------
// Writable / secret / helm helpers
// ---------------------------------------------------------------------------

/// Refuse the two kinds whose YAML must never be written back.
///
/// Shared by `apply_yaml` and `dry_run_yaml` so the two can't drift — a dry run
/// that succeeded on a kind the real apply then refuses would be worse than no
/// preview at all. Accepts both `"helm"` and `"helmreleases"` for the Helm kind
/// to match what the web shell historically sent.
pub fn ensure_writable(kind: &str) -> AppResult<()> {
    if kind == ResourceKind::Helm.id() || kind == "helmreleases" {
        return Err(AppError::Other(
            "Helm releases are read-only here — use `helm upgrade` to change one".into(),
        ));
    }
    if kind == "secrets" {
        return Err(AppError::Other("editing Secrets is disabled".into()));
    }
    Ok(())
}

/// Map a built-in kind id (e.g. "deployments") to its PascalCase kind name
/// (e.g. "Deployment"). Returns `None` for unknown or custom (CRD) kinds.
fn expected_kind_name(kind: &str) -> Option<&'static str> {
    // Endpoints is not in ResourceKind but is valid for YAML validation.
    if kind == "endpoints" {
        return Some("Endpoints");
    }
    ResourceKind::from_id(kind).map(|rk| rk.kind_name())
}

/// Validate a parsed `DynamicObject` before applying it to the cluster.
///
/// Catches common mistakes early with clear error messages instead of
/// letting the API server return a cryptic 422 or 409:
/// - Missing apiVersion / kind
/// - kind mismatch (editing a Deployment but applying as Service)
/// - name mismatch (accidentally changing the resource name)
/// - namespace mismatch
/// - missing resourceVersion (required for PUT / replace)
pub fn validate_apply_yaml(
    obj: &DynamicObject,
    expected_kind: &str,
    expected_name: &str,
    expected_namespace: &str,
    namespaced: bool,
) -> AppResult<()> {
    // 1. Check apiVersion and kind are present.
    let types = obj
        .types
        .as_ref()
        .ok_or_else(|| AppError::Other("YAML is missing apiVersion and kind fields".into()))?;

    if types.api_version.is_empty() {
        return Err(AppError::Other("YAML has empty apiVersion".into()));
    }
    if types.kind.is_empty() {
        return Err(AppError::Other("YAML has empty kind".into()));
    }

    // 2. Cross-check kind for built-in resources.
    //    Custom (CRD) kinds contain '/' in their id — skip the check for those.
    if !expected_kind.contains('/') {
        if let Some(expected_pascal) = expected_kind_name(expected_kind) {
            if types.kind != expected_pascal {
                return Err(AppError::Other(format!(
                    "YAML kind '{}' does not match the expected kind '{}' for resource type '{}'",
                    types.kind, expected_pascal, expected_kind
                )));
            }
        }
    }

    // 3. Cross-check name.
    let yaml_name = obj.name_any();
    if yaml_name.is_empty() {
        return Err(AppError::Other("YAML is missing metadata.name".into()));
    }
    if yaml_name != expected_name {
        return Err(AppError::Other(format!(
            "YAML metadata.name '{}' does not match the expected resource name '{}'",
            yaml_name, expected_name
        )));
    }

    // 4. Cross-check namespace (for namespaced resources).
    if namespaced {
        let yaml_ns = obj.namespace().unwrap_or_default();
        if !yaml_ns.is_empty() && yaml_ns != expected_namespace {
            return Err(AppError::Other(format!(
                "YAML metadata.namespace '{}' does not match the expected namespace '{}'",
                yaml_ns, expected_namespace
            )));
        }
    }

    // 5. Check resourceVersion is present (required for replace/PUT).
    if obj.metadata.resource_version.is_none() {
        return Err(AppError::Other(
            "YAML is missing metadata.resourceVersion — this is required for updating resources. \
             Fetch the latest YAML first, then edit and re-apply."
                .into(),
        ));
    }

    Ok(())
}

/// Replace `data` values in a Secret with a placeholder so raw values never
/// leave the backend.
pub fn redact_secret(obj: &mut DynamicObject) {
    for field in ["data", "stringData"] {
        if let Some(k7s_deps::serde_json::Value::Object(map)) = obj.data.get_mut(field) {
            for v in map.values_mut() {
                *v = k7s_deps::serde_json::Value::String("<redacted>".into());
            }
        }
    }
}

/// The rendered manifest of a Helm release, newest revision (B26).
///
/// Finds the release by label rather than reconstructing the Secret's name:
/// `sh.helm.release.v1.<name>.v<revision>` requires knowing the revision, and
/// the labels are what Helm itself queries on.
pub async fn helm_manifest(
    client: k7s_deps::kube::Client,
    namespace: &str,
    name: &str,
) -> AppResult<String> {
    let api: Api<Secret> = Api::namespaced(client, namespace);
    let lp = ListParams::default()
        .fields(&format!("type={}", crate::kube::helm::RELEASE_SECRET_TYPE))
        .labels(&format!("name={name},owner=helm"));
    let list = api.list(&lp).await?;

    let latest = list
        .items
        .iter()
        .filter_map(crate::kube::helm::decode_release)
        .max_by_key(|r| r.revision)
        .ok_or_else(|| {
            AppError::NotFound(format!("helm release {name} not found in {namespace}"))
        })?;

    if latest.manifest.trim().is_empty() {
        return Err(AppError::Other(format!(
            "release {name} has no rendered manifest"
        )));
    }
    Ok(latest.manifest)
}

// ---------------------------------------------------------------------------
// Context merging
// ---------------------------------------------------------------------------

/// Build the switcher list: default kubeconfig contexts plus every imported
/// context not already present (imported files never shadow the default).
pub async fn merged_contexts(manager: &ClientManager) -> Vec<crate::kube::client::ContextInfo> {
    let mut merged = crate::kube::client::list_contexts().unwrap_or_default();
    let existing: std::collections::HashSet<String> =
        merged.iter().map(|c| c.name.clone()).collect();
    for (name, imp) in manager.imports().await {
        if !existing.contains(&name) {
            merged.push(crate::kube::client::ContextInfo {
                name,
                cluster: imp.cluster,
                current: false,
            });
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// Shared shell / log spawning
// ---------------------------------------------------------------------------

/// Start an interactive shell in a pod container.
///
/// Encapsulates the sequence that was previously duplicated between the Tauri
/// `start_shell` command and the web `start_shell` handler: generate an id,
/// create channels, read the shell-command override from prefs, spawn the exec
/// task, and register the session with the manager.
pub async fn spawn_shell_session(
    manager: &ClientManager,
    client: k7s_deps::kube::Client,
    namespace: String,
    pod: String,
    container: String,
    data_dir: &std::path::Path,
) -> AppResult<ShellInfo> {
    let id = format!("sh-{}-{}", pod, STREAM_SEQ.fetch_add(1, Ordering::Relaxed));
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>(8);
    let sink = manager.sink();
    // Read per-session, so changing the override applies to the next shell you
    // open rather than needing a reconnect (B23).
    let shell_command = prefs::read_prefs(data_dir)
        .shell_command
        .unwrap_or_default();
    let ns_for_task = namespace.clone();
    let pod_for_task = pod.clone();
    let id_for_task = id.clone();
    // Outlives the exec task, which takes ownership of `container`.
    let container_for_audit = container.clone();
    let task = k7s_deps::tokio::spawn(async move {
        exec::run_shell(
            client,
            sink,
            id_for_task,
            ns_for_task,
            pod_for_task,
            container,
            shell_command,
            input_rx,
            resize_rx,
        )
        .await;
    });

    manager
        .add_shell(
            id.clone(),
            ShellSession {
                task,
                input_tx,
                resize_tx,
            },
        )
        .await;
    // Audit identifiers only (no shell command/output).
    crate::core::audit::record(
        "shell.start",
        k7s_deps::serde_json::json!({
            "stream_id": &id,
            "namespace": &namespace,
            "pod": &pod,
            "container": &container_for_audit,
        }),
    );
    Ok(ShellInfo {
        stream_id: id,
        namespace,
        pod,
    })
}

/// Open a root shell on a node's host OS (B53).
///
/// Encapsulates the sequence that was previously duplicated between the Tauri
/// `start_node_shell` command and the web `start_node_shell` handler: sweep
/// old debug pods, create a new one, wait for it to be ready, then nsenter
/// into the host's namespaces.
pub async fn spawn_node_shell_session(
    manager: &ClientManager,
    client: k7s_deps::kube::Client,
    node_name: String,
    data_dir: &std::path::Path,
) -> AppResult<NodeShellInfo> {
    let api: Api<k7s_deps::k8s_openapi::api::core::v1::Pod> =
        Api::namespaced(client.clone(), nodeshell::DEBUG_NAMESPACE);

    // Sweep this node's leftovers first. A previous session that died without
    // cleaning up would otherwise collide on the name or, worse, quietly leave a
    // privileged pod running alongside the new one.
    if let Ok(old) = api
        .list(&ListParams::default().labels(&nodeshell::node_selector(&node_name)))
        .await
    {
        for pod in old.items {
            nodeshell::delete_debug_pod(&api, &pod.name_any()).await;
        }
    }

    let seq = STREAM_SEQ.fetch_add(1, Ordering::Relaxed);
    let pod_name = nodeshell::pod_name(&node_name, seq);
    let image = prefs::read_prefs(data_dir)
        .node_shell_image
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| nodeshell::DEFAULT_IMAGE.to_string());

    api.create(
        &PostParams::default(),
        &nodeshell::debug_pod_spec(&node_name, &image, &pod_name),
    )
    .await?;

    // From here on the pod exists, so any failure must clean up after itself
    // rather than leave a privileged pod behind on the strength of an error
    // return.
    if let Err(e) = nodeshell::await_debug_pod(&api, &pod_name).await {
        nodeshell::delete_debug_pod(&api, &pod_name).await;
        return Err(e);
    }

    let id = format!("nsh-{pod_name}");
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>(8);
    let sink = manager.sink();
    let id_for_task = id.clone();
    let pod_for_task = pod_name.clone();
    let task = k7s_deps::tokio::spawn(async move {
        exec::run_argv(
            client,
            sink,
            id_for_task,
            nodeshell::DEBUG_NAMESPACE.to_string(),
            pod_for_task,
            "debug".to_string(),
            nodeshell::nsenter_cmd(),
            input_rx,
            resize_rx,
        )
        .await;
    });

    manager
        .add_shell(
            id.clone(),
            ShellSession {
                task,
                input_tx,
                resize_tx,
            },
        )
        .await;
    // Audit identifiers only — the node shell is root-equivalent on the host.
    crate::core::audit::record(
        "node_shell.start",
        k7s_deps::serde_json::json!({
            "stream_id": &id,
            "node": &node_name,
            "namespace": nodeshell::DEBUG_NAMESPACE,
            "pod": &pod_name,
        }),
    );
    Ok(NodeShellInfo {
        stream_id: id,
        namespace: nodeshell::DEBUG_NAMESPACE.to_string(),
        pod: pod_name,
    })
}

/// Start a log stream for a pod container.
///
/// Encapsulates the sequence that was previously duplicated between the Tauri
/// `start_log_stream` command and the web `start_log_stream` handler: generate
/// an id, build `LogStreamOptions`, spawn the stream task, and register with
/// the manager.
pub async fn spawn_log_stream(
    manager: &ClientManager,
    client: k7s_deps::kube::Client,
    namespace: String,
    pod: String,
    container: String,
    opts: LogStreamOptions,
) -> String {
    let stream_id = format!("{}-{}", pod, STREAM_SEQ.fetch_add(1, Ordering::Relaxed));
    let sink = manager.sink();
    let id_for_task = stream_id.clone();
    // Outlive the stream task, which takes ownership of the originals.
    let ns_for_audit = namespace.clone();
    let pod_for_audit = pod.clone();
    let container_for_audit = container.clone();
    let handle: JoinHandle<()> = k7s_deps::tokio::spawn(async move {
        logs::run_log_stream(client, sink, id_for_task, namespace, pod, container, opts).await;
    });
    manager.add_log(stream_id.clone(), handle).await;
    // Audit identifiers only (never log content).
    crate::core::audit::record(
        "logs.start",
        k7s_deps::serde_json::json!({
            "stream_id": &stream_id,
            "namespace": &ns_for_audit,
            "pod": &pod_for_audit,
            "container": &container_for_audit,
        }),
    );
    stream_id
}

// ---------------------------------------------------------------------------
// Shared resource-operation cores
// ---------------------------------------------------------------------------
//
// Each function below contains the logic that was previously duplicated
// between `commands::core` (Tauri) and the HTTP handler layer (the old
// `web::resource_handlers`, since folded into the registry catch-all).
// The thin command/handler layer is responsible for obtaining a `kube::Client`
// and forwarding errors; everything else lives here.

/// Fetch an object's YAML for the detail panel. Strips `managedFields`;
/// Secret values are redacted. Helm releases are decoded from their
/// release Secret.
pub async fn fetch_object_yaml(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    mgr: &ClientManager,
) -> AppResult<String> {
    let (api, is_helm) = dynamic_api(client.clone(), kind, namespace, mgr).await?;
    if is_helm {
        return helm_manifest(client, namespace, name).await;
    }
    let mut obj: DynamicObject = api.get(name).await?;
    obj.metadata.managed_fields = None;
    if kind == "secrets" {
        redact_secret(&mut obj);
    }
    Ok(k7s_deps::yaml_serde::to_string(&obj)?)
}

/// Server-side dry-run replace: returns both the live object and what would
/// be stored after admission, each serialized as YAML with `managedFields`
/// stripped.
pub async fn dry_run_yaml_core(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    yaml: &str,
    mgr: &ClientManager,
) -> AppResult<YamlDiff> {
    ensure_writable(kind)?;
    let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml)?;
    let (_ar, namespaced) = resource_for(kind, mgr).await?;
    validate_apply_yaml(&obj, kind, name, namespace, namespaced)?;
    let (api, _is_helm) = dynamic_api(client, kind, namespace, mgr).await?;

    let mut current = api.get(name).await?;
    current.metadata.managed_fields = None;

    let pp = PostParams {
        dry_run: true,
        ..Default::default()
    };
    let mut proposed = api.replace(name, &pp, &obj).await?;
    proposed.metadata.managed_fields = None;

    Ok(YamlDiff {
        current: k7s_deps::yaml_serde::to_string(&current)?,
        proposed: k7s_deps::yaml_serde::to_string(&proposed)?,
    })
}

/// Apply edited YAML back to the cluster via replace.
pub async fn apply_yaml_core(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    yaml: &str,
    mgr: &ClientManager,
) -> AppResult<()> {
    ensure_writable(kind)?;
    let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml)?;
    let (_ar, namespaced) = resource_for(kind, mgr).await?;
    validate_apply_yaml(&obj, kind, name, namespace, namespaced)?;
    let (api, _is_helm) = dynamic_api(client, kind, namespace, mgr).await?;
    api.replace(name, &PostParams::default(), &obj).await?;
    Ok(())
}

/// Delete a resource of any kind.
pub async fn delete_resource_core(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    mgr: &ClientManager,
) -> AppResult<()> {
    let (api, _is_helm) = dynamic_api(client, kind, namespace, mgr).await?;
    api.delete(name, &DeleteParams::default()).await?;
    Ok(())
}

/// Scale a Deployment/StatefulSet by patching `spec.replicas`.
pub async fn scale_resource_core(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    replicas: i32,
    mgr: &ClientManager,
) -> AppResult<()> {
    let (api, _is_helm) = dynamic_api(client, kind, namespace, mgr).await?;
    let patch = Patch::Merge(k7s_deps::serde_json::json!({ "spec": { "replicas": replicas } }));
    api.patch(name, &PatchParams::default(), &patch).await?;
    Ok(())
}

/// Cordon or uncordon a node by patching `spec.unschedulable`.
pub async fn set_cordon_core(
    client: k7s_deps::kube::Client,
    name: &str,
    unschedulable: bool,
    mgr: &ClientManager,
) -> AppResult<()> {
    let (api, _is_helm) = dynamic_api(client, "nodes", "", mgr).await?;
    let patch =
        Patch::Merge(k7s_deps::serde_json::json!({ "spec": { "unschedulable": unschedulable } }));
    api.patch(name, &PatchParams::default(), &patch).await?;
    Ok(())
}

/// Restart a pod by deleting it so its controller recreates a fresh one.
/// Refuses a pod with no controlling owner.
pub async fn restart_pod_core(
    client: k7s_deps::kube::Client,
    namespace: &str,
    name: &str,
) -> AppResult<()> {
    let api: Api<k7s_deps::k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, namespace);
    let pod = api.get(name).await?;
    if !crate::kube::restart::has_controller(&pod) {
        return Err(AppError::Other(format!(
            "{name} has no controller — deleting it would not recreate it. Use Delete instead."
        )));
    }
    api.delete(name, &DeleteParams::default()).await?;
    crate::core::audit::record(
        "pod.restart",
        k7s_deps::serde_json::json!({
            "namespace": namespace,
            "pod": name,
        }),
    );
    Ok(())
}

/// Rollout-restart a Deployment/StatefulSet/DaemonSet by patching the pod
/// template's `restartedAt` annotation.
pub async fn restart_rollout_core(
    client: k7s_deps::kube::Client,
    kind: &str,
    namespace: &str,
    name: &str,
    mgr: &ClientManager,
) -> AppResult<()> {
    if !crate::kube::restart::is_rollout_kind(kind) {
        return Err(AppError::Other(format!(
            "{kind} cannot be rollout-restarted"
        )));
    }
    let (api, _is_helm) = dynamic_api(client, kind, namespace, mgr).await?;
    let now = k7s_deps::chrono::Utc::now().to_rfc3339();
    let patch = Patch::Merge(crate::kube::restart::restart_patch(&now));
    api.patch(name, &PatchParams::default(), &patch).await?;
    crate::core::audit::record(
        "rollout.restart",
        k7s_deps::serde_json::json!({
            "kind": kind,
            "namespace": namespace,
            "name": name,
        }),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid DynamicObject for testing.
    fn make_obj(kind: &str, api_version: &str, name: &str, namespace: &str) -> DynamicObject {
        let yaml = format!(
            r#"
apiVersion: {api_version}
kind: {kind}
metadata:
  name: {name}
  namespace: {namespace}
  resourceVersion: "12345"
"#
        );
        k7s_deps::yaml_serde::from_str(&yaml).unwrap()
    }

    #[test]
    fn valid_yaml_passes() {
        let obj = make_obj("Deployment", "apps/v1", "my-deploy", "default");
        assert!(validate_apply_yaml(&obj, "deployments", "my-deploy", "default", true).is_ok());
    }

    #[test]
    fn missing_types_fails() {
        let yaml = r#"
metadata:
  name: foo
  resourceVersion: "1"
"#;
        let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml).unwrap();
        let err = validate_apply_yaml(&obj, "deployments", "foo", "default", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing apiVersion and kind"), "got: {err}");
    }

    #[test]
    fn empty_api_version_fails() {
        let yaml = r#"
apiVersion: ""
kind: Deployment
metadata:
  name: foo
  namespace: default
  resourceVersion: "1"
"#;
        let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml).unwrap();
        let err = validate_apply_yaml(&obj, "deployments", "foo", "default", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty apiVersion"), "got: {err}");
    }

    #[test]
    fn empty_kind_fails() {
        let yaml = r#"
apiVersion: apps/v1
kind: ""
metadata:
  name: foo
  namespace: default
  resourceVersion: "1"
"#;
        let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml).unwrap();
        let err = validate_apply_yaml(&obj, "deployments", "foo", "default", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty kind"), "got: {err}");
    }

    #[test]
    fn kind_mismatch_fails() {
        let obj = make_obj("Service", "v1", "my-svc", "default");
        let err = validate_apply_yaml(&obj, "deployments", "my-svc", "default", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("kind 'Service' does not match"), "got: {err}");
    }

    #[test]
    fn name_mismatch_fails() {
        let obj = make_obj("Deployment", "apps/v1", "wrong-name", "default");
        let err = validate_apply_yaml(&obj, "deployments", "expected-name", "default", true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("metadata.name 'wrong-name' does not match"),
            "got: {err}"
        );
    }

    #[test]
    fn empty_name_fails() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ""
  namespace: default
  resourceVersion: "1"
"#;
        let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml).unwrap();
        let err = validate_apply_yaml(&obj, "deployments", "anything", "default", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing metadata.name"), "got: {err}");
    }

    #[test]
    fn namespace_mismatch_fails() {
        let obj = make_obj("Deployment", "apps/v1", "my-deploy", "wrong-ns");
        let err = validate_apply_yaml(&obj, "deployments", "my-deploy", "expected-ns", true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("namespace 'wrong-ns' does not match"),
            "got: {err}"
        );
    }

    #[test]
    fn missing_resource_version_fails() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
  namespace: default
"#;
        let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml).unwrap();
        let err = validate_apply_yaml(&obj, "deployments", "my-deploy", "default", true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing metadata.resourceVersion"),
            "got: {err}"
        );
    }

    #[test]
    fn cluster_scoped_skips_namespace_check() {
        // Nodes are cluster-scoped — namespace mismatch should be ignored.
        let obj = make_obj("Node", "v1", "node-1", "some-random-ns");
        assert!(validate_apply_yaml(&obj, "nodes", "node-1", "", false).is_ok());
    }

    #[test]
    fn custom_kind_skips_kind_check() {
        // CRD kinds contain '/' — the kind name check is skipped.
        let obj = make_obj("MyCustomResource", "example.com/v1", "my-cr", "default");
        assert!(validate_apply_yaml(
            &obj,
            "example.com/mycustomresources",
            "my-cr",
            "default",
            true
        )
        .is_ok());
    }

    #[test]
    fn namespaced_resource_with_empty_namespace_passes() {
        // If the YAML omits namespace entirely, we don't flag it (the server
        // will default it or the caller provides the right one).
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
  resourceVersion: "12345"
"#;
        let obj: DynamicObject = k7s_deps::yaml_serde::from_str(yaml).unwrap();
        assert!(validate_apply_yaml(&obj, "deployments", "my-deploy", "default", true).is_ok());
    }
}
