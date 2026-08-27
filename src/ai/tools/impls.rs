//! Shared tool implementations — the canonical logic for every tool.
//!
//! Both the AI module's `Tool::call()` and the MCP server's `#[tool]` handlers
//! call into these functions. This eliminates duplication and ensures both
//! surfaces behave identically.
//!
//! Each function takes a `&ClientManager` + raw args, returns
//! `AppResult<serde_json::Value>`. The caller (AI or MCP) wraps the result
//! in its own error/result type.

use crate::core::shell_common;
use crate::error::{AppError, AppResult};
use crate::kube::manager::{ClientManager, ConnectionInfo};
use crate::kube::ResourceKind;
use k7s_deps::kube::api::{
    Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
};
use k7s_deps::kube::ResourceExt;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Read tools
// ---------------------------------------------------------------------------

/// List resources of a kind. Returns `[{name, namespace, kind, summary}]`.
pub async fn list_resources_impl(
    manager: &ClientManager,
    kind: &str,
    namespace: &str,
    label_selector: Option<&str>,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let (api, _is_helm) = shell_common::dynamic_api(client, kind, namespace, manager).await?;
    let mut lp = ListParams::default();
    if let Some(ls) = label_selector {
        if !ls.trim().is_empty() {
            lp = lp.labels(ls);
        }
    }
    let list: k7s_deps::kube::api::ObjectList<DynamicObject> = api.list(&lp).await?;
    let rows: Vec<k7s_deps::serde_json::Value> = list
        .iter()
        .map(|obj| {
            k7s_deps::serde_json::json!({
                "name": obj.name_any(),
                "namespace": obj.metadata.namespace,
                "kind": kind,
            })
        })
        .collect();
    Ok(k7s_deps::serde_json::json!(rows))
}

/// Redact Secret payloads in place. Kubernetes Secrets carry their sensitive
/// material in the `data` / `stringData` maps of the object body; every value is
/// replaced with `***` so nothing sensitive leaks into LLM context, tool
/// results, or the audit log. `kind` is the kind id the caller fetched (e.g.
/// `"secrets"`); other kinds are a no-op.
pub fn redact_secret_data(obj: &mut DynamicObject, kind: &str) {
    if !kind.eq_ignore_ascii_case("secrets") {
        return;
    }
    // DynamicObject.data is the whole object body; Kubernetes Secrets have
    // `data` and optionally `stringData` keys inside it.
    if let Some(map) = obj.data.as_object_mut() {
        for key in &["data", "stringData"] {
            if let Some(inner) = map.get_mut(*key) {
                if let Some(inner_map) = inner.as_object_mut() {
                    for v in inner_map.values_mut() {
                        *v = k7s_deps::serde_json::Value::String("***".to_string());
                    }
                }
            }
        }
    }
}

/// Describe a resource (structured JSON, managedFields stripped, secrets redacted).
pub async fn describe_resource_impl(
    manager: &ClientManager,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let (api, _) = shell_common::dynamic_api(client, kind, namespace, manager).await?;
    let mut obj: DynamicObject = api.get(name).await?;
    obj.metadata.managed_fields = None;
    redact_secret_data(&mut obj, kind);
    k7s_deps::serde_json::to_value(&obj).map_err(|e| AppError::Other(e.to_string()))
}

/// Get resource YAML (managedFields stripped, secrets redacted).
pub async fn get_resource_yaml_impl(
    manager: &ClientManager,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<String> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let (api, _) = shell_common::dynamic_api(client, kind, namespace, manager).await?;
    let mut obj: DynamicObject = api.get(name).await?;
    obj.metadata.managed_fields = None;
    redact_secret_data(&mut obj, kind);
    k7s_deps::yaml_serde::to_string(&obj).map_err(|e| AppError::Yaml(e.to_string()))
}

/// Get events for a resource.
pub async fn get_events_impl(
    manager: &ClientManager,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let kind_id = kind.rsplit('/').next().unwrap_or(kind);
    let involved_kind = match ResourceKind::from_id(kind_id) {
        Some(rk) => rk.kind_name(),
        None => kind_id,
    };
    let events: Api<k7s_deps::k8s_openapi::api::core::v1::Event> = if namespace.is_empty() {
        Api::all(client)
    } else {
        Api::namespaced(client, namespace)
    };
    let list = events
        .list(&ListParams::default().fields(&format!(
            "involvedObject.name={name},involvedObject.kind={involved_kind}"
        )))
        .await?;
    let rows: Vec<k7s_deps::serde_json::Value> = list
        .iter()
        .map(|e| {
            k7s_deps::serde_json::json!({
                "type": e.type_.clone().unwrap_or_default(),
                "reason": e.reason.clone().unwrap_or_default(),
                "message": e.message.clone().unwrap_or_default(),
                "count": e.count.unwrap_or(1),
            })
        })
        .collect();
    Ok(k7s_deps::serde_json::json!(rows))
}

/// Get pod logs.
pub async fn get_pod_logs_impl(
    manager: &ClientManager,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    tail: Option<i64>,
    previous: bool,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let pods: Api<k7s_deps::k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, namespace);
    let lp = k7s_deps::kube::api::LogParams {
        container: container.map(|s| s.to_string()),
        tail_lines: tail,
        previous,
        ..Default::default()
    };
    let logs = pods.logs(pod, &lp).await?;
    Ok(k7s_deps::serde_json::json!({ "logs": logs }))
}

/// Cluster health snapshot.
pub async fn get_cluster_health_impl(
    manager: &ClientManager,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let nodes: k7s_deps::kube::api::ObjectList<k7s_deps::k8s_openapi::api::core::v1::Node> =
        Api::all(client.clone()).list(&Default::default()).await?;
    let pods: k7s_deps::kube::api::ObjectList<k7s_deps::k8s_openapi::api::core::v1::Pod> =
        Api::all(client).list(&Default::default()).await?;
    let mut problems = Vec::new();
    let nodes_ready = nodes
        .iter()
        .filter(|n| {
            let ready = n
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .map(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
                .unwrap_or(false);
            if !ready {
                problems.push(format!("Node {} is NotReady", n.name_any()));
            }
            ready
        })
        .count();
    let pods_running = pods
        .iter()
        .filter(|p| {
            let phase = p
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("");
            let name = p.name_any();
            let ns = p.metadata.namespace.clone().unwrap_or_default();
            match phase {
                "Running" => true,
                "Failed" => {
                    problems.push(format!("Pod {ns}/{name} is Failed"));
                    false
                }
                "Pending" => {
                    if let Some(cs) = p
                        .status
                        .as_ref()
                        .and_then(|s| s.container_statuses.as_ref())
                    {
                        for c in cs {
                            if let Some(w) = c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                                problems.push(format!(
                                    "Pod {ns}/{name} waiting: {} ({})",
                                    w.reason.as_deref().unwrap_or("?"),
                                    w.message.as_deref().unwrap_or("")
                                ));
                            }
                        }
                    }
                    false
                }
                _ => false,
            }
        })
        .count();
    Ok(k7s_deps::serde_json::json!({
        "nodes_ready": nodes_ready,
        "nodes_total": nodes.items.len(),
        "pods_running": pods_running,
        "pods_total": pods.items.len(),
        "problems": problems,
    }))
}

// ---------------------------------------------------------------------------
// Write tools
// ---------------------------------------------------------------------------

/// Scale a workload.
pub async fn scale_resource_impl(
    manager: &ClientManager,
    kind: &str,
    namespace: &str,
    name: &str,
    replicas: i32,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    shell_common::ensure_writable(kind)?;
    let (api, _) = shell_common::dynamic_api(client, kind, namespace, manager).await?;
    let patch = Patch::Merge(k7s_deps::serde_json::json!({ "spec": { "replicas": replicas } }));
    api.patch(name, &PatchParams::default(), &patch).await?;
    Ok(
        k7s_deps::serde_json::json!({ "scaled": true, "kind": kind, "namespace": namespace, "name": name, "replicas": replicas }),
    )
}

/// Restart a workload (rollout restart).
pub async fn restart_workload_impl(
    manager: &ClientManager,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    if !crate::kube::restart::is_rollout_kind(kind) {
        return Err(AppError::Other(format!(
            "{kind} cannot be rollout-restarted"
        )));
    }
    let (api, _) = shell_common::dynamic_api(client, kind, namespace, manager).await?;
    let now = k7s_deps::chrono::Utc::now().to_rfc3339();
    let patch = Patch::Merge(crate::kube::restart::restart_patch(&now));
    api.patch(name, &PatchParams::default(), &patch).await?;
    Ok(
        k7s_deps::serde_json::json!({ "restarted": true, "kind": kind, "namespace": namespace, "name": name }),
    )
}

/// Delete a resource.
///
/// `ensure_writable` runs before the client is touched so the secrets/helm
/// refusal surfaces even when no cluster is connected — same contract as
/// `apply_manifest_impl`.
pub async fn delete_resource_impl(
    manager: &ClientManager,
    kind: &str,
    namespace: &str,
    name: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    // Audit the attempt before anything can refuse it — "who tried to delete
    // what" matters even (especially) when the write guard blocks it.
    crate::core::audit::record(
        "ai.delete",
        k7s_deps::serde_json::json!({ "kind": kind, "name": name, "namespace": namespace }),
    );
    shell_common::ensure_writable(kind)?;
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let (api, _) = shell_common::dynamic_api(client, kind, namespace, manager).await?;
    api.delete(name, &DeleteParams::default()).await?;
    Ok(
        k7s_deps::serde_json::json!({ "deleted": true, "kind": kind, "namespace": namespace, "name": name }),
    )
}

/// Apply a YAML manifest.
pub async fn apply_manifest_impl(
    manager: &ClientManager,
    yaml: &str,
    namespace: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let obj: DynamicObject =
        k7s_deps::yaml_serde::from_str(yaml).map_err(|e| AppError::Yaml(e.to_string()))?;
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or_else(|| AppError::Other("manifest has no metadata.name".into()))?;
    let kind_str = obj
        .types
        .as_ref()
        .map(|t| t.kind.clone())
        .ok_or_else(|| AppError::Other("manifest has no apiVersion/kind".into()))?;
    let kind_id = match ResourceKind::from_kind_name(&kind_str) {
        Some(rk) => rk.id(),
        None => return Err(AppError::Other(format!("unsupported kind: {kind_str}"))),
    };
    // Audit the attempt (with the parsed target) before mutating anything.
    crate::core::audit::record(
        "ai.apply",
        k7s_deps::serde_json::json!({ "kind": kind_id, "name": name, "namespace": namespace }),
    );
    shell_common::ensure_writable(kind_id)?;
    let (api, _) = shell_common::dynamic_api(client, kind_id, namespace, manager).await?;
    api.replace(&name, &PostParams::default(), &obj).await?;
    Ok(
        k7s_deps::serde_json::json!({ "applied": true, "kind": kind_id, "namespace": namespace, "name": name }),
    )
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Diagnose unhealthy resources.
pub async fn diagnose_unhealthy_impl(
    manager: &ClientManager,
    namespace: Option<&str>,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let mut problems: Vec<k7s_deps::serde_json::Value> = Vec::new();

    // Nodes.
    let nodes: k7s_deps::kube::api::ObjectList<k7s_deps::k8s_openapi::api::core::v1::Node> =
        Api::all(client.clone()).list(&Default::default()).await?;
    for n in nodes {
        let name = n.name_any();
        if let Some(conds) = n.status.as_ref().and_then(|s| s.conditions.as_ref()) {
            for c in conds {
                if c.type_ == "Ready" && c.status != "True" {
                    problems.push(k7s_deps::serde_json::json!({ "severity": "critical", "resource": name, "kind": "node", "reason": "NotReady" }));
                }
                if c.status == "True"
                    && matches!(
                        c.type_.as_str(),
                        "DiskPressure" | "MemoryPressure" | "PIDPressure" | "NetworkUnavailable"
                    )
                {
                    problems.push(k7s_deps::serde_json::json!({ "severity": "warning", "resource": name, "kind": "node", "reason": c.type_ }));
                }
            }
        }
    }

    // Pods.
    let pods: k7s_deps::kube::api::ObjectList<k7s_deps::k8s_openapi::api::core::v1::Pod> =
        match namespace {
            Some(ns) => Api::namespaced(client.clone(), ns),
            None => Api::all(client.clone()),
        }
        .list(&Default::default())
        .await?;
    for p in pods {
        let ns = p.metadata.namespace.clone().unwrap_or_default();
        let pod_name = p.name_any();
        let full = if ns.is_empty() {
            pod_name.clone()
        } else {
            format!("{ns}/{pod_name}")
        };
        if let Some(cs) = p
            .status
            .as_ref()
            .and_then(|s| s.container_statuses.as_ref())
        {
            for c in cs {
                // Waiting-reason checks.
                if let Some(w) = c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                    let reason = w.reason.as_deref().unwrap_or("Waiting");
                    if matches!(
                        reason,
                        "CrashLoopBackOff"
                            | "ImagePullBackOff"
                            | "ErrImagePull"
                            | "CreateContainerConfigError"
                    ) {
                        problems.push(k7s_deps::serde_json::json!({ "severity": "critical", "resource": full, "kind": "pod", "reason": reason }));
                    }
                }
                // Terminated-container checks.
                if let Some(t) = c.state.as_ref().and_then(|s| s.terminated.as_ref()) {
                    match t.exit_code {
                        137 => problems.push(k7s_deps::serde_json::json!({
                            "severity": "critical",
                            "resource": full,
                            "kind": "pod",
                            "reason": format!("OOMKilled: container '{}' exceeded memory limit", c.name),
                        })),
                        139 => problems.push(k7s_deps::serde_json::json!({
                            "severity": "critical",
                            "resource": full,
                            "kind": "pod",
                            "reason": format!("SegFault: container '{}' crashed with SIGSEGV", c.name),
                        })),
                        code if code > 0 => problems.push(k7s_deps::serde_json::json!({
                            "severity": "warning",
                            "resource": full,
                            "kind": "pod",
                            "reason": format!("CrashExit: container '{}' exited with code {}", c.name, code),
                        })),
                        _ => {}
                    }
                }
                // High restart count.
                if c.restart_count > 5 {
                    problems.push(k7s_deps::serde_json::json!({
                        "severity": "warning",
                        "resource": format!("{ns}/{}", c.name),
                        "kind": "pod",
                        "reason": format!("HighRestarts: container '{}' restarted {} times", c.name, c.restart_count),
                    }));
                }
            }
        }
    }

    // Deployments.
    let deps: k7s_deps::kube::api::ObjectList<k7s_deps::k8s_openapi::api::apps::v1::Deployment> =
        match namespace {
            Some(ns) => Api::namespaced(client.clone(), ns),
            None => Api::all(client),
        }
        .list(&Default::default())
        .await?;
    for d in deps {
        let ns = d.metadata.namespace.clone().unwrap_or_default();
        let full = if ns.is_empty() {
            d.name_any()
        } else {
            format!("{}/{}", ns, d.name_any())
        };
        if let Some(status) = &d.status {
            let unavailable = status.unavailable_replicas.unwrap_or(0);
            if unavailable > 0 {
                problems.push(k7s_deps::serde_json::json!({ "severity": "warning", "resource": full, "kind": "deployment", "reason": format!("{unavailable} unavailable replicas") }));
            }
        }
    }

    Ok(k7s_deps::serde_json::json!({ "problems": problems }))
}

// ---------------------------------------------------------------------------
// New tools (not in the original AI 12)
// ---------------------------------------------------------------------------

/// Batch-get multiple resources at once.
pub async fn batch_get_impl(
    manager: &ClientManager,
    requests: &[k7s_deps::serde_json::Value],
) -> AppResult<k7s_deps::serde_json::Value> {
    let mut results = Vec::new();
    for req in requests {
        let kind = req.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let ns = req.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
        let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let result = describe_resource_impl(manager, kind, ns, name).await;
        results.push(match result {
            Ok(v) => k7s_deps::serde_json::json!({ "kind": kind, "namespace": ns, "name": name, "data": v }),
            Err(e) => k7s_deps::serde_json::json!({ "kind": kind, "namespace": ns, "name": name, "error": e.to_string() }),
        });
    }
    Ok(k7s_deps::serde_json::json!({ "results": results }))
}

/// Diff two resources or two versions of the same resource.
pub async fn diff_resources_impl(
    manager: &ClientManager,
    kind: &str,
    ns_a: &str,
    name_a: &str,
    ns_b: &str,
    name_b: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    let yaml_a = get_resource_yaml_impl(manager, kind, ns_a, name_a).await?;
    let yaml_b = get_resource_yaml_impl(manager, kind, ns_b, name_b).await?;
    let same = yaml_a == yaml_b;
    Ok(k7s_deps::serde_json::json!({
        "same": same,
        "resource_a": { "kind": kind, "namespace": ns_a, "name": name_a },
        "resource_b": { "kind": kind, "namespace": ns_b, "name": name_b },
        "yaml_a_lines": yaml_a.lines().count(),
        "yaml_b_lines": yaml_b.lines().count(),
    }))
}

/// HPA status for a workload.
pub async fn hpa_status_impl(
    manager: &ClientManager,
    namespace: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let hpas: Api<k7s_deps::k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler> =
        Api::namespaced(client, namespace);
    let list = hpas.list(&ListParams::default()).await?;
    let rows: Vec<k7s_deps::serde_json::Value> = list
        .iter()
        .map(|h| {
            let name = h.name_any();
            let spec = &h.spec;
            let status = h.status.as_ref();
            k7s_deps::serde_json::json!({
                "name": name,
                "minReplicas": spec.min_replicas.unwrap_or(1),
                "maxReplicas": spec.max_replicas,
                "currentReplicas": status.as_ref().and_then(|s| s.current_replicas).unwrap_or(0),
                "targetCPU": spec.metrics.as_ref().and_then(|m| m.first()).map(|_| "configured"),
            })
        })
        .collect();
    Ok(k7s_deps::serde_json::json!({ "hpas": rows }))
}

// ---------------------------------------------------------------------------
// Security audit
// ---------------------------------------------------------------------------

/// Run the RBAC security audit and return findings.
pub async fn security_audit_impl(
    manager: &ClientManager,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let report = crate::kube::security::security_audit::run_audit(client).await?;
    k7s_deps::serde_json::to_value(report).map_err(|e| AppError::Other(e.to_string()))
}

/// Build the RBAC permission matrix and return it.
pub async fn rbac_permission_matrix_impl(
    manager: &ClientManager,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let matrix = crate::kube::security::rbac_matrix::build_rbac_matrix(client).await?;
    k7s_deps::serde_json::to_value(matrix).map_err(|e| AppError::Other(e.to_string()))
}

/// Deep diagnosis of a single pod: identifies OOMKilled, CrashLoop, ImagePullFailed,
/// config errors, segfaults, and other failure patterns.
pub async fn diagnose_pod_impl(
    manager: &ClientManager,
    namespace: &str,
    pod: &str,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;
    let diagnosis = crate::kube::pod_diagnosis::diagnose_pod(client, namespace, pod).await?;
    k7s_deps::serde_json::to_value(diagnosis).map_err(|e| AppError::Other(e.to_string()))
}

// ---------------------------------------------------------------------------
// Capacity planning (metrics.k8s.io wire types)
// ---------------------------------------------------------------------------

/// Raw wire types for metrics.k8s.io responses. These mirror the types in
/// `mcp::kube_api` and `kube::observability::metrics` but are defined here so the AI module
/// does not depend on feature-gated code.

#[derive(serde::Deserialize)]
struct MetricsList<T> {
    items: Vec<T>,
}

#[derive(serde::Deserialize)]
struct MetaName {
    name: String,
    #[serde(default)]
    namespace: String,
}

#[derive(serde::Deserialize)]
struct Usage {
    #[serde(default)]
    cpu: String,
    #[serde(default)]
    memory: String,
}

#[derive(serde::Deserialize)]
struct PodMetric {
    metadata: MetaName,
    containers: Vec<ContainerUsage>,
}

#[derive(serde::Deserialize)]
struct ContainerUsage {
    usage: Usage,
}

#[derive(serde::Deserialize)]
struct NodeMetric {
    metadata: MetaName,
    usage: Usage,
}

/// Helper: percentage used/capacity, guarding divide-by-zero.
fn pct(used: i64, cap: i64) -> f64 {
    if cap <= 0 {
        0.0
    } else {
        ((used as f64 / cap as f64) * 1000.0).round() / 10.0
    }
}

/// Get per-node CPU/memory usage and capacity from metrics.k8s.io.
pub async fn top_nodes_impl(manager: &ClientManager) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;

    // Fetch node metrics from metrics.k8s.io.
    let req = k7s_deps::http::Request::get("/apis/metrics.k8s.io/v1beta1/nodes")
        .body(Vec::new())
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let metrics: MetricsList<NodeMetric> = client.request(req).await?;

    // Fetch node objects for allocatable capacity.
    let nodes: Api<k7s_deps::k8s_openapi::api::core::v1::Node> = Api::all(client);
    let node_list = nodes.list(&ListParams::default()).await?;

    // Build capacity map from allocatable.
    let mut capacity: HashMap<String, (i64, i64)> = HashMap::new();
    for node in &node_list.items {
        let name = node.metadata.name.clone().unwrap_or_default();
        if let Some(status) = &node.status {
            if let Some(alloc) = &status.allocatable {
                let cpu = alloc
                    .get("cpu")
                    .map(|q| crate::kube::observability::metrics::parse_cpu_millis(&q.0))
                    .unwrap_or(0);
                let mem = alloc
                    .get("memory")
                    .map(|q| crate::kube::observability::metrics::parse_mem_bytes(&q.0))
                    .unwrap_or(0);
                capacity.insert(name, (cpu, mem));
            }
        }
    }

    // Combine metrics + capacity.
    let mut rows: Vec<k7s_deps::serde_json::Value> = Vec::new();
    for m in &metrics.items {
        let name = m.metadata.name.clone();
        let cpu = crate::kube::observability::metrics::parse_cpu_millis(&m.usage.cpu);
        let mem = crate::kube::observability::metrics::parse_mem_bytes(&m.usage.memory);
        let (cpu_cap, mem_cap) = capacity.get(&name).copied().unwrap_or((0, 0));
        let cpu_pct = pct(cpu, cpu_cap);
        let mem_pct = pct(mem, mem_cap);
        rows.push(k7s_deps::serde_json::json!({
            "node": name,
            "cpuMillis": cpu,
            "memBytes": mem,
            "cpuCapacityMillis": cpu_cap,
            "memCapacityBytes": mem_cap,
            "cpuPercent": cpu_pct,
            "memPercent": mem_pct,
        }));
    }
    rows.sort_by(|a, b| {
        b["cpuPercent"]
            .as_f64()
            .unwrap_or(0.0)
            .partial_cmp(&a["cpuPercent"].as_f64().unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(k7s_deps::serde_json::json!(rows))
}

/// Get per-pod CPU/memory usage from metrics.k8s.io.
pub async fn top_pods_impl(
    manager: &ClientManager,
    namespace: Option<&str>,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;

    let path = match namespace {
        Some(ns) if !ns.is_empty() => {
            format!("/apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods")
        }
        _ => "/apis/metrics.k8s.io/v1beta1/pods".to_string(),
    };
    let req = k7s_deps::http::Request::get(path)
        .body(Vec::new())
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let metrics: MetricsList<PodMetric> = client.request(req).await?;

    let mut rows: Vec<k7s_deps::serde_json::Value> = metrics
        .items
        .iter()
        .map(|pm| {
            let cpu: i64 = pm
                .containers
                .iter()
                .map(|c| crate::kube::observability::metrics::parse_cpu_millis(&c.usage.cpu))
                .sum();
            let mem: i64 = pm
                .containers
                .iter()
                .map(|c| crate::kube::observability::metrics::parse_mem_bytes(&c.usage.memory))
                .sum();
            k7s_deps::serde_json::json!({
                "namespace": pm.metadata.namespace,
                "pod": pm.metadata.name,
                "cpuMillis": cpu,
                "memBytes": mem,
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        b["cpuMillis"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["cpuMillis"].as_i64().unwrap_or(0))
    });

    Ok(k7s_deps::serde_json::json!(rows))
}

/// Generate a cluster capacity report with node usage, namespace aggregation,
/// and scaling recommendations.
pub async fn capacity_report_impl(
    manager: &ClientManager,
) -> AppResult<k7s_deps::serde_json::Value> {
    // Get node metrics.
    let nodes_json = top_nodes_impl(manager).await?;
    let nodes: Vec<k7s_deps::serde_json::Value> =
        k7s_deps::serde_json::from_value(nodes_json).unwrap_or_default();

    // Get pod metrics.
    let pods_json = top_pods_impl(manager, None).await?;
    let pods: Vec<k7s_deps::serde_json::Value> =
        k7s_deps::serde_json::from_value(pods_json).unwrap_or_default();

    // Cluster totals.
    let total_cpu: i64 = nodes
        .iter()
        .map(|n| n["cpuCapacityMillis"].as_i64().unwrap_or(0))
        .sum();
    let used_cpu: i64 = nodes
        .iter()
        .map(|n| n["cpuMillis"].as_i64().unwrap_or(0))
        .sum();
    let total_mem: i64 = nodes
        .iter()
        .map(|n| n["memCapacityBytes"].as_i64().unwrap_or(0))
        .sum();
    let used_mem: i64 = nodes
        .iter()
        .map(|n| n["memBytes"].as_i64().unwrap_or(0))
        .sum();

    // Per-namespace aggregation.
    let mut ns_map: HashMap<String, (i64, i64, usize)> = HashMap::new();
    for pod in &pods {
        let ns = pod["namespace"].as_str().unwrap_or("default");
        let cpu = pod["cpuMillis"].as_i64().unwrap_or(0);
        let mem = pod["memBytes"].as_i64().unwrap_or(0);
        let entry = ns_map.entry(ns.to_string()).or_insert((0, 0, 0));
        entry.0 += cpu;
        entry.1 += mem;
        entry.2 += 1;
    }
    let mut namespaces: Vec<k7s_deps::serde_json::Value> = ns_map
        .iter()
        .map(|(ns, (cpu, mem, count))| {
            k7s_deps::serde_json::json!({"name": ns, "podCount": count, "cpuMillis": cpu, "memBytes": mem})
        })
        .collect();
    namespaces.sort_by(|a, b| {
        b["cpuMillis"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["cpuMillis"].as_i64().unwrap_or(0))
    });

    // Alerts for nodes above 85%.
    let mut alerts = Vec::new();
    for node in &nodes {
        let name = node["node"].as_str().unwrap_or("?");
        let cpu_pct = node["cpuPercent"].as_f64().unwrap_or(0.0);
        let mem_pct = node["memPercent"].as_f64().unwrap_or(0.0);
        if cpu_pct > 85.0 {
            alerts.push(k7s_deps::serde_json::json!({
                "level": "warning",
                "node": name,
                "message": format!("{name} at {cpu_pct}% CPU")
            }));
        }
        if mem_pct > 85.0 {
            alerts.push(k7s_deps::serde_json::json!({
                "level": "warning",
                "node": name,
                "message": format!("{name} at {mem_pct}% memory")
            }));
        }
    }

    // Recommendations.
    let mut recommendations: Vec<String> = Vec::new();
    let cpu_pct = if total_cpu > 0 {
        used_cpu as f64 / total_cpu as f64 * 100.0
    } else {
        0.0
    };
    let mem_pct = if total_mem > 0 {
        used_mem as f64 / total_mem as f64 * 100.0
    } else {
        0.0
    };
    if cpu_pct > 75.0 {
        recommendations.push(
            "Cluster CPU usage above 75% \u{2014} consider adding nodes or scaling down workloads"
                .into(),
        );
    }
    if mem_pct > 75.0 {
        recommendations.push(
            "Cluster memory usage above 75% \u{2014} consider adding nodes or reducing memory requests"
                .into(),
        );
    }

    Ok(k7s_deps::serde_json::json!({
        "cluster": {
            "totalCpuMillis": total_cpu,
            "usedCpuMillis": used_cpu,
            "totalMemBytes": total_mem,
            "usedMemBytes": used_mem,
            "cpuPercent": (cpu_pct * 10.0).round() / 10.0,
            "memPercent": (mem_pct * 10.0).round() / 10.0,
            "nodeCount": nodes.len(),
        },
        "nodes": nodes,
        "namespaces": namespaces,
        "topPods": pods.iter().take(10).collect::<Vec<_>>(),
        "alerts": alerts,
        "recommendations": recommendations,
    }))
}

// ---------------------------------------------------------------------------
// kubectl context helper
// ---------------------------------------------------------------------------

/// Generate kubectl context information for command construction.
/// Returns the current cluster context, available namespaces, and common
/// kubectl command templates. The LLM uses this to build accurate,
/// context-aware kubectl commands the user can copy-paste.
pub async fn kubectl_context_impl(
    manager: &ClientManager,
) -> AppResult<k7s_deps::serde_json::Value> {
    let client = manager.client().await.ok_or(AppError::Disconnected)?;

    // Current context and server version from the connection info.
    let info = manager.connection_info().await.unwrap_or(ConnectionInfo {
        context: String::new(),
        server: String::new(),
        version: String::new(),
    });

    // List all namespaces.
    let ns_api: k7s_deps::kube::Api<k7s_deps::k8s_openapi::api::core::v1::Namespace> =
        k7s_deps::kube::Api::all(client);
    let ns_list = ns_api.list(&ListParams::default()).await?;
    let namespaces: Vec<String> = ns_list
        .items
        .iter()
        .filter_map(|ns| ns.metadata.name.clone())
        .collect();

    Ok(k7s_deps::serde_json::json!({
        "context": info.context,
        "serverVersion": info.version,
        "namespaces": namespaces,
        "templates": {
            "get": "kubectl get {resource} -n {namespace}",
            "describe": "kubectl describe {resource} {name} -n {namespace}",
            "logs": "kubectl logs {pod} -n {namespace} --tail=100",
            "exec": "kubectl exec -it {pod} -n {namespace} -- {command}",
            "portForward": "kubectl port-forward {pod} {local}:{remote} -n {namespace}",
            "scale": "kubectl scale {resource} {name} --replicas={n} -n {namespace}",
            "rollout": "kubectl rollout restart {resource} {name} -n {namespace}",
            "delete": "kubectl delete {resource} {name} -n {namespace}",
            "apply": "kubectl apply -f {file}",
            "top": "kubectl top {resource} -n {namespace}",
            "cordon": "kubectl cordon {node}",
            "drain": "kubectl drain {node} --ignore-daemonsets --delete-emptydir-data",
            "taint": "kubectl taint nodes {node} {key}={value}:{effect}",
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> ClientManager {
        ClientManager::new(crate::core::events::EventSink::Mcp(
            crate::core::events::McpEventSink::default(),
        ))
    }

    /// `delete_resource_impl` must refuse the same read-only kinds as
    /// `apply_manifest_impl` — the AI/MCP delete path used to bypass
    /// `ensure_writable` entirely, letting the agent delete Secrets and
    /// "Helm release" pseudo-resources.
    #[tokio::test]
    async fn delete_resource_refuses_secrets_and_helm() {
        let mgr = manager();
        for kind in ["secrets", "helm", "helmreleases"] {
            let err = delete_resource_impl(&mgr, kind, "default", "x")
                .await
                .expect_err("read-only kinds must be refused");
            let msg = err.to_string();
            assert!(
                msg.contains("Secret") || msg.contains("Helm"),
                "kind {kind}: unexpected error {msg}"
            );
        }
        // The refusal fires before the client is needed, so a disconnected
        // manager still yields the policy error rather than Disconnected.
        assert!(!delete_resource_impl(&mgr, "secrets", "default", "x")
            .await
            .unwrap_err()
            .to_string()
            .contains("connect"));
    }

    /// `redact_secret_data` masks every `data`/`stringData` value of a Secret
    /// and leaves other kinds (and other object fields) untouched — this is
    /// the single choke point describe/get-yaml/batch-get rely on to keep
    /// secret bytes out of LLM context.
    #[test]
    fn redact_secret_data_masks_secret_payloads() {
        let mut secret: DynamicObject =
            k7s_deps::serde_json::from_value(k7s_deps::serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "db-creds", "namespace": "prod" },
                "data": { "password": "cGFzc3dvcmQ=", "username": "YWRtaW4=" },
                "stringData": { "token": "raw-token" },
                "type": "Opaque"
            }))
            .unwrap();
        redact_secret_data(&mut secret, "secrets");
        let v = k7s_deps::serde_json::to_value(&secret).unwrap();
        assert_eq!(v["data"]["password"], "***");
        assert_eq!(v["data"]["username"], "***");
        assert_eq!(v["stringData"]["token"], "***");
        // Non-payload fields survive.
        assert_eq!(v["metadata"]["name"], "db-creds");
        assert_eq!(v["type"], "Opaque");

        // Non-secret kinds are a no-op.
        let mut cm: DynamicObject = k7s_deps::serde_json::from_value(k7s_deps::serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "cfg" },
            "data": { "keep": "me" }
        }))
        .unwrap();
        redact_secret_data(&mut cm, "configmaps");
        let v = k7s_deps::serde_json::to_value(&cm).unwrap();
        assert_eq!(v["data"]["keep"], "me");

        // Kind match is case-insensitive (callers may pass "Secrets").
        let mut secret2 = secret.clone();
        redact_secret_data(&mut secret2, "Secrets");
        let v = k7s_deps::serde_json::to_value(&secret2).unwrap();
        assert_eq!(v["data"]["password"], "***");
    }
}
