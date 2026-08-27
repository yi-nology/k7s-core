//! Draining a node (B20): cordon it, then evict the pods it's running.
//!
//! Eviction — not deletion — is the point: it goes through the API server's
//! eviction subresource, which honours PodDisruptionBudgets. A PDB that would be
//! violated makes the request fail with 429, and that is *information*, not a
//! transient error: it means evicting this pod now would take the workload below
//! its owner's declared availability. So a 429 is reported and the pod is left
//! alone, rather than retried in a loop until the budget happens to allow it.
//!
//! Two classes of pod are skipped, matching `kubectl drain`:
//!   - DaemonSet-owned pods, which the DaemonSet controller would immediately
//!     recreate on the same (now-cordoned) node — evicting them achieves nothing
//!   - static/mirror pods, which the kubelet owns and the API server can't evict
//!
//! Progress is emitted as it goes: a drain can take minutes, and the caller needs
//! to see which pods are stuck rather than watching a spinner.

use super::events;
use crate::core::events::EventSink;
use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::api::{Api, DeleteParams, EvictParams, ListParams, Patch, PatchParams};
use k7s_deps::kube::{Client, ResourceExt};
use serde::Serialize;

/// A pod that could not be evicted, and why.
#[derive(Serialize, Clone)]
pub struct DrainFailure {
    pub pod: String,
    pub message: String,
    /// True when a PodDisruptionBudget blocked it (HTTP 429) rather than a real
    /// error — the drain is being held back deliberately.
    pub blocked_by_pdb: bool,
}

/// Progress for one node's drain, emitted on [`events::DRAIN_PROGRESS`].
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DrainProgress {
    pub node: String,
    pub evicted: usize,
    /// Pods that are eligible for eviction (excludes DaemonSet/mirror pods).
    pub total: usize,
    pub failures: Vec<DrainFailure>,
    /// False while still working; true once every pod has been attempted.
    pub done: bool,
}

/// Cordon a node so nothing new schedules onto it.
pub async fn cordon(client: Client, node: &str) -> AppResult<()> {
    let api: Api<k7s_deps::k8s_openapi::api::core::v1::Node> = Api::all(client);
    let patch = k7s_deps::serde_json::json!({ "spec": { "unschedulable": true } });
    api.patch(node, &PatchParams::default(), &Patch::Merge(patch))
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    Ok(())
}

/// Evict every eligible pod on `node`, emitting progress as it goes.
///
/// Assumes the node is already cordoned (see [`cordon`]) — otherwise the
/// scheduler could place new pods on it while we're evicting.
pub async fn run_drain(client: Client, sink: EventSink, node: String) {
    let pods: Api<Pod> = Api::all(client.clone());
    // Only this node's pods. Field-selected server-side: a big cluster shouldn't
    // ship every pod over the wire to filter locally.
    let lp = ListParams::default().fields(&format!("spec.nodeName={node}"));
    let list = match pods.list(&lp).await {
        Ok(l) => l,
        Err(e) => {
            emit(
                &sink,
                DrainProgress {
                    node,
                    evicted: 0,
                    total: 0,
                    failures: vec![DrainFailure {
                        pod: String::new(),
                        message: format!("could not list pods: {e}"),
                        blocked_by_pdb: false,
                    }],
                    done: true,
                },
            );
            return;
        }
    };

    let targets: Vec<Pod> = list.items.into_iter().filter(is_evictable).collect();
    let total = targets.len();
    // Audit the dangerous operation up front with identifiers only — a drain
    // both cordons the node and evicts every eligible pod on it.
    crate::core::audit::record(
        "node.drain",
        k7s_deps::serde_json::json!({
            "node": &node,
            "pods": total,
        }),
    );
    let mut progress = DrainProgress {
        node: node.clone(),
        evicted: 0,
        total,
        failures: Vec::new(),
        done: false,
    };
    emit(&sink, progress.clone());

    let ep = EvictParams {
        delete_options: Some(DeleteParams::default()),
        ..Default::default()
    };
    for pod in targets {
        let name = pod.name_any();
        let ns = pod.namespace().unwrap_or_default();
        // Eviction is namespaced, and a node's pods span namespaces, so the Api is
        // per-pod — but it's built from a cheap Client clone rather than by
        // unwrapping the listing Api each time round.
        let api: Api<Pod> = Api::namespaced(client.clone(), &ns);
        match api.evict(&name, &ep).await {
            Ok(_) => progress.evicted += 1,
            Err(e) => {
                let blocked = is_pdb_block(&e);
                progress.failures.push(DrainFailure {
                    pod: format!("{ns}/{name}"),
                    message: if blocked {
                        // The raw 429 body is unhelpful; say what it means.
                        format!("blocked by a PodDisruptionBudget: {e}")
                    } else {
                        e.to_string()
                    },
                    blocked_by_pdb: blocked,
                });
            }
        }
        emit(&sink, progress.clone());
    }

    progress.done = true;
    emit(&sink, progress);
}

/// Emit progress (best-effort; the webview may be gone).
fn emit(sink: &EventSink, p: DrainProgress) {
    sink.emit(events::DRAIN_PROGRESS, &p);
}

/// True when this pod should be evicted as part of a drain.
fn is_evictable(pod: &Pod) -> bool {
    !is_daemonset_pod(pod) && !is_mirror_pod(pod) && !is_finished(pod) && !is_terminating(pod)
}

/// Already being deleted — the disruption has happened, and evicting it again
/// would just fail and be reported as a drain failure. kubectl skips these too.
fn is_terminating(pod: &Pod) -> bool {
    pod.metadata.deletion_timestamp.is_some()
}

/// DaemonSet-owned: the controller would put it straight back on this node.
fn is_daemonset_pod(pod: &Pod) -> bool {
    pod.metadata
        .owner_references
        .iter()
        .flatten()
        .any(|o| o.kind == "DaemonSet")
}

/// Static pods run by the kubelet; the API server has no way to evict them.
fn is_mirror_pod(pod: &Pod) -> bool {
    pod.metadata
        .annotations
        .as_ref()
        .map(|a| a.contains_key("kubernetes.io/config.mirror"))
        .unwrap_or(false)
}

/// Already Succeeded/Failed — nothing to disrupt.
fn is_finished(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.phase.as_deref())
        .map(|p| p == "Succeeded" || p == "Failed")
        .unwrap_or(false)
}

/// True when the API server refused the eviction because of a PodDisruptionBudget.
fn is_pdb_block(e: &k7s_deps::kube::Error) -> bool {
    matches!(e, k7s_deps::kube::Error::Api(resp) if resp.code == 429)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json::json;

    fn pod_json(v: k7s_deps::serde_json::Value) -> Pod {
        k7s_deps::serde_json::from_value(v).unwrap()
    }

    /// A plain Deployment-owned pod is what a drain is for.
    #[test]
    fn ordinary_pod_is_evictable() {
        let p = pod_json(json!({
            "metadata": { "name": "api", "namespace": "prod",
                          "ownerReferences": [{ "apiVersion": "apps/v1", "kind": "ReplicaSet",
                                                "name": "api-1", "uid": "u1" }] },
            "status": { "phase": "Running" },
        }));
        assert!(is_evictable(&p));
    }

    /// DaemonSet pods are skipped: the controller would recreate them on the same
    /// cordoned node, so evicting them is pure churn.
    #[test]
    fn daemonset_pods_are_skipped() {
        let p = pod_json(json!({
            "metadata": { "name": "node-exporter", "namespace": "monitoring",
                          "ownerReferences": [{ "apiVersion": "apps/v1", "kind": "DaemonSet",
                                                "name": "node-exporter", "uid": "u2" }] },
            "status": { "phase": "Running" },
        }));
        assert!(!is_evictable(&p));
    }

    /// Mirror pods are the kubelet's; the API server can't evict them.
    #[test]
    fn mirror_pods_are_skipped() {
        let p = pod_json(json!({
            "metadata": { "name": "kube-apiserver-node1", "namespace": "kube-system",
                          "annotations": { "kubernetes.io/config.mirror": "abc123" } },
            "status": { "phase": "Running" },
        }));
        assert!(!is_evictable(&p));
    }

    /// Completed pods have nothing to disrupt.
    #[test]
    fn finished_pods_are_skipped() {
        for phase in ["Succeeded", "Failed"] {
            let p = pod_json(json!({
                "metadata": { "name": "job-1", "namespace": "prod" },
                "status": { "phase": phase },
            }));
            assert!(!is_evictable(&p), "{phase} pods should be skipped");
        }
    }

    /// A pod already being deleted is left alone: the disruption has happened,
    /// and re-evicting it would fail and be reported as a drain failure.
    #[test]
    fn terminating_pods_are_skipped() {
        let p = pod_json(json!({
            "metadata": { "name": "api", "namespace": "prod",
                          "deletionTimestamp": "2026-07-16T09:00:00Z" },
            "status": { "phase": "Running" },
        }));
        assert!(!is_evictable(&p));
    }

    /// A pod with no owner (created by hand) still drains — kubectl warns about
    /// these, but leaving them would silently fail to empty the node.
    #[test]
    fn standalone_pod_is_evictable() {
        let p = pod_json(json!({
            "metadata": { "name": "debug", "namespace": "default" },
            "status": { "phase": "Running" },
        }));
        assert!(is_evictable(&p));
    }

    /// 429 means a PDB held the eviction back; anything else is a real error.
    #[test]
    fn pdb_block_is_detected_by_status_code() {
        use k7s_deps::kube::core::Status;
        let too_many = k7s_deps::kube::Error::Api(Box::new(Status {
            message: "Cannot evict pod as it would violate the pod's disruption budget.".into(),
            reason: "TooManyRequests".into(),
            code: 429,
            ..Default::default()
        }));
        assert!(is_pdb_block(&too_many));

        let not_found = k7s_deps::kube::Error::Api(Box::new(Status {
            message: "pods \"x\" not found".into(),
            reason: "NotFound".into(),
            code: 404,
            ..Default::default()
        }));
        assert!(!is_pdb_block(&not_found));
    }
}
