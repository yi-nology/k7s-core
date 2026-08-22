//! Pod mapping: NAME, NAMESPACE, READY, RESTARTS, CPU, MEM, AGE, STATUS.

use super::*;
use crate::kube::dto::{PodMeta, PodResources};
use crate::kube::observability::metrics::{parse_cpu_millis, parse_mem_bytes};
use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::ResourceExt;

/// Pods: NAME, NAMESPACE, READY, RESTARTS, CPU, MEM, AGE, STATUS.
pub fn map_pod(pod: &Pod) -> Row {
    let status = pod_status(pod);
    let tone = status_tone(&status);
    let (ready_str, ready_degraded) = pod_ready(pod);
    let restarts = pod_restarts(pod);

    let containers: Vec<String> = pod
        .spec
        .as_ref()
        .map(|s| s.containers.iter().map(|c| c.name.clone()).collect())
        .unwrap_or_default();
    let node = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.clone())
        .unwrap_or_else(|| "—".into());

    let cells = vec![
        name_cell(pod),
        ns_cell(pod),
        Cell::new(
            &ready_str,
            if ready_degraded {
                Tone::Warn
            } else {
                Tone::Secondary
            },
        ),
        Cell::new(
            restarts.to_string(),
            if restarts > 5 {
                Tone::Bad
            } else {
                Tone::Secondary
            },
        ),
        // CPU / MEM are overlaid from the metrics feed on the frontend.
        Cell::new("—", Tone::Secondary),
        Cell::new("—", Tone::Secondary),
        age_cell(pod),
        Cell::status(&status, tone),
    ];

    Row {
        uid: uid_of(pod),
        name: pod.name_any(),
        namespace: pod.namespace(),
        cells,
        pod: Some(PodMeta {
            node,
            containers,
            status,
            ready: ready_str,
            restarts,
            creation_ts: creation_rfc3339(pod),
            status_tone: tone,
            resources: pod_resources(pod),
        }),
        // Labels drive the "view pods" label-selector filter (B33).
        labels: pod.metadata.labels.clone(),
        ..Default::default()
    }
}

/// Derive a kubectl-like status word for a pod: a container's waiting/terminated
/// reason (e.g. CrashLoopBackOff) takes precedence over the phase.
fn pod_status(pod: &Pod) -> String {
    let phase = pod
        .status
        .as_ref()
        .and_then(|s| s.phase.clone())
        .unwrap_or_else(|| "Unknown".into());

    if let Some(st) = &pod.status {
        // A pod-level reason (e.g. "Evicted") overrides the phase.
        if let Some(reason) = &st.reason {
            if !reason.is_empty() {
                return reason.clone();
            }
        }
        // The first container that is waiting/terminated with a non-normal reason
        // determines the displayed status (CrashLoopBackOff, ImagePullBackOff, ...).
        for cs in st.container_statuses.iter().flatten() {
            if let Some(state) = &cs.state {
                if let Some(w) = &state.waiting {
                    if let Some(r) = &w.reason {
                        if !r.is_empty() {
                            return r.clone();
                        }
                    }
                }
                if let Some(t) = &state.terminated {
                    if let Some(r) = &t.reason {
                        if !r.is_empty() && r != "Completed" {
                            return r.clone();
                        }
                    }
                }
            }
        }
    }
    phase
}

/// "readyCount/total" plus whether it's degraded (not all ready).
fn pod_ready(pod: &Pod) -> (String, bool) {
    let statuses = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref());
    let total = pod.spec.as_ref().map(|s| s.containers.len()).unwrap_or(0);
    let ready = statuses
        .map(|cs| cs.iter().filter(|c| c.ready).count())
        .unwrap_or(0);
    (format!("{ready}/{total}"), ready != total || total == 0)
}

/// Total restart count across the pod's containers.
fn pod_restarts(pod: &Pod) -> i32 {
    pod.status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
        .map(|cs| cs.iter().map(|c| c.restart_count).sum())
        .unwrap_or(0)
}

/// Sum a pod's regular containers' CPU/memory requests and limits into pod totals
/// (see [`PodResources`] for the None semantics). Init containers are excluded so
/// the totals compare like-for-like against the usage the metrics feed reports.
fn pod_resources(pod: &Pod) -> PodResources {
    let containers = match pod.spec.as_ref() {
        Some(s) => &s.containers,
        None => return PodResources::default(),
    };
    if containers.is_empty() {
        return PodResources::default();
    }

    // A request total is meaningful once any container sets one; a limit total is
    // a true pod ceiling only when *every* container caps that resource, so an
    // uncapped container drops the whole limit to None.
    let (mut cpu_req, mut any_cpu_req) = (0i64, false);
    let (mut mem_req, mut any_mem_req) = (0i64, false);
    let (mut cpu_lim, mut all_cpu_lim) = (0i64, true);
    let (mut mem_lim, mut all_mem_lim) = (0i64, true);

    for ct in containers {
        let requests = ct.resources.as_ref().and_then(|r| r.requests.as_ref());
        let limits = ct.resources.as_ref().and_then(|r| r.limits.as_ref());

        if let Some(q) = requests.and_then(|m| m.get("cpu")) {
            cpu_req += parse_cpu_millis(&q.0);
            any_cpu_req = true;
        }
        if let Some(q) = requests.and_then(|m| m.get("memory")) {
            mem_req += parse_mem_bytes(&q.0);
            any_mem_req = true;
        }
        match limits.and_then(|m| m.get("cpu")) {
            Some(q) => cpu_lim += parse_cpu_millis(&q.0),
            None => all_cpu_lim = false,
        }
        match limits.and_then(|m| m.get("memory")) {
            Some(q) => mem_lim += parse_mem_bytes(&q.0),
            None => all_mem_lim = false,
        }
    }

    PodResources {
        cpu_request_millis: any_cpu_req.then_some(cpu_req),
        cpu_limit_millis: all_cpu_lim.then_some(cpu_lim),
        mem_request_bytes: any_mem_req.then_some(mem_req),
        mem_limit_bytes: all_mem_lim.then_some(mem_lim),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json::json;

    /// A healthy Running pod: status Good with a dot, ready/restarts Secondary.
    #[test]
    fn healthy_running_pod() {
        let pod: Pod = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "ok-pod", "namespace": "prod", "uid": "u1",
                          "creationTimestamp": "2026-07-01T00:00:00Z" },
            "spec": { "nodeName": "n1", "containers": [{ "name": "app" }, { "name": "side" }] },
            "status": { "phase": "Running", "containerStatuses": [
                { "name": "app", "ready": true, "restartCount": 0, "image": "i", "imageID": "d", "state": { "running": {} } },
                { "name": "side", "ready": true, "restartCount": 0, "image": "i", "imageID": "d", "state": { "running": {} } }
            ]}
        })).unwrap();
        let row = map_pod(&pod);
        // Columns: NAME,NAMESPACE,READY,RESTARTS,CPU,MEM,AGE,STATUS
        assert_eq!(
            row.cells[2].tone,
            Tone::Secondary,
            "2/2 ready is not degraded"
        );
        assert_eq!(row.cells[3].tone, Tone::Secondary, "0 restarts");
        assert_eq!(row.cells[7].tone, Tone::Good);
        assert!(row.cells[7].dot, "status cell has a leading dot");
        assert_eq!(row.pod.as_ref().unwrap().status, "Running");
    }

    /// CrashLoopBackOff: status Bad, degraded ready Warn, high restarts Bad.
    #[test]
    fn crashloop_pod() {
        let pod: Pod = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "crash", "namespace": "prod", "uid": "u2",
                          "creationTimestamp": "2026-07-15T09:00:00Z" },
            "spec": { "nodeName": "n2", "containers": [{ "name": "auth" }, { "name": "side" }] },
            "status": { "phase": "Running", "containerStatuses": [
                { "name": "auth", "ready": false, "restartCount": 14, "image": "i", "imageID": "d",
                  "state": { "waiting": { "reason": "CrashLoopBackOff" } } },
                { "name": "side", "ready": true, "restartCount": 0, "image": "i", "imageID": "d", "state": { "running": {} } }
            ]}
        })).unwrap();
        let row = map_pod(&pod);
        assert_eq!(row.cells[2].text, "1/2");
        assert_eq!(row.cells[2].tone, Tone::Warn, "1/2 ready is degraded");
        assert_eq!(row.cells[3].text, "14");
        assert_eq!(row.cells[3].tone, Tone::Bad, "restarts > 5");
        assert_eq!(row.cells[7].text, "CrashLoopBackOff");
        assert_eq!(row.cells[7].tone, Tone::Bad);
    }

    /// Pending pod: status Warn, CPU/MEM em-dash placeholders.
    #[test]
    fn pending_pod() {
        let pod: Pod = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "canary", "namespace": "staging", "uid": "u3",
                          "creationTimestamp": "2026-07-15T11:59:00Z" },
            "spec": { "containers": [{ "name": "a" }, { "name": "b" }, { "name": "c" }] },
            "status": { "phase": "Pending" }
        }))
        .unwrap();
        let row = map_pod(&pod);
        assert_eq!(row.cells[2].text, "0/3");
        assert_eq!(row.cells[2].tone, Tone::Warn);
        assert_eq!(row.cells[4].text, "—", "CPU is a placeholder");
        assert_eq!(row.cells[5].text, "—", "MEM is a placeholder");
        assert_eq!(row.cells[7].tone, Tone::Warn);
    }

    /// Pod resources sum across the regular containers, so the Metrics overlay
    /// lines up with the (likewise summed) usage feed.
    #[test]
    fn pod_resources_sum_across_containers() {
        let pod: Pod = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "two", "namespace": "prod", "uid": "r1" },
            "spec": { "containers": [
                { "name": "app", "resources": {
                    "requests": { "cpu": "250m", "memory": "256Mi" },
                    "limits": { "cpu": "500m", "memory": "512Mi" } } },
                { "name": "side", "resources": {
                    "requests": { "cpu": "100m", "memory": "64Mi" },
                    "limits": { "cpu": "200m", "memory": "128Mi" } } }
            ]}
        }))
        .unwrap();
        let r = map_pod(&pod).pod.unwrap().resources;
        assert_eq!(r.cpu_request_millis, Some(350));
        assert_eq!(r.cpu_limit_millis, Some(700));
        assert_eq!(r.mem_request_bytes, Some((256 + 64) * 1024 * 1024));
        assert_eq!(r.mem_limit_bytes, Some((512 + 128) * 1024 * 1024));
    }

    /// One uncapped container makes the pod uncapped: the limit total drops to
    /// None (no ceiling line), while the request total still sums what's set.
    #[test]
    fn pod_resources_uncapped_container_has_no_limit() {
        let pod: Pod = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "mixed", "namespace": "prod", "uid": "r2" },
            "spec": { "containers": [
                { "name": "app", "resources": {
                    "requests": { "cpu": "250m" },
                    "limits": { "cpu": "500m" } } },
                { "name": "side", "resources": { "requests": { "cpu": "100m" } } }
            ]}
        }))
        .unwrap();
        let r = map_pod(&pod).pod.unwrap().resources;
        assert_eq!(r.cpu_request_millis, Some(350), "requests still sum");
        assert_eq!(
            r.cpu_limit_millis, None,
            "an uncapped container means no ceiling"
        );
        assert_eq!(r.mem_request_bytes, None, "no memory requests set");
        assert_eq!(r.mem_limit_bytes, None);
    }

    /// A pod with no resources at all reports all-None rather than zeros, so the
    /// overlay draws nothing instead of a misleading line at zero.
    #[test]
    fn pod_resources_absent_are_none() {
        let pod: Pod = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "bare", "namespace": "prod", "uid": "r3" },
            "spec": { "containers": [{ "name": "app" }] }
        }))
        .unwrap();
        let r = map_pod(&pod).pod.unwrap().resources;
        assert_eq!(r.cpu_request_millis, None);
        assert_eq!(r.cpu_limit_millis, None);
        assert_eq!(r.mem_request_bytes, None);
        assert_eq!(r.mem_limit_bytes, None);
    }

    /// A pod carries its labels so the selector filter can match it (B33).
    #[test]
    fn pod_carries_labels() {
        let pod: Pod = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "wiki-x", "namespace": "wiki", "uid": "p2",
                          "labels": { "app": "wiki" } },
            "spec": { "containers": [{ "name": "app" }] },
            "status": { "phase": "Running" },
        }))
        .unwrap();
        let labels = map_pod(&pod).labels.expect("labels present");
        assert_eq!(labels.get("app").map(String::as_str), Some("wiki"));
    }

    // ---- property-based tests (proptest) ----

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn map_pod_never_panics(
            name in "[a-z][a-z0-9-]{0,20}",
            namespace in "[a-z][a-z0-9-]{0,20}",
            phase in "(Running|Pending|Failed|Succeeded|Unknown)",
            restarts in 0i32..1000,
        ) {
            let pod_json = k7s_deps::serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "uid": "test-uid",
                    "creationTimestamp": "2025-01-15T10:30:00Z"
                },
                "spec": { "nodeName": "node1", "containers": [] },
                "status": {
                    "phase": phase,
                    "containerStatuses": [{
                        "name": "app",
                        "ready": phase == "Running",
                        "restartCount": restarts,
                        "state": if phase == "Running" {
                            k7s_deps::serde_json::json!({"running": {}})
                        } else if phase == "Pending" {
                            k7s_deps::serde_json::json!({"waiting": {"reason": "ContainerCreating"}})
                        } else {
                            k7s_deps::serde_json::json!({"terminated": {"exitCode": 1, "reason": "Error"}})
                        }
                    }]
                }
            });
            let pod: Pod = k7s_deps::serde_json::from_value(pod_json).unwrap();
            let row = map_pod(&pod);

            // Universal invariants
            assert!(!row.uid.is_empty());
            assert!(!row.name.is_empty());
            assert!(row.namespace.is_some());
            assert_eq!(row.cells.len(), 8); // pods always have 8 cells
            for cell in &row.cells {
                assert!(!cell.text.is_empty(), "empty cell text in pod row");
            }

            // First cell is name with Primary tone
            assert_eq!(row.cells[0].tone, Tone::Primary);

            // PodMeta consistency
            if let Some(meta) = &row.pod {
                assert_eq!(meta.status, row.cells[7].text);
                assert_eq!(meta.restarts, restarts);
            }
        }
    }
}
