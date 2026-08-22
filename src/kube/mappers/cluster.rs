//! Cluster-scoped mapping: Node, Namespace, Event, and event utilities.

use super::*;
use crate::kube::dto::InvolvedRef;
use k7s_deps::k8s_openapi::api::core::v1::{Namespace, Node};
use k7s_deps::kube::ResourceExt;

/// Nodes: NAME, STATUS, ROLES, CPU, MEMORY, VERSION. (No namespace column.)
/// CPU/MEMORY are "—" placeholders overlaid from the node metrics feed.
pub fn map_node(node: &Node) -> Row {
    let conditions = node
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|cs| cs.as_slice())
        .unwrap_or(&[]);
    let is_ready = conditions
        .iter()
        .any(|c| c.type_ == "Ready" && c.status == "True");
    let has_pressure = conditions.iter().any(|c| {
        matches!(
            (c.type_.as_str(), c.status.as_str()),
            (
                "MemoryPressure" | "DiskPressure" | "PIDPressure" | "NetworkUnavailable",
                "True"
            )
        )
    });
    let (status_text, status_tone) = if !is_ready {
        ("NotReady", Tone::Bad)
    } else if has_pressure {
        ("Ready \u{26a0}", Tone::Warn)
    } else {
        ("Ready", Tone::Good)
    };

    // Roles come from "node-role.kubernetes.io/<role>" labels.
    let roles = node
        .labels()
        .keys()
        .filter_map(|k| k.strip_prefix("node-role.kubernetes.io/"))
        .filter(|r| !r.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    let roles = if roles.is_empty() {
        "<none>".to_string()
    } else {
        roles
    };

    let version = node
        .status
        .as_ref()
        .map(|s| {
            s.node_info
                .as_ref()
                .map(|i| i.kubelet_version.clone())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    let cells = vec![
        name_cell(node),
        Cell::status(status_text, status_tone),
        Cell::new(roles, Tone::Secondary),
        Cell::new("—", Tone::Secondary), // CPU % (overlaid)
        Cell::new("—", Tone::Secondary), // MEMORY % (overlaid)
        Cell::new(version, Tone::Secondary),
    ];
    Row {
        uid: uid_of(node),
        name: node.name_any(),
        namespace: None,
        cells,
        ..Default::default()
    }
}

/// Namespaces: NAME, STATUS, PODS, AGE. (No namespace column.)
/// PODS is "—": a per-namespace pod count would require a cross-watcher join,
/// deferred as a follow-up.
pub fn map_namespace(ns: &Namespace) -> Row {
    let phase = ns
        .status
        .as_ref()
        .and_then(|s| s.phase.clone())
        .unwrap_or_else(|| "Active".into());
    let tone = status_tone(&phase);
    let cells = vec![
        name_cell(ns),
        Cell::status(&phase, tone),
        Cell::new("—", Tone::Secondary),
        age_cell(ns),
    ];
    Row {
        uid: uid_of(ns),
        name: ns.name_any(),
        namespace: None,
        cells,
        ..Default::default()
    }
}

/// Events: TYPE, REASON, OBJECT, NAMESPACE, AGE, COUNT, MESSAGE.
///
/// The AGE cell carries a last-seen epoch as its sort key, which the watcher's
/// post-processing uses to order the feed (Warnings first, then newest).
pub fn map_event(e: &k7s_deps::k8s_openapi::api::core::v1::Event) -> Row {
    let type_ = e.type_.clone().unwrap_or_else(|| "Normal".into());
    // Warning is the only tone that should draw the eye; Normal reads green.
    let tone = if type_ == "Warning" {
        Tone::Bad
    } else {
        Tone::Good
    };

    let last = event_last_seen(e);
    let object = format!(
        "{}/{}",
        e.involved_object.kind.clone().unwrap_or_default(),
        e.involved_object.name.clone().unwrap_or_default()
    );

    let cells = vec![
        Cell::new(&type_, tone),
        Cell::new(e.reason.clone().unwrap_or_default(), Tone::Primary),
        Cell::new(object, Tone::Secondary),
        Cell::new(e.namespace().unwrap_or_default(), Tone::Muted),
        // Age from last-seen (not creation): events repeat and update lastTimestamp.
        Cell::age(Some(last.to_string())).with_sort(last.as_millisecond() as f64),
        Cell::new(format!("×{}", e.count.unwrap_or(1)), Tone::Secondary),
        Cell::new(e.message.clone().unwrap_or_default(), Tone::Secondary),
    ];

    Row {
        uid: uid_of(e),
        name: e.name_any(),
        namespace: e.namespace(),
        cells,
        // The object this event is about, for click-through (B33). The involved
        // object's own namespace is preferred; it usually equals the event's but
        // can differ (and cluster-scoped targets have none).
        involved: e.involved_object.kind.as_ref().map(|kind| InvolvedRef {
            kind: kind.clone(),
            name: e.involved_object.name.clone().unwrap_or_default(),
            namespace: e.involved_object.namespace.clone(),
            api_version: e.involved_object.api_version.clone(),
        }),
        ..Default::default()
    }
}

/// Best "last seen" time for an event: lastTimestamp, else eventTime, else creation.
fn event_last_seen(
    e: &k7s_deps::k8s_openapi::api::core::v1::Event,
) -> k7s_deps::k8s_openapi::jiff::Timestamp {
    if let Some(t) = &e.last_timestamp {
        return t.0;
    }
    if let Some(t) = &e.event_time {
        return t.0;
    }
    e.creation_timestamp().map(|t| t.0).unwrap_or_default()
}

/// Order the events feed: Warnings first, then most-recent first, capped.
/// Applied to the whole snapshot by the events watcher before emitting.
pub fn sort_events(mut rows: Vec<Row>, cap: usize) -> Vec<Row> {
    rows.sort_by(|a, b| {
        let warn = |r: &Row| {
            r.cells
                .first()
                .map(|c| c.text == "Warning")
                .unwrap_or(false)
        };
        let seen = |r: &Row| r.cells.get(4).and_then(|c| c.sort).unwrap_or(0.0);
        // Warnings before Normals, then newest first.
        warn(b).cmp(&warn(a)).then(
            seen(b)
                .partial_cmp(&seen(a))
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    rows.truncate(cap);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json::json;

    /// A Ready node shows a green status cell with a dot.
    #[test]
    fn ready_node() {
        let node: Node = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "n1", "uid": "nn1",
                          "labels": { "node-role.kubernetes.io/worker": "" } },
            "status": {
                "conditions": [{ "type": "Ready", "status": "True" }],
                "nodeInfo": { "kubeletVersion": "v1.31.2",
                    "machineID":"","systemUUID":"","bootID":"","kernelVersion":"",
                    "osImage":"","containerRuntimeVersion":"","kubeProxyVersion":"",
                    "operatingSystem":"linux","architecture":"arm64" }
            }
        }))
        .unwrap();
        let row = map_node(&node);
        // Columns: NAME,STATUS,ROLES,CPU,MEMORY,VERSION (no namespace)
        assert_eq!(row.namespace, None);
        assert_eq!(row.cells[1].text, "Ready");
        assert_eq!(row.cells[1].tone, Tone::Good);
        assert!(row.cells[1].dot);
        assert_eq!(row.cells[2].text, "worker");
        assert_eq!(row.cells[5].text, "v1.31.2");
    }

    // ---- Events feed (B14) ----

    /// Build an Event with a given type/reason and last-seen time.
    fn event(type_: &str, reason: &str, last: &str) -> k7s_deps::k8s_openapi::api::core::v1::Event {
        k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": format!("obj.{reason}"), "namespace": "prod", "uid": reason },
            "type": type_,
            "reason": reason,
            "count": 3,
            "message": "something happened",
            "lastTimestamp": last,
            "involvedObject": { "kind": "Pod", "name": "my-pod", "namespace": "prod" },
        }))
        .unwrap()
    }

    /// Columns TYPE, REASON, OBJECT, NAMESPACE, AGE, COUNT, MESSAGE; Warning tones red.
    #[test]
    fn warning_event_columns() {
        let row = map_event(&event("Warning", "FailedMount", "2026-07-16T09:00:00Z"));
        assert_eq!(row.cells[0].text, "Warning");
        assert_eq!(row.cells[0].tone, Tone::Bad);
        assert_eq!(row.cells[1].text, "FailedMount");
        assert_eq!(row.cells[2].text, "Pod/my-pod", "OBJECT is kind/name");
        assert_eq!(row.cells[3].text, "prod");
        assert_eq!(
            row.cells[4].format,
            Some("age"),
            "AGE is formatted by the frontend"
        );
        assert!(
            row.cells[4].sort.is_some(),
            "AGE carries the last-seen sort key"
        );
        assert_eq!(row.cells[5].text, "×3");
    }

    /// The involvedObject is threaded onto the row for click-through (B33) — the
    /// object's own kind/name/namespace, not the event's display-string cell.
    #[test]
    fn event_carries_involved_object() {
        let inv = map_event(&event("Warning", "FailedMount", "2026-07-16T09:00:00Z"))
            .involved
            .expect("involved present");
        assert_eq!(inv.kind, "Pod");
        assert_eq!(inv.name, "my-pod");
        assert_eq!(inv.namespace.as_deref(), Some("prod"));
    }

    /// Normal events read green.
    #[test]
    fn normal_event_tone() {
        let row = map_event(&event("Normal", "Pulled", "2026-07-16T09:00:00Z"));
        assert_eq!(row.cells[0].tone, Tone::Good);
    }

    /// The feed puts every Warning above every Normal, and newest first within each.
    #[test]
    fn feed_orders_warnings_then_newest() {
        let rows = vec![
            map_event(&event("Normal", "NewNormal", "2026-07-16T09:00:00Z")),
            map_event(&event("Warning", "OldWarn", "2026-07-16T08:00:00Z")),
            map_event(&event("Normal", "OldNormal", "2026-07-16T07:00:00Z")),
            map_event(&event("Warning", "NewWarn", "2026-07-16T08:30:00Z")),
        ];
        let sorted = sort_events(rows, 500);
        let reasons: Vec<&str> = sorted.iter().map(|r| r.cells[1].text.as_str()).collect();
        assert_eq!(reasons, ["NewWarn", "OldWarn", "NewNormal", "OldNormal"]);
    }

    /// The cap bounds the payload, keeping the highest-priority rows.
    #[test]
    fn feed_truncates_to_cap() {
        let rows = vec![
            map_event(&event("Warning", "Keep", "2026-07-16T09:00:00Z")),
            map_event(&event("Normal", "Drop", "2026-07-16T08:00:00Z")),
        ];
        let sorted = sort_events(rows, 1);
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].cells[1].text, "Keep");
    }

    /// A node with MemoryPressure=True shows a warning status.
    #[test]
    fn node_memory_pressure_warns() {
        let node: Node = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "n1", "uid": "nn1" },
            "status": {
                "conditions": [
                    { "type": "Ready", "status": "True" },
                    { "type": "MemoryPressure", "status": "True" }
                ],
                "nodeInfo": { "kubeletVersion": "v1.31.2",
                    "machineID":"","systemUUID":"","bootID":"","kernelVersion":"",
                    "osImage":"","containerRuntimeVersion":"","kubeProxyVersion":"",
                    "operatingSystem":"linux","architecture":"arm64" }
            }
        }))
        .unwrap();
        let row = map_node(&node);
        assert_eq!(row.cells[1].text, "Ready \u{26a0}");
        assert_eq!(row.cells[1].tone, Tone::Warn);
    }

    /// A node with no pressures and Ready=True shows green status.
    #[test]
    fn node_healthy_shows_ready() {
        let node: Node = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "n1", "uid": "nn1" },
            "status": {
                "conditions": [
                    { "type": "Ready", "status": "True" },
                    { "type": "MemoryPressure", "status": "False" },
                    { "type": "DiskPressure", "status": "False" },
                    { "type": "PIDPressure", "status": "False" }
                ],
                "nodeInfo": { "kubeletVersion": "v1.31.2",
                    "machineID":"","systemUUID":"","bootID":"","kernelVersion":"",
                    "osImage":"","containerRuntimeVersion":"","kubeProxyVersion":"",
                    "operatingSystem":"linux","architecture":"arm64" }
            }
        }))
        .unwrap();
        let row = map_node(&node);
        assert_eq!(row.cells[1].text, "Ready");
        assert_eq!(row.cells[1].tone, Tone::Good);
    }

    /// A node that is NotReady shows red regardless of pressure conditions.
    #[test]
    fn node_notready_overrides_pressure() {
        let node: Node = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "n1", "uid": "nn1" },
            "status": {
                "conditions": [
                    { "type": "Ready", "status": "False" },
                    { "type": "MemoryPressure", "status": "True" }
                ],
                "nodeInfo": { "kubeletVersion": "v1.31.2",
                    "machineID":"","systemUUID":"","bootID":"","kernelVersion":"",
                    "osImage":"","containerRuntimeVersion":"","kubeProxyVersion":"",
                    "operatingSystem":"linux","architecture":"arm64" }
            }
        }))
        .unwrap();
        let row = map_node(&node);
        assert_eq!(row.cells[1].text, "NotReady");
        assert_eq!(row.cells[1].tone, Tone::Bad);
    }

    /// lastTimestamp is preferred, but events that only carry eventTime still sort.
    #[test]
    fn event_time_fallback() {
        let e: k7s_deps::k8s_openapi::api::core::v1::Event =
            k7s_deps::serde_json::from_value(json!({
                "metadata": { "name": "e", "namespace": "prod", "uid": "u" },
                "type": "Normal",
                "reason": "Started",
                "eventTime": "2026-07-16T09:00:00.000000Z",
                "involvedObject": { "kind": "Pod", "name": "p" },
            }))
            .unwrap();
        let row = map_event(&e);
        assert!(row.cells[4].sort.is_some());
        assert_eq!(row.cells[5].text, "×1", "missing count defaults to 1");
    }
}
