//! ConfigMap/Secret version snapshots: captures changes as the watcher sees them.
//!
//! Since Kubernetes does not store historical versions of ConfigMaps or Secrets,
//! this module snapshots them into a ring buffer when the user views a resource.
//! Each snapshot is keyed by resourceVersion so duplicate views are deduplicated.
//! Users can then compare any two snapshots to see what changed.

use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k7s_deps::kube::api::Api;
use k7s_deps::kube::Client;
use k7s_deps::tokio::sync::RwLock;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Maximum snapshots to keep per ConfigMap/Secret.
const MAX_SNAPSHOTS_PER_RESOURCE: usize = 20;

/// A point-in-time snapshot of a ConfigMap or Secret's data.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSnapshot {
    /// Kubernetes resourceVersion — the cluster's monotonic revision counter.
    pub resource_version: String,
    /// RFC3339 timestamp when this snapshot was taken.
    pub timestamp: String,
    /// Sorted list of data keys at this version.
    pub data_keys: Vec<String>,
    /// Serialized YAML of the resource (secrets are redacted).
    pub yaml: String,
}

/// Thread-safe store for ConfigMap/Secret snapshots.
///
/// Lives outside [`ClientManager::Inner`] because snapshots survive
/// disconnect/reconnect — the user may want to compare a snapshot from a
/// previous connection with one from a new connection to the same cluster.
#[derive(Clone)]
pub struct SnapshotStore {
    inner: Arc<RwLock<HashMap<String, VecDeque<ConfigSnapshot>>>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a snapshot for a ConfigMap or Secret.
    ///
    /// `key` is `"{kind}:{namespace}/{name}"` (e.g. `"configmaps:default/my-config"`).
    /// Deduplicates by `resource_version`: if the latest snapshot for this key
    /// already has the same version, the record is silently skipped.
    pub async fn record(&self, key: String, snapshot: ConfigSnapshot) {
        let mut map = self.inner.write().await;
        let queue = map.entry(key).or_insert_with(VecDeque::new);
        // Don't duplicate if resource_version hasn't changed.
        if queue
            .back()
            .map(|s| s.resource_version == snapshot.resource_version)
            .unwrap_or(false)
        {
            return;
        }
        queue.push_back(snapshot);
        while queue.len() > MAX_SNAPSHOTS_PER_RESOURCE {
            queue.pop_front();
        }
    }

    /// List available snapshots for a resource, newest last (chronological order).
    pub async fn list(&self, key: &str) -> Vec<ConfigSnapshot> {
        let map = self.inner.read().await;
        map.get(key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    /// Get a specific snapshot by resource version.
    pub async fn get(&self, key: &str, resource_version: &str) -> Option<ConfigSnapshot> {
        let map = self.inner.read().await;
        map.get(key)?
            .iter()
            .find(|s| s.resource_version == resource_version)
            .cloned()
    }

    /// Remove all snapshots for a resource key. Useful for housekeeping.
    pub async fn clear(&self, key: &str) {
        self.inner.write().await.remove(key);
    }

    /// Total number of resources being tracked (for diagnostics).
    pub async fn resource_count(&self) -> usize {
        self.inner.read().await.len()
    }
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Snapshot-on-view: fetch current state, record it, return the history.
// ---------------------------------------------------------------------------

/// Fetch the current state of a ConfigMap, snapshot it, and return all available
/// snapshots for that resource. This is the "snapshot on view" approach: each
/// time the user opens a ConfigMap's detail, we capture the current version.
pub async fn snapshot_configmap(
    store: &SnapshotStore,
    client: Client,
    namespace: &str,
    name: &str,
) -> AppResult<Vec<ConfigSnapshot>> {
    let api: Api<ConfigMap> = Api::namespaced(client, namespace);
    let cm = api.get(name).await?;

    let rv = cm.metadata.resource_version.clone().unwrap_or_default();
    let data_keys: Vec<String> = cm
        .data
        .as_ref()
        .map(|d| {
            let mut keys: Vec<String> = d.keys().cloned().collect();
            keys.sort();
            keys
        })
        .unwrap_or_default();

    // Serialize to YAML with managedFields stripped (same as get_yaml).
    let mut obj: k7s_deps::kube::api::DynamicObject = k7s_deps::serde_json::from_value(
        k7s_deps::serde_json::to_value(&cm).map_err(|e| AppError::Other(e.to_string()))?,
    )
    .map_err(|e| AppError::Other(e.to_string()))?;
    obj.metadata.managed_fields = None;
    let yaml = k7s_deps::yaml_serde::to_string(&obj)?;

    let snapshot = ConfigSnapshot {
        resource_version: rv,
        timestamp: k7s_deps::chrono::Utc::now().to_rfc3339(),
        data_keys,
        yaml,
    };

    let key = format!("configmaps:{namespace}/{name}");
    store.record(key.clone(), snapshot).await;
    Ok(store.list(&key).await)
}

/// Fetch the current state of a Secret, snapshot it, and return all available
/// snapshots. Secret values are redacted in the YAML (same as `get_yaml`).
pub async fn snapshot_secret(
    store: &SnapshotStore,
    client: Client,
    namespace: &str,
    name: &str,
) -> AppResult<Vec<ConfigSnapshot>> {
    let api: Api<Secret> = Api::namespaced(client, namespace);
    let sec = api.get(name).await?;

    let rv = sec.metadata.resource_version.clone().unwrap_or_default();
    let data_keys: Vec<String> = sec
        .data
        .as_ref()
        .map(|d| {
            let mut keys: Vec<String> = d.keys().cloned().collect();
            keys.sort();
            keys
        })
        .unwrap_or_default();

    // Serialize to YAML with managedFields stripped and secret values redacted.
    let mut obj: k7s_deps::kube::api::DynamicObject = k7s_deps::serde_json::from_value(
        k7s_deps::serde_json::to_value(&sec).map_err(|e| AppError::Other(e.to_string()))?,
    )
    .map_err(|e| AppError::Other(e.to_string()))?;
    obj.metadata.managed_fields = None;
    crate::core::shell_common::redact_secret(&mut obj);
    let yaml = k7s_deps::yaml_serde::to_string(&obj)?;

    let snapshot = ConfigSnapshot {
        resource_version: rv,
        timestamp: k7s_deps::chrono::Utc::now().to_rfc3339(),
        data_keys,
        yaml,
    };

    let key = format!("secrets:{namespace}/{name}");
    store.record(key.clone(), snapshot).await;
    Ok(store.list(&key).await)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(rv: &str) -> ConfigSnapshot {
        ConfigSnapshot {
            resource_version: rv.into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            data_keys: vec!["key-a".into(), "key-b".into()],
            yaml: "data:\n  key-a: val1\n  key-b: val2\n".into(),
        }
    }

    #[k7s_deps::tokio::test]
    async fn record_and_list() {
        let store = SnapshotStore::new();
        store
            .record("configmaps:ns/cm".into(), make_snapshot("100"))
            .await;
        store
            .record("configmaps:ns/cm".into(), make_snapshot("200"))
            .await;
        let list = store.list("configmaps:ns/cm").await;
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].resource_version, "100");
        assert_eq!(list[1].resource_version, "200");
    }

    #[k7s_deps::tokio::test]
    async fn dedup_by_resource_version() {
        let store = SnapshotStore::new();
        store
            .record("configmaps:ns/cm".into(), make_snapshot("100"))
            .await;
        store
            .record("configmaps:ns/cm".into(), make_snapshot("100"))
            .await;
        let list = store.list("configmaps:ns/cm").await;
        assert_eq!(
            list.len(),
            1,
            "duplicate resource_version should be deduped"
        );
    }

    #[k7s_deps::tokio::test]
    async fn ring_buffer_eviction() {
        let store = SnapshotStore::new();
        for i in 0..25 {
            store
                .record("configmaps:ns/cm".into(), make_snapshot(&i.to_string()))
                .await;
        }
        let list = store.list("configmaps:ns/cm").await;
        assert_eq!(list.len(), MAX_SNAPSHOTS_PER_RESOURCE);
        // Oldest (0..4) should have been evicted.
        assert_eq!(list[0].resource_version, "5");
        assert_eq!(list[19].resource_version, "24");
    }

    #[k7s_deps::tokio::test]
    async fn get_by_resource_version() {
        let store = SnapshotStore::new();
        store
            .record("secrets:ns/s".into(), make_snapshot("10"))
            .await;
        store
            .record("secrets:ns/s".into(), make_snapshot("20"))
            .await;
        let snap = store.get("secrets:ns/s", "10").await;
        assert!(snap.is_some());
        assert_eq!(snap.unwrap().resource_version, "10");
        assert!(store.get("secrets:ns/s", "99").await.is_none());
    }

    #[k7s_deps::tokio::test]
    async fn separate_keys_are_independent() {
        let store = SnapshotStore::new();
        store
            .record("configmaps:ns/a".into(), make_snapshot("1"))
            .await;
        store
            .record("configmaps:ns/b".into(), make_snapshot("2"))
            .await;
        assert_eq!(store.list("configmaps:ns/a").await.len(), 1);
        assert_eq!(store.list("configmaps:ns/b").await.len(), 1);
        assert_eq!(store.resource_count().await, 2);
    }

    #[k7s_deps::tokio::test]
    async fn clear_removes_key() {
        let store = SnapshotStore::new();
        store
            .record("configmaps:ns/cm".into(), make_snapshot("1"))
            .await;
        store.clear("configmaps:ns/cm").await;
        assert!(store.list("configmaps:ns/cm").await.is_empty());
    }
}
