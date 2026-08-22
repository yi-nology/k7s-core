//! Per-kind watchers. Each kind gets a task that drives a `kube` reflector (so a
//! local store stays current, including deletes) and emits a *full row snapshot*
//! for that kind, debounced to at most once per [`DEBOUNCE`]. Snapshots are
//! idempotent, which avoids any delta-reconciliation bugs in the UI.
//!
//! A watcher that fails (e.g. RBAC forbids a kind) logs and — thanks to
//! `default_backoff` — keeps retrying without affecting the other kinds.
//!
//! Each watcher also carries a post-processor applied to the snapshot before it
//! is emitted. Most kinds use [`identity`] (the frontend sorts); the Events feed
//! uses it to order and cap a stream that can otherwise run to thousands of rows.

use super::discovery::CustomKind;
use super::{
    dto::Row, events, helm, mappers, ClientManager, KindStatus, ResourceKind, ResourceUpdate,
};
use crate::core::events::EventSink;
use k7s_deps::futures::stream::BoxStream;
use k7s_deps::futures::StreamExt;
use k7s_deps::k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k7s_deps::k8s_openapi::api::batch::v1::{CronJob, Job};
use k7s_deps::k8s_openapi::api::core::v1::{
    ConfigMap, Event, Namespace, Node, PersistentVolume, PersistentVolumeClaim, Pod, Secret,
    Service, ServiceAccount,
};
use k7s_deps::k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use k7s_deps::k8s_openapi::api::storage::v1::StorageClass;
use k7s_deps::kube::core::{ApiResource, DynamicObject};
use k7s_deps::kube::runtime::reflector::Lookup;
use k7s_deps::kube::runtime::{reflector, watcher, WatchStreamExt};
use k7s_deps::kube::{Api, Client, Resource};
use k7s_deps::tokio::time::{interval, Duration, MissedTickBehavior};
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::hash::Hash;

/// Maximum snapshot emit rate per kind (coalesces bursts of watch events).
const DEBOUNCE: Duration = Duration::from_millis(150);

/// Cap on the cluster-wide events feed (B14) — busy clusters produce thousands.
const EVENTS_CAP: usize = 500;

/// Default snapshot post-processing: emit rows as the reflector holds them.
fn identity(rows: Vec<Row>) -> Vec<Row> {
    rows
}

/// Events feed ordering: Warnings first, newest first, capped.
fn events_order(rows: Vec<Row>) -> Vec<Row> {
    mappers::sort_events(rows, EVENTS_CAP)
}

/// Start watchers for every kind and register their tasks with the manager so
/// they are aborted on disconnect/context-switch. Returns the number started.
pub async fn spawn_all(mgr: &ClientManager, client: Client) -> usize {
    let mut count: usize = 0;
    // Each line pairs a typed resource with its mapper (the column contract) and
    // a snapshot post-processor (ordering/capping; identity for most kinds).
    spawn::<Pod>(mgr, &client, ResourceKind::Pods, mappers::map_pod, identity).await;
    count += 1;
    spawn::<Deployment>(
        mgr,
        &client,
        ResourceKind::Deployments,
        mappers::map_deployment,
        identity,
    )
    .await;
    count += 1;
    spawn::<ReplicaSet>(
        mgr,
        &client,
        ResourceKind::Replicasets,
        mappers::map_replicaset,
        identity,
    )
    .await;
    count += 1;
    spawn::<StatefulSet>(
        mgr,
        &client,
        ResourceKind::Statefulsets,
        mappers::map_statefulset,
        identity,
    )
    .await;
    count += 1;
    spawn::<DaemonSet>(
        mgr,
        &client,
        ResourceKind::Daemonsets,
        mappers::map_daemonset,
        identity,
    )
    .await;
    count += 1;
    spawn::<Job>(mgr, &client, ResourceKind::Jobs, mappers::map_job, identity).await;
    count += 1;
    spawn::<CronJob>(
        mgr,
        &client,
        ResourceKind::Cronjobs,
        mappers::map_cronjob,
        identity,
    )
    .await;
    count += 1;
    spawn::<Service>(
        mgr,
        &client,
        ResourceKind::Services,
        mappers::map_service,
        identity,
    )
    .await;
    count += 1;
    spawn::<Ingress>(
        mgr,
        &client,
        ResourceKind::Ingresses,
        mappers::map_ingress,
        identity,
    )
    .await;
    count += 1;
    spawn::<IngressClass>(
        mgr,
        &client,
        ResourceKind::Ingressclasses,
        mappers::map_ingressclass,
        identity,
    )
    .await;
    count += 1;
    spawn::<ConfigMap>(
        mgr,
        &client,
        ResourceKind::Configmaps,
        mappers::map_configmap,
        identity,
    )
    .await;
    count += 1;
    spawn::<Secret>(
        mgr,
        &client,
        ResourceKind::Secrets,
        mappers::map_secret,
        identity,
    )
    .await;
    count += 1;
    spawn::<ServiceAccount>(
        mgr,
        &client,
        ResourceKind::Serviceaccounts,
        mappers::map_serviceaccount,
        identity,
    )
    .await;
    count += 1;
    spawn::<PersistentVolumeClaim>(
        mgr,
        &client,
        ResourceKind::Persistentvolumeclaims,
        mappers::map_pvc,
        identity,
    )
    .await;
    count += 1;
    spawn::<PersistentVolume>(
        mgr,
        &client,
        ResourceKind::Persistentvolumes,
        mappers::map_pv,
        identity,
    )
    .await;
    count += 1;
    spawn::<StorageClass>(
        mgr,
        &client,
        ResourceKind::Storageclasses,
        mappers::map_storageclass,
        identity,
    )
    .await;
    count += 1;
    spawn::<Node>(
        mgr,
        &client,
        ResourceKind::Nodes,
        mappers::map_node,
        identity,
    )
    .await;
    count += 1;
    spawn::<Namespace>(
        mgr,
        &client,
        ResourceKind::Namespaces,
        mappers::map_namespace,
        identity,
    )
    .await;
    count += 1;
    // Phase 2 Tier-2: HPA (HorizontalPodAutoscaler) — namespaced, autoscaling/v1.
    // Uses DynamicObject path because map_hpa expects DynamicObject (same as
    // NetworkPolicy, ResourceQuota, LimitRange — their mappers are written
    // against DynamicObject for consistency with the CRD discovery path).
    {
        let kind = ResourceKind::Horizontalpodautoscalers;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(client_clone, sink, id, ar, namespaced, mappers::map_hpa).await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    // RBAC resources — DynamicObject-based watchers.
    {
        let kind = ResourceKind::Roles;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(client_clone, sink, id, ar, namespaced, mappers::map_role).await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    {
        let kind = ResourceKind::Clusterroles;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(
                client_clone,
                sink,
                id,
                ar,
                namespaced,
                mappers::map_clusterrole,
            )
            .await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    {
        let kind = ResourceKind::Rolebindings;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(
                client_clone,
                sink,
                id,
                ar,
                namespaced,
                mappers::map_rolebinding,
            )
            .await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    {
        let kind = ResourceKind::Clusterrolebindings;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(
                client_clone,
                sink,
                id,
                ar,
                namespaced,
                mappers::map_clusterrolebinding,
            )
            .await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    // PDB — DynamicObject-based watcher.
    {
        let kind = ResourceKind::Poddisruptionbudgets;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(client_clone, sink, id, ar, namespaced, mappers::map_pdb).await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    // MutatingWebhookConfiguration — DynamicObject-based watcher.
    {
        let kind = ResourceKind::Mutatingwebhookconfigurations;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(
                client_clone,
                sink,
                id,
                ar,
                namespaced,
                mappers::map_mutating_webhook,
            )
            .await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    // ValidatingWebhookConfiguration — DynamicObject-based watcher.
    {
        let kind = ResourceKind::Validatingwebhookconfigurations;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(
                client_clone,
                sink,
                id,
                ar,
                namespaced,
                mappers::map_validating_webhook,
            )
            .await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    // APIService — DynamicObject-based watcher.
    {
        let kind = ResourceKind::Apiservices;
        let ar = kind.api_resource();
        let namespaced = kind.is_namespaced();
        let sink = mgr.sink();
        let client_clone = client.clone();
        let id = kind.id().to_string();
        let handle = k7s_deps::tokio::spawn(async move {
            run_dynamic_watcher(
                client_clone,
                sink,
                id,
                ar,
                namespaced,
                mappers::map_api_service,
            )
            .await;
        });
        mgr.push_task(handle).await;
        count += 1;
    }
    // Cluster-wide events feed: ordered Warnings-first/newest and capped (B14).
    spawn::<Event>(
        mgr,
        &client,
        ResourceKind::Events,
        mappers::map_event,
        events_order,
    )
    .await;
    count += 1;
    // Helm releases, decoded from their Secrets (B26).
    let sink = mgr.sink();
    let helm_client = client.clone();
    let handle = k7s_deps::tokio::spawn(async move { run_helm_watcher(helm_client, sink).await });
    mgr.push_task(handle).await;
    count += 1;
    count
}

/// Spawn one watcher task and register it with the manager.
async fn spawn<K>(
    mgr: &ClientManager,
    client: &Client,
    kind: ResourceKind,
    map_fn: fn(&K) -> Row,
    post_fn: fn(Vec<Row>) -> Vec<Row>,
) where
    // All of these are concrete typed resources whose DynamicType (for both the
    // Resource and Lookup traits) is the unit type; pinning it to () disambiguates
    // the two associated types and satisfies the Default/Eq/Hash/Clone/Send bounds
    // required by Api::all, watcher(), and reflector::store().
    K: Resource<DynamicType = ()>
        + Lookup<DynamicType = ()>
        + Clone
        + DeserializeOwned
        + Debug
        + Send
        + Sync
        + 'static,
{
    let sink = mgr.sink();
    let client = client.clone();
    let handle = k7s_deps::tokio::spawn(async move {
        run_watcher::<K>(client, sink, kind, map_fn, post_fn).await;
    });
    mgr.push_task(handle).await;
}

/// Drive a reflector for `K` and emit debounced, post-processed snapshots for `kind`.
async fn run_watcher<K>(
    client: Client,
    sink: EventSink,
    kind: ResourceKind,
    map_fn: fn(&K) -> Row,
    post_fn: fn(Vec<Row>) -> Vec<Row>,
) where
    // Pin both DynamicType assoc types to () (see spawn()'s bound for why).
    K: Resource<DynamicType = ()>
        + Lookup<DynamicType = ()>
        + Clone
        + DeserializeOwned
        + Debug
        + Send
        + Sync
        + 'static,
{
    // Cluster-wide watch for this kind.
    let api: Api<K> = Api::all(client);
    let (reader, writer) = reflector::store::<K>();

    // reflector() writes every event into the store and passes it through; the
    // store therefore reflects adds *and* deletes. default_backoff() retries on
    // transient/permission errors instead of terminating the stream.
    let stream = reflector(writer, watcher(api, watcher::Config::default()))
        .default_backoff()
        .boxed();

    pump(
        reader,
        stream,
        sink,
        kind.id().to_string(),
        |o| Some(map_fn(o)),
        post_fn,
    )
    .await;
}

/// Ordering/reduction for the Helm feed: newest revision per release (B26).
fn helm_latest(rows: Vec<Row>) -> Vec<Row> {
    helm::latest_only(rows)
}

/// Watch Helm releases (B26).
///
/// A second Secrets watch, field-selected to Helm's release type — the API server
/// does the filtering, so this doesn't re-ship every Secret in the cluster just to
/// throw most of them away. It's separate from the Secrets kind on purpose: that
/// one redacts and lists Secrets as Secrets, while this one decodes them into
/// something else entirely.
async fn run_helm_watcher(client: Client, sink: EventSink) {
    let api: Api<Secret> = Api::all(client);
    let (reader, writer) = reflector::store::<Secret>();
    let cfg = watcher::Config::default().fields(&format!("type={}", helm::RELEASE_SECRET_TYPE));
    let stream = reflector(writer, watcher(api, cfg))
        .default_backoff()
        .boxed();

    pump(
        reader,
        stream,
        sink,
        ResourceKind::Helm.id().to_string(),
        helm::map_release,
        helm_latest,
    )
    .await;
}

/// Spawn a watcher for a CRD-backed kind (B15), registered so it can be aborted
/// on its own when the user navigates away. Unlike the built-ins these start
/// lazily: murphy-yi alone has 44 CRDs, and watching them all on connect would open
/// dozens of pointless streams.
pub async fn spawn_custom(mgr: &ClientManager, client: Client, kind: &CustomKind) {
    let sink = mgr.sink();
    let id = kind.id.clone();
    let ar = kind.api_resource();
    let namespaced = kind.namespaced;
    let handle = k7s_deps::tokio::spawn(async move {
        run_custom_watcher(client, sink, id, ar, namespaced).await;
    });
    mgr.add_custom_watcher(kind.id.clone(), handle).await;
}

/// Drive a `DynamicObject` reflector for one CRD-backed kind.
async fn run_custom_watcher(
    client: Client,
    sink: EventSink,
    id: String,
    ar: ApiResource,
    namespaced: bool,
) {
    let api: Api<DynamicObject> = Api::all_with(client, &ar);

    // DynamicObject's DynamicType is the ApiResource itself (it's what tells the
    // store how to identify objects), so the store is built from `ar` rather than
    // via reflector::store()'s Default-based path used for typed kinds.
    let writer = reflector::store::Writer::<DynamicObject>::new(ar.clone());
    let reader = writer.as_reader();

    let stream = reflector(writer, watcher(api, watcher::Config::default()))
        .default_backoff()
        .boxed();

    // Generic columns only: a CRD's interesting fields live in an arbitrary schema.
    pump(
        reader,
        stream,
        sink,
        id,
        move |o| Some(mappers::map_dynamic(o, namespaced)),
        identity,
    )
    .await;
}

/// Drive a `DynamicObject` reflector for one built-in kind that uses
/// DynamicObject mappers (HPA, NetworkPolicy, ResourceQuota, LimitRange).
/// Similar to `run_custom_watcher` but accepts a custom mapper function.
async fn run_dynamic_watcher(
    client: Client,
    sink: EventSink,
    id: String,
    ar: ApiResource,
    _namespaced: bool,
    map_fn: fn(&DynamicObject) -> Row,
) {
    let api: Api<DynamicObject> = Api::all_with(client, &ar);

    // DynamicObject's DynamicType is the ApiResource itself (it's what tells the
    // store how to identify objects), so the store is built from `ar` rather than
    // via reflector::store()'s Default-based path used for typed kinds.
    let writer = reflector::store::Writer::<DynamicObject>::new(ar.clone());
    let reader = writer.as_reader();

    let stream = reflector(writer, watcher(api, watcher::Config::default()))
        .default_backoff()
        .boxed();

    pump(reader, stream, sink, id, move |o| Some(map_fn(o)), identity).await;
}

/// The shared watch loop: coalesce watch events, and emit a full post-processed
/// snapshot at most once per [`DEBOUNCE`]. Generic over the object type so typed
/// and dynamic watchers share one implementation.
async fn pump<K>(
    reader: reflector::Store<K>,
    mut stream: BoxStream<'static, Result<watcher::Event<K>, watcher::Error>>,
    sink: EventSink,
    kind: String,
    // Option, not Row: the Helm watcher (B26) sees Secrets it can't decode, and a
    // watcher that must invent a row for every object it's handed would have to
    // put junk in the table.
    map_fn: impl Fn(&K) -> Option<Row>,
    post_fn: fn(Vec<Row>) -> Vec<Row>,
) where
    K: Lookup + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    // A ticker gates emits to at most one per DEBOUNCE window.
    let mut ticker = interval(DEBOUNCE);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut dirty = false;
    let mut was_forbidden = false;
    loop {
        k7s_deps::tokio::select! {
            // A watch event arrived; the store is already updated. Mark dirty so the
            // next tick emits a fresh snapshot.
            ev = stream.next() => match ev {
                Some(Ok(_)) => {
                    if was_forbidden {
                        was_forbidden = false;
                        sink.emit(
                            events::WATCH_KIND_STATUS,
                            &KindStatus { kind: kind.clone(), status: "ok".into() },
                        );
                    }
                    dirty = true;
                }
                Some(Err(e)) => {
                    // Logged, not fatal — backoff will retry this one kind.
                    k7s_deps::tracing::warn!("watch {kind} error: {e}");
                    let err_str = e.to_string();
                    if (err_str.contains("403") || err_str.contains("Forbidden"))
                        && !was_forbidden
                    {
                        was_forbidden = true;
                        sink.emit(
                            events::WATCH_KIND_STATUS,
                            &KindStatus { kind: kind.clone(), status: "forbidden".into() },
                        );
                    }
                }
                None => break, // stream ended (client dropped on reset)
            },
            // Debounce window elapsed; emit if anything changed.
            _ = ticker.tick() => {
                if dirty {
                    dirty = false;
                    let rows: Vec<Row> =
                        reader.state().iter().filter_map(|o| map_fn(o.as_ref())).collect();
                    let rows = post_fn(rows);
                    // Emit failures are non-fatal (webview may be gone).
                    sink.emit(
                        events::RESOURCE_UPDATE,
                        &ResourceUpdate { kind: kind.clone(), rows },
                    );
                }
            }
        }
    }
}
