//! [`ClientManager`] — the single owner of the active Kubernetes client and every
//! background task (watchers, pollers, log streams) spawned for the current
//! connection. Switching context or disconnecting aborts *all* of them here, so no
//! task ever outlives the connection that created it (Story 6.1).

use super::config_snapshots::SnapshotStore;
use super::discovery::CustomKind;
use super::events;
use crate::core::events::EventSink;
use k7s_deps::kube::Client;
use k7s_deps::tokio::sync::{mpsc, RwLock};
use k7s_deps::tokio::task::JoinHandle;
use serde::Serialize;
use std::collections::HashMap;

/// A running interactive shell session (B4): its pump task and the channels used
/// to feed it stdin and terminal-resize events.
pub struct ShellSession {
    pub task: JoinHandle<()>,
    pub input_tx: mpsc::Sender<Vec<u8>>,
    pub resize_tx: mpsc::Sender<(u16, u16)>,
}

/// Frontend-facing description of an active port-forward (B6).
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardDto {
    pub id: String,
    pub namespace: String,
    /// The pod traffic actually reaches — for a Service forward, the one that was
    /// selected (B16).
    pub pod: String,
    /// Set when this forward was started from a Service: the service's name, which
    /// is what the user asked for and what the strip shows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The port on the pod. For a Service forward this is the resolved targetPort,
    /// which may differ from the service port the user typed.
    pub remote_port: u16,
    /// The port as the user asked for it — the Service's own port (B16). Only set
    /// for Service forwards, and only when it differs from `remote_port`; the
    /// strip shows this, since the resolved targetPort is a port the Service
    /// doesn't publish and nobody asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_port: Option<u16>,
    pub local_port: u16,
    /// Last per-connection failure, if any (B16). The listener stays up, so this
    /// is how a forward whose pod died surfaces instead of silently timing out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A running port-forward: its accept-loop task plus the DTO for listing.
struct ForwardEntry {
    task: JoinHandle<()>,
    dto: ForwardDto,
}

/// What the UI shows in the connection banner: which context we're on,
/// where it points, and what the API server reported. Cheap to clone —
/// it's read by `GET /api/status` on every poll.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub context: String,
    pub server: String,
    pub version: String,
}

/// Mutable connection state guarded by an async RwLock.
#[derive(Default)]
struct Inner {
    /// Active client (None when disconnected).
    client: Option<Client>,
    /// Active cluster's connection metadata (None when disconnected). Cleared
    /// on reset so a `connection_info()` reader can tell "no current
    /// connection" from "stale info from a previous context".
    connection: Option<ConnectionInfo>,
    /// Watcher + poller tasks tied to the current connection.
    tasks: Vec<JoinHandle<()>>,
    /// Live log-stream tasks keyed by stream id.
    logs: HashMap<String, JoinHandle<()>>,
    /// Live shell sessions keyed by stream id.
    shells: HashMap<String, ShellSession>,
    /// Live port-forwards keyed by id.
    forwards: HashMap<String, ForwardEntry>,
    /// Number of resource watchers running (set on connect, 0 when disconnected).
    watcher_count: usize,
    /// CRD-backed kinds discovered on connect, keyed by kind id (B15). Populated
    /// on connect so commands can resolve a custom id back to its ApiResource.
    custom_kinds: HashMap<String, CustomKind>,
    /// Lazily-started watchers for custom kinds, keyed by kind id. Held separately
    /// from `tasks` because these are aborted individually when the user navigates
    /// away, not only on reset.
    custom_watchers: HashMap<String, JoinHandle<()>>,
    /// Node-exporter scrapers, keyed by node name (B27). Same lifetime rule as
    /// custom watchers: one runs only while its node's Metrics tab is open.
    node_scrapers: HashMap<String, JoinHandle<()>>,
}

/// A context imported from a non-default kubeconfig file: its source path and the
/// cluster it points at (for display in the switcher).
///
/// The `kubeconfig` field is `Some` only in the web shell — the Tauri
/// shell has the real file on disk and can re-read it from `path` on
/// every `connect`, while the web shell only ever has the bytes the user
/// picked in the browser. Storing the parsed `Kubeconfig` here lets
/// `connect` work in both shells without re-parsing or re-reading from
/// disk.
#[derive(Clone)]
pub struct ImportedContext {
    pub path: String,
    pub cluster: String,
    /// Parsed kubeconfig. `Some` in the web shell, `None` in the Tauri
    /// shell (which re-reads from `path` on every connect).
    pub kubeconfig: Option<k7s_deps::kube::config::Kubeconfig>,
}

/// Owns the client + all connection-scoped tasks. Stored in Tauri managed state
/// and shared across commands via `State<Arc<ClientManager>>`.
///
/// The manager no longer holds a Tauri `AppHandle` — it holds an `EventSink`
/// instead, so the same manager can be used by the standalone web shell (with
/// a `WebEventSink` that publishes to a broadcast channel) and the Tauri
/// shell (with a `TauriEventSink` that calls `app.emit`). Wire format on the
/// Tauri IPC channel is unchanged; the web shell sees the same event names.
pub struct ClientManager {
    sink: EventSink,
    inner: RwLock<Inner>,
    /// Contexts imported from extra kubeconfig files, keyed by context name.
    /// Persists across connect/reset (it's not connection-scoped) so `connect` can
    /// find which file to build a client from.
    imports: RwLock<HashMap<String, ImportedContext>>,
    /// ConfigMap/Secret version snapshots. Persists across connections so users
    /// can compare versions even after a context switch.
    snapshot_store: SnapshotStore,
}

impl ClientManager {
    pub fn new(sink: EventSink) -> Self {
        ClientManager {
            sink,
            inner: RwLock::new(Inner::default()),
            imports: RwLock::new(HashMap::new()),
            snapshot_store: SnapshotStore::new(),
        }
    }

    /// Record an imported context so a later `connect` builds from its source file.
    pub async fn add_import(&self, name: String, imported: ImportedContext) {
        self.imports.write().await.insert(name, imported);
    }

    /// The source file for an imported context, if it was imported.
    pub async fn import_path(&self, context: &str) -> Option<String> {
        self.imports
            .read()
            .await
            .get(context)
            .map(|i| i.path.clone())
    }

    /// The parsed `Kubeconfig` for an imported context, if it was uploaded
    /// through the web shell (which can't read the file again later). The
    /// Tauri shell always returns `None` here — it has the real file on
    /// disk and re-reads it through `import_path` + `build_client_from_file`.
    pub async fn import_kubeconfig(
        &self,
        context: &str,
    ) -> Option<k7s_deps::kube::config::Kubeconfig> {
        self.imports
            .read()
            .await
            .get(context)
            .and_then(|i| i.kubeconfig.clone())
    }

    /// Snapshot of all imported contexts (name → source), for building the merged
    /// switcher list.
    pub async fn imports(&self) -> HashMap<String, ImportedContext> {
        self.imports.read().await.clone()
    }

    /// Clone of the active client, if connected.
    pub async fn client(&self) -> Option<Client> {
        self.inner.read().await.client.clone()
    }

    /// Snapshot of the active connection (context / server / version). `None`
    /// when disconnected — distinct from "stale info", because `reset`
    /// clears this field atomically with the client.
    pub async fn connection_info(&self) -> Option<ConnectionInfo> {
        self.inner.read().await.connection.clone()
    }

    /// Number of resource watchers running for the current connection. Zero
    /// when disconnected. Used by the sidebar footer (k7s) and by
    /// `GET /api/status` (web shell).
    pub async fn watcher_count(&self) -> usize {
        self.inner.read().await.watcher_count
    }

    /// Tear down the current connection: abort every watcher, poller, and log
    /// stream, and clear the client. Emits watch-status 0. Called on disconnect
    /// and before switching context.
    pub async fn reset(&self) {
        let mut inner = self.inner.write().await;
        for t in inner.tasks.drain(..) {
            t.abort();
        }
        for (_, t) in inner.logs.drain() {
            t.abort();
        }
        for (_, s) in inner.shells.drain() {
            s.task.abort();
        }
        for (_, f) in inner.forwards.drain() {
            f.task.abort();
        }
        // Lazily-started CRD watchers (B15) are connection-scoped too.
        for (_, t) in inner.custom_watchers.drain() {
            t.abort();
        }
        // As are node-exporter scrapers (B27) — each holds a port-forward.
        for (_, t) in inner.node_scrapers.drain() {
            t.abort();
        }
        // The discovered kinds belong to the old cluster; the next connect re-discovers.
        inner.custom_kinds.clear();
        inner.client = None;
        // Drop connection metadata so a reader can't see "context: prod,
        // server: X" with no actual client behind it. Important for the
        // status endpoint: `connected: true` only when both are present.
        inner.connection = None;
        inner.watcher_count = 0;
        drop(inner);
        self.emit_watch().await;
        // Forwards are gone with the connection; tell the strip so it empties.
        self.emit_forwards().await;
    }

    /// Record a freshly established connection. Watchers are registered separately
    /// via [`push_task`]; `watcher_count` is the number of kinds being watched,
    /// used for the sidebar footer. `info` is what `GET /api/status` returns
    /// to identify the cluster to the user.
    pub async fn set_connected(&self, client: Client, info: ConnectionInfo, watcher_count: usize) {
        let mut inner = self.inner.write().await;
        inner.client = Some(client);
        inner.connection = Some(info);
        inner.watcher_count = watcher_count;
        drop(inner);
        self.emit_watch().await;
    }

    /// Register a connection-scoped background task so it is aborted on reset.
    pub async fn push_task(&self, handle: JoinHandle<()>) {
        self.inner.write().await.tasks.push(handle);
    }

    /// Register a log-stream task by id and bump the watch count.
    pub async fn add_log(&self, id: String, handle: JoinHandle<()>) {
        {
            let mut inner = self.inner.write().await;
            // Replace any existing stream with the same id (defensive).
            if let Some(old) = inner.logs.insert(id, handle) {
                old.abort();
            }
        }
        self.emit_watch().await;
    }

    /// Abort a log stream by id (idempotent) and drop the watch count.
    pub async fn remove_log(&self, id: &str) {
        let existed = {
            let mut inner = self.inner.write().await;
            inner.logs.remove(id).map(|h| h.abort()).is_some()
        };
        if existed {
            self.emit_watch().await;
        }
    }

    // ---- shell sessions (B4) ----

    /// Register a shell session by id.
    pub async fn add_shell(&self, id: String, session: ShellSession) {
        {
            let mut inner = self.inner.write().await;
            if let Some(old) = inner.shells.insert(id, session) {
                old.task.abort();
            }
        }
        self.emit_watch().await;
    }

    /// Send stdin bytes to a shell session (no-op if the id is unknown).
    pub async fn shell_input(&self, id: &str, data: Vec<u8>) {
        let tx = self
            .inner
            .read()
            .await
            .shells
            .get(id)
            .map(|s| s.input_tx.clone());
        if let Some(tx) = tx {
            let _ = tx.send(data).await;
        }
    }

    /// Send a terminal resize to a shell session.
    pub async fn shell_resize(&self, id: &str, cols: u16, rows: u16) {
        let tx = self
            .inner
            .read()
            .await
            .shells
            .get(id)
            .map(|s| s.resize_tx.clone());
        if let Some(tx) = tx {
            let _ = tx.send((cols, rows)).await;
        }
    }

    /// Abort a shell session by id (idempotent).
    pub async fn remove_shell(&self, id: &str) {
        let existed = {
            let mut inner = self.inner.write().await;
            inner.shells.remove(id).map(|s| s.task.abort()).is_some()
        };
        if existed {
            self.emit_watch().await;
        }
    }

    // ---- port-forwards (B6) ----

    /// Register a port-forward.
    pub async fn add_forward(&self, dto: ForwardDto, task: JoinHandle<()>) {
        {
            let mut inner = self.inner.write().await;
            inner
                .forwards
                .insert(dto.id.clone(), ForwardEntry { task, dto });
        }
        self.emit_watch().await;
        self.emit_forwards().await;
    }

    /// Abort a port-forward by id (idempotent).
    pub async fn remove_forward(&self, id: &str) {
        let existed = {
            let mut inner = self.inner.write().await;
            inner.forwards.remove(id).map(|f| f.task.abort()).is_some()
        };
        if existed {
            self.emit_watch().await;
            self.emit_forwards().await;
        }
    }

    /// Record a per-connection failure against a forward and push it to the UI
    /// (B16). The forward keeps running: its listener is still bound, and the pod
    /// may well come back.
    pub async fn set_forward_error(&self, id: &str, error: String) {
        let changed = {
            let mut inner = self.inner.write().await;
            match inner.forwards.get_mut(id) {
                Some(f) => {
                    f.dto.error = Some(error);
                    true
                }
                None => false,
            }
        };
        if changed {
            self.emit_forwards().await;
        }
    }

    /// Snapshot of active port-forwards for the UI list.
    pub async fn list_forwards(&self) -> Vec<ForwardDto> {
        self.inner
            .read()
            .await
            .forwards
            .values()
            .map(|f| f.dto.clone())
            .collect()
    }

    /// Push the current forwards to the UI.
    async fn emit_forwards(&self) {
        let list = self.list_forwards().await;
        self.sink.emit(events::FORWARDS_UPDATE, &list);
    }

    // ---- custom (CRD-backed) kinds (B15) ----

    /// Record the kinds discovered for this connection.
    pub async fn set_custom_kinds(&self, kinds: Vec<CustomKind>) {
        let mut inner = self.inner.write().await;
        inner.custom_kinds = kinds.into_iter().map(|k| (k.id.clone(), k)).collect();
    }

    /// Look up a discovered custom kind by id (e.g. "argoproj.io/applications").
    pub async fn custom_kind(&self, id: &str) -> Option<CustomKind> {
        self.inner.read().await.custom_kinds.get(id).cloned()
    }

    /// Register a lazily-started watcher for a custom kind. Replaces (and aborts)
    /// any existing watcher for the same kind, so double-registration is safe.
    pub async fn add_custom_watcher(&self, id: String, handle: JoinHandle<()>) {
        {
            let mut inner = self.inner.write().await;
            if let Some(old) = inner.custom_watchers.insert(id, handle) {
                old.abort();
            }
        }
        self.emit_watch().await;
    }

    /// True when a watcher for this custom kind is already running.
    pub async fn has_custom_watcher(&self, id: &str) -> bool {
        self.inner.read().await.custom_watchers.contains_key(id)
    }

    /// Abort a custom kind's watcher (idempotent), e.g. when the user navigates away.
    pub async fn remove_custom_watcher(&self, id: &str) {
        let existed = {
            let mut inner = self.inner.write().await;
            inner
                .custom_watchers
                .remove(id)
                .map(|h| h.abort())
                .is_some()
        };
        if existed {
            self.emit_watch().await;
        }
    }

    /// Register a node-exporter scraper (B27). Replaces any existing one for the
    /// same node, so opening the tab twice can't leave a forward behind.
    pub async fn add_node_scraper(&self, node: String, handle: JoinHandle<()>) {
        {
            let mut inner = self.inner.write().await;
            if let Some(old) = inner.node_scrapers.insert(node, handle) {
                old.abort();
            }
        }
        self.emit_watch().await;
    }

    /// True when this node is already being scraped.
    pub async fn has_node_scraper(&self, node: &str) -> bool {
        self.inner.read().await.node_scrapers.contains_key(node)
    }

    /// Stop scraping a node (idempotent), dropping its port-forward with it.
    pub async fn remove_node_scraper(&self, node: &str) {
        let existed = {
            let mut inner = self.inner.write().await;
            inner
                .node_scrapers
                .remove(node)
                .map(|h| h.abort())
                .is_some()
        };
        if existed {
            self.emit_watch().await;
        }
    }

    /// Emit the current live-stream count (watchers + logs + shells + forwards).
    /// Custom kinds count only while their watcher is open (B15).
    async fn emit_watch(&self) {
        let count = {
            let inner = self.inner.read().await;
            inner.watcher_count
                + inner.custom_watchers.len()
                + inner.node_scrapers.len()
                + inner.logs.len()
                + inner.shells.len()
                + inner.forwards.len()
        };
        // Emit failures are non-fatal (the webview may be gone during shutdown).
        self.sink.emit(events::WATCH_STATUS, &count);
    }

    /// The event sink, for tasks that need to emit their own events. Cloning
    /// the `EventSink` enum is cheap (it holds either a Tauri `AppHandle` —
    /// already cheap to clone — or a `broadcast::Sender` — already `Arc`-wrapped).
    pub fn sink(&self) -> EventSink {
        self.sink.clone()
    }

    /// The ConfigMap/Secret snapshot store. Persists across connections so
    /// version history survives context switches.
    pub fn snapshot_store(&self) -> &SnapshotStore {
        &self.snapshot_store
    }
}
