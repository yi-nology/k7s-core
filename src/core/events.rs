//! EventSink — the one seam between the core and whatever's running the show.
//!
//! Background tasks spawned by the core (watchers, metrics pollers, log streams,
//! drains, port-forwards, shells) push events to the user through this type. In
//! the Tauri shell, [`TauriEventSink`] forwards each call to `AppHandle::emit`
//! so the existing Tauri event contract on the wire is unchanged. In the
//! standalone web shell, [`WebEventSink`] writes to a `tokio::sync::broadcast`
//! channel that the SSE handler fans out to every connected browser tab.
//!
//! `EventSink` is an **enum**, not a trait object, so its `emit` method keeps
//! the generic `<T: Serialize>` signature that the rest of the core already
//! uses. The alternative (a `dyn EventSink` trait) would have meant dropping
//! the generic and calling `serde_json::to_value(...).unwrap()` at every
//! emit site — a thousand call sites for a one-time saving of one virtual
//! call. Enum dispatch is also faster, and there's only ever one variant
//! live at a time, so the match is monomorphised by the compiler.

use k7s_deps::tokio::sync::broadcast;
#[cfg(feature = "tauri")]
use tauri::Emitter;

/// Where every `app.emit(...)` call in the core ends up.
///
/// The contract is intentionally narrow: a name (the Tauri event name) and a
/// serialisable payload. No response, no back-pressure, no delivery guarantee
/// — shells are free to drop events (the Tauri webview may be gone, an SSE
/// client may have disconnected mid-line, etc.) and the core must accept that.
#[derive(Clone)]
pub enum EventSink {
    #[cfg(feature = "tauri")]
    Tauri(TauriEventSink),
    Web(WebEventSink),
    /// No-op sink used by the MCP server (and any future headless driver).
    /// MCP is request/response over stdio — there's no live channel to push
    /// events to, so the manager's watchers still run and still call
    /// `sink.emit(...)`, but the bytes go nowhere. We keep a real sink type
    /// rather than a `bool` because the existing call sites are already
    /// typed `&EventSink`; swapping the variant is a one-line match update.
    Mcp(McpEventSink),
}

impl EventSink {
    /// Send `event` with `payload` to all current subscribers. Mirrors the
    /// Tauri `Emitter::emit` signature so call sites read the same.
    pub fn emit<T: serde::Serialize>(&self, event: &str, payload: &T) {
        match self {
            #[cfg(feature = "tauri")]
            EventSink::Tauri(t) => t.emit(event, payload),
            EventSink::Web(w) => w.emit(event, payload),
            EventSink::Mcp(m) => m.emit(event, payload),
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri sink
// ---------------------------------------------------------------------------

/// Forwards events to the Tauri runtime via `AppHandle::emit`.
///
/// Used by the desktop shell. Behaviour is byte-for-byte the same as the
/// `app.emit(...)` calls the core used to make before the refactor — the wire
/// format on the Tauri IPC channel doesn't change, so neither does the
/// TauriProvider on the frontend.
#[cfg(feature = "tauri")]
#[derive(Clone)]
pub struct TauriEventSink {
    app: tauri::AppHandle,
}

#[cfg(feature = "tauri")]
impl TauriEventSink {
    pub fn new(app: tauri::AppHandle) -> Self {
        Self { app }
    }
}

#[cfg(feature = "tauri")]
impl TauriEventSink {
    pub fn emit<T: serde::Serialize>(&self, event: &str, payload: &T) {
        // Emit failures are non-fatal (webview may be gone during shutdown).
        let _ = self.app.emit(event, payload);
    }
}

// ---------------------------------------------------------------------------
// Web sink
// ---------------------------------------------------------------------------

/// One event ready to be pushed down an SSE stream.
#[derive(Debug, Clone)]
pub struct WebEvent {
    pub name: String,
    pub data: k7s_deps::serde_json::Value,
}

/// Forwards events to a `tokio::sync::broadcast::Sender<WebEvent>`, which the
/// SSE handler in `web/sse.rs` subscribes to and writes to each connected
/// client.
///
/// A broadcast channel is the right primitive here:
/// - **Multi-receiver**: every browser tab is an independent subscriber; one
///   `resource-update` from the watcher reaches all of them.
/// - **Lossy on overflow**: if a slow client falls behind, the channel drops
///   messages for it rather than blocking the watcher — the alternative would
///   let one stuck tab freeze the whole UI.
/// - **Cheap to clone**: the sender wraps an `Arc` internally, so cloning it
///   to pass into a spawned task is free.
#[derive(Clone)]
pub struct WebEventSink {
    tx: broadcast::Sender<WebEvent>,
}

impl WebEventSink {
    /// Build a sink plus its companion receiver. The receiver is held by the
    /// SSE handler; the sender is the `EventSink` the core uses.
    ///
    /// `capacity` is the broadcast's per-receiver buffer. Tweak with care: too
    /// small and a momentarily-slow browser tab drops events; too large and
    /// idle tabs accumulate memory. 1024 is a reasonable starting point —
    /// matches the front-end log buffer cap, so a single tab's worst-case
    /// backlog won't outrun the channel.
    pub fn new(capacity: usize) -> (Self, broadcast::Receiver<WebEvent>) {
        let (tx, rx) = broadcast::channel(capacity);
        (Self { tx }, rx)
    }

    /// Hand out a fresh subscriber. Used by `web/server.rs` to spawn one
    /// per incoming SSE connection.
    pub fn subscribe(&self) -> broadcast::Receiver<WebEvent> {
        self.tx.subscribe()
    }
}

impl WebEventSink {
    pub fn emit<T: serde::Serialize>(&self, event: &str, payload: &T) {
        // Drop on overflow — the broadcast returns Err if there are no
        // receivers OR the channel is full. Both are fine: nobody listening
        // or somebody slow.
        let value =
            k7s_deps::serde_json::to_value(payload).unwrap_or(k7s_deps::serde_json::Value::Null);
        let _ = self.tx.send(WebEvent {
            name: event.to_string(),
            data: value,
        });
    }
}

// ---------------------------------------------------------------------------
// MCP sink — drop on the floor. MCP is request/response; the only "events"
// that matter are the live data tables in the UI, and the AI client gets those
// by calling `list_resources` / `get_resource` itself.
// ---------------------------------------------------------------------------

/// No-op event sink for the MCP shell. See [`EventSink::Mcp`] for context.
#[derive(Clone, Default)]
pub struct McpEventSink;

impl McpEventSink {
    pub fn new() -> Self {
        Self
    }
}

impl McpEventSink {
    pub fn emit<T: serde::Serialize>(&self, _event: &str, _payload: &T) {
        // Intentional no-op. We could log here for debugging, but the
        // watchers can be chatty and this gets called per resource-update.
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Shorthand for `EventSink::Tauri(TauriEventSink::new(app))`.
#[cfg(feature = "tauri")]
pub fn tauri_sink(app: tauri::AppHandle) -> EventSink {
    EventSink::Tauri(TauriEventSink::new(app))
}

/// Shorthand for `EventSink::Web(WebEventSink::new(capacity).0)`. Returns
/// `(EventSink, broadcast::Receiver<WebEvent>)` — the receiver is what
/// `web/server.rs` subscribes to SSE clients from.
pub fn web_sink(capacity: usize) -> (EventSink, broadcast::Receiver<WebEvent>) {
    let (sink, rx) = WebEventSink::new(capacity);
    (EventSink::Web(sink), rx)
}

/// Shorthand for `EventSink::Mcp(McpEventSink::new())`. Used by `k7s-mcp`
/// to wire a `ClientManager` that has nowhere to push live events.
pub fn mcp_sink() -> EventSink {
    EventSink::Mcp(McpEventSink::new())
}

/// Hand out a fresh SSE subscriber from a web sink. Returns `None` if the
/// sink isn't a `WebEventSink` (i.e. we're in the Tauri shell — the web
/// routes are never wired up there).
pub fn web_sink_subscribe(sink: &EventSink) -> Option<broadcast::Receiver<WebEvent>> {
    match sink {
        EventSink::Web(w) => Some(w.subscribe()),
        #[cfg(feature = "tauri")]
        EventSink::Tauri(_) => None,
        EventSink::Mcp(_) => None,
    }
}

/// Keep callers from accidentally paying for a `WebEventSink` they never use.
/// The `Arc<...>` indirection around a `broadcast::Sender` is internal to
/// `WebEventSink`; this re-exports it so the web module doesn't have to know.
pub type WebEventReceiver = broadcast::Receiver<WebEvent>;

/// Extract a fresh `broadcast::Sender` from the `WebEventSink` the manager
/// is using. Used by the web shell to keep one sender alive (so the broadcast
/// doesn't auto-close when the last SSE client disconnects) and to issue
/// receivers on demand.
///
/// Panics if the manager is wired to a `TauriEventSink` — the web shell is
/// the only caller, and it should always have built a web sink via
/// [`web_sink`].
pub fn web_sink_sender(core: &crate::core::CoreState) -> broadcast::Sender<WebEvent> {
    match core.manager.sink() {
        EventSink::Web(w) => w.tx.clone(),
        _ => {
            panic!("web_sink_sender: core is not wired to a WebEventSink; build a web sink via web_sink() instead")
        }
    }
}
