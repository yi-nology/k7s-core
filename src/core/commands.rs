//! Transport-agnostic command registry — the seam shared by every shell.
//!
//! A [`CommandRegistry`] maps a command name (the same string the frontend's
//! `invoke()` uses) to a handler that takes `Arc<CoreState>` plus a JSON value
//! of the command arguments and returns a JSON value. Tauri commands (via
//! `k7s-commands`) and the web shell's `POST /api/invoke/{cmd}` route both
//! resolve through the same table, so a command exists exactly once no matter
//! which transport calls it.
//!
//! Handlers here are dynamic-dispatch wrappers around the ordinary typed
//! `*_impl` async functions in `k7s-commands`; the registry itself only deals
//! in `serde_json::Value`, so `k7s-core` stays free of any transport types.

use crate::core::CoreState;
use crate::error::AppResult;
use k7s_deps::serde_json::Value;
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

/// The boxed future a dynamic handler returns.
pub type CommandFuture = Pin<Box<dyn Future<Output = AppResult<Value>> + Send>>;

/// A registered dynamic handler: `(state, arguments) -> future of a JSON value`.
pub type DynHandler = Arc<dyn Fn(Arc<CoreState>, Value) -> CommandFuture + Send + Sync>;

/// Name → handler table shared by the Tauri IPC and the web `/invoke` route.
#[derive(Default)]
pub struct CommandRegistry {
    handlers: HashMap<&'static str, DynHandler>,
}

impl CommandRegistry {
    /// Register `name`, deserializing the request body into `A` and
    /// serializing the handler's return value back to JSON.
    ///
    /// `A` should carry `#[serde(rename_all = "camelCase")]` when it has
    /// multi-word fields — the frontend sends camelCase keys on the wire
    /// (Tauri's convention).
    ///
    /// A duplicate `name` is logged loudly and the later registration wins
    /// (plain insert semantics). A duplicate means one of the two call sites
    /// is wrong — but panicking here took the whole shell down at startup,
    /// which is worse than one shadowed command: the error log keeps the
    /// conflict visible without breaking boot.
    pub fn register<A, R, F, Fut>(&mut self, name: &'static str, handler: F)
    where
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(Arc<CoreState>, A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AppResult<R>> + Send + 'static,
    {
        if self.handlers.contains_key(name) {
            k7s_deps::tracing::error!(
                "CommandRegistry: duplicate registration for `{name}` — the \
                 second handler shadows the first. Remove one of the \
                 `register(\"{name}\")` call sites."
            );
        }
        let handler = Arc::new(handler);
        self.handlers.insert(
            name,
            Arc::new(move |state, body| {
                let handler = handler.clone();
                Box::pin(async move {
                    let args: A = k7s_deps::serde_json::from_value(body).map_err(|e| {
                        crate::error::AppError::Other(format!("bad arguments for `{name}`: {e}"))
                    })?;
                    let out = handler(state, args).await?;
                    k7s_deps::serde_json::to_value(out).map_err(|e| {
                        crate::error::AppError::Other(format!(
                            "serialize response for `{name}`: {e}"
                        ))
                    })
                })
            }),
        );
    }

    /// Look up a handler by command name.
    pub fn get(&self, name: &str) -> Option<DynHandler> {
        self.handlers.get(name).cloned()
    }

    /// Whether `name` is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// All registered command names, in unspecified order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + use<'_> {
        self.handlers.keys().copied()
    }

    /// Number of registered commands.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Always false for a meaningful registry.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<CoreState> {
        CoreState::new(
            Arc::new(crate::kube::ClientManager::new(
                crate::core::events::EventSink::Mcp(crate::core::events::McpEventSink::new()),
            )),
            std::env::temp_dir().join(format!("k7s-registry-test-{}", std::process::id())),
        )
    }

    async fn echo(state: Arc<CoreState>, n: usize) -> AppResult<usize> {
        // Touch the state so the signature is realistic (we don't read it).
        let _ = state.data_dir.as_os_str().len();
        Ok(n * 2)
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EchoArgs {
        pub count: usize,
    }

    #[test]
    fn registry_dispatches_and_serializes() {
        let mut r = CommandRegistry::default();
        r.register("echo", |state, a: EchoArgs| async move {
            echo(state, a.count).await
        });

        let handler = r.get("echo").expect("echo registered");
        let out = block_on(handler(
            test_state(),
            k7s_deps::serde_json::json!({ "count": 21 }),
        ))
        .expect("echo ok");
        assert_eq!(out, k7s_deps::serde_json::json!(42));
    }

    #[test]
    fn unknown_name_is_none() {
        let r = CommandRegistry::default();
        assert!(r.get("nope").is_none());
        assert!(!r.contains("nope"));
        assert_eq!(r.names().count(), 0);
    }

    #[test]
    fn bad_arguments_surface_as_error() {
        let mut r = CommandRegistry::default();
        r.register("echo", |state, a: EchoArgs| async move {
            echo(state, a.count).await
        });
        let handler = r.get("echo").unwrap();
        let err = block_on(handler(test_state(), k7s_deps::serde_json::json!({}))).unwrap_err();
        assert!(err.to_string().contains("bad arguments"));
    }

    /// A duplicate name must not take the shell down at startup: the second
    /// registration replaces the first (insert semantics) after logging an
    /// error, so the conflict stays visible without breaking boot.
    #[test]
    fn duplicate_registration_logs_and_shadows() {
        let mut r = CommandRegistry::default();
        r.register("dup", |state, a: k7s_deps::serde_json::Value| async move {
            echo(state, a.as_u64().unwrap_or(0) as usize).await
        });
        r.register("dup", |state, a: k7s_deps::serde_json::Value| async move {
            // Second handler: different observable result (x100) so the
            // test can prove which registration is live.
            echo(state, (a.as_u64().unwrap_or(0) * 100) as usize).await
        });
        let handler = r.get("dup").expect("dup still registered");
        let out =
            block_on(handler(test_state(), k7s_deps::serde_json::json!(1))).expect("dispatch ok");
        // The later registration won.
        assert_eq!(out, k7s_deps::serde_json::json!(200));
    }

    /// Minimal block_on for tests.
    fn block_on<F: Future>(fut: F) -> F::Output {
        k7s_deps::tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(fut)
    }
}
