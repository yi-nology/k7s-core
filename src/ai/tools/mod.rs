//! Independent AI tool set (Plan C core).
//!
//! These tools are **separate** from the MCP server's 91 `#[tool]`-macro tools.
//! They exist for one reason: the MCP tools are tuned for human-driven AI
//! clients and use the rmcp protocol's result/error types; the agent loop here
//! needs tools described as OpenAI function-call JSON Schemas, returning
//! LLM-friendly structured JSON, with a clean `is_write` flag for the
//! permission gate.
//!
//! Under the hood every tool reuses [`crate::core::shell_common`]'s free
//! functions (`dynamic_api`, `resource_for`) plus raw `kube` calls — that's the
//! Plan A reuse. We deliberately do **not** depend on `crate::mcp::kube_api`,
//! because that module is feature-gated (`mcp`/`web`) and the AI module must
//! ship in the plain desktop build. There's no second cluster-access layer;
//! the AI tools and the existing Tauri commands both go through `shell_common`.
//!
//! Adding a tool: implement [`Tool`], then register it in [`ToolRegistry::new`].

pub mod diag_tools;
pub mod error_shape;
pub mod impls;
pub mod read_tools;
pub mod write_tools;

use crate::ai::config::PermissionMode;
use crate::ai::error::{AiError, AiResult};
use crate::ai::llm::FunctionDef;
use crate::core::shell_common;
use crate::kube::manager::ClientManager;
use k7s_deps::async_trait::async_trait;
use k7s_deps::kube::Client;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Everything a tool needs to execute. Cheap to clone — the manager is an
/// `Arc`, the data_dir is only read for config.
#[derive(Clone)]
pub struct ToolContext {
    pub manager: Arc<ClientManager>,
    #[allow(dead_code)]
    pub data_dir: PathBuf,
}

/// Get a connected `kube::Client` or bail with the standard "disconnected"
/// error (kept here so every tool reads the same).
pub async fn require_client(manager: &ClientManager) -> AiResult<Client> {
    manager
        .client()
        .await
        .ok_or(AiError::Tool("not connected to a cluster".into()))
}

/// The single trait every AI tool implements. `#[async_trait]` keeps it
/// object-safe so the registry can hold `Box<dyn Tool>`.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Name the LLM sees, e.g. `"list_resources"`. Must be unique in the registry.
    fn name(&self) -> &str;

    /// Description the LLM uses to pick the tool. Be specific about *when* to
    /// reach for it — this is the single biggest factor in call accuracy.
    fn description(&self) -> &str;

    /// JSON Schema for the tool's `parameters` object (OpenAI function-calling
    /// shape: `{"type":"object","properties":{...},"required":[...]}`).
    fn parameters_schema(&self) -> k7s_deps::serde_json::Value;

    /// True if the tool mutates the cluster (scale/restart/delete/apply/…).
    /// Write tools route through the permission gate before execution.
    fn is_write(&self) -> bool {
        false
    }

    /// Execute with the LLM-supplied arguments (already parsed to a Value).
    async fn call(
        &self,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value>;
}

/// Holds all registered tools and the function defs handed to the LLM.
pub struct ToolRegistry {
    tools: Vec<Box<dyn Tool>>,
}

impl ToolRegistry {
    /// Build the registry with the default tool set.
    pub fn new() -> Self {
        let tools: Vec<Box<dyn Tool>> = vec![
            // read-only
            Box::new(read_tools::ListResources),
            Box::new(read_tools::DescribeResource),
            Box::new(read_tools::GetResourceYaml),
            Box::new(read_tools::GetEvents),
            Box::new(read_tools::GetPodLogs),
            Box::new(read_tools::GetClusterHealth),
            Box::new(read_tools::TopNodes),
            Box::new(read_tools::TopPods),
            Box::new(read_tools::CapacityReport),
            Box::new(read_tools::BatchGet),
            Box::new(read_tools::DiffResources),
            Box::new(read_tools::HpaStatus),
            Box::new(read_tools::SecurityAudit),
            Box::new(read_tools::RbacPermissionMatrix),
            Box::new(read_tools::SpawnSubAgent),
            Box::new(read_tools::KubectlGenerator),
            // write
            Box::new(write_tools::ScaleWorkload),
            Box::new(write_tools::RestartWorkload),
            Box::new(write_tools::DeleteResource),
            Box::new(write_tools::ApplyManifest),
            // diag
            Box::new(diag_tools::DiagnoseUnhealthy),
            Box::new(diag_tools::DiagnosePod),
        ];

        debug_assert!(names_unique(&tools), "duplicate tool name in AI registry");

        Self { tools }
    }

    /// The OpenAI `tools` array for this turn, filtered by permission mode.
    /// In ReadOnly mode write tools are omitted entirely so the LLM can't even
    /// ask for them.
    pub fn function_defs(&self, mode: PermissionMode) -> Vec<FunctionDef> {
        self.tools
            .iter()
            .filter(|t| !(t.is_write() && mode == PermissionMode::ReadOnly))
            .map(|t| FunctionDef {
                name: t.name().to_string(),
                description: t.description().to_string(),
                parameters: t.parameters_schema(),
            })
            .collect()
    }

    /// Look up a tool by name.
    fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.iter().find(|t| t.name() == name).map(|b| &**b)
    }

    /// Whether the named tool is a write operation (for the gate).
    pub fn is_write(&self, name: &str) -> bool {
        self.get(name).map(|t| t.is_write()).unwrap_or(false)
    }

    /// Run a tool by name. The caller is responsible for the permission gate —
    /// see [`crate::ai::permission`].
    pub async fn dispatch(
        &self,
        name: &str,
        ctx: &ToolContext,
        args: k7s_deps::serde_json::Value,
    ) -> AiResult<k7s_deps::serde_json::Value> {
        let tool = self
            .get(name)
            .ok_or_else(|| AiError::ToolArgs(format!("unknown tool '{name}'")))?;
        tool.call(ctx, args).await
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn names_unique(tools: &[Box<dyn Tool>]) -> bool {
    let mut seen = HashMap::new();
    for t in tools {
        if seen.insert(t.name(), ()).is_none() {
            // inserted — ok
        } else {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Shared arg helpers
// ---------------------------------------------------------------------------

pub fn get_arg_str(args: &k7s_deps::serde_json::Value, key: &str) -> AiResult<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AiError::ToolArgs(format!("missing string arg '{key}'")))
}

pub fn get_opt_str(args: &k7s_deps::serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn get_arg_i64(args: &k7s_deps::serde_json::Value, key: &str) -> AiResult<i64> {
    args.get(key)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AiError::ToolArgs(format!("missing integer arg '{key}'")))
}

pub fn get_opt_i64(args: &k7s_deps::serde_json::Value, key: &str) -> Option<i64> {
    args.get(key).and_then(|v| v.as_i64())
}

pub fn get_opt_bool(args: &k7s_deps::serde_json::Value, key: &str) -> Option<bool> {
    args.get(key).and_then(|v| v.as_bool())
}

/// Resolve a dynamic API via `shell_common` (always-available, unlike
/// `mcp::kube_api` which is feature-gated). Wraps the kube error as `AiError`.
pub async fn dynamic_api(
    ctx: &ToolContext,
    kind: &str,
    namespace: &str,
) -> AiResult<(
    k7s_deps::kube::Api<k7s_deps::kube::api::DynamicObject>,
    bool,
)> {
    let client = require_client(&ctx.manager).await?;
    shell_common::dynamic_api(client, kind, namespace, &ctx.manager)
        .await
        .map_err(|e| AiError::Tool(e.to_string()))
}

/// Wrap a serialisable payload into the JSON value tools return. Centralised so
/// serialisation errors map to `AiError::Tool` consistently.
pub fn ok_value<T: Serialize + ?Sized>(payload: &T) -> AiResult<k7s_deps::serde_json::Value> {
    k7s_deps::serde_json::to_value(payload).map_err(|e| AiError::Tool(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default registry ships the documented tool set and each tool name is
    /// unique (a duplicate would silently shadow one in the dispatch map).
    #[test]
    fn default_registry_has_unique_names() {
        let reg = ToolRegistry::new();
        let names: Vec<&str> = reg.tools.iter().map(|t| t.name()).collect();
        let expected = [
            "list_resources",
            "describe_resource",
            "get_resource_yaml",
            "get_events",
            "get_pod_logs",
            "get_cluster_health",
            "top_nodes",
            "top_pods",
            "capacity_report",
            "security_audit",
            "rbac_permission_matrix",
            "scale_workload",
            "restart_workload",
            "delete_resource",
            "apply_manifest",
            "diagnose_unhealthy",
            "diagnose_pod",
            "kubectl_generate",
        ];
        for e in expected {
            assert!(names.contains(&e), "missing tool: {e}");
        }
        // uniqueness
        let mut sorted = names.clone();
        sorted.sort();
        let mut dups = 0;
        for w in sorted.windows(2) {
            if w[0] == w[1] {
                dups += 1;
            }
        }
        assert_eq!(dups, 0, "duplicate tool names: {:?}", sorted);
    }

    /// `function_defs` must hand the LLM the read tools in every mode, but drop
    /// the write tools in ReadOnly mode — otherwise the LLM would try to call
    /// them and the gate would refuse, wasting a turn.
    #[test]
    fn function_defs_filter_writes_in_readonly() {
        let reg = ToolRegistry::new();
        let full = reg.function_defs(PermissionMode::FullAuto);
        let ro = reg.function_defs(PermissionMode::ReadOnly);
        // FullAuto exposes everything.
        assert!(full.iter().any(|d| d.name == "scale_workload"));
        assert!(full.iter().any(|d| d.name == "list_resources"));
        // ReadOnly drops all writes but keeps reads.
        assert!(!ro.iter().any(|d| d.name == "scale_workload"));
        assert!(!ro.iter().any(|d| d.name == "delete_resource"));
        assert!(ro.iter().any(|d| d.name == "list_resources"));
        assert!(ro.iter().any(|d| d.name == "diagnose_unhealthy"));
    }

    /// `is_write` correctly classifies a few representative tools — this is what
    /// the permission gate keys off, so a misclassification here is a security
    /// hole (a write that slips through as a read).
    #[test]
    fn is_write_classification() {
        let reg = ToolRegistry::new();
        assert!(reg.is_write("scale_workload"));
        assert!(reg.is_write("delete_resource"));
        assert!(reg.is_write("apply_manifest"));
        assert!(!reg.is_write("list_resources"));
        assert!(!reg.is_write("describe_resource"));
        assert!(!reg.is_write("get_pod_logs"));
        // Unknown tool is treated as non-write (and dispatch will error), so a
        // bad name can never accidentally execute as a write.
        assert!(!reg.is_write("does_not_exist"));
    }

    /// Dispatching an unknown tool yields a ToolArgs error rather than panicking.
    #[k7s_deps::tokio::test]
    async fn unknown_tool_errors() {
        let reg = ToolRegistry::new();
        let ctx = ToolContext {
            manager: std::sync::Arc::new(crate::kube::ClientManager::new(
                crate::core::events::mcp_sink(),
            )),
            data_dir: std::path::PathBuf::new(),
        };
        let err = reg
            .dispatch("no_such_tool", &ctx, k7s_deps::serde_json::Value::Null)
            .await
            .unwrap_err();
        assert!(matches!(err, AiError::ToolArgs(_)));
    }
}
