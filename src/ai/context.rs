//! Context builder — assembles the system prompt and any implicit context the
//! LLM needs to reason about *this* cluster, *this* turn.
//!
//! The agent loop calls [`build_system_prompt`] once per run to seed the
//! conversation. The selected-resource injection (when the UI has a resource
//! focused) is optional and supplied per-turn via `ChatRequest::context` in
//! the commands layer; [`selected_resource_context`] turns it into a JSON blob
//! describing the live object.

use crate::ai::error::{AiError, AiResult};
use crate::core::shell_common;
use serde::{Deserialize, Serialize};

/// The "what am I looking at" context the UI can attach to a chat message.
/// All fields optional — the user might just type a question with nothing
/// selected.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedContext {
    /// Lowercase kind id, e.g. "pods".
    pub kind: Option<String>,
    pub namespace: Option<String>,
    pub name: Option<String>,
}

/// The fixed system prompt every run starts with. The agent loop passes the
/// cluster version + connected context name so the LLM knows where it is.
pub fn build_system_prompt(cluster_version: Option<&str>, context: Option<&str>) -> String {
    let ver = cluster_version.unwrap_or("unknown");
    let ctx = context.unwrap_or("unknown");
    format!(
        "You are k7s AI, a Kubernetes operations assistant embedded in the k7s \
desktop app. You operate against a REAL cluster the user is connected to — \
your tool calls execute live.

Environment:
- Kubernetes version: {ver}
- Current kubeconfig context: {ctx}

Operating rules:
1. ALWAYS prefer read tools (list_resources, describe_resource, get_events, \
get_pod_logs, diagnose_unhealthy) before suggesting or making changes. Gather \
evidence first.
2. When you diagnose a problem, cite the specific resource name and the \
events/log lines you found.
3. For write operations (scale/restart/delete/apply), state plainly what you \
are about to do and why, in one short sentence, before calling the tool.
4. Never delete a resource unless the user explicitly asked. If unsure, ask.
5. Keep answers concise. Use short bullet points. Show command output only \
when it directly answers the question.
6. If a tool returns an error, read the message, adjust (e.g. wrong namespace, \
wrong kind), and retry with the corrected arguments — don't repeat the same \
failing call.
7. If the user references 'this' / 'the current resource', it's in the \
context block provided with the message. If none is provided, ask which \
resource they mean."
    )
}

/// Fetch the describe payload for the selected resource, to inject as context.
/// Returns `None` silently if the resource can't be read (the LLM will then
/// ask the user to clarify rather than fail the whole turn).
pub async fn selected_resource_context(
    manager: &crate::kube::manager::ClientManager,
    sel: &SelectedContext,
) -> Option<k7s_deps::serde_json::Value> {
    let (kind, ns, name) = (
        sel.kind.as_deref()?,
        sel.namespace.as_deref().unwrap_or(""),
        sel.name.as_deref()?,
    );
    let result: AiResult<k7s_deps::serde_json::Value> = async {
        let client = manager
            .client()
            .await
            .ok_or(AiError::Tool("not connected".into()))?;
        let (api, _) = shell_common::dynamic_api(client, kind, ns, manager)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))?;
        let mut obj = api
            .get(name)
            .await
            .map_err(|e| AiError::Tool(e.to_string()))?;
        obj.metadata.managed_fields = None;
        // A focused Secret is still a Secret: mask its payload before the
        // object is injected into the prompt (same choke point as the
        // describe/get-yaml tools).
        crate::ai::tools::impls::redact_secret_data(&mut obj, kind);
        k7s_deps::serde_json::to_value(&obj).map_err(|e| AiError::Tool(e.to_string()))
    }
    .await;
    match result {
        Ok(v) => Some(k7s_deps::serde_json::json!({
            "selectedResource": { "kind": kind, "namespace": ns, "name": name },
            "describe": v,
        })),
        Err(_) => None,
    }
}
