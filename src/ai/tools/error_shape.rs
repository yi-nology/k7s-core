//! Structured tool-error payloads for LLM/MCP consumption.
//!
//! A bare error string invites the model to retry the exact same failing
//! call. These payloads add a `hint` (what to do differently) and a
//! `retryable` flag (whether retrying makes sense at all), so an agent that
//! reads the result can self-correct instead of looping: "not connected →
//! call list_contexts/connect first", "unknown command → list tools",
//! "bad arguments → check the parameter types".
//!
//! Shared by the agent loop's tool-result errors and the MCP server's tool
//! error messages, so both surfaces speak the same shape.

use k7s_deps::serde_json::{json, Value};

/// Build the structured payload for a tool error.
pub fn tool_error_payload(err: &str) -> Value {
    let (hint, retryable) = classify(err);
    json!({
        "error": err,
        "hint": hint,
        "retryable": retryable,
    })
}

/// Classify an error string into (hint, retryable). Substring matching over
/// the `AppError`/`AiError` display strings — deliberately coarse; the goal
/// is better-than-nothing guidance, not taxonomy.
fn classify(err: &str) -> (&'static str, bool) {
    let e = err.to_ascii_lowercase();
    if e.contains("not connected") || e.contains("disconnected") || e.contains("no cluster") {
        return (
            "No cluster connection. Call list_contexts, then connect with a kubeconfig context before retrying.",
            true,
        );
    }
    if e.contains("unknown command") || e.contains("unsupported kind") || e.contains("unknown kind")
    {
        return (
            "The kind/command name is not recognised. List what exists first (list_resources with a valid kind, or the tool list) and retry with a corrected name.",
            true,
        );
    }
    if e.contains("not found") || e.contains("\"notfound\"") {
        return (
            "The named resource does not exist in that namespace. Call list_resources for the kind+namespace to see valid names.",
            true,
        );
    }
    if e.contains("bad arguments") || e.contains("invalid type") || e.contains("deserializ") {
        return (
            "An argument has the wrong type or shape (parameters are camelCase). Check the tool schema and retry with corrected arguments.",
            true,
        );
    }
    if e.contains("permission")
        || e.contains("denied")
        || e.contains("sandbox")
        || e.contains("forbidden")
    {
        return (
            "Blocked by policy (permission mode, sandbox rule, or RBAC). Adjusting arguments will not help — ask the user or use a read-only tool.",
            false,
        );
    }
    if e.contains("yaml") || e.contains("manifest") {
        return (
            "The manifest failed validation/parsing. Fix the YAML (apiVersion/kind/metadata.name present, correct indentation) and retry.",
            true,
        );
    }
    if e.contains("timeout") || e.contains("timed out") {
        return (
            "The operation timed out. Retry once; if it persists the cluster API server is likely overloaded.",
            true,
        );
    }
    if e.contains("already exists") {
        return (
            "The resource already exists. Get it (get_yaml/describe_resource) and update it instead of creating a new one.",
            false,
        );
    }
    ("", false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_gets_connect_hint() {
        let v = tool_error_payload("not connected");
        assert_eq!(v["retryable"], json!(true));
        assert!(
            v["hint"].as_str().unwrap().contains("list_contexts"),
            "hint should point at connecting: {}",
            v["hint"]
        );
    }

    #[test]
    fn not_found_points_at_listing() {
        let v = tool_error_payload("pods \"x\" not found");
        assert_eq!(v["retryable"], json!(true));
        assert!(v["hint"].as_str().unwrap().contains("list_resources"));
    }

    #[test]
    fn permission_blocks_are_not_retryable() {
        let v = tool_error_payload("sandbox denied 'delete_resource': namespace is denied");
        assert_eq!(v["retryable"], json!(false));
    }

    #[test]
    fn payload_always_carries_the_original_error() {
        let v = tool_error_payload("something novel");
        assert_eq!(v["error"], json!("something novel"));
        assert!(v.get("hint").is_some());
        assert!(v.get("retryable").is_some());
    }
}
