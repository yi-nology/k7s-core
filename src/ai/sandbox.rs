//! Sandbox security — inspired by openocta's SecurityConfig + CommandPolicy.
//!
//! Provides fine-grained security controls beyond the simple permission gate:
//!
//! - **Command policy**: deny/ask/allow rules for specific tool names and
//!   argument patterns (e.g., "deny delete_resource on namespace=kube-system",
//!   "ask before any write to production").
//! - **Path restrictions**: limit which namespaces/resources the agent can touch.
//! - **Resource limits**: cap CPU/memory the agent's operations can consume.
//! - **Secret detection**: block tool calls that would expose secrets.
//! - **Approval queue**: persistent queue with timeout for pending approvals.
//!
//! The sandbox sits between the permission gate and tool execution — it's a
//! more granular layer that evaluates specific tool+args combinations.

use serde::{Deserialize, Serialize};

/// Sandbox security configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxConfig {
    /// Master switch. Defaults to `true` (fail-secure: a partially-written
    /// config file must not silently disable the sandbox), matching the
    /// `Default` impl below.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Security preset: "off", "loose", "standard", "strict".
    #[serde(default = "default_preset")]
    pub preset: String,
    /// Allowed namespaces (empty = all). The agent can only operate in these.
    #[serde(default)]
    pub allowed_namespaces: Vec<String>,
    /// Denied namespaces. The agent cannot touch these under any circumstances.
    #[serde(default)]
    pub denied_namespaces: Vec<String>,
    /// Command policy rules.
    #[serde(default)]
    pub rules: Vec<CommandRule>,
    /// Secret patterns to detect and block (regex).
    #[serde(default)]
    pub secret_patterns: Vec<String>,
    /// Max tool calls per minute.
    #[serde(default = "default_max_calls_per_minute")]
    pub max_calls_per_minute: u32,
    /// Max turns per run.
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
}

fn default_true() -> bool {
    true
}

fn default_preset() -> String {
    "standard".to_string()
}
fn default_max_calls_per_minute() -> u32 {
    30
}
fn default_max_turns() -> u32 {
    10
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            preset: "standard".to_string(),
            allowed_namespaces: Vec::new(),
            denied_namespaces: vec!["kube-system".to_string(), "kube-public".to_string()],
            rules: Vec::new(),
            secret_patterns: vec![
                r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+".to_string()
            ],
            max_calls_per_minute: 30,
            max_turns: 10,
        }
    }
}

/// A single command policy rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandRule {
    /// "deny", "ask", "allow".
    pub action: String,
    /// Tool name pattern (e.g., "delete_*", "scale_*", "*").
    pub tool_pattern: String,
    /// Argument pattern (e.g., "namespace=kube-system", "kind=secrets").
    /// Empty = matches all arguments.
    #[serde(default)]
    pub arg_pattern: Option<String>,
    /// Human-readable reason (shown to user when blocking).
    #[serde(default)]
    pub reason: String,
}

/// The result of sandbox evaluation.
#[derive(Clone, Debug)]
pub enum SandboxDecision {
    /// Allow the tool call.
    Allow,
    /// Ask the user for approval (with a reason).
    Ask { reason: String },
    /// Deny the tool call entirely.
    Deny { reason: String },
}

/// Evaluate a tool call against the sandbox rules.
pub fn evaluate(
    config: &SandboxConfig,
    tool_name: &str,
    args: &k7s_deps::serde_json::Value,
) -> SandboxDecision {
    if !config.enabled {
        return SandboxDecision::Allow;
    }

    // Check denied namespaces.
    if let Some(ns) = args.get("namespace").and_then(|v| v.as_str()) {
        if config.denied_namespaces.iter().any(|d| d == ns) {
            return SandboxDecision::Deny {
                reason: format!("namespace '{ns}' is in the denied list"),
            };
        }
        // If allowed_namespaces is non-empty, the namespace must be in it.
        if !config.allowed_namespaces.is_empty()
            && !config.allowed_namespaces.iter().any(|a| a == ns)
        {
            return SandboxDecision::Deny {
                reason: format!("namespace '{ns}' is not in the allowed list"),
            };
        }
    }

    // Check command policy rules (first match wins).
    for rule in &config.rules {
        if matches_pattern(tool_name, &rule.tool_pattern) {
            // Check arg pattern if specified.
            if let Some(ref arg_pat) = rule.arg_pattern {
                if !arg_pattern_matches(arg_pat, args) {
                    continue; // arg pattern doesn't match, skip this rule
                }
            }
            return match rule.action.as_str() {
                "deny" => SandboxDecision::Deny {
                    reason: rule.reason.clone(),
                },
                "ask" => SandboxDecision::Ask {
                    reason: rule.reason.clone(),
                },
                _ => SandboxDecision::Allow,
            };
        }
    }

    // Check for secret exposure in arguments.
    let args_str = k7s_deps::serde_json::to_string(args).unwrap_or_default();
    for pattern in &config.secret_patterns {
        if let Ok(re) = k7s_deps::regex::Regex::new(pattern) {
            if re.is_match(&args_str) {
                return SandboxDecision::Deny {
                    reason:
                        "arguments may contain secrets (password/token/api_key pattern detected)"
                            .into(),
                };
            }
        }
    }

    SandboxDecision::Allow
}

fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_suffix('*') {
        return name.starts_with(suffix);
    }
    if let Some(prefix) = pattern.strip_prefix('*') {
        return name.ends_with(prefix);
    }
    name == pattern
}

/// Match a rule's `arg_pattern` against a call's arguments.
///
/// Preferred form is `key=value`: an exact comparison against the string form
/// of `args[key]` (numbers and booleans are compared by their string form, so
/// `replicas=3` matches `"replicas": 3`). This is what the documented examples
/// (`namespace=kube-system`, `kind=secrets`) mean, and what the old substring
/// check failed to honour: `"namespace":"kube-system"` serialized as JSON never
/// contains the literal `namespace=kube-system`, so those rules silently never
/// fired. Patterns without `=` (and keys absent from the args) fall back to a
/// substring check on the serialized arguments, preserving the original loose
/// behaviour for hand-written patterns.
fn arg_pattern_matches(pattern: &str, args: &k7s_deps::serde_json::Value) -> bool {
    if let Some((key, expected)) = pattern.split_once('=') {
        let (key, expected) = (key.trim(), expected.trim());
        match args.get(key) {
            Some(k7s_deps::serde_json::Value::String(s)) => s == expected,
            // Non-string scalars (numbers, bools) stringify for comparison.
            Some(other) => &other.to_string() == expected,
            None => k7s_deps::serde_json::to_string(args)
                .unwrap_or_default()
                .contains(pattern),
        }
    } else {
        k7s_deps::serde_json::to_string(args)
            .unwrap_or_default()
            .contains(pattern)
    }
}

/// Preset sandbox configurations.
pub fn presets() -> Vec<(&'static str, SandboxConfig)> {
    vec![
        (
            "off",
            SandboxConfig {
                enabled: false,
                preset: "off".into(),
                ..Default::default()
            },
        ),
        (
            "loose",
            SandboxConfig {
                enabled: true,
                preset: "loose".into(),
                denied_namespaces: vec!["kube-system".into()],
                max_calls_per_minute: 60,
                max_turns: 15,
                ..Default::default()
            },
        ),
        ("standard", SandboxConfig::default()),
        (
            "strict",
            SandboxConfig {
                enabled: true,
                preset: "strict".into(),
                denied_namespaces: vec![
                    "kube-system".into(),
                    "kube-public".into(),
                    "kube-node-lease".into(),
                ],
                rules: vec![
                    CommandRule {
                        action: "ask".into(),
                        tool_pattern: "delete_*".into(),
                        arg_pattern: None,
                        reason: "delete operations require approval in strict mode".into(),
                    },
                    CommandRule {
                        action: "ask".into(),
                        tool_pattern: "apply_manifest".into(),
                        arg_pattern: None,
                        reason: "apply operations require approval in strict mode".into(),
                    },
                ],
                max_calls_per_minute: 15,
                max_turns: 8,
                ..Default::default()
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented `key=value` patterns must actually fire — the old
    /// substring check compared `namespace=kube-system` against
    /// `{"namespace":"kube-system"}` and never matched.
    #[test]
    fn arg_pattern_matches_documented_examples() {
        let args = k7s_deps::serde_json::json!({ "namespace": "kube-system", "kind": "secrets" });
        assert!(arg_pattern_matches("namespace=kube-system", &args));
        assert!(arg_pattern_matches("kind=secrets", &args));
        // Non-matching values must not fire.
        assert!(!arg_pattern_matches("namespace=default", &args));
        assert!(!arg_pattern_matches("kind=configmaps", &args));
    }

    /// Numbers and booleans compare by their string form, so JSON-typed
    /// arguments match without quoting gymnastics.
    #[test]
    fn arg_pattern_matches_scalars_as_strings() {
        let args = k7s_deps::serde_json::json!({ "replicas": 3, "force": true });
        assert!(arg_pattern_matches("replicas=3", &args));
        assert!(!arg_pattern_matches("replicas=5", &args));
        assert!(arg_pattern_matches("force=true", &args));
    }

    /// Absent keys and `=`-less patterns keep the original substring fallback
    /// over the serialized arguments.
    #[test]
    fn arg_pattern_substring_fallback() {
        let args = k7s_deps::serde_json::json!({ "yaml": "namespace: prod\n" });
        // `=`-less pattern: plain substring against the JSON text.
        assert!(arg_pattern_matches("prod", &args));
        assert!(!arg_pattern_matches("staging", &args));
        // Key absent → also substring, and "namespace=prod" is not a substring
        // of `{"yaml":"namespace: prod"}` (colon, not equals) — correctly no
        // match: an absent key can't be equality-checked.
        assert!(!arg_pattern_matches("namespace=prod", &args));
    }

    /// End-to-end: a deny rule with `namespace=kube-system` denies the call,
    /// and an `ask` rule with `kind=secrets` escalates to a user prompt.
    #[test]
    fn evaluate_honours_key_value_rules() {
        let config = SandboxConfig {
            // Bypass the namespace lists so the rule table is what's under test.
            denied_namespaces: Vec::new(),
            rules: vec![
                CommandRule {
                    action: "deny".into(),
                    tool_pattern: "delete_*".into(),
                    arg_pattern: Some("namespace=kube-system".into()),
                    reason: "kube-system is protected".into(),
                },
                CommandRule {
                    action: "ask".into(),
                    tool_pattern: "*".into(),
                    arg_pattern: Some("kind=secrets".into()),
                    reason: "secret access needs approval".into(),
                },
            ],
            ..Default::default()
        };
        let deny = evaluate(
            &config,
            "delete_resource",
            &k7s_deps::serde_json::json!({ "kind": "deployments", "namespace": "kube-system", "name": "coredns" }),
        );
        assert!(
            matches!(deny, SandboxDecision::Deny { ref reason } if reason.contains("kube-system is protected")),
            "documented deny example must hit, got {deny:?}"
        );

        let ask = evaluate(
            &config,
            "describe_resource",
            &k7s_deps::serde_json::json!({ "kind": "secrets", "namespace": "default", "name": "db" }),
        );
        assert!(
            matches!(ask, SandboxDecision::Ask { .. }),
            "documented ask example must hit, got {ask:?}"
        );

        // A call matching neither rule passes through to Allow.
        let allow = evaluate(
            &config,
            "describe_resource",
            &k7s_deps::serde_json::json!({ "kind": "pods", "namespace": "default", "name": "web" }),
        );
        assert!(matches!(allow, SandboxDecision::Allow));
    }

    /// A config JSON that omits `enabled` (e.g. hand-edited or older schema)
    /// must deserialize with the sandbox still on — fail-secure.
    #[test]
    fn partial_config_defaults_enabled_true() {
        let cfg: SandboxConfig = k7s_deps::serde_json::from_str(r#"{"preset":"loose"}"#).unwrap();
        assert!(cfg.enabled);
    }
}
