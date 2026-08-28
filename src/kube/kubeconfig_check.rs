//! kubeconfig structural validation (`validate_kubeconfig`).
//!
//! Import used to stop at YAML parsing: a file with dangling cluster/user
//! references or a missing `server` parsed fine and only blew up at connect
//! time. This module runs after parsing and classifies problems into
//! blocking `Error`s and advisory `Warning`s so both shells (web upload and
//! desktop file dialog) can tell the user exactly what is wrong, per context.

use std::collections::HashSet;

use k7s_deps::kube::config::Kubeconfig;
use k7s_deps::serde::Serialize;

use crate::kube::client::ContextInfo;

/// How severe an issue is: `Error` blocks the import, `Warning` lets it
/// through but is surfaced to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IssueSeverity {
    Error,
    Warning,
}

/// One problem found while validating a parsed kubeconfig.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeconfigIssue {
    pub severity: IssueSeverity,
    /// Stable machine code ("missingClusterRef", …). The UI renders
    /// `message`, but tests and future i18n key off this.
    pub code: String,
    pub message: String,
    /// The context the issue belongs to; `None` for file-level problems.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Successful import result shared by both shells. `issues` carries advisory
/// warnings only — error-level issues never get this far.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportKubeconfigResult {
    pub contexts: Vec<ContextInfo>,
    pub path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<KubeconfigIssue>,
}

fn issue(
    severity: IssueSeverity,
    code: &str,
    message: String,
    context: Option<&str>,
) -> KubeconfigIssue {
    KubeconfigIssue {
        severity,
        code: code.to_string(),
        message,
        context: context.map(str::to_string),
    }
}

/// True when any issue is blocking (the import must not proceed).
pub fn has_errors(issues: &[KubeconfigIssue]) -> bool {
    issues.iter().any(|i| i.severity == IssueSeverity::Error)
}

/// Multi-line human summary for error channels that carry no structure
/// (the Tauri command rejects with a plain string).
pub fn summarize_issues(issues: &[KubeconfigIssue]) -> String {
    let mut out = format!("kubeconfig validation failed ({} issue(s)):", issues.len());
    for i in issues {
        let sev = match i.severity {
            IssueSeverity::Error => "error",
            IssueSeverity::Warning => "warning",
        };
        let ctx = i
            .context
            .as_deref()
            .map(|c| format!("context '{c}': "))
            .unwrap_or_default();
        out.push_str(&format!("\n- [{sev}] {ctx}{}", i.message));
    }
    out
}

/// Validate a parsed kubeconfig: per-context reference/URL/credential checks
/// plus file-level sanity. One broken context never masks the others — every
/// problem found is reported.
pub fn validate_kubeconfig(kc: &Kubeconfig) -> Vec<KubeconfigIssue> {
    let mut issues = Vec::new();

    if kc.contexts.is_empty() {
        issues.push(issue(
            IssueSeverity::Error,
            "noContexts",
            "the file defines no contexts".to_string(),
            None,
        ));
    }

    let clusters: HashSet<&str> = kc.clusters.iter().map(|c| c.name.as_str()).collect();
    let users: HashSet<&str> = kc.auth_infos.iter().map(|u| u.name.as_str()).collect();

    for ctx in &kc.contexts {
        let name = ctx.name.as_str();
        let Some(body) = &ctx.context else {
            issues.push(issue(
                IssueSeverity::Error,
                "missingContextBody",
                format!("context '{name}' has no context section"),
                Some(name),
            ));
            continue;
        };
        if !clusters.contains(body.cluster.as_str()) {
            issues.push(issue(
                IssueSeverity::Error,
                "missingClusterRef",
                format!("cluster '{}' not found in clusters", body.cluster),
                Some(name),
            ));
        }
        // kube 0.99 types `user` as optional — a missing user is its own
        // finding rather than a lookup miss.
        let user = body.user.as_deref();
        match user {
            None => issues.push(issue(
                IssueSeverity::Error,
                "missingUserRef",
                format!("context '{name}' sets no user"),
                Some(name),
            )),
            Some(user) => {
                if !users.contains(user) {
                    issues.push(issue(
                        IssueSeverity::Error,
                        "missingUserRef",
                        format!("user '{user}' not found in users"),
                        Some(name),
                    ));
                }
            }
        }

        if let Some(cluster) = kc.clusters.iter().find(|c| c.name == body.cluster) {
            match cluster.cluster.as_ref().and_then(|c| c.server.as_deref()) {
                None => issues.push(issue(
                    IssueSeverity::Error,
                    "missingServer",
                    format!("cluster '{}' has no server address", body.cluster),
                    Some(name),
                )),
                Some(server) => {
                    let lower = server.to_ascii_lowercase();
                    // "https://" is the shortest legal form — anything that
                    // short carries no host at all.
                    if !(lower.starts_with("https://") || lower.starts_with("http://"))
                        || server.trim().len() <= lower.split("://").next().map_or(0, |s| s.len() + 3)
                    {
                        issues.push(issue(
                            IssueSeverity::Error,
                            "badServerUrl",
                            format!(
                                "cluster '{0}' server '{server}' is not a valid http(s) URL",
                                body.cluster
                            ),
                            Some(name),
                        ));
                    } else if lower.starts_with("https://") {
                        let c = cluster.cluster.as_ref().expect("cluster body matched above");
                        let has_ca = c.certificate_authority.is_some()
                            || c.certificate_authority_data.is_some();
                        if !has_ca && !c.insecure_skip_tls_verify.unwrap_or(false) {
                            issues.push(issue(
                                IssueSeverity::Warning,
                                "noCaBundle",
                                format!("cluster '{0}' uses https without a CA bundle — the server certificate cannot be verified (set certificate-authority-data or insecure-skip-tls-verify)", body.cluster),
                                Some(name),
                            ));
                        }
                    }
                }
            }
        }

        // Credential advisory — only meaningful once the user reference
        // resolves; a dangling user already reported above.
        if let Some(nai) = body.user.as_deref().and_then(|user| {
            kc.auth_infos.iter().find(|u| u.name == user)
        }) {
            let has_credentials = nai.auth_info.as_ref().is_some_and(|a| {
                a.token.is_some()
                    || a.token_file.is_some()
                    || a.client_certificate.is_some()
                    || a.client_certificate_data.is_some()
                    || a.username.is_some()
                    || a.password.is_some()
                    || a.auth_provider.is_some()
                    || a.exec.is_some()
            });
            if !has_credentials {
                issues.push(issue(
                    IssueSeverity::Warning,
                    "noCredentials",
                    format!("user '{}' defines no credentials (token, client cert, basic auth, exec, or auth-provider)", nai.name),
                    Some(name),
                ));
            }
        }
    }

    if let Some(current) = &kc.current_context {
        if !kc.contexts.iter().any(|c| &c.name == current) {
            issues.push(issue(
                IssueSeverity::Warning,
                "danglingCurrentContext",
                format!("current-context '{current}' does not match any context"),
                None,
            ));
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> Kubeconfig {
        Kubeconfig::from_yaml(yaml).expect("test yaml parses")
    }

    fn codes(issues: &[KubeconfigIssue]) -> Vec<&str> {
        issues.iter().map(|i| i.code.as_str()).collect()
    }

    #[test]
    fn good_file_has_no_issues() {
        let kc = config(
            r#"
apiVersion: v1
kind: Config
current-context: prod
clusters:
  - name: prod
    cluster:
      server: https://k8s.example.com:6443
      certificate-authority-data: Zm9v
contexts:
  - name: prod
    context: { cluster: prod, user: prod-user }
users:
  - name: prod-user
    user: { token: s3cret }
"#,
        );
        assert!(validate_kubeconfig(&kc).is_empty());
    }

    #[test]
    fn empty_contexts_is_an_error() {
        let kc = config("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n");
        let issues = validate_kubeconfig(&kc);
        assert!(has_errors(&issues));
        assert!(codes(&issues).contains(&"noContexts"));
    }

    #[test]
    fn dangling_cluster_and_user_refs_are_errors() {
        let kc = config(
            r#"
clusters: []
contexts:
  - name: c1
    context: { cluster: nope, user: also-nope }
users: []
"#,
        );
        let issues = validate_kubeconfig(&kc);
        assert!(has_errors(&issues));
        let c = codes(&issues);
        assert!(c.contains(&"missingClusterRef") && c.contains(&"missingUserRef"));
        assert_eq!(issues[0].context.as_deref(), Some("c1"));
    }

    #[test]
    fn missing_server_is_an_error() {
        let kc = config(
            r#"
clusters:
  - name: c
    cluster: {}
contexts:
  - name: c1
    context: { cluster: c, user: u }
users:
  - name: u
    user: { token: t }
"#,
        );
        let issues = validate_kubeconfig(&kc);
        assert!(codes(&issues).contains(&"missingServer"));
    }

    #[test]
    fn bad_server_url_is_an_error() {
        let kc = config(
            r#"
clusters:
  - name: c
    cluster: { server: "not-a-url" }
contexts:
  - name: c1
    context: { cluster: c, user: u }
users:
  - name: u
    user: { token: t }
"#,
        );
        let issues = validate_kubeconfig(&kc);
        assert!(codes(&issues).contains(&"badServerUrl"));
    }

    #[test]
    fn https_without_ca_warns_but_does_not_block() {
        let kc = config(
            r#"
clusters:
  - name: c
    cluster: { server: https://k8s.example.com }
contexts:
  - name: c1
    context: { cluster: c, user: u }
users:
  - name: u
    user: { token: t }
"#,
        );
        let issues = validate_kubeconfig(&kc);
        assert!(!has_errors(&issues));
        assert!(codes(&issues).contains(&"noCaBundle"));
    }

    #[test]
    fn insecure_skip_tls_verify_suppresses_ca_warning() {
        let kc = config(
            r#"
clusters:
  - name: c
    cluster: { server: https://k8s.example.com, insecure-skip-tls-verify: true }
contexts:
  - name: c1
    context: { cluster: c, user: u }
users:
  - name: u
    user: { token: t }
"#,
        );
        assert!(validate_kubeconfig(&kc).is_empty());
    }

    #[test]
    fn user_without_credentials_warns() {
        let kc = config(
            r#"
clusters:
  - name: c
    cluster: { server: https://k8s.example.com }
contexts:
  - name: c1
    context: { cluster: c, user: u }
users:
  - name: u
    user: {}
"#,
        );
        let issues = validate_kubeconfig(&kc);
        assert!(!has_errors(&issues));
        assert!(codes(&issues).contains(&"noCredentials"));
    }

    #[test]
    fn exec_plugin_counts_as_credentials() {
        let kc = config(
            r#"
clusters:
  - name: c
    cluster: { server: https://k8s.example.com, insecure-skip-tls-verify: true }
contexts:
  - name: c1
    context: { cluster: c, user: u }
users:
  - name: u
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: my-auth-plugin
        interactiveMode: Never
"#,
        );
        assert!(validate_kubeconfig(&kc).is_empty());
    }

    #[test]
    fn dangling_current_context_warns() {
        let kc = config(
            r#"
current-context: missing
clusters:
  - name: c
    cluster: { server: https://k8s.example.com }
contexts:
  - name: c1
    context: { cluster: c, user: u }
users:
  - name: u
    user: { token: t }
"#,
        );
        let issues = validate_kubeconfig(&kc);
        assert!(!has_errors(&issues));
        assert!(codes(&issues).contains(&"danglingCurrentContext"));
    }

    #[test]
    fn summarize_lists_every_issue() {
        let kc = config(
            r#"
clusters: []
contexts:
  - name: c1
    context: { cluster: nope, user: nobody }
users: []
"#,
        );
        let issues = validate_kubeconfig(&kc);
        let summary = summarize_issues(&issues);
        assert!(
            summary.starts_with("kubeconfig validation failed (2 issue(s)):"),
            "got: {summary}"
        );
        assert!(summary.contains("[error] context 'c1': cluster 'nope' not found"));
        assert!(summary.contains("[error] context 'c1': user 'nobody' not found"));
    }
}
