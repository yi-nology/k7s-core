//! RBAC security audit: scans Roles, ClusterRoles, RoleBindings, and
//! ClusterRoleBindings for common misconfigurations and privilege risks.

use crate::error::AppResult;
use k7s_deps::chrono::Utc;
use k7s_deps::k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use k7s_deps::kube::api::Api;
use k7s_deps::kube::Client;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A single audit finding describing one security issue.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuditFinding {
    /// Rule identifier, e.g. "wildcard-verbs".
    pub id: String,
    /// Severity: Critical, High, Medium, or Low.
    pub severity: String,
    /// The Kubernetes resource kind: Role, ClusterRole, etc.
    pub resource_kind: String,
    /// Name of the resource that triggered the finding.
    pub resource_name: String,
    /// Namespace for namespaced resources; None for cluster-scoped ones.
    pub namespace: Option<String>,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Aggregate counts by severity.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuditSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub total: u32,
}

/// The complete audit report returned to callers.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub findings: Vec<AuditFinding>,
    pub summary: AuditSummary,
    /// ISO 8601 timestamp of when the audit was performed.
    pub scanned_at: String,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run a full RBAC security audit against the current cluster.
///
/// Fetches all Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings,
/// applies a set of security rules, and returns a sorted report.  Individual
/// resource types that cannot be listed (e.g. due to RBAC restrictions) are
/// skipped gracefully rather than failing the entire audit.
pub async fn run_audit(client: Client) -> AppResult<AuditReport> {
    let mut findings: Vec<AuditFinding> = Vec::new();

    // -- Fetch RBAC resources, tolerating permission errors ------------------

    let roles: Vec<Role> = match Api::<Role>::all(client.clone())
        .list(&Default::default())
        .await
    {
        Ok(list) => list.items,
        Err(e) => {
            findings.push(AuditFinding {
                id: "fetch-error".into(),
                severity: "Low".into(),
                resource_kind: "Role".into(),
                resource_name: "(listing)".into(),
                namespace: None,
                message: format!("Could not list Roles: {e}"),
            });
            Vec::new()
        }
    };

    let cluster_roles: Vec<ClusterRole> = match Api::<ClusterRole>::all(client.clone())
        .list(&Default::default())
        .await
    {
        Ok(list) => list.items,
        Err(e) => {
            findings.push(AuditFinding {
                id: "fetch-error".into(),
                severity: "Low".into(),
                resource_kind: "ClusterRole".into(),
                resource_name: "(listing)".into(),
                namespace: None,
                message: format!("Could not list ClusterRoles: {e}"),
            });
            Vec::new()
        }
    };

    let role_bindings: Vec<RoleBinding> = match Api::<RoleBinding>::all(client.clone())
        .list(&Default::default())
        .await
    {
        Ok(list) => list.items,
        Err(e) => {
            findings.push(AuditFinding {
                id: "fetch-error".into(),
                severity: "Low".into(),
                resource_kind: "RoleBinding".into(),
                resource_name: "(listing)".into(),
                namespace: None,
                message: format!("Could not list RoleBindings: {e}"),
            });
            Vec::new()
        }
    };

    let cluster_role_bindings: Vec<ClusterRoleBinding> =
        match Api::<ClusterRoleBinding>::all(client)
            .list(&Default::default())
            .await
        {
            Ok(list) => list.items,
            Err(e) => {
                findings.push(AuditFinding {
                    id: "fetch-error".into(),
                    severity: "Low".into(),
                    resource_kind: "ClusterRoleBinding".into(),
                    resource_name: "(listing)".into(),
                    namespace: None,
                    message: format!("Could not list ClusterRoleBindings: {e}"),
                });
                Vec::new()
            }
        };

    // -- Build lookup sets for orphaned-binding checks ----------------------

    let role_names: std::collections::HashSet<String> = roles
        .iter()
        .filter_map(|r| r.metadata.name.clone())
        .collect();

    let cluster_role_names: std::collections::HashSet<String> = cluster_roles
        .iter()
        .filter_map(|r| r.metadata.name.clone())
        .collect();

    // -- Audit Roles --------------------------------------------------------

    for role in &roles {
        let name = role.metadata.name.clone().unwrap_or_default();
        let ns = role.metadata.namespace.clone();
        findings.extend(check_role_rules(
            &name,
            ns.as_deref(),
            role.rules.as_deref(),
        ));
    }

    // -- Audit ClusterRoles -------------------------------------------------

    for cr in &cluster_roles {
        let name = cr.metadata.name.clone().unwrap_or_default();
        findings.extend(check_cluster_role_rules(&name, cr.rules.as_deref()));
    }

    // -- Audit RoleBindings --------------------------------------------------

    for rb in &role_bindings {
        let name = rb.metadata.name.clone().unwrap_or_default();
        let ns = rb.metadata.namespace.clone();
        findings.extend(check_binding(
            &name,
            ns.as_deref(),
            "RoleBinding",
            &rb.role_ref,
            rb.subjects.as_deref(),
            &role_names,
            &cluster_role_names,
        ));
    }

    // -- Audit ClusterRoleBindings ------------------------------------------

    for crb in &cluster_role_bindings {
        let name = crb.metadata.name.clone().unwrap_or_default();
        findings.extend(check_binding(
            &name,
            None,
            "ClusterRoleBinding",
            &crb.role_ref,
            crb.subjects.as_deref(),
            &role_names,
            &cluster_role_names,
        ));
    }

    // -- Cross-reference checks ---------------------------------------------

    findings.extend(check_default_sa_privileged(
        &role_bindings,
        &cluster_role_bindings,
    ));
    findings.extend(check_sa_many_bindings(
        &role_bindings,
        &cluster_role_bindings,
    ));

    // -- Sort by severity (Critical first) and build report ------------------

    let severity_order = |s: &str| match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        _ => 3,
    };
    findings.sort_by_key(|a| severity_order(&a.severity));

    let mut summary = AuditSummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: findings.len() as u32,
    };
    for f in &findings {
        match f.severity.as_str() {
            "Critical" => summary.critical += 1,
            "High" => summary.high += 1,
            "Medium" => summary.medium += 1,
            _ => summary.low += 1,
        }
    }

    Ok(AuditReport {
        findings,
        summary,
        scanned_at: Utc::now().to_rfc3339(),
    })
}

// ---------------------------------------------------------------------------
// Helper: check rules for a namespaced Role
// ---------------------------------------------------------------------------

/// Audit the rules of a single Role (namespaced).
pub fn check_role_rules(
    name: &str,
    namespace: Option<&str>,
    rules: Option<&[k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule]>,
) -> Vec<AuditFinding> {
    let ns_display = namespace.unwrap_or("");
    rules
        .unwrap_or(&[])
        .iter()
        .flat_map(|rule| check_policy_rule(rule, "Role", name, Some(ns_display)))
        .collect()
}

// ---------------------------------------------------------------------------
// Helper: check rules for a ClusterRole
// ---------------------------------------------------------------------------

/// Audit the rules of a single ClusterRole (cluster-scoped).
pub fn check_cluster_role_rules(
    name: &str,
    rules: Option<&[k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule]>,
) -> Vec<AuditFinding> {
    rules
        .unwrap_or(&[])
        .iter()
        .flat_map(|rule| check_policy_rule(rule, "ClusterRole", name, None))
        .collect()
}

// ---------------------------------------------------------------------------
// Helper: check a single PolicyRule
// ---------------------------------------------------------------------------

fn check_policy_rule(
    rule: &k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule,
    kind: &str,
    name: &str,
    namespace: Option<&str>,
) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    let verbs: Vec<&str> = rule.verbs.iter().map(String::as_str).collect();
    let resources: Vec<&str> = rule
        .resources
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let api_groups: Vec<&str> = rule
        .api_groups
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let resource_names: Vec<&str> = rule
        .resource_names
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();

    // wildcard-verbs: verbs=["*"]
    if verbs.contains(&"*") {
        out.push(finding(
            "wildcard-verbs",
            "Critical",
            kind,
            name,
            namespace,
            "Rule grants wildcard verbs (\"*\"), allowing every operation.",
        ));
    }

    // wildcard-resources: resources=["*"]
    if resources.contains(&"*") {
        out.push(finding(
            "wildcard-resources",
            "Critical",
            kind,
            name,
            namespace,
            "Rule grants wildcard resources (\"*\"), covering every resource type.",
        ));
    }

    // wildcard-apigroups: api_groups=["*"]
    if api_groups.contains(&"*") {
        out.push(finding(
            "wildcard-apigroups",
            "High",
            kind,
            name,
            namespace,
            "Rule grants wildcard API groups (\"*\"), spanning all API groups.",
        ));
    }

    // secret-access: get/list/watch on "secrets"
    let is_secret_resource = resources.iter().any(|r| r == &"secrets" || r == &"*");
    let is_read_verb = verbs
        .iter()
        .any(|v| matches!(*v, "get" | "list" | "watch" | "*"));
    if is_secret_resource && is_read_verb {
        out.push(finding(
            "secret-access",
            "High",
            kind,
            name,
            namespace,
            "Rule allows reading Secrets (get/list/watch), which may expose credentials.",
        ));
    }

    // exec-allowed: create on "pods/exec"
    let is_exec = resources.iter().any(|r| r == &"pods/exec" || r == &"*");
    let is_create = verbs.iter().any(|v| *v == "create" || *v == "*");
    if is_exec && is_create {
        out.push(finding(
            "exec-allowed",
            "High",
            kind,
            name,
            namespace,
            "Rule allows creating pods/exec, enabling arbitrary command execution inside containers.",
        ));
    }

    // pod-create-allowed: create on "pods"
    let is_pods = resources.iter().any(|r| r == &"pods" || r == &"*");
    if is_pods && is_create && !resource_names.iter().any(|n| !n.is_empty()) {
        out.push(finding(
            "pod-create-allowed",
            "Critical",
            kind,
            name,
            namespace,
            "Rule allows creating Pods, which can be used to run arbitrary workloads.",
        ));
    }

    // token-request-allowed: create on "serviceaccounts/token"
    let is_sa_token = resources
        .iter()
        .any(|r| r == &"serviceaccounts/token" || r == &"*");
    if is_sa_token && is_create {
        out.push(finding(
            "token-request-allowed",
            "High",
            kind,
            name,
            namespace,
            "Rule allows creating service account tokens, enabling token minting for any SA.",
        ));
    }

    out
}

// ---------------------------------------------------------------------------
// Helper: check a RoleBinding or ClusterRoleBinding
// ---------------------------------------------------------------------------

/// Audit a binding for cluster-admin references, anonymous subjects, and
/// orphaned role references.
pub fn check_binding(
    name: &str,
    namespace: Option<&str>,
    kind: &str,
    role_ref: &k7s_deps::k8s_openapi::api::rbac::v1::RoleRef,
    subjects: Option<&[k7s_deps::k8s_openapi::api::rbac::v1::Subject]>,
    existing_roles: &std::collections::HashSet<String>,
    existing_cluster_roles: &std::collections::HashSet<String>,
) -> Vec<AuditFinding> {
    let mut out = Vec::new();

    // cluster-admin-bound
    if role_ref.name == "cluster-admin" {
        out.push(finding(
            "cluster-admin-bound",
            "Critical",
            kind,
            name,
            namespace,
            "Binding references the built-in cluster-admin ClusterRole, granting full cluster access.",
        ));
    }

    // orphaned-binding: referenced role does not exist
    let exists = match role_ref.kind.as_str() {
        "Role" => existing_roles.contains(&role_ref.name),
        "ClusterRole" => existing_cluster_roles.contains(&role_ref.name),
        _ => true, // unknown kind — don't flag
    };
    if !exists {
        out.push(finding(
            "orphaned-binding",
            "Medium",
            kind,
            name,
            namespace,
            &format!(
                "Binding references {} \"{}\" which does not exist.",
                role_ref.kind, role_ref.name
            ),
        ));
    }

    // anonymous-binding
    for sub in subjects.unwrap_or(&[]) {
        let is_anonymous = (sub.kind == "User"
            && (sub.name == "system:anonymous" || sub.name == "system:unauthenticated"))
            || (sub.kind == "Group" && sub.name == "system:unauthenticated");
        if is_anonymous {
            out.push(finding(
                "anonymous-binding",
                "High",
                kind,
                name,
                namespace,
                &format!(
                    "Binding grants permissions to anonymous/unauthenticated subject \"{}\".",
                    sub.name
                ),
            ));
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Cross-reference: default ServiceAccount bound to a non-trivial role
// ---------------------------------------------------------------------------

fn check_default_sa_privileged(
    role_bindings: &[RoleBinding],
    cluster_role_bindings: &[ClusterRoleBinding],
) -> Vec<AuditFinding> {
    let mut out = Vec::new();

    // Check RoleBindings where the "default" SA is a subject and the
    // referenced role is not a well-known read-only or empty role.
    let trivial_roles: std::collections::HashSet<&str> = [
        "system:discovery",
        "system:basic-user",
        "system:public-info-viewer",
    ]
    .into_iter()
    .collect();

    for rb in role_bindings {
        let ns = rb.metadata.namespace.as_deref().unwrap_or("default");
        let has_default_sa = rb.subjects.iter().flatten().any(|s| {
            s.kind == "ServiceAccount" && s.name == "default" && s.namespace.as_deref() == Some(ns)
        });
        if has_default_sa && !trivial_roles.contains(rb.role_ref.name.as_str()) {
            out.push(finding(
                "default-sa-privileged",
                "High",
                "RoleBinding",
                rb.metadata.name.as_deref().unwrap_or(""),
                Some(ns),
                &format!(
                    "The \"default\" ServiceAccount is bound to {} \"{}\" via this RoleBinding.",
                    rb.role_ref.kind, rb.role_ref.name
                ),
            ));
        }
    }

    // Same check for ClusterRoleBindings
    for crb in cluster_role_bindings {
        let has_default_sa = crb
            .subjects
            .iter()
            .flatten()
            .any(|s| s.kind == "ServiceAccount" && s.name == "default");
        if has_default_sa && !trivial_roles.contains(crb.role_ref.name.as_str()) {
            out.push(finding(
                "default-sa-privileged",
                "High",
                "ClusterRoleBinding",
                crb.metadata.name.as_deref().unwrap_or(""),
                None,
                &format!(
                    "The \"default\" ServiceAccount is bound to {} \"{}\" via this ClusterRoleBinding.",
                    crb.role_ref.kind, crb.role_ref.name
                ),
            ));
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Cross-reference: ServiceAccount with many bindings
// ---------------------------------------------------------------------------

fn check_sa_many_bindings(
    role_bindings: &[RoleBinding],
    cluster_role_bindings: &[ClusterRoleBinding],
) -> Vec<AuditFinding> {
    use std::collections::HashMap;

    // Count bindings per (kind, name) subject.
    let mut counts: HashMap<(String, String), u32> = HashMap::new();

    for rb in role_bindings {
        for s in rb
            .subjects
            .iter()
            .flatten()
            .filter(|s| s.kind == "ServiceAccount")
        {
            let key = (s.namespace.clone().unwrap_or_default(), s.name.clone());
            *counts.entry(key).or_default() += 1;
        }
    }
    for crb in cluster_role_bindings {
        for s in crb
            .subjects
            .iter()
            .flatten()
            .filter(|s| s.kind == "ServiceAccount")
        {
            let key = (s.namespace.clone().unwrap_or_default(), s.name.clone());
            *counts.entry(key).or_default() += 1;
        }
    }

    counts
        .into_iter()
        .filter(|(_, count)| *count > 3)
        .map(|((ns, name), count)| {
            finding(
                "sa-many-bindings",
                "Medium",
                "ServiceAccount",
                &name,
                Some(&ns),
                &format!(
                    "ServiceAccount \"{name}\" in namespace \"{ns}\" has {count} role bindings, \
                     which may indicate over-permissioning.",
                ),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helper to build an AuditFinding
// ---------------------------------------------------------------------------

fn finding(
    id: &str,
    severity: &str,
    kind: &str,
    name: &str,
    namespace: Option<&str>,
    message: &str,
) -> AuditFinding {
    AuditFinding {
        id: id.to_string(),
        severity: severity.to_string(),
        resource_kind: kind.to_string(),
        resource_name: name.to_string(),
        namespace: namespace.map(String::from),
        message: message.to_string(),
    }
}
