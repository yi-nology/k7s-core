//! RBAC permission matrix: shows who can do what on which resources.
//!
//! Builds a cross-tabulation of subjects (rows) versus verb+resource
//! combinations (columns) by resolving all RoleBindings/ClusterRoleBindings
//! to their referenced roles' PolicyRules.

use crate::error::AppResult;
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::Client;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A subject in the permission matrix (User, Group, or ServiceAccount).
#[derive(Serialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSubject {
    pub kind: String, // "User", "Group", "ServiceAccount"
    pub name: String,
    pub namespace: Option<String>,
}

/// A verb+resource+apiGroup action key.
#[derive(Serialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ActionKey {
    pub verb: String,
    pub resource: String,
    pub api_group: String,
}

/// One cell in the matrix: which binding/role grants this permission.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GrantSource {
    pub role: String,
    pub binding: String,
    pub binding_kind: String, // "RoleBinding" or "ClusterRoleBinding"
}

/// The full permission matrix.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionMatrix {
    pub subjects: Vec<MatrixSubject>,
    pub actions: Vec<ActionKey>,
    /// Sparse matrix: (subject_index, action_index) -> grant source.
    pub grants: Vec<MatrixGrant>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixGrant {
    pub subject_idx: usize,
    pub action_idx: usize,
    pub source: GrantSource,
}

/// Standard verbs to expand wildcards against.
const STANDARD_VERBS: &[&str] = &[
    "get",
    "list",
    "watch",
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
];

/// Build the RBAC permission matrix.
pub async fn build_rbac_matrix(client: Client) -> AppResult<PermissionMatrix> {
    // 1. Fetch all RBAC resources, tolerating permission errors gracefully.
    let roles: Vec<k7s_deps::k8s_openapi::api::rbac::v1::Role> =
        match Api::<k7s_deps::k8s_openapi::api::rbac::v1::Role>::all(client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(list) => list.items,
            Err(_) => Vec::new(),
        };

    let cluster_roles: Vec<k7s_deps::k8s_openapi::api::rbac::v1::ClusterRole> =
        match Api::<k7s_deps::k8s_openapi::api::rbac::v1::ClusterRole>::all(client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(list) => list.items,
            Err(_) => Vec::new(),
        };

    let role_bindings: Vec<k7s_deps::k8s_openapi::api::rbac::v1::RoleBinding> =
        match Api::<k7s_deps::k8s_openapi::api::rbac::v1::RoleBinding>::all(client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(list) => list.items,
            Err(_) => Vec::new(),
        };

    let cluster_role_bindings: Vec<k7s_deps::k8s_openapi::api::rbac::v1::ClusterRoleBinding> =
        match Api::<k7s_deps::k8s_openapi::api::rbac::v1::ClusterRoleBinding>::all(client)
            .list(&ListParams::default())
            .await
        {
            Ok(list) => list.items,
            Err(_) => Vec::new(),
        };

    // 2. Build role lookup: name -> rules
    let mut role_rules: BTreeMap<String, Vec<k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule>> =
        BTreeMap::new();
    for r in &roles {
        let name = r.metadata.name.clone().unwrap_or_default();
        let ns = r.metadata.namespace.clone().unwrap_or_default();
        let key = format!("Role:{ns}/{name}");
        role_rules.insert(key, r.rules.clone().unwrap_or_default());
    }
    for r in &cluster_roles {
        let name = r.metadata.name.clone().unwrap_or_default();
        let key = format!("ClusterRole:{name}");
        role_rules.insert(key, r.rules.clone().unwrap_or_default());
    }

    // 3. Process bindings and build matrix
    let mut subjects_set: BTreeSet<MatrixSubject> = BTreeSet::new();
    let mut actions_set: BTreeSet<ActionKey> = BTreeSet::new();
    let mut grants_raw: Vec<(MatrixSubject, ActionKey, GrantSource)> = Vec::new();

    // Process ClusterRoleBindings
    for crb in &cluster_role_bindings {
        let binding_name = crb.metadata.name.clone().unwrap_or_default();
        let role_name = crb.role_ref.name.clone();
        let role_key = format!("ClusterRole:{role_name}");

        let rules = match role_rules.get(&role_key) {
            Some(r) => r,
            None => continue,
        };

        let source = GrantSource {
            role: role_name,
            binding: binding_name,
            binding_kind: "ClusterRoleBinding".into(),
        };

        for subject in crb.subjects.iter().flatten() {
            let ms = MatrixSubject {
                kind: subject.kind.clone(),
                name: subject.name.clone(),
                namespace: subject.namespace.clone(),
            };
            subjects_set.insert(ms.clone());

            expand_rules(rules, &ms, &source, &mut actions_set, &mut grants_raw);
        }
    }

    // Process RoleBindings
    for rb in &role_bindings {
        let binding_name = rb.metadata.name.clone().unwrap_or_default();
        let binding_ns = rb.metadata.namespace.clone().unwrap_or_default();
        let role_name = rb.role_ref.name.clone();
        let role_kind = rb.role_ref.kind.clone();

        let role_key = if role_kind == "ClusterRole" {
            format!("ClusterRole:{role_name}")
        } else {
            format!("Role:{binding_ns}/{role_name}")
        };

        let rules = match role_rules.get(&role_key) {
            Some(r) => r,
            None => continue,
        };

        let source = GrantSource {
            role: role_name,
            binding: binding_name,
            binding_kind: "RoleBinding".into(),
        };

        for subject in rb.subjects.iter().flatten() {
            let ms = MatrixSubject {
                kind: subject.kind.clone(),
                name: subject.name.clone(),
                namespace: subject.namespace.clone(),
            };
            subjects_set.insert(ms.clone());

            expand_rules(rules, &ms, &source, &mut actions_set, &mut grants_raw);
        }
    }

    // 4. Build indexed output
    let subjects: Vec<MatrixSubject> = subjects_set.into_iter().collect();
    let actions: Vec<ActionKey> = actions_set.into_iter().collect();
    let subject_idx: BTreeMap<&MatrixSubject, usize> =
        subjects.iter().enumerate().map(|(i, s)| (s, i)).collect();
    let action_idx: BTreeMap<&ActionKey, usize> =
        actions.iter().enumerate().map(|(i, a)| (a, i)).collect();

    let grants: Vec<MatrixGrant> = grants_raw
        .into_iter()
        .filter_map(|(subj, action, source)| {
            let si = subject_idx.get(&subj)?;
            let ai = action_idx.get(&action)?;
            Some(MatrixGrant {
                subject_idx: *si,
                action_idx: *ai,
                source,
            })
        })
        .collect();

    Ok(PermissionMatrix {
        subjects,
        actions,
        grants,
    })
}

/// Expand a role's PolicyRules into (subject, action, source) tuples.
fn expand_rules(
    rules: &[k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule],
    subject: &MatrixSubject,
    source: &GrantSource,
    actions_set: &mut BTreeSet<ActionKey>,
    grants_raw: &mut Vec<(MatrixSubject, ActionKey, GrantSource)>,
) {
    for rule in rules {
        let verbs = expand_wildcards(&rule.verbs, STANDARD_VERBS);
        let resources = expand_wildcards(
            rule.resources.as_deref().unwrap_or(&[]),
            &[], // No standard expansion for resources — use as-is
        );
        let api_groups = expand_wildcards(
            rule.api_groups.as_deref().unwrap_or(&["".into()]),
            &[""], // Empty string means core API group
        );

        for verb in &verbs {
            for resource in &resources {
                for api_group in &api_groups {
                    let action = ActionKey {
                        verb: verb.clone(),
                        resource: resource.clone(),
                        api_group: api_group.clone(),
                    };
                    actions_set.insert(action.clone());
                    grants_raw.push((subject.clone(), action, source.clone()));
                }
            }
        }
    }
}

/// Expand wildcard `"*"` to all standard values.
fn expand_wildcards(values: &[String], standards: &[&str]) -> Vec<String> {
    if values.is_empty() {
        return vec!["".into()];
    }
    if values.iter().any(|v| v == "*") {
        if standards.is_empty() {
            return vec!["*".into()]; // Can't expand resources
        }
        return standards.iter().map(|s| s.to_string()).collect();
    }
    values.to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_wildcards_with_star_and_standards() {
        let values = vec!["*".into()];
        let result = expand_wildcards(&values, &["get", "list"]);
        assert_eq!(result, vec!["get", "list"]);
    }

    #[test]
    fn expand_wildcards_with_star_no_standards() {
        let values = vec!["*".into()];
        let result = expand_wildcards(&values, &[]);
        assert_eq!(result, vec!["*"]);
    }

    #[test]
    fn expand_wildcards_no_star() {
        let values = vec!["get".into(), "list".into()];
        let result = expand_wildcards(&values, &["get", "list", "watch"]);
        assert_eq!(result, vec!["get", "list"]);
    }

    #[test]
    fn expand_wildcards_empty() {
        let values: Vec<String> = vec![];
        let result = expand_wildcards(&values, &["get"]);
        assert_eq!(result, vec![""]);
    }

    #[test]
    fn expand_rules_basic() {
        let rule = k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule {
            verbs: vec!["get".into(), "list".into()],
            resources: Some(vec!["pods".into()]),
            api_groups: Some(vec!["".into()]),
            ..Default::default()
        };
        let subject = MatrixSubject {
            kind: "User".into(),
            name: "alice".into(),
            namespace: None,
        };
        let source = GrantSource {
            role: "pod-reader".into(),
            binding: "alice-pod-reader".into(),
            binding_kind: "RoleBinding".into(),
        };
        let mut actions_set = BTreeSet::new();
        let mut grants_raw = Vec::new();

        expand_rules(
            &[rule],
            &subject,
            &source,
            &mut actions_set,
            &mut grants_raw,
        );

        assert_eq!(grants_raw.len(), 2); // get pods, list pods
        assert_eq!(actions_set.len(), 2);
    }

    #[test]
    fn expand_rules_wildcard_verbs() {
        let rule = k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule {
            verbs: vec!["*".into()],
            resources: Some(vec!["pods".into()]),
            api_groups: Some(vec!["".into()]),
            ..Default::default()
        };
        let subject = MatrixSubject {
            kind: "ServiceAccount".into(),
            name: "default".into(),
            namespace: Some("kube-system".into()),
        };
        let source = GrantSource {
            role: "admin".into(),
            binding: "sa-admin".into(),
            binding_kind: "ClusterRoleBinding".into(),
        };
        let mut actions_set = BTreeSet::new();
        let mut grants_raw = Vec::new();

        expand_rules(
            &[rule],
            &subject,
            &source,
            &mut actions_set,
            &mut grants_raw,
        );

        // 8 standard verbs * 1 resource * 1 api_group = 8
        assert_eq!(grants_raw.len(), 8);
        assert_eq!(actions_set.len(), 8);
    }

    #[test]
    fn expand_rules_wildcard_resources() {
        let rule = k7s_deps::k8s_openapi::api::rbac::v1::PolicyRule {
            verbs: vec!["get".into()],
            resources: Some(vec!["*".into()]),
            api_groups: Some(vec!["".into()]),
            ..Default::default()
        };
        let subject = MatrixSubject {
            kind: "User".into(),
            name: "bob".into(),
            namespace: None,
        };
        let source = GrantSource {
            role: "viewer".into(),
            binding: "bob-viewer".into(),
            binding_kind: "RoleBinding".into(),
        };
        let mut actions_set = BTreeSet::new();
        let mut grants_raw = Vec::new();

        expand_rules(
            &[rule],
            &subject,
            &source,
            &mut actions_set,
            &mut grants_raw,
        );

        // Resources wildcard can't be expanded, so stays as "*"
        assert_eq!(grants_raw.len(), 1);
        assert_eq!(actions_set.len(), 1);
        assert_eq!(grants_raw[0].1.resource, "*");
    }

    #[test]
    fn matrix_subject_ordering() {
        let a = MatrixSubject {
            kind: "User".into(),
            name: "alice".into(),
            namespace: None,
        };
        let b = MatrixSubject {
            kind: "User".into(),
            name: "bob".into(),
            namespace: None,
        };
        assert!(a < b);
    }

    #[test]
    fn action_key_ordering() {
        let a = ActionKey {
            verb: "get".into(),
            resource: "pods".into(),
            api_group: "".into(),
        };
        let b = ActionKey {
            verb: "list".into(),
            resource: "pods".into(),
            api_group: "".into(),
        };
        assert!(a < b);
    }
}
