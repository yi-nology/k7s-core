//! Network Policy Simulator: answers "can pod A communicate with pod B?".
//!
//! Evaluates all applicable NetworkPolicies in both the source and destination
//! namespaces to determine whether egress from the source and ingress to the
//! destination are allowed. The result includes human-readable reasons and the
//! list of matching policies.

use crate::error::AppResult;
use k7s_deps::k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer};
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::Client;
use serde::Serialize;
use std::collections::BTreeMap;

/// Result of a connectivity simulation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationResult {
    pub allowed: bool,
    pub ingress_allowed: bool,
    pub egress_allowed: bool,
    pub ingress_reason: String,
    pub egress_reason: String,
    pub matching_policies: Vec<MatchedPolicy>,
}

/// A policy that matched during simulation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchedPolicy {
    pub name: String,
    pub namespace: String,
    /// "ingress" or "egress".
    pub direction: String,
    /// "allows" or "denies".
    pub effect: String,
}

/// Fetch a namespace's labels, with a synthetic
/// `kubernetes.io/metadata.name` entry so namespaceSelector evaluation still
/// works when the Namespace read is RBAC-denied.
async fn namespace_labels(
    ns_api: &Api<k7s_deps::k8s_openapi::api::core::v1::Namespace>,
    name: &str,
) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = ns_api
        .get(name)
        .await
        .ok()
        .and_then(|n| n.metadata.labels)
        .unwrap_or_default();
    map.entry("kubernetes.io/metadata.name".to_string())
        .or_insert_with(|| name.to_string());
    map
}

/// Simulate connectivity between two pods.
///
/// Fetches both pods (to read their labels and IPs) and all NetworkPolicies in
/// their respective namespaces, then evaluates egress from the source and ingress
/// to the destination.
pub async fn simulate_connectivity(
    client: Client,
    src_namespace: &str,
    src_pod: &str,
    dst_namespace: &str,
    dst_pod: &str,
    port: Option<i32>,
    protocol: Option<String>,
) -> AppResult<SimulationResult> {
    // 1. Fetch source and destination pods.
    let src_api: Api<k7s_deps::k8s_openapi::api::core::v1::Pod> =
        Api::namespaced(client.clone(), src_namespace);
    let dst_api: Api<k7s_deps::k8s_openapi::api::core::v1::Pod> =
        Api::namespaced(client.clone(), dst_namespace);

    let src_pod_obj = src_api
        .get(src_pod)
        .await
        .map_err(|e| crate::error::AppError::Kube(format!("source pod: {e}")))?;
    let dst_pod_obj = dst_api
        .get(dst_pod)
        .await
        .map_err(|e| crate::error::AppError::Kube(format!("destination pod: {e}")))?;

    let src_labels = src_pod_obj.metadata.labels.clone().unwrap_or_default();
    let dst_labels = dst_pod_obj.metadata.labels.clone().unwrap_or_default();
    let src_ip = src_pod_obj
        .status
        .as_ref()
        .and_then(|s| s.pod_ip.clone())
        .unwrap_or_default();
    let dst_ip = dst_pod_obj
        .status
        .as_ref()
        .and_then(|s| s.pod_ip.clone())
        .unwrap_or_default();

    // Namespace labels — needed for namespaceSelector evaluation. On RBAC
    // failure, fall back to the synthetic metadata.name label so the
    // historical special case still works.
    let ns_api: Api<k7s_deps::k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    let src_ns_labels = namespace_labels(&ns_api, src_namespace).await;
    let dst_ns_labels = namespace_labels(&ns_api, dst_namespace).await;

    // 2. Fetch all NetworkPolicies in both namespaces.
    let src_np_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), src_namespace);
    let dst_np_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), dst_namespace);

    let src_policies = src_np_api.list(&ListParams::default()).await?;
    let dst_policies = dst_np_api.list(&ListParams::default()).await?;

    let proto = protocol.as_deref();

    // 3. Evaluate egress (from source pod).
    let (egress_allowed, egress_reason, egress_matches) = evaluate_egress(
        &src_policies.items,
        &src_labels,
        &dst_ns_labels,
        &dst_labels,
        &dst_ip,
        port,
        proto,
    );

    // 4. Evaluate ingress (to destination pod).
    let (ingress_allowed, ingress_reason, ingress_matches) = evaluate_ingress(
        &dst_policies.items,
        &dst_labels,
        &src_ns_labels,
        &src_labels,
        &src_ip,
        port,
        proto,
    );

    let mut matching_policies = egress_matches;
    matching_policies.extend(ingress_matches);

    Ok(SimulationResult {
        allowed: egress_allowed && ingress_allowed,
        ingress_allowed,
        egress_allowed,
        ingress_reason,
        egress_reason,
        matching_policies,
    })
}

/// Evaluate egress policies on the source pod.
fn evaluate_egress(
    policies: &[NetworkPolicy],
    src_labels: &BTreeMap<String, String>,
    dst_ns_labels: &BTreeMap<String, String>,
    dst_labels: &BTreeMap<String, String>,
    dst_ip: &str,
    port: Option<i32>,
    protocol: Option<&str>,
) -> (bool, String, Vec<MatchedPolicy>) {
    // Find policies that select the source pod.
    let selecting: Vec<_> = policies
        .iter()
        .filter(|p| {
            let spec = p.spec.clone().unwrap_or_default();
            pod_matches_selector(&spec.pod_selector, src_labels)
        })
        .collect();

    // No policies select this pod => egress is unrestricted.
    if selecting.is_empty() {
        return (
            true,
            "No egress policy selects source pod — egress allowed by default".into(),
            vec![],
        );
    }

    // At least one policy must list "Egress" in policyTypes to restrict egress.
    let has_egress_policy = selecting.iter().any(|p| {
        let spec = p.spec.clone().unwrap_or_default();
        spec.policy_types
            .as_ref()
            .map(|types| types.iter().any(|t| t == "Egress"))
            .unwrap_or(false)
    });

    if !has_egress_policy {
        return (
            true,
            "No policy restricts egress from source pod".into(),
            vec![],
        );
    }

    // Check if any egress rule allows the traffic.
    let mut matches = Vec::new();
    for policy in &selecting {
        let spec = policy.spec.clone().unwrap_or_default();
        if let Some(rules) = &spec.egress {
            for rule in rules {
                // Port check.
                if let Some(target_port) = port {
                    if let Some(ports) = &rule.ports {
                        if !ports
                            .iter()
                            .any(|p| port_matches(p, target_port, protocol.unwrap_or("TCP")))
                        {
                            continue;
                        }
                    }
                }

                // Peer check.
                if let Some(peers) = &rule.to {
                    if peers.is_empty() {
                        // Empty `to` list = all destinations allowed.
                        matches.push(policy_match(policy, "egress"));
                        continue;
                    }
                    for peer in peers {
                        if peer_matches(peer, dst_ns_labels, dst_labels, dst_ip) {
                            matches.push(policy_match(policy, "egress"));
                        }
                    }
                }
            }
        }
    }

    if matches.is_empty() {
        (
            false,
            "All egress from source pod is denied by NetworkPolicy".into(),
            vec![],
        )
    } else {
        (true, "Egress allowed by policy".into(), matches)
    }
}

/// Evaluate ingress policies on the destination pod.
fn evaluate_ingress(
    policies: &[NetworkPolicy],
    dst_labels: &BTreeMap<String, String>,
    src_ns_labels: &BTreeMap<String, String>,
    src_labels: &BTreeMap<String, String>,
    src_ip: &str,
    port: Option<i32>,
    protocol: Option<&str>,
) -> (bool, String, Vec<MatchedPolicy>) {
    let selecting: Vec<_> = policies
        .iter()
        .filter(|p| {
            let spec = p.spec.clone().unwrap_or_default();
            pod_matches_selector(&spec.pod_selector, dst_labels)
        })
        .collect();

    if selecting.is_empty() {
        return (
            true,
            "No ingress policy selects destination pod — ingress allowed by default".into(),
            vec![],
        );
    }

    let has_ingress_policy = selecting.iter().any(|p| {
        let spec = p.spec.clone().unwrap_or_default();
        spec.policy_types
            .as_ref()
            .map(|types| types.iter().any(|t| t == "Ingress"))
            .unwrap_or(false)
    });

    if !has_ingress_policy {
        return (
            true,
            "No policy restricts ingress to destination pod".into(),
            vec![],
        );
    }

    let mut matches = Vec::new();
    for policy in &selecting {
        let spec = policy.spec.clone().unwrap_or_default();
        if let Some(rules) = &spec.ingress {
            for rule in rules {
                if let Some(target_port) = port {
                    if let Some(ports) = &rule.ports {
                        if !ports
                            .iter()
                            .any(|p| port_matches(p, target_port, protocol.unwrap_or("TCP")))
                        {
                            continue;
                        }
                    }
                }

                if let Some(peers) = &rule.from {
                    if peers.is_empty() {
                        matches.push(policy_match(policy, "ingress"));
                        continue;
                    }
                    for peer in peers {
                        if peer_matches(peer, src_ns_labels, src_labels, src_ip) {
                            matches.push(policy_match(policy, "ingress"));
                        }
                    }
                }
            }
        }
    }

    if matches.is_empty() {
        (
            false,
            "All ingress to destination pod is denied by NetworkPolicy".into(),
            vec![],
        )
    } else {
        (true, "Ingress allowed by policy".into(), matches)
    }
}

/// Build a [`MatchedPolicy`] from a policy reference.
fn policy_match(p: &NetworkPolicy, direction: &str) -> MatchedPolicy {
    MatchedPolicy {
        name: p.metadata.name.clone().unwrap_or_default(),
        namespace: p.metadata.namespace.clone().unwrap_or_default(),
        direction: direction.into(),
        effect: "allows".into(),
    }
}

/// Check if a network policy port entry matches the target port and protocol.
fn port_matches(
    port_entry: &k7s_deps::k8s_openapi::api::networking::v1::NetworkPolicyPort,
    target_port: i32,
    protocol: &str,
) -> bool {
    let proto_ok = port_entry
        .protocol
        .as_deref()
        .unwrap_or("TCP")
        .eq_ignore_ascii_case(protocol);
    if !proto_ok {
        return false;
    }
    match &port_entry.port {
        Some(k7s_deps::k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(n)) => {
            *n == target_port
        }
        // Named ports cannot be resolved without the pod spec; treat as no match.
        Some(k7s_deps::k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::String(_)) => {
            false
        }
        // No port specified = all ports.
        None => true,
    }
}

/// Check if a pod's labels match a label selector.
///
/// An empty or absent selector selects all pods.
fn pod_matches_selector(
    selector: &Option<k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector_matches(selector.as_ref(), labels)
}

/// Full LabelSelector semantics: matchLabels (all equal) plus
/// matchExpressions (In/NotIn/Exists/DoesNotExist).
///
/// The simulator previously honoured matchLabels only — a selector built
/// solely from matchExpressions matched EVERYTHING, so policies like
/// `matchExpressions: [{key: env, operator: In, values: [prod]}]` were
/// reported as "allows" when they should deny. An empty selector still
/// selects all; an unknown operator fails open to a plain match to avoid
/// over-denying on future spec extensions.
fn selector_matches(
    selector: Option<&k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector>,
    labels: &BTreeMap<String, String>,
) -> bool {
    let Some(sel) = selector else { return true };
    if let Some(ml) = &sel.match_labels {
        if !ml.iter().all(|(k, v)| labels.get(k.as_str()) == Some(v)) {
            return false;
        }
    }
    if let Some(exprs) = &sel.match_expressions {
        for ex in exprs {
            let values: Vec<&str> = ex
                .values
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|s| s.as_str())
                .collect();
            let ok = match ex.operator.as_str() {
                "In" => labels
                    .get(ex.key.as_str())
                    .map(|v| values.contains(&v.as_str()))
                    .unwrap_or(false),
                "NotIn" => labels
                    .get(ex.key.as_str())
                    .map(|v| !values.contains(&v.as_str()))
                    .unwrap_or(true),
                "Exists" => labels.contains_key(ex.key.as_str()),
                "DoesNotExist" => !labels.contains_key(ex.key.as_str()),
                _ => true,
            };
            if !ok {
                return false;
            }
        }
    }
    true
}

/// Check if a [`NetworkPolicyPeer`] matches a target pod/namespace/IP.
///
/// `ns_labels` are the target namespace's real labels (the API server sets
/// `kubernetes.io/metadata.name` on every namespace, so that historical
/// special case is covered by the general selector match).
fn peer_matches(
    peer: &NetworkPolicyPeer,
    target_ns_labels: &BTreeMap<String, String>,
    target_labels: &BTreeMap<String, String>,
    target_ip: &str,
) -> bool {
    // ipBlock is exclusive with the selectors.
    if let Some(ipb) = &peer.ip_block {
        if let Some(excepts) = &ipb.except {
            for except in excepts {
                if ip_in_cidr(target_ip, except) {
                    return false;
                }
            }
        }
        return ip_in_cidr(target_ip, &ipb.cidr);
    }

    let mut matched_something = false;

    // podSelector (implicit same-namespace when no namespaceSelector).
    if let Some(ps) = &peer.pod_selector {
        if !selector_matches(Some(ps), target_labels) {
            return false;
        }
        if peer.namespace_selector.is_none() {
            // podSelector alone = same namespace, which we already know matches.
            return true;
        }
        matched_something = true;
    }

    // namespaceSelector — full selector against the namespace's labels.
    if let Some(ns) = &peer.namespace_selector {
        if !selector_matches(Some(ns), target_ns_labels) {
            return false;
        }
        matched_something = true;
    }

    matched_something
}

/// Simple CIDR matching (IPv4 only).
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix_len: u32 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let ip_u32 = match parse_ipv4(ip) {
        Some(n) => n,
        None => return false,
    };
    let cidr_u32 = match parse_ipv4(parts[0]) {
        Some(n) => n,
        None => return false,
    };
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    (ip_u32 & mask) == (cidr_u32 & mask)
}

/// Parse a dotted-quad IPv4 address into a u32.
fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut result = 0u32;
    for part in parts {
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        result = (result << 8) | octet;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("192.168.1.1"), Some(0xC0A80101));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(0xFFFFFFFF));
        assert_eq!(parse_ipv4("10.0.0.1"), Some(0x0A000001));
        assert_eq!(parse_ipv4("not-an-ip"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4("256.0.0.1"), None);
    }

    #[test]
    fn test_ip_in_cidr() {
        // /32 exact match
        assert!(ip_in_cidr("192.168.1.1", "192.168.1.1/32"));
        assert!(!ip_in_cidr("192.168.1.2", "192.168.1.1/32"));

        // /24 subnet
        assert!(ip_in_cidr("192.168.1.100", "192.168.1.0/24"));
        assert!(ip_in_cidr("192.168.1.1", "192.168.1.0/24"));
        assert!(!ip_in_cidr("192.168.2.1", "192.168.1.0/24"));

        // /16 subnet
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.0/8"));
        assert!(ip_in_cidr("10.255.255.255", "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.0.0.1", "10.0.0.0/8"));

        // /0 matches everything
        assert!(ip_in_cidr("1.2.3.4", "0.0.0.0/0"));

        // Invalid inputs
        assert!(!ip_in_cidr("bad", "192.168.1.0/24"));
        assert!(!ip_in_cidr("192.168.1.1", "bad"));
        assert!(!ip_in_cidr("192.168.1.1", "192.168.1.0"));
        assert!(!ip_in_cidr("192.168.1.1", "192.168.1.0/33"));
    }

    #[test]
    fn test_pod_matches_selector_none() {
        let labels = BTreeMap::from([("app".into(), "web".into())]);
        assert!(pod_matches_selector(&None, &labels));
    }

    #[test]
    fn test_pod_matches_selector_empty() {
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let labels = BTreeMap::from([("app".into(), "web".into())]);
        let sel = LabelSelector {
            match_labels: Some(BTreeMap::new()),
            match_expressions: None,
        };
        assert!(pod_matches_selector(&Some(sel), &labels));
    }

    #[test]
    fn test_pod_matches_selector_matching() {
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let labels = BTreeMap::from([
            ("app".into(), "web".into()),
            ("tier".into(), "frontend".into()),
        ]);
        let sel = LabelSelector {
            match_labels: Some(BTreeMap::from([("app".into(), "web".into())])),
            match_expressions: None,
        };
        assert!(pod_matches_selector(&Some(sel), &labels));
    }

    #[test]
    fn test_pod_matches_selector_not_matching() {
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let labels = BTreeMap::from([("app".into(), "db".into())]);
        let sel = LabelSelector {
            match_labels: Some(BTreeMap::from([("app".into(), "web".into())])),
            match_expressions: None,
        };
        assert!(!pod_matches_selector(&Some(sel), &labels));
    }

    // -----------------------------------------------------------------------
    // matchExpressions-only selectors (no matchLabels at all)
    // -----------------------------------------------------------------------

    /// matchLabels and matchExpressions AND together: the selector below has
    /// a matching matchLabels part and a non-matching expression.
    #[test]
    fn match_labels_and_expressions_both_must_hold() {
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let labels = BTreeMap::from([
            ("app".into(), "web".into()),
            ("tier".into(), "frontend".into()),
        ]);
        let sel = LabelSelector {
            match_labels: Some(BTreeMap::from([("app".into(), "web".into())])),
            match_expressions: Some(vec![build_expr("tier", "In", vec!["backend"])]),
        };
        // matchLabels matches but the expression doesn't → no match.
        assert!(!pod_matches_selector(&Some(sel), &labels));
    }

    // -----------------------------------------------------------------------
    // namespaceSelector matchLabels (peer evaluation)
    // -----------------------------------------------------------------------

    /// A namespaceSelector must be evaluated against the target namespace's
    /// real labels, not only the well-known name label.
    #[test]
    fn peer_matches_namespace_selector_by_labels() {
        use k7s_deps::k8s_openapi::api::networking::v1::NetworkPolicyPeer;
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

        let peer = NetworkPolicyPeer {
            pod_selector: None,
            namespace_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([
                    ("env".into(), "prod".into()),
                    ("kubernetes.io/metadata.name".into(), "payments".into()),
                ])),
                match_expressions: None,
            }),
            ip_block: None,
        };

        let matching_ns = BTreeMap::from([
            ("env".into(), "prod".into()),
            ("kubernetes.io/metadata.name".into(), "payments".into()),
        ]);
        assert!(peer_matches(
            &peer,
            &matching_ns,
            &BTreeMap::new(),
            "10.0.0.1"
        ));

        // Right name label, wrong custom label → no match.
        let wrong_env = BTreeMap::from([
            ("env".into(), "dev".into()),
            ("kubernetes.io/metadata.name".into(), "payments".into()),
        ]);
        assert!(!peer_matches(
            &peer,
            &wrong_env,
            &BTreeMap::new(),
            "10.0.0.1"
        ));

        // Right custom label, different namespace → no match.
        let wrong_name = BTreeMap::from([
            ("env".into(), "prod".into()),
            ("kubernetes.io/metadata.name".into(), "default".into()),
        ]);
        assert!(!peer_matches(
            &peer,
            &wrong_name,
            &BTreeMap::new(),
            "10.0.0.1"
        ));
    }

    #[test]
    fn test_peer_matches_pod_selector_same_ns() {
        use k7s_deps::k8s_openapi::api::networking::v1::NetworkPolicyPeer;
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

        let peer = NetworkPolicyPeer {
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([("app".into(), "frontend".into())])),
                match_expressions: None,
            }),
            namespace_selector: None,
            ip_block: None,
        };
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        assert!(peer_matches(&peer, &BTreeMap::new(), &labels, "10.0.0.1"));

        let wrong_labels = BTreeMap::from([("app".into(), "backend".into())]);
        assert!(!peer_matches(
            &peer,
            &BTreeMap::new(),
            &wrong_labels,
            "10.0.0.1"
        ));
    }

    /// Helper: build one LabelSelectorRequirement.
    fn build_expr(
        key: &str,
        op: &str,
        values: Vec<&str>,
    ) -> k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement {
        k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement {
            key: key.into(),
            operator: op.into(),
            values: Some(values.into_iter().map(|s| s.to_string()).collect()),
        }
    }

    fn ns_labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Regression: selectors built only from matchExpressions used to match
    /// EVERYTHING (matchExpressions was never read) — the simulator then
    /// reported "allowed" for traffic those policies deny.
    #[test]
    fn selector_match_expressions_are_honoured() {
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let sel = LabelSelector {
            match_labels: None,
            match_expressions: Some(vec![build_expr("env", "In", vec!["prod"])]),
        };
        let prod = ns_labels(&[("env", "prod")]);
        let staging = ns_labels(&[("env", "staging")]);
        assert!(selector_matches(Some(&sel), &prod));
        assert!(!selector_matches(Some(&sel), &staging));
    }

    #[test]
    fn selector_match_expressions_operators() {
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let labels = ns_labels(&[("tier", "backend")]);

        let notin = LabelSelector {
            match_labels: None,
            match_expressions: Some(vec![build_expr("tier", "NotIn", vec!["frontend"])]),
        };
        assert!(selector_matches(Some(&notin), &labels));
        let notin_hit = LabelSelector {
            match_labels: None,
            match_expressions: Some(vec![build_expr("tier", "NotIn", vec!["backend"])]),
        };
        assert!(!selector_matches(Some(&notin_hit), &labels));

        let exists = LabelSelector {
            match_labels: None,
            match_expressions: Some(vec![build_expr("tier", "Exists", vec![])]),
        };
        assert!(selector_matches(Some(&exists), &labels));
        let dne = LabelSelector {
            match_labels: None,
            match_expressions: Some(vec![build_expr("zone", "DoesNotExist", vec![])]),
        };
        assert!(selector_matches(Some(&dne), &labels));
    }

    #[test]
    fn peer_namespace_selector_uses_real_labels() {
        use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let peer = NetworkPolicyPeer {
            pod_selector: None,
            namespace_selector: Some(LabelSelector {
                match_labels: None,
                match_expressions: Some(vec![build_expr("env", "In", vec!["prod"])]),
            }),
            ip_block: None,
        };
        let prod_ns = ns_labels(&[("kubernetes.io/metadata.name", "ns-a"), ("env", "prod")]);
        let staging_ns = ns_labels(&[("kubernetes.io/metadata.name", "ns-b"), ("env", "staging")]);
        assert!(peer_matches(&peer, &prod_ns, &BTreeMap::new(), "10.0.0.1"));
        assert!(!peer_matches(
            &peer,
            &staging_ns,
            &BTreeMap::new(),
            "10.0.0.1"
        ));
    }

    #[test]
    fn test_peer_matches_ip_block() {
        use k7s_deps::k8s_openapi::api::networking::v1::{IPBlock, NetworkPolicyPeer};

        let peer = NetworkPolicyPeer {
            pod_selector: None,
            namespace_selector: None,
            ip_block: Some(IPBlock {
                cidr: "10.0.0.0/8".into(),
                except: Some(vec!["10.0.1.0/24".into()]),
            }),
        };
        let labels = BTreeMap::new();

        assert!(peer_matches(&peer, &BTreeMap::new(), &labels, "10.0.0.1"));
        assert!(!peer_matches(&peer, &BTreeMap::new(), &labels, "10.0.1.5"));
        assert!(!peer_matches(
            &peer,
            &BTreeMap::new(),
            &labels,
            "192.168.1.1"
        ));
    }
}
