//! Resource dependency graph: maps relationships between Kubernetes resources.

use crate::error::AppResult;
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::Client;
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub from: GraphNode,
    pub to: GraphNode,
    pub relation: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// Deduplication key for nodes.
type NodeKey = (String, String, Option<String>);

fn make_key(kind: &str, name: &str, ns: &Option<String>) -> NodeKey {
    (kind.to_string(), name.to_string(), ns.clone())
}

pub async fn build_dependency_graph(client: Client) -> AppResult<DependencyGraph> {
    use std::collections::HashSet;

    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut seen: HashSet<NodeKey> = HashSet::new();

    // --- Deployments ---
    let dep_api: Api<k7s_deps::k8s_openapi::api::apps::v1::Deployment> = Api::all(client.clone());
    let deps = dep_api.list(&ListParams::default()).await?;
    for dep in &deps.items {
        let name = dep.metadata.name.clone().unwrap_or_default();
        let ns = dep.metadata.namespace.clone();
        let key = make_key("Deployment", &name, &ns);
        if seen.insert(key) {
            nodes.push(GraphNode {
                kind: "Deployment".into(),
                name,
                namespace: ns,
            });
        }
    }

    // --- ReplicaSets (link to Deployment via ownerRef) ---
    let rs_api: Api<k7s_deps::k8s_openapi::api::apps::v1::ReplicaSet> = Api::all(client.clone());
    let rss = rs_api.list(&ListParams::default()).await?;
    for rs in &rss.items {
        let name = rs.metadata.name.clone().unwrap_or_default();
        let ns = rs.metadata.namespace.clone();
        let key = make_key("ReplicaSet", &name, &ns);
        if seen.insert(key) {
            nodes.push(GraphNode {
                kind: "ReplicaSet".into(),
                name: name.clone(),
                namespace: ns.clone(),
            });
        }
        for owner in rs.metadata.owner_references.iter().flatten() {
            if owner.kind == "Deployment" {
                edges.push(GraphEdge {
                    from: GraphNode {
                        kind: "Deployment".into(),
                        name: owner.name.clone(),
                        namespace: ns.clone(),
                    },
                    to: GraphNode {
                        kind: "ReplicaSet".into(),
                        name: name.clone(),
                        namespace: ns.clone(),
                    },
                    relation: "owns".into(),
                });
            }
        }
    }

    // --- StatefulSets ---
    let ss_api: Api<k7s_deps::k8s_openapi::api::apps::v1::StatefulSet> = Api::all(client.clone());
    let sss = ss_api.list(&ListParams::default()).await?;
    for ss in &sss.items {
        let name = ss.metadata.name.clone().unwrap_or_default();
        let ns = ss.metadata.namespace.clone();
        let key = make_key("StatefulSet", &name, &ns);
        if seen.insert(key) {
            nodes.push(GraphNode {
                kind: "StatefulSet".into(),
                name,
                namespace: ns,
            });
        }
    }

    // --- DaemonSets ---
    let ds_api: Api<k7s_deps::k8s_openapi::api::apps::v1::DaemonSet> = Api::all(client.clone());
    let dss = ds_api.list(&ListParams::default()).await?;
    for ds in &dss.items {
        let name = ds.metadata.name.clone().unwrap_or_default();
        let ns = ds.metadata.namespace.clone();
        let key = make_key("DaemonSet", &name, &ns);
        if seen.insert(key) {
            nodes.push(GraphNode {
                kind: "DaemonSet".into(),
                name,
                namespace: ns,
            });
        }
    }

    // --- Pods (link to owner via ownerRef) ---
    let pod_api: Api<k7s_deps::k8s_openapi::api::core::v1::Pod> = Api::all(client.clone());
    let pods = pod_api.list(&ListParams::default()).await?;
    for pod in &pods.items {
        let name = pod.metadata.name.clone().unwrap_or_default();
        let ns = pod.metadata.namespace.clone();
        let key = make_key("Pod", &name, &ns);
        if seen.insert(key) {
            nodes.push(GraphNode {
                kind: "Pod".into(),
                name: name.clone(),
                namespace: ns.clone(),
            });
        }
        for owner in pod.metadata.owner_references.iter().flatten() {
            edges.push(GraphEdge {
                from: GraphNode {
                    kind: owner.kind.clone(),
                    name: owner.name.clone(),
                    namespace: ns.clone(),
                },
                to: GraphNode {
                    kind: "Pod".into(),
                    name: name.clone(),
                    namespace: ns.clone(),
                },
                relation: "owns".into(),
            });
        }
    }

    // --- Services (link to Pods via selector matching) ---
    let svc_api: Api<k7s_deps::k8s_openapi::api::core::v1::Service> = Api::all(client.clone());
    let svcs = svc_api.list(&ListParams::default()).await?;
    for svc in &svcs.items {
        let svc_name = svc.metadata.name.clone().unwrap_or_default();
        let ns = svc.metadata.namespace.clone();
        let key = make_key("Service", &svc_name, &ns);
        if seen.insert(key) {
            nodes.push(GraphNode {
                kind: "Service".into(),
                name: svc_name.clone(),
                namespace: ns.clone(),
            });
        }

        if let Some(selector) = svc.spec.as_ref().and_then(|s| s.selector.as_ref()) {
            if !selector.is_empty() {
                for pod in &pods.items {
                    let pod_ns = pod.metadata.namespace.clone().unwrap_or_default();
                    if pod_ns != ns.clone().unwrap_or_default() {
                        continue;
                    }
                    if let Some(labels) = &pod.metadata.labels {
                        if selector
                            .iter()
                            .all(|(k, v)| labels.get(k.as_str()) == Some(v))
                        {
                            let pod_name = pod.metadata.name.clone().unwrap_or_default();
                            edges.push(GraphEdge {
                                from: GraphNode {
                                    kind: "Service".into(),
                                    name: svc_name.clone(),
                                    namespace: ns.clone(),
                                },
                                to: GraphNode {
                                    kind: "Pod".into(),
                                    name: pod_name,
                                    namespace: ns.clone(),
                                },
                                relation: "selects".into(),
                            });
                        }
                    }
                }
            }
        }
    }

    // --- Ingresses (link to Services via backend rules) ---
    let ing_api: Api<k7s_deps::k8s_openapi::api::networking::v1::Ingress> =
        Api::all(client.clone());
    let ings = ing_api.list(&ListParams::default()).await?;
    for ing in &ings.items {
        let ing_name = ing.metadata.name.clone().unwrap_or_default();
        let ns = ing.metadata.namespace.clone();
        let key = make_key("Ingress", &ing_name, &ns);
        if seen.insert(key) {
            nodes.push(GraphNode {
                kind: "Ingress".into(),
                name: ing_name.clone(),
                namespace: ns.clone(),
            });
        }

        if let Some(rules) = ing.spec.as_ref().and_then(|s| s.rules.as_ref()) {
            for rule in rules {
                if let Some(http) = &rule.http {
                    for path in &http.paths {
                        if let Some(svc) = &path.backend.service {
                            let svc_name = &svc.name;
                            if !svc_name.is_empty() {
                                edges.push(GraphEdge {
                                    from: GraphNode {
                                        kind: "Ingress".into(),
                                        name: ing_name.clone(),
                                        namespace: ns.clone(),
                                    },
                                    to: GraphNode {
                                        kind: "Service".into(),
                                        name: svc_name.clone(),
                                        namespace: ns.clone(),
                                    },
                                    relation: "routes".into(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(DependencyGraph { nodes, edges })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_node_dedup_key() {
        let a = make_key("Pod", "nginx", &Some("default".into()));
        let b = make_key("Pod", "nginx", &Some("default".into()));
        assert_eq!(a, b);
    }

    #[test]
    fn graph_node_dedup_different_ns() {
        let a = make_key("Pod", "nginx", &Some("default".into()));
        let b = make_key("Pod", "nginx", &Some("kube-system".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn graph_node_dedup_different_kind() {
        let a = make_key("Pod", "nginx", &Some("default".into()));
        let b = make_key("Service", "nginx", &Some("default".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn graph_node_dedup_cluster_scoped() {
        let a = make_key("Node", "node1", &None);
        let b = make_key("Node", "node1", &None);
        assert_eq!(a, b);
    }

    #[test]
    fn graph_node_dedup_mixed_scope() {
        let a = make_key("Node", "node1", &None);
        let b = make_key("Node", "node1", &Some("default".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn graph_edge_serializes_camel_case() {
        let edge = GraphEdge {
            from: GraphNode {
                kind: "Deployment".into(),
                name: "nginx".into(),
                namespace: Some("default".into()),
            },
            to: GraphNode {
                kind: "ReplicaSet".into(),
                name: "nginx-abc123".into(),
                namespace: Some("default".into()),
            },
            relation: "owns".into(),
        };
        let json = k7s_deps::serde_json::to_value(&edge).unwrap();
        assert_eq!(json["from"]["kind"], "Deployment");
        assert_eq!(json["to"]["kind"], "ReplicaSet");
        assert_eq!(json["relation"], "owns");
        // Verify camelCase serialization
        assert!(json.get("from").unwrap().is_object());
    }

    #[test]
    fn graph_node_serializes_optional_namespace() {
        let node_with_ns = GraphNode {
            kind: "Pod".into(),
            name: "nginx".into(),
            namespace: Some("default".into()),
        };
        let json = k7s_deps::serde_json::to_value(&node_with_ns).unwrap();
        assert_eq!(json["namespace"], "default");

        let node_no_ns = GraphNode {
            kind: "Node".into(),
            name: "node1".into(),
            namespace: None,
        };
        let json = k7s_deps::serde_json::to_value(&node_no_ns).unwrap();
        assert!(json["namespace"].is_null());
    }

    #[test]
    fn dependency_graph_serializes() {
        let graph = DependencyGraph {
            nodes: vec![
                GraphNode {
                    kind: "Deployment".into(),
                    name: "nginx".into(),
                    namespace: Some("default".into()),
                },
                GraphNode {
                    kind: "Pod".into(),
                    name: "nginx-abc".into(),
                    namespace: Some("default".into()),
                },
            ],
            edges: vec![GraphEdge {
                from: GraphNode {
                    kind: "Deployment".into(),
                    name: "nginx".into(),
                    namespace: Some("default".into()),
                },
                to: GraphNode {
                    kind: "Pod".into(),
                    name: "nginx-abc".into(),
                    namespace: Some("default".into()),
                },
                relation: "owns".into(),
            }],
        };
        let json = k7s_deps::serde_json::to_value(&graph).unwrap();
        assert!(json["nodes"].is_array());
        assert!(json["edges"].is_array());
        assert_eq!(json["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(json["edges"].as_array().unwrap().len(), 1);
    }
}
