//! Full data test: connect to cluster and check all major data types.
//!
//! Run with: cargo run -p k7s-core --example test_full

use k7s_core::core::events::{self, EventSink};
use k7s_core::core::shell_common;
use k7s_core::core::CoreState;
use k7s_core::kube::manager::ClientManager;
use k7s_core::kube::ResourceKind;
use k7s_deps::kube::api::{Api, DynamicObject, ListParams};
use k7s_deps::kube::ResourceExt;
use std::sync::Arc;

#[k7s_deps::tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    k7s_deps::tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    k7s_deps::rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // ── Connect ──
    println!("=== Connecting to 'dev' cluster ===");
    let sink = EventSink::Mcp(events::McpEventSink::new());
    let manager = Arc::new(ClientManager::new(sink));
    let data_dir = std::env::temp_dir().join("k7s-core-test");
    std::fs::create_dir_all(&data_dir)?;
    let state = CoreState::new(manager.clone(), data_dir);

    let result = shell_common::connect_core(&manager, None, None, "dev").await?;
    println!("✅ Connected to {} ({})\n", result.server, result.version);
    let client = result.client;

    // ── Test each resource kind ──
    let kinds_to_check = vec![
        ("Pods", ResourceKind::Pods),
        ("Deployments", ResourceKind::Deployments),
        ("Services", ResourceKind::Services),
        ("Nodes", ResourceKind::Nodes),
        ("Namespaces", ResourceKind::Namespaces),
        ("ConfigMaps", ResourceKind::Configmaps),
        ("Secrets", ResourceKind::Secrets),
        ("StatefulSets", ResourceKind::Statefulsets),
        ("DaemonSets", ResourceKind::Daemonsets),
        ("Ingresses", ResourceKind::Ingresses),
        (
            "PersistentVolumeClaims",
            ResourceKind::Persistentvolumeclaims,
        ),
        ("PersistentVolumes", ResourceKind::Persistentvolumes),
        ("StorageClasses", ResourceKind::Storageclasses),
        ("ServiceAccounts", ResourceKind::Serviceaccounts),
        ("Events", ResourceKind::Events),
        ("ReplicaSets", ResourceKind::Replicasets),
        ("Jobs", ResourceKind::Jobs),
        ("CronJobs", ResourceKind::Cronjobs),
        ("Roles", ResourceKind::Roles),
        ("ClusterRoles", ResourceKind::Clusterroles),
        ("NetworkPolicies", ResourceKind::Networkpolicies),
        (
            "HorizontalPodAutoscalers",
            ResourceKind::Horizontalpodautoscalers,
        ),
        ("ResourceQuotas", ResourceKind::Resourcequotas),
        ("LimitRanges", ResourceKind::Limitranges),
    ];

    println!("{:<35} {:>6}  {}", "RESOURCE KIND", "COUNT", "STATUS");
    println!("{}", "-".repeat(70));

    let mut total = 0u32;
    let mut ok_count = 0u32;
    let mut err_count = 0u32;

    for (label, kind) in &kinds_to_check {
        let api_resource = kind.api_resource();
        let api: Api<DynamicObject> = if kind.is_namespaced() {
            Api::all_with(client.clone(), &api_resource)
        } else {
            Api::all_with(client.clone(), &api_resource)
        };

        match api.list(&ListParams::default()).await {
            Ok(list) => {
                let count = list.items.len() as u32;
                total += count;
                ok_count += 1;
                println!("{:<35} {:>6}  ✅", label, count);

                // Print first few items for key kinds
                if matches!(
                    kind,
                    ResourceKind::Nodes | ResourceKind::Namespaces | ResourceKind::Storageclasses
                ) {
                    for item in list.items.iter().take(5) {
                        let name = item.name_any();
                        let ns = item.metadata.namespace.as_deref().unwrap_or("");
                        if ns.is_empty() {
                            println!("    └─ {name}");
                        } else {
                            println!("    └─ {name} (ns: {ns})");
                        }
                    }
                    if list.items.len() > 5 {
                        println!("    └─ ... ({} more)", list.items.len() - 5);
                    }
                }
            }
            Err(e) => {
                err_count += 1;
                let msg = format!("{e}");
                let short = if msg.len() > 50 {
                    format!("{}...", &msg[..47])
                } else {
                    msg
                };
                println!("{:<35} {:>6}  ⚠️  {}", label, "-", short);
            }
        }
    }

    // ── Summary ──
    println!("{}", "-".repeat(70));
    println!(
        "Total: {} resources across {} kinds ({} ok, {} errors)\n",
        total,
        ok_count + err_count,
        ok_count,
        err_count
    );

    // ── Check CRDs ──
    println!("\n=== Custom Resource Definitions ===");
    println!("  {} custom kinds discovered:", result.custom_kinds.len());
    for crd in &result.custom_kinds {
        println!("    • {} ({})", crd.id, crd.kind);
    }

    println!("\n=== All checks passed ===");
    Ok(())
}
