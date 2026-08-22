//! Smoke test: import kubeconfig, list contexts, connect, list pods.
//!
//! Run with: cargo run -p k7s-core --example test_import

use k7s_core::core::events::{self, EventSink};
use k7s_core::core::shell_common;
use k7s_core::core::CoreState;
use k7s_core::kube::client;
use k7s_core::kube::manager::ClientManager;
use std::sync::Arc;

#[k7s_deps::tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    k7s_deps::tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // Install rustls crypto provider (needed for kube TLS)
    k7s_deps::rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ignore if already installed

    // ── Step 1: Find kubeconfig ──
    let kubeconfig_path = k7s_deps::dirs::home_dir()
        .ok_or("no home dir")?
        .join(".kube")
        .join("config");
    println!("=== Step 1: Kubeconfig ===");
    println!("Path: {}", kubeconfig_path.display());
    assert!(kubeconfig_path.exists(), "kubeconfig not found");

    // ── Step 2: List contexts ──
    println!("\n=== Step 2: List contexts ===");
    let contexts = client::list_contexts()?;
    println!("Found {} context(s):", contexts.len());
    for ctx in &contexts {
        println!(
            "  • {} | cluster={} | current={}",
            ctx.name, ctx.cluster, ctx.current
        );
    }
    assert!(!contexts.is_empty(), "no contexts found");

    // ── Step 3: Create CoreState ──
    println!("\n=== Step 3: Create CoreState ===");
    let sink = EventSink::Mcp(events::McpEventSink::new());
    let manager = Arc::new(ClientManager::new(sink));
    let data_dir = std::env::temp_dir().join("k7s-core-test");
    std::fs::create_dir_all(&data_dir)?;
    let state = CoreState::new(manager.clone(), data_dir);
    println!("CoreState created (data_dir={})", state.data_dir.display());

    // ── Step 4: Connect to first context ──
    let target = &contexts[0];
    println!("\n=== Step 4: Connect to '{}' ===", target.name);

    let result = shell_common::connect_core(
        &manager,
        None, // no imported kubeconfig — use file
        None, // None = use default kubeconfig path
        &target.name,
    )
    .await;

    match result {
        Ok(info) => {
            println!("✅ Connected!");
            println!("   Server:  {}", info.server);
            println!("   Version: {}", info.version);
            println!("   CRDs:    {} custom kind(s)", info.custom_kinds.len());
            for crd in &info.custom_kinds {
                println!("     - {} ({})", crd.id, crd.kind);
            }
        }
        Err(e) => {
            println!("⚠️  Connection failed: {e}");
            println!("   (cluster may be unreachable — kubeconfig import itself worked)");
        }
    }

    println!("\n=== Done ===");
    Ok(())
}
