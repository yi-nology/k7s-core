//! Kubeconfig parsing and client construction.
//!
//! `list_contexts` enumerates kubeconfig contexts for the cluster switcher, and
//! `build_client` / `probe_cluster` construct a client for a chosen context and
//! read its server version. No watchers are started here — that is the manager's
//! job (see manager.rs) after a successful connect.

use crate::error::{AppError, AppResult};
use k7s_deps::kube::config::{Config, KubeConfigOptions, Kubeconfig};
use k7s_deps::kube::Client;
use serde::Serialize;

/// A kubeconfig context entry for the cluster switcher.
#[derive(Serialize, Clone, Debug)]
pub struct ContextInfo {
    pub name: String,
    /// Cluster this context points at (shown as the right-hand env tag).
    pub cluster: String,
    /// True for the kubeconfig's current-context.
    pub current: bool,
}

/// Result of a successful connect.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInfo {
    pub context: String,
    pub cluster_name: String,
    /// API server URL.
    pub server: String,
    /// Server git version (e.g. "v1.31.2").
    pub version: String,
}

/// Read the kubeconfig and list its contexts, flagging the current one.
///
/// Returns an empty list (not an error) when no kubeconfig exists, so the UI can
/// show a clean "disconnected" state rather than crashing.
pub fn list_contexts() -> AppResult<Vec<ContextInfo>> {
    let kubeconfig = match Kubeconfig::read() {
        Ok(kc) => kc,
        // Missing/unreadable kubeconfig is a normal state, not a hard error.
        Err(e) => {
            k7s_deps::tracing::warn!("could not read kubeconfig: {e}");
            return Ok(Vec::new());
        }
    };

    let current = kubeconfig.current_context.clone().unwrap_or_default();
    let contexts = kubeconfig
        .contexts
        .iter()
        .map(|ctx| {
            // A NamedContext's inner Context carries the cluster name.
            let cluster = ctx
                .context
                .as_ref()
                .map(|c| c.cluster.clone())
                .unwrap_or_default();
            ContextInfo {
                name: ctx.name.clone(),
                cluster,
                current: ctx.name == current,
            }
        })
        .collect();

    Ok(contexts)
}

/// Read a kubeconfig file from disk (the import paths' shared entry).
pub fn read_kubeconfig(path: &str) -> AppResult<Kubeconfig> {
    Ok(Kubeconfig::read_from(path)?)
}

/// Map a parsed kubeconfig into switcher entries. Entries report
/// `current: false` — the notion of a "current" context belongs to the
/// default kubeconfig, not to an imported file.
pub fn contexts_from_kubeconfig(kubeconfig: &Kubeconfig) -> Vec<ContextInfo> {
    kubeconfig
        .contexts
        .iter()
        .map(|ctx| {
            let cluster = ctx
                .context
                .as_ref()
                .map(|c| c.cluster.clone())
                .unwrap_or_default();
            ContextInfo {
                name: ctx.name.clone(),
                cluster,
                current: false,
            }
        })
        .collect()
}

/// Read a kubeconfig file at an arbitrary path and list its contexts.
///
/// Used by the "Import kubeconfig" action.
pub fn contexts_from_file(path: &str) -> AppResult<Vec<ContextInfo>> {
    let kubeconfig = read_kubeconfig(path)?;
    Ok(contexts_from_kubeconfig(&kubeconfig))
}

/// Build a client for a context defined in a specific kubeconfig file (an imported
/// file that is not the default kubeconfig).
pub async fn build_client_from_file(path: &str, context: &str) -> AppResult<(Client, String)> {
    let kubeconfig = Kubeconfig::read_from(path)?;
    let options = KubeConfigOptions {
        context: Some(context.to_string()),
        cluster: None,
        user: None,
    };
    let config = Config::from_custom_kubeconfig(kubeconfig, &options)
        .await
        .map_err(|e| AppError::Kubeconfig(e.to_string()))?;
    let server = config.cluster_url.to_string();
    let client = Client::try_from(config)?;
    Ok((client, server))
}

/// Build a client from an already-parsed `Kubeconfig` (used when the caller
/// has bytes in memory rather than a file on disk — e.g. web shell uploads or
/// the `kubeconfig_bytes` code path in `connect_core`).
pub async fn build_client_from_kubeconfig(
    kubeconfig: Kubeconfig,
    context: &str,
) -> AppResult<(Client, String)> {
    let options = KubeConfigOptions {
        context: Some(context.to_string()),
        cluster: None,
        user: None,
    };
    let config = Config::from_custom_kubeconfig(kubeconfig, &options)
        .await
        .map_err(|e| AppError::Kubeconfig(e.to_string()))?;
    let server = config.cluster_url.to_string();
    let client = Client::try_from(config)?;
    Ok((client, server))
}

/// Best-effort path to kubectl's default kubeconfig: the first entry of
/// $KUBECONFIG, else ~/.kube/config. Used to pre-point the import file dialog.
///
/// Both halves are platform-sensitive, and getting either wrong lands the dialog
/// in the wrong directory rather than failing loudly. `KUBECONFIG` is a path
/// *list* using the platform's separator — `;` on Windows, where `:` would also
/// split the drive letter off `C:\Users\…`. And Windows has no `HOME`; kubectl
/// itself reads `USERPROFILE` there.
pub fn default_kubeconfig_path() -> String {
    if let Ok(kubeconfig) = std::env::var("KUBECONFIG") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        if let Some(first) = kubeconfig.split(sep).find(|s| !s.is_empty()) {
            return first.to_string();
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    if home.is_empty() {
        return String::new();
    }
    // Join through PathBuf so the result uses the platform's own separator.
    std::path::Path::new(&home)
        .join(".kube")
        .join("config")
        .to_string_lossy()
        .into_owned()
}

/// Build a Kubernetes client for a specific kubeconfig context.
pub async fn build_client(context: &str) -> AppResult<(Client, String)> {
    // Select the requested context explicitly (don't rely on current-context).
    let options = KubeConfigOptions {
        context: Some(context.to_string()),
        cluster: None,
        user: None,
    };
    let config = Config::from_kubeconfig(&options)
        .await
        .map_err(|e| AppError::Kubeconfig(e.to_string()))?;

    let server = config.cluster_url.to_string();
    let client = Client::try_from(config)?;
    Ok((client, server))
}

/// Probe the API server for its version. Also serves as a reachability check.
pub async fn probe_version(client: &Client) -> AppResult<String> {
    let info = client.apiserver_version().await?;
    Ok(info.git_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write `body` to a uniquely-named temp file and return its path.
    fn temp_file(tag: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "k7s-test-{tag}-{}-{:?}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    const KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: alpha
clusters:
  - name: alpha-cluster
    cluster: { server: https://alpha.example:6443 }
  - name: beta-cluster
    cluster: { server: https://beta.example:6443 }
contexts:
  - name: alpha
    context: { cluster: alpha-cluster, user: alpha-user }
  - name: beta
    context: { cluster: beta-cluster, user: beta-user }
users:
  - name: alpha-user
    user: {}
  - name: beta-user
    user: {}
"#;

    /// An imported file contributes each of its contexts, tagged with its cluster.
    #[test]
    fn reads_contexts_from_a_kubeconfig_file() {
        let path = temp_file("ok", KUBECONFIG);
        let contexts = contexts_from_file(path.to_str().unwrap()).unwrap();
        let names: Vec<&str> = contexts.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["alpha", "beta"]);
        assert_eq!(contexts[0].cluster, "alpha-cluster");
        // current-context belongs to the *default* kubeconfig; an imported file
        // never claims to be current (the merge in commands.rs relies on this).
        assert!(contexts.iter().all(|c| !c.current));
        std::fs::remove_file(path).ok();
    }

    /// A file that has been deleted since it was imported errors rather than
    /// panicking — restore_imports (B17) turns this into a silent drop on boot.
    #[test]
    fn missing_file_is_an_error() {
        let path = std::env::temp_dir().join("k7s-test-definitely-absent.yaml");
        assert!(contexts_from_file(path.to_str().unwrap()).is_err());
    }

    /// So does a file that is no longer a kubeconfig.
    #[test]
    fn unparseable_file_is_an_error() {
        let path = temp_file("junk", "this is not a kubeconfig at all\n\t- [");
        assert!(contexts_from_file(path.to_str().unwrap()).is_err());
        std::fs::remove_file(path).ok();
    }
}
