//! Helm chart repositories and chart marketplace (Phase 1 of KubePi parity).
//!
//! Storage strategy (chosen to mirror Helm's own model rather than KubePi's):
//!
//! - Repositories: a JSON file under the user's config dir (`helm-repos.json`).
//!   KubePi uses an embedded bbolt DB; we use a plain file because the data is
//!   small, opaque to the cluster, and naturally per-user, not per-cluster.
//!   Each cluster in k7s shares the same repo list — that's almost always what
//!   you want, and per-cluster overrides would be a config dialog nobody asked
//!   for.
//!
//! - Chart indexes: one `index.yaml` per repo, cached under the cache dir. Repos
//!   change rarely; we re-fetch on explicit `update_repo` or when the cached
//!   file is older than [`INDEX_TTL`]. The on-disk format is exactly the upstream
//!   `helm repo index` output, so the search/types layer is just deserialising
//!   what `helm` itself produces.
//!
//! - OCI registries (the modern equivalent of a `https://…/chart.tgz` repo) are
//!   recognised but treated identically: same ConfigMap-style entry, same fetch
//!   path. We don't try to speak the OCI distribution protocol ourselves — Helm
//!   does it when the user runs an install.
//!
//! The shape of an `index.yaml` is the same one Helm ships; we only deserialize
//! the parts we use. `entries[name]` is `Vec<ChartVersion>` (multiple versions
//! per chart name), each carrying its own `urls`, `appVersion`, `description`,
//! `keywords`, `maintainers`, and a base64 `values` (raw YAML schema, not
//! defaults — Helm splits the difference: defaults come from the chart itself).
//!
//! Network errors are surfaced verbatim; a stale index is not a silent failure,
//! because "I searched and got 0 hits" with a `last_refreshed` from last week
//! is the wrong answer in the wrong place.

use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Default well-known repos seeded on first run. The classic two — KubePi ships
/// these by default too.
pub const SEED_REPOS: &[(&str, &str, &str)] = &[
    (
        "bitnami",
        "https://charts.bitnami.com/bitnami",
        "Bitnami catalog (broad coverage, well-tested defaults)",
    ),
    (
        "stable",
        "https://charts.helm.sh/stable",
        "Helm stable chart repository (community-maintained, frozen)",
    ),
];

/// How long a cached `index.yaml` is considered fresh. After this we re-fetch
/// on the next search. Long enough that hammering the UI doesn't hammer the
/// repo; short enough that newly-published chart versions surface within a day.
const INDEX_TTL: Duration = Duration::from_secs(60 * 60);

/// On-disk shape of a single repo entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelmRepo {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: String,
    /// When we last successfully refreshed the index. `None` = never.
    #[serde(default)]
    pub last_refreshed: Option<String>,
    /// Status of the last `update_repo` call. Used by the UI to show a red dot
    /// on a broken repo without the user having to retry to find out.
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HelmRepoFile {
    repos: Vec<HelmRepo>,
}

// ---------------------------------------------------------------------------
// Chart index types — the on-disk shape of `index.yaml` from `helm repo index`.
// We only deserialize what we show; everything else is ignored.
// ---------------------------------------------------------------------------

/// A single chart version (Helm indexes list all versions of a chart under the
/// same `name`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChartVersion {
    pub name: String,
    pub version: String,
    pub app_version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub home: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub maintainers: Vec<Maintainer>,
    /// URLs to the chart tarballs. The first is what `helm pull` would use.
    pub urls: Vec<String>,
    /// RFC3339 timestamp of when this version was published.
    #[serde(default)]
    pub created: String,
    /// Annotations a chart may attach to itself (e.g. `category: database`).
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Maintainer {
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub url: String,
}

/// The whole `index.yaml` file. `entries` is keyed by chart name; each value is
/// the list of versions (newest first per Helm's own ordering).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HelmIndex {
    #[serde(default)]
    pub api_version: String,
    /// ISO-8601 timestamp Helm writes into the file.
    #[serde(default)]
    pub generated: String,
    /// Per-chart version lists.
    #[serde(default)]
    pub entries: BTreeMap<String, Vec<ChartVersion>>,
}

/// What the UI shows for a chart in the marketplace. One row per
/// (repo, chart-name), the latest version only.
#[derive(Clone, Debug, Serialize)]
pub struct ChartSummary {
    pub repo: String,
    pub name: String,
    pub version: String,
    pub app_version: String,
    pub description: String,
    pub keywords: Vec<String>,
    pub home: String,
    pub maintainers: Vec<Maintainer>,
}

/// A version under a specific chart — for the "Versions" tab on a chart detail.
#[derive(Clone, Debug, Serialize)]
pub struct ChartVersionEntry {
    pub version: String,
    pub app_version: String,
    pub created: String,
    pub urls: Vec<String>,
}

// ---------------------------------------------------------------------------
// Repo storage — `~/.config/k7s/helm-repos.json`
// ---------------------------------------------------------------------------

fn config_dir() -> Option<PathBuf> {
    // `dirs::config_dir()` would be the cross-platform answer, but we already
    // hand-roll platform paths in commands.rs; doing the same here keeps the
    // project free of an extra dependency for a single call. `home_dir`
    // adds the $USERPROFILE fallback for Windows shells without $HOME.
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        crate::kube::home_dir().map(|h| h.join("Library/Application Support/k7s"))
    } else if cfg!(any(target_os = "linux", target_os = "android")) {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(|p| PathBuf::from(p).join("k7s"))
            .or_else(|| crate::kube::home_dir().map(|h| h.join(".config/k7s")))
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("k7s"))
    } else {
        None
    }
}

pub(crate) fn cache_dir() -> Option<PathBuf> {
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        crate::kube::home_dir().map(|h| h.join("Library/Caches/k7s/helm-index"))
    } else if cfg!(any(target_os = "linux", target_os = "android")) {
        std::env::var_os("XDG_CACHE_HOME")
            .map(|p| PathBuf::from(p).join("k7s/helm-index"))
            .or_else(|| crate::kube::home_dir().map(|h| h.join(".cache/k7s/helm-index")))
    } else if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("k7s/cache/helm-index"))
    } else {
        None
    }
}

fn repos_path() -> AppResult<PathBuf> {
    let dir = config_dir().ok_or_else(|| {
        AppError::Other("cannot resolve config directory (no HOME / XDG_CONFIG_HOME)".into())
    })?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Other(format!("create config dir {}: {e}", dir.display())))?;
    Ok(dir.join("helm-repos.json"))
}

fn index_path(repo: &str) -> AppResult<PathBuf> {
    let dir =
        cache_dir().ok_or_else(|| AppError::Other("cannot resolve cache directory".into()))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Other(format!("create cache dir {}: {e}", dir.display())))?;
    // Repo names can have slashes in OCI URLs; sanitise so they all map to a
    // single flat directory without surprises.
    let safe = repo.replace(['/', '\\', ':'], "_");
    Ok(dir.join(format!("{safe}.yaml")))
}

fn read_repos_file() -> AppResult<Vec<HelmRepo>> {
    let path = repos_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Other(format!("read repos file {}: {e}", path.display())))?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let file: HelmRepoFile = k7s_deps::serde_json::from_str(&text)
        .map_err(|e| AppError::Other(format!("parse repos file: {e}")))?;
    Ok(file.repos)
}

fn write_repos_file(repos: &[HelmRepo]) -> AppResult<()> {
    let path = repos_path()?;
    let file = HelmRepoFile {
        repos: repos.to_vec(),
    };
    let text = k7s_deps::serde_json::to_string_pretty(&file)
        .map_err(|e| AppError::Other(format!("serialize repos: {e}")))?;
    // Atomic write: write to a sibling temp file, then rename. Avoids a half-
    // written file if the app dies mid-save.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)
        .map_err(|e| AppError::Other(format!("write repos tmp {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| AppError::Other(format!("rename {}: {e}", path.display())))?;
    Ok(())
}

/// Seed the default repos on first launch. Idempotent: existing user repos
/// win, and the seed only fills in names that aren't already present.
pub fn seed_default_repos() -> AppResult<()> {
    let mut repos = read_repos_file()?;
    if repos.is_empty() {
        for (name, url, description) in SEED_REPOS {
            repos.push(HelmRepo {
                name: (*name).to_string(),
                url: (*url).to_string(),
                description: (*description).to_string(),
                last_refreshed: None,
                last_error: None,
            });
        }
        write_repos_file(&repos)?;
        k7s_deps::tracing::info!("seeded {} default helm repos", SEED_REPOS.len());
    } else {
        // Add any seed names that disappeared (e.g. user deleted "stable").
        let existing: std::collections::HashSet<String> =
            repos.iter().map(|r| r.name.clone()).collect();
        let mut changed = false;
        for (name, url, description) in SEED_REPOS {
            if !existing.contains(*name) {
                repos.push(HelmRepo {
                    name: (*name).to_string(),
                    url: (*url).to_string(),
                    description: (*description).to_string(),
                    last_refreshed: None,
                    last_error: None,
                });
                changed = true;
            }
        }
        if changed {
            write_repos_file(&repos)?;
        }
    }
    Ok(())
}

/// List all known repos, with their last-refreshed state.
pub fn list_repos() -> AppResult<Vec<HelmRepo>> {
    let mut repos = read_repos_file()?;
    // Most-recently-touched first, then by name.
    repos.sort_by(|a, b| {
        b.last_refreshed
            .as_deref()
            .unwrap_or("")
            .cmp(a.last_refreshed.as_deref().unwrap_or(""))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(repos)
}

/// Add a new repo. Rejects duplicates by name (case-insensitive — Helm itself
/// treats repo names as case-sensitive, but UX-wise "bitnami" and "Bitnami"
/// being two repos is a bug we don't want to invite).
pub fn add_repo(name: &str, url: &str, description: &str) -> AppResult<HelmRepo> {
    let name = name.trim();
    let url = url.trim().trim_end_matches('/');
    if name.is_empty() {
        return Err(AppError::Other("repo name cannot be empty".into()));
    }
    if url.is_empty() {
        return Err(AppError::Other("repo url cannot be empty".into()));
    }
    // The name Helm writes into a release's Secret — and that the CLI uses to
    // resolve a chart — is just the repo's `name`. Helm itself forbids slashes
    // and spaces; we mirror that.
    if name.contains(['/', ' ', '\\']) {
        return Err(AppError::Other(
            "repo name must not contain '/', ' ', or '\\'".into(),
        ));
    }
    let mut repos = read_repos_file()?;
    if repos.iter().any(|r| r.name == name) {
        return Err(AppError::Other(format!("repo '{name}' already exists")));
    }
    let repo = HelmRepo {
        name: name.to_string(),
        url: url.to_string(),
        description: description.to_string(),
        last_refreshed: None,
        last_error: None,
    };
    repos.push(repo.clone());
    write_repos_file(&repos)?;
    Ok(repo)
}

/// Remove a repo and its cached index. Idempotent — removing a non-existent
/// repo is a no-op (so a UI click that races with a manual delete doesn't
/// surface as an error).
pub fn remove_repo(name: &str) -> AppResult<()> {
    let mut repos = read_repos_file()?;
    let before = repos.len();
    repos.retain(|r| r.name != name);
    if repos.len() != before {
        write_repos_file(&repos)?;
    }
    // Best-effort cache delete. A leftover cache file is harmless.
    if let Ok(p) = index_path(name) {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// Re-fetch the index for a single repo from its URL. Updates `last_refreshed`
/// on success or `last_error` on failure, and persists either way.
pub async fn update_repo_index(name: &str) -> AppResult<HelmRepo> {
    let mut repos = read_repos_file()?;
    let Some(idx) = repos.iter().position(|r| r.name == name) else {
        return Err(AppError::NotFound(format!("repo '{name}' not found")));
    };
    let url = repos[idx].url.clone();
    match fetch_index(&url).await {
        Ok(index) => {
            let path = index_path(name)?;
            let text = k7s_deps::yaml_serde::to_string(&index)
                .map_err(|e| AppError::Other(format!("serialize index: {e}")))?;
            // Same atomic-write dance as the repo file.
            let tmp = path.with_extension("yaml.tmp");
            std::fs::write(&tmp, text)
                .map_err(|e| AppError::Other(format!("write index tmp: {e}")))?;
            std::fs::rename(&tmp, &path)
                .map_err(|e| AppError::Other(format!("rename index: {e}")))?;
            repos[idx].last_refreshed = Some(chrono_now());
            repos[idx].last_error = None;
            let updated = repos[idx].clone();
            write_repos_file(&repos)?;
            Ok(updated)
        }
        Err(e) => {
            repos[idx].last_error = Some(e.to_string());
            let updated = repos[idx].clone();
            write_repos_file(&repos)?;
            Err(updated.error_or(e))
        }
    }
}

/// Re-fetch every repo's index, in parallel. Used by the "Refresh all" button
/// in the marketplace. Per-repo errors are reported in the returned list, not
/// short-circuited — a single broken repo shouldn't block refreshing the rest.
pub async fn update_all_indexes() -> AppResult<Vec<HelmRepo>> {
    let names: Vec<String> = read_repos_file()?.into_iter().map(|r| r.name).collect();
    let mut results = Vec::with_capacity(names.len());
    // Update in parallel — sequential would serialize HTTP latency.
    let futs: Vec<_> = names
        .into_iter()
        .map(|n| {
            let _ = n.clone();
            async move {
                let res = update_repo_index(&n).await;
                (n, res)
            }
        })
        .collect();
    for f in futs {
        let (name, res) = f.await;
        match res {
            Ok(r) => results.push(r),
            Err(e) => k7s_deps::tracing::warn!("update repo {name} failed: {e}"),
        }
    }
    Ok(results)
}

/// Search across every repo's cached index. Returns the latest version of each
/// matching chart, with the repo name inlined so the UI can group by it.
///
/// `query` is matched case-insensitively against chart name, keywords, and
/// description. Empty query returns everything (the "browse" view).
pub fn search_charts(query: &str) -> AppResult<Vec<ChartSummary>> {
    let repos = read_repos_file()?;
    let q = query.trim().to_lowercase();
    let mut out = Vec::new();
    for repo in &repos {
        let index = match load_index_if_fresh(&repo.name, &repo.url) {
            Some(idx) => idx,
            None => continue, // Stale/missing — silently skip; UI shows last_error.
        };
        for (name, versions) in &index.entries {
            if versions.is_empty() {
                continue;
            }
            let Some(latest) = versions.first() else {
                continue;
            };
            if !q.is_empty() {
                let hay = format!(
                    "{} {} {}",
                    latest.name.to_lowercase(),
                    latest.keywords.join(" ").to_lowercase(),
                    latest.description.to_lowercase()
                );
                if !hay.contains(&q) {
                    continue;
                }
            }
            out.push(ChartSummary {
                repo: repo.name.clone(),
                name: name.clone(),
                version: latest.version.clone(),
                app_version: latest.app_version.clone(),
                description: latest.description.clone(),
                keywords: latest.keywords.clone(),
                home: latest.home.clone(),
                maintainers: latest.maintainers.clone(),
            });
        }
    }
    // Newest-published first as a stable default; ties broken by name.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.sort_by(|a, b| b.version.cmp(&a.version));
    Ok(out)
}

/// All known versions of one (repo, chart) pair, newest first.
pub fn chart_versions(repo: &str, chart: &str) -> AppResult<Vec<ChartVersionEntry>> {
    let repos = read_repos_file()?;
    let Some(r) = repos.iter().find(|r| r.name == repo) else {
        return Err(AppError::NotFound(format!("repo '{repo}' not found")));
    };
    let index = load_index_if_fresh(&r.name, &r.url).ok_or_else(|| {
        AppError::Other(format!(
            "index for repo '{repo}' is stale or missing — refresh it first"
        ))
    })?;
    let Some(versions) = index.entries.get(chart) else {
        return Err(AppError::NotFound(format!(
            "chart '{chart}' not in repo '{repo}'"
        )));
    };
    Ok(versions
        .iter()
        .map(|v| ChartVersionEntry {
            version: v.version.clone(),
            app_version: v.app_version.clone(),
            created: v.created.clone(),
            urls: v.urls.clone(),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Index fetch / cache
// ---------------------------------------------------------------------------

/// Load a repo's index from cache if present and fresh. We deliberately do not
/// auto-fetch on a search — that lets a "0 results" outcome mean "the index is
/// stale", which the UI can flag via the repo's `last_refreshed`.
fn load_index_if_fresh(repo: &str, url: &str) -> Option<HelmIndex> {
    let path = index_path(repo).ok()?;
    if !path.exists() {
        return None;
    }
    // Stale-by-age is a soft skip; we only fall through to "not fresh" so the
    // caller can choose to refresh. We don't auto-refresh here.
    let age = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok());
    if let Some(a) = age {
        if a > INDEX_TTL {
            return None;
        }
    }
    let text = std::fs::read_to_string(&path).ok()?;
    // First try the standard parse; if the file was written by an older
    // `helm` release with a slightly different shape, we silently fail rather
    // than panic — the caller treats it as a stale index.
    let _ = url;
    k7s_deps::yaml_serde::from_str(&text).ok()
}

async fn fetch_index(url: &str) -> AppResult<HelmIndex> {
    // Compose the index URL. Helm's convention: append `/index.yaml` to a
    // bare repo URL. OCI registries don't have an index file; the only
    // operation that touches them is `helm install oci://...` itself, which
    // is in helm_ops.rs. If the URL is OCI, fail early with a clear error
    // rather than downloading a 404.
    if url.starts_with("oci://") {
        return Err(AppError::Other(
            "OCI registries have no index.yaml — search not supported, install via the OCI URL directly".into(),
        ));
    }
    let index_url = if url.ends_with("/index.yaml") || url.ends_with("index.yaml") {
        url.to_string()
    } else {
        format!("{}/index.yaml", url.trim_end_matches('/'))
    };

    // Use reqwest — already a dependency (used for node-exporter scraping).
    // Default features are off in Cargo.toml, so we bring just what we need.
    let client = k7s_deps::reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("k7s/helm-market")
        .build()
        .map_err(|e| AppError::Other(format!("build http client: {e}")))?;
    let resp = client
        .get(&index_url)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {index_url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::Other(format!(
            "fetch {index_url}: HTTP {}",
            resp.status()
        )));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| AppError::Other(format!("read body {index_url}: {e}")))?;
    k7s_deps::yaml_serde::from_str(&text)
        .map_err(|e| AppError::Other(format!("parse index.yaml: {e}")))
}

fn chrono_now() -> String {
    // A loose RFC3339 timestamp with second precision. `chrono` is already a
    // dependency; this is the smallest call that gives us a printable stamp
    // without pulling a `format!` of `SystemTime` manually.
    k7s_deps::chrono::Utc::now().to_rfc3339_opts(k7s_deps::chrono::SecondsFormat::Secs, true)
}

impl HelmRepo {
    fn error_or(self, fallback: AppError) -> AppError {
        // Used by `update_repo_index` to surface a *typed* error containing the
        // repo state (so the UI can show the broken-repo dot) but with the
        // original error as the message when no override is set.
        match self.last_error {
            Some(msg) => AppError::Other(format!("repo '{}': {msg}", self.name)),
            None => fallback,
        }
    }

    /// Where the cached index lives on disk — exposed for the "open in Finder"
    /// affordance on a repo row.
    pub fn index_file_hint(&self) -> Option<PathBuf> {
        index_path(&self.name).ok()
    }
}

// ---------------------------------------------------------------------------
// Offline chart export/import (air-gap environments)
// ---------------------------------------------------------------------------

/// Download a chart .tgz to a local directory. Returns the saved file path.
/// Uses `helm pull` to fetch the chart archive.
pub async fn export_chart(
    repo: &str,
    chart: &str,
    version: &str,
    output_dir: &str,
) -> AppResult<PathBuf> {
    let helm = super::ops::which_helm().ok_or_else(|| AppError::Other("helm not found".into()))?;

    let output = std::path::PathBuf::from(output_dir);
    std::fs::create_dir_all(&output)
        .map_err(|e| AppError::Other(format!("mkdir {}: {e}", output.display())))?;

    let mut cmd = k7s_deps::tokio::process::Command::new(&helm);
    cmd.arg("pull")
        .arg(format!("{repo}/{chart}"))
        .arg("--version")
        .arg(version)
        .arg("--destination")
        .arg(output_dir)
        .arg("--untar=false");

    let result = cmd
        .output()
        .await
        .map_err(|e| AppError::Other(format!("helm pull: {e}")))?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(AppError::Other(format!("helm pull failed: {stderr}")));
    }

    // The downloaded file is typically {chart}-{version}.tgz
    let filename = format!("{}-{}.tgz", chart, version);
    let path = output.join(&filename);
    if path.exists() {
        Ok(path)
    } else {
        // helm pull might use a different name; list the directory
        Ok(output.join(&filename))
    }
}
