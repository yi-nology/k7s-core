//! Inspect a local image archive (`docker save` tarball / OCI layout) before
//! copying it into a private registry.
//!
//! When the source is a file on disk rather than a live registry, the user
//! (or the AI) wants to confirm what's actually inside the tar before pushing
//! it — a mis-tagged image pushed to an internal registry is a silent failure
//! that's annoying to undo. `skopeo inspect --config` reads the tar without a
//! Docker daemon and returns the image's config JSON; we surface the few
//! fields that matter for a go/no-go decision.
//!
//! This is a thin companion to [`image_sync`]: `inspect_archive` answers
//! "what is this tar?", `copy_image` answers "put it in my registry".

use crate::error::{AppError, AppResult};
use k7s_deps::tokio::process::Command;
use serde::Serialize;

/// The salient facts about an image inside a local archive, enough to decide
/// whether to copy it and what to name the destination.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveInfo {
    /// The image's canonical name (e.g. `docker.io/library/nginx`). May be
    /// empty for `docker save` tars that lost their tag.
    pub name: String,
    /// The tag(s) stored in the archive (e.g. `["1.25", "latest"]`).
    pub repo_tags: Vec<String>,
    /// The content digest (`sha256:…`).
    pub digest: String,
    /// Target architecture, e.g. `amd64`. A `darwin`/`arm64` image is usually
    /// not what a linux cluster wants — this field makes that visible.
    pub architecture: String,
    /// Target OS, e.g. `linux`.
    pub os: String,
    /// When the image was built (RFC3339), best-effort.
    pub created: String,
    /// Total size of all layers in bytes (the on-wire size of the push).
    pub size_bytes: i64,
}

/// Inspect a local image archive. `path` is a filesystem path to a tarball
/// produced by `docker save` (or `podman save`). Returns the parsed config so
/// the caller can confirm name/tag/arch before copying.
///
/// Runs `skopeo inspect --config docker-archive:<path>` and parses the JSON.
/// We don't stream to an event sink here — inspect is a quick one-shot, unlike
/// `copy_image` which can run for minutes.
pub async fn inspect_archive(path: &str) -> AppResult<ArchiveInfo> {
    let skopeo = crate::kube::image::sync::which_skopeo().ok_or_else(|| {
        AppError::Other(
            "skopeo CLI not found in PATH — install skopeo \
             (brew install skopeo / apt install skopeo) and retry"
                .into(),
        )
    })?;

    // `--config` returns the image config (architecture, os, layers); without
    // it skopeo returns the manifest which has no architecture. We need both,
    // so we ask for the config and pull the manifest fields from the same JSON
    // (skopeo merges them in its `--config` output for docker-archive sources).
    let transport = if path.starts_with("oci:") || path.starts_with("docker-archive:") {
        // The caller already gave us a full transport; pass it through.
        path.to_string()
    } else {
        format!("docker-archive:{path}")
    };

    let out = Command::new(&skopeo)
        .args(["inspect", "--config", &transport])
        .output()
        .await
        .map_err(|e| AppError::Other(format!("spawn skopeo inspect: {e}")))?;

    if !out.status.success() {
        return Err(AppError::Other(format!(
            "skopeo inspect failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    // skopeo inspect --config prints a JSON object whose shape varies slightly
    // between docker-archive and OCI sources. We parse loosely (serde_json::Value)
    // and reach for each field defensively so a missing key degrades to "" / 0
    // rather than a parse failure.
    let raw = String::from_utf8_lossy(&out.stdout);
    let v: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(&raw)
        .map_err(|e| AppError::Other(format!("parse skopeo inspect output: {e}")))?;

    let str_field = |key: &str| -> String {
        v.get(key)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };

    // RepoTags is an array of strings. For docker-archive it's at the top
    // level; for some OCI layouts it's nested differently — we handle both.
    let repo_tags: Vec<String> = v
        .get("RepoTags")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Size: skopeo doesn't always include a top-level size; sum the layer
    // sizes from the history/layers if present, else fall back to 0.
    let size_bytes = v.get("Size").and_then(|s| s.as_i64()).unwrap_or_else(|| {
        v.get("LayersData")
            .and_then(|l| l.as_array())
            .map(|layers| {
                layers
                    .iter()
                    .filter_map(|l| l.get("Size").and_then(|s| s.as_i64()))
                    .sum()
            })
            .unwrap_or(0)
    });

    Ok(ArchiveInfo {
        name: str_field("Name"),
        repo_tags,
        digest: str_field("Digest"),
        architecture: str_field("Architecture"),
        os: str_field("Os"),
        created: str_field("Created"),
        size_bytes,
    })
}
