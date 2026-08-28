//! Deployment profiles — saved Helm install/upgrade parameter sets.
//!
//! A profile is everything the deploy dialog needs in one named blob: the
//! chart reference, version pin, namespace, values text, `--set` map, and
//! the flag trio (atomic / force / create-namespace) plus a timeout. The
//! user saves a working configuration once and redeploys it after an
//! upgrade without re-typing any of it.
//!
//! Storage: one JSON file per data dir, `<dir>/helm-profiles.json`,
//! holding `{"profiles": [...]}` — the wrapped-object shape the other
//! registry-style modules use, so a later `created_at`-style envelope
//! field can be added without a migration. Pure functions taking the
//! data dir as a parameter (like [`crate::kube::helm::local`]); the
//! command layer supplies `mgr.data_dir`.
//!
//! Failure stance matches the local chart library's skip-don't-fail
//! policy: a missing or corrupt file reads as an empty list (logged), so
//! one bad write never bricks the deploy dialog — the next successful
//! save rewrites the file from scratch.
//!
//! `created_at` is filled by the command layer (`Utc::now().to_rfc3339()`);
//! this module only preserves the original timestamp when a save overwrites
//! an existing profile.

use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The profiles file under a data dir.
pub const PROFILES_FILE: &str = "helm-profiles.json";

/// A saved deployment configuration. camelCase on the wire (Tauri IPC +
/// web JSON) to match the frontend's `HelmProfile` type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct HelmProfile {
    /// Unique key of the profile; `[a-zA-Z0-9-_]`, ≤64 chars.
    pub name: String,
    /// `repo/name` or a local absolute path.
    pub chart_ref: String,
    /// Chart version; empty = latest.
    pub version: String,
    pub namespace: String,
    /// values.yaml text ("" = chart defaults).
    pub values: String,
    /// `--set` pairs. Keys are literal Helm paths (`image.tag`) — the JSON
    /// map is never case-renamed, only the struct fields are.
    pub set: Option<k7s_deps::serde_json::Map<String, k7s_deps::serde_json::Value>>,
    pub atomic: bool,
    pub force: bool,
    pub create_namespace: bool,
    /// Operation timeout in seconds; None = helm's default.
    pub timeout_secs: Option<u64>,
    /// RFC3339 creation time; preserved on overwrite, filled by the
    /// command layer.
    pub created_at: String,
}

/// The on-disk envelope.
#[derive(Default, Serialize, Deserialize)]
struct ProfilesFile {
    #[serde(default)]
    profiles: Vec<HelmProfile>,
}

fn profiles_path(dir: &Path) -> PathBuf {
    dir.join(PROFILES_FILE)
}

/// Read the profiles file: missing, unreadable, or corrupt → empty list
/// (logged), never an error. The next save rewrites the file wholesale,
/// so a bad write self-heals instead of wedging the feature.
fn read_file(dir: &Path) -> Vec<HelmProfile> {
    let path = profiles_path(dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    match k7s_deps::serde_json::from_str::<ProfilesFile>(&text) {
        Ok(mut f) => {
            f.profiles.sort_by(|a, b| a.name.cmp(&b.name));
            f.profiles
        }
        Err(e) => {
            k7s_deps::tracing::warn!("helm profiles: corrupt {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Write the profiles file atomically: serialise to a `.tmp` sibling in
/// the same dir, then rename over the target — a crash mid-write leaves
/// the previous file intact rather than a truncated one.
fn write_file(dir: &Path, profiles: Vec<HelmProfile>) -> AppResult<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| AppError::Other(format!("mkdir {}: {e}", dir.display())))?;
    let path = profiles_path(dir);
    let text = k7s_deps::serde_json::to_string_pretty(&ProfilesFile { profiles })
        .map_err(|e| AppError::Other(format!("serialise profiles: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| AppError::Other(format!("write tmp: {e}")))?;
    std::fs::rename(&tmp, &path).map_err(|e| AppError::Other(format!("rename: {e}")))?;
    Ok(())
}

/// Load every profile from `<dir>/helm-profiles.json`, sorted by name.
/// Missing or corrupt file → empty list.
pub fn load_profiles(dir: &Path) -> Vec<HelmProfile> {
    read_file(dir)
}

/// Upsert a profile by name and return the full list, sorted by name.
/// Overwriting an existing profile keeps its original `created_at`.
/// The name is validated before the file is touched.
pub fn save_profile(dir: &Path, p: HelmProfile) -> AppResult<Vec<HelmProfile>> {
    validate_profile_name(&p.name)?;
    let mut profiles = read_file(dir);
    match profiles.iter_mut().find(|e| e.name == p.name) {
        Some(existing) => {
            // Birthday is the first save, not the latest edit.
            let created_at = existing.created_at.clone();
            *existing = p;
            existing.created_at = created_at;
        }
        None => profiles.push(p),
    }
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    write_file(dir, profiles.clone())?;
    Ok(profiles)
}

/// Delete the profile named `name` and return the remaining list, sorted
/// by name. A missing name is a [`AppError::NotFound`].
pub fn delete_profile(dir: &Path, name: &str) -> AppResult<Vec<HelmProfile>> {
    let mut profiles = read_file(dir);
    let before = profiles.len();
    profiles.retain(|p| p.name != name);
    if profiles.len() == before {
        return Err(AppError::NotFound(format!("profile `{name}`")));
    }
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    write_file(dir, profiles.clone())?;
    Ok(profiles)
}

/// Profile names are also usable as Helm release names, so keep them
/// boring: non-empty, at most 64 chars, `[a-zA-Z0-9-_]` only.
pub fn validate_profile_name(name: &str) -> AppResult<()> {
    if name.is_empty() {
        return Err(AppError::Other("profile name cannot be empty".into()));
    }
    if name.chars().count() > 64 {
        return Err(AppError::Other("profile name exceeds 64 characters".into()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::Other(
            "profile name may only contain letters, digits, '-' and '_'".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json::json;

    /// Per-test scratch dir (tests in one binary run in parallel).
    fn tmp(label: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("k7s-profiles-{}-{}", label, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fully-populated profile exercising every field, including the
    /// set map and the optional timeout.
    fn full_profile(name: &str, created_at: &str) -> HelmProfile {
        let mut set = k7s_deps::serde_json::Map::new();
        set.insert("replicaCount".into(), json!(3));
        set.insert("image.tag".into(), json!("v2.1.0"));
        set.insert("ingress.hosts".into(), json!(["a.example", "b.example"]));
        HelmProfile {
            name: name.into(),
            chart_ref: "bitnami/nginx".into(),
            version: "15.4.0".into(),
            namespace: "web".into(),
            values: "replicaCount: 1\n".into(),
            set: Some(set),
            atomic: true,
            force: false,
            create_namespace: true,
            timeout_secs: Some(300),
            created_at: created_at.into(),
        }
    }

    // ---- load ----

    /// A fresh data dir has no profiles yet, and that's not an error.
    #[test]
    fn missing_file_loads_empty() {
        let dir = tmp("missing");
        assert!(load_profiles(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt file degrades to an empty list (warn-logged), matching
    /// the skip-don't-fail policy — and the next save recovers it.
    #[test]
    fn corrupt_file_loads_empty_and_save_recovers() {
        let dir = tmp("corrupt");
        std::fs::write(profiles_path(&dir), "{not json at all").unwrap();
        assert!(load_profiles(&dir).is_empty());

        let p = full_profile("recovered", "2026-01-01T00:00:00Z");
        let out = save_profile(&dir, p.clone()).unwrap();
        assert_eq!(out, vec![p.clone()]);
        assert_eq!(load_profiles(&dir), vec![p]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- upsert ----

    /// Saving over an existing name replaces it (one entry left) and keeps
    /// the original `created_at` — the profile's birthday is when it was
    /// first saved, not last edited.
    #[test]
    fn upsert_overwrites_and_preserves_created_at() {
        let dir = tmp("upsert");
        let v1 = full_profile("prod", "2026-01-01T00:00:00Z");
        save_profile(&dir, v1).unwrap();

        let mut v2 = full_profile("prod", "2026-08-28T00:00:00Z");
        v2.chart_ref = "bitnami/nginx".to_string();
        v2.version = String::new(); // latest
        v2.timeout_secs = None;
        let out = save_profile(&dir, v2).unwrap();

        assert_eq!(out.len(), 1, "same name upserts, not appends");
        assert_eq!(out[0].version, "", "the edit took");
        assert_eq!(
            out[0].created_at, "2026-01-01T00:00:00Z",
            "original created_at survives an overwrite"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Different names append; the returned (and stored) list is sorted
    /// by name regardless of save order.
    #[test]
    fn save_appends_and_sorts_by_name() {
        let dir = tmp("sorted");
        save_profile(&dir, full_profile("zed", "2026-01-03T00:00:00Z")).unwrap();
        save_profile(&dir, full_profile("alpha", "2026-01-01T00:00:00Z")).unwrap();
        save_profile(&dir, full_profile("mid", "2026-01-02T00:00:00Z")).unwrap();

        let names: Vec<_> = load_profiles(&dir).iter().map(|p| p.name.clone()).collect();
        assert_eq!(names, vec!["alpha", "mid", "zed"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Saving validates the name before touching the file.
    #[test]
    fn save_rejects_invalid_name() {
        let dir = tmp("save-invalid");
        let mut p = full_profile("bad name!", "2026-01-01T00:00:00Z");
        assert!(save_profile(&dir, p.clone()).is_err());

        p.name = String::new();
        assert!(save_profile(&dir, p).is_err());
        // Nothing was written by either failed attempt.
        assert!(!profiles_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- delete ----

    /// Deleting a missing profile is a NotFound, not a silent success.
    #[test]
    fn delete_missing_is_not_found() {
        let dir = tmp("del-missing");
        let err = delete_profile(&dir, "ghost").unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got: {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Delete removes exactly the named profile and returns the rest.
    #[test]
    fn delete_removes_named_and_returns_rest() {
        let dir = tmp("del");
        for n in ["alpha", "mid", "zed"] {
            save_profile(&dir, full_profile(n, "2026-01-01T00:00:00Z")).unwrap();
        }
        let out = delete_profile(&dir, "mid").unwrap();
        let names: Vec<_> = out.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zed"]);
        assert_eq!(load_profiles(&dir).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- round-trip ----

    /// Every field survives a save → load round-trip, including the set
    /// map (keys untouched — `image.tag` must not become `imageTag`) and
    /// the optional timeout.
    #[test]
    fn round_trip_preserves_all_fields() {
        let dir = tmp("roundtrip");
        let p = full_profile("full", "2026-03-04T05:06:07Z");
        save_profile(&dir, p.clone()).unwrap();

        let loaded = load_profiles(&dir);
        assert_eq!(loaded, vec![p]);

        let set = loaded[0].set.as_ref().unwrap();
        assert_eq!(set.get("image.tag"), Some(&json!("v2.1.0")));
        assert_eq!(set.get("replicaCount"), Some(&json!(3)));
        assert_eq!(loaded[0].timeout_secs, Some(300));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- name validation ----

    #[test]
    fn name_validation_boundaries() {
        assert!(validate_profile_name("").is_err(), "empty refused");
        assert!(validate_profile_name("   ").is_err(), "blank refused");
        let max = "a".repeat(64);
        assert!(validate_profile_name(&max).is_ok(), "64 chars allowed");
        let over = "a".repeat(65);
        assert!(validate_profile_name(&over).is_err(), "65 chars refused");
        assert!(validate_profile_name("a b").is_err(), "space refused");
        assert!(validate_profile_name("a/b").is_err(), "slash refused");
        assert!(validate_profile_name("a.b").is_err(), "dot refused");
        assert!(validate_profile_name("配置").is_err(), "non-ascii refused");
        assert!(validate_profile_name("Prod-Web_2").is_ok());
    }
}
