//! SBOM persistence: stores scan results to disk with an index file.

use super::sbom::{SbomResult, SbomSource, SbomSummary};
use crate::error::{AppError, AppResult};
use std::path::{Path, PathBuf};

const SBOM_DIR: &str = "sbom";
const INDEX_FILE: &str = "sbom_index.json";

pub struct SbomStorage {
    base_dir: PathBuf,
}

impl SbomStorage {
    pub fn new(data_dir: &Path) -> Self {
        let base_dir = data_dir.join(SBOM_DIR);
        Self { base_dir }
    }

    /// Save an SBOM result to disk and update the index.
    pub fn save(&self, sbom: &SbomResult) -> AppResult<()> {
        std::fs::create_dir_all(&self.base_dir)
            .map_err(|e| AppError::Other(format!("create sbom dir: {e}")))?;

        let source_dir = self.source_dir(&sbom.source);
        std::fs::create_dir_all(&source_dir)
            .map_err(|e| AppError::Other(format!("create source dir: {e}")))?;

        let filename = format!("{}_{}.json", sbom.format.as_str(), sbom.id);
        let path = source_dir.join(&filename);
        let json = k7s_deps::serde_json::to_string_pretty(sbom)
            .map_err(|e| AppError::Other(format!("serialize sbom: {e}")))?;
        std::fs::write(&path, json).map_err(|e| AppError::Other(format!("write sbom: {e}")))?;

        self.update_index(sbom)?;
        Ok(())
    }

    /// Load an SBOM by ID.
    pub fn load(&self, id: &str) -> AppResult<SbomResult> {
        let index = self.read_index()?;
        let entry = index
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| AppError::Other(format!("SBOM not found: {id}")))?;

        let source_dir = self.source_dir(&entry.source);
        let filename = format!("{}_{}.json", entry.format.as_str(), id);
        let path = source_dir.join(&filename);
        let json = std::fs::read_to_string(&path)
            .map_err(|e| AppError::Other(format!("read sbom: {e}")))?;
        let sbom: SbomResult =
            k7s_deps::serde_json::from_str(&json).map_err(|e| AppError::Other(format!("parse sbom: {e}")))?;
        Ok(sbom)
    }

    /// List all SBOM summaries.
    pub fn list(&self) -> AppResult<Vec<SbomSummary>> {
        self.read_index()
    }

    /// Delete an SBOM by ID.
    pub fn delete(&self, id: &str) -> AppResult<()> {
        let index = self.read_index()?;
        let entry = index.iter().find(|e| e.id == id);

        if let Some(entry) = entry {
            let source_dir = self.source_dir(&entry.source);
            let filename = format!("{}_{}.json", entry.format.as_str(), id);
            let path = source_dir.join(&filename);
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| AppError::Other(format!("delete sbom: {e}")))?;
            }
        }

        let new_index: Vec<SbomSummary> = index.into_iter().filter(|e| e.id != id).collect();
        self.write_index(&new_index)?;
        Ok(())
    }

    fn source_dir(&self, source: &SbomSource) -> PathBuf {
        match source {
            SbomSource::Image { image_ref, .. } => {
                let safe_name = image_ref.replace([':', '/', '@'], "_").replace("..", "__");
                self.base_dir.join("images").join(safe_name)
            }
            SbomSource::Cluster { context } => {
                let safe_name = context.replace([':', '/', '@', '.'], "_");
                self.base_dir.join("clusters").join(safe_name)
            }
        }
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join(INDEX_FILE)
    }

    fn read_index(&self) -> AppResult<Vec<SbomSummary>> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(vec![]);
        }
        let json = std::fs::read_to_string(&path)
            .map_err(|e| AppError::Other(format!("read sbom index: {e}")))?;
        let index: Vec<SbomSummary> = k7s_deps::serde_json::from_str(&json)
            .map_err(|e| AppError::Other(format!("parse sbom index: {e}")))?;
        Ok(index)
    }

    fn write_index(&self, index: &[SbomSummary]) -> AppResult<()> {
        std::fs::create_dir_all(&self.base_dir)
            .map_err(|e| AppError::Other(format!("create sbom dir: {e}")))?;
        let json = k7s_deps::serde_json::to_string_pretty(index)
            .map_err(|e| AppError::Other(format!("serialize sbom index: {e}")))?;
        // Atomic write: write to temp file then rename
        let tmp_path = self.index_path().with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| AppError::Other(format!("write sbom index tmp: {e}")))?;
        std::fs::rename(&tmp_path, self.index_path())
            .map_err(|e| AppError::Other(format!("rename sbom index: {e}")))?;
        Ok(())
    }

    fn update_index(&self, sbom: &SbomResult) -> AppResult<()> {
        let mut index = self.read_index()?;
        // Remove existing entry with same ID to prevent duplicates
        index.retain(|e| e.id != sbom.id);
        let summary = SbomSummary {
            id: sbom.id.clone(),
            source: sbom.source.clone(),
            format: sbom.format.clone(),
            component_count: sbom.components.len(),
            vulnerability_count: sbom.vulnerabilities.len(),
            tool: sbom.metadata.tool.clone(),
            created_at: sbom.created_at,
        };
        index.push(summary);
        self.write_index(&index)
    }
}

// ---------------------------------------------------------------------------
// Export path validation (shared by Tauri commands and web handlers)
// ---------------------------------------------------------------------------

/// Validate and canonicalize an export path for SBOM output.
///
/// Performs the following security checks:
/// - Resolves bare filenames (no directory component) to the system temp directory.
/// - Canonicalizes the path to defeat symlink, `../`, and URL-encoded traversal tricks.
/// - Verifies the canonical path falls within one of the allowed directories
///   (data_dir, home dir, or system temp).
/// - Confirms the parent directory exists on disk.
///
/// Returns the canonical `PathBuf` on success.
pub fn validate_export_path(
    output: &str,
    data_dir: &std::path::Path,
) -> AppResult<std::path::PathBuf> {
    let path = std::path::Path::new(output);

    // If the path is just a filename (no directory component), use the temp directory
    let resolved_path =
        if path.parent().is_none() || path.parent() == Some(std::path::Path::new("")) {
            // Just a filename - use temp directory
            std::env::temp_dir().join(path)
        } else {
            path.to_path_buf()
        };

    // Canonicalize the path to resolve symlinks, URL-encoded sequences, and other tricks.
    // This prevents path traversal attacks using ../, symlinks, or encoded characters.
    let canonical_path = k7s_deps::dunce::canonicalize(&resolved_path).or_else(|_| {
        // If the file doesn't exist yet, canonicalize the parent directory
        if let Some(parent) = resolved_path.parent() {
            let canonical_parent = k7s_deps::dunce::canonicalize(parent).map_err(|e| {
                AppError::Other(format!(
                    "Cannot resolve export directory '{}': {e}",
                    parent.display()
                ))
            })?;
            Ok::<std::path::PathBuf, AppError>(
                canonical_parent.join(resolved_path.file_name().unwrap_or_default()),
            )
        } else {
            Err(AppError::Other(
                "Invalid export path: no parent directory".to_string(),
            ))
        }
    })?;

    // Define allowed export directories: user's home, data_dir, or temp
    let allowed_dirs: Vec<std::path::PathBuf> = {
        let mut dirs = vec![data_dir.to_path_buf()];
        if let Some(home) = k7s_deps::dirs::home_dir() {
            dirs.push(home);
        }
        dirs.push(std::env::temp_dir());
        dirs
    };

    // Verify the canonical path is within an allowed directory
    let is_allowed = allowed_dirs
        .iter()
        .any(|allowed| canonical_path.starts_with(allowed));

    if !is_allowed {
        return Err(AppError::Other(format!(
            "Export path '{}' is not within allowed directories. Allowed: home, data dir, or temp.",
            output
        )));
    }

    // Ensure parent directory exists
    if let Some(parent) = canonical_path.parent() {
        if !parent.exists() {
            return Err(AppError::Other(format!(
                "Export directory does not exist: {}",
                parent.display()
            )));
        }
    }

    Ok(canonical_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube::security::sbom::*;

    fn make_test_sbom(id: &str, image: &str) -> SbomResult {
        SbomResult {
            id: id.to_string(),
            source: SbomSource::Image {
                image_ref: image.to_string(),
                namespace: "default".to_string(),
                pod: None,
            },
            format: SbomFormat::CycloneDx,
            spec_version: "1.5".to_string(),
            metadata: SbomMetadata {
                tool: "test".to_string(),
                tool_version: "0.1.0".to_string(),
                scan_duration_ms: 100,
            },
            components: vec![SbomComponent {
                name: "openssl".to_string(),
                version: "3.1.4".to_string(),
                purl: None,
                cpe: None,
                component_type: "library".to_string(),
                licenses: vec![],
                supplier: None,
                hashes: vec![],
            }],
            dependencies: vec![],
            vulnerabilities: vec![],
            raw_output: None,
            created_at: k7s_deps::chrono::Utc::now(),
        }
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join("k7s_sbom_test_save_load");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = SbomStorage::new(&dir);
        let sbom = make_test_sbom("test-001", "nginx:1.25");

        storage.save(&sbom).unwrap();
        let loaded = storage.load("test-001").unwrap();

        assert_eq!(loaded.id, "test-001");
        assert_eq!(loaded.metadata.tool, "test");
        assert_eq!(loaded.components.len(), 1);
        assert_eq!(loaded.components[0].name, "openssl");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_history() {
        let dir = std::env::temp_dir().join("k7s_sbom_test_list");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = SbomStorage::new(&dir);
        assert!(storage.list().unwrap().is_empty());

        storage.save(&make_test_sbom("a", "nginx:1.25")).unwrap();
        storage.save(&make_test_sbom("b", "alpine:3.19")).unwrap();

        let list = storage.list().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|s| s.id == "a"));
        assert!(list.iter().any(|s| s.id == "b"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_sbom() {
        let dir = std::env::temp_dir().join("k7s_sbom_test_delete");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = SbomStorage::new(&dir);
        storage
            .save(&make_test_sbom("del-001", "nginx:1.25"))
            .unwrap();
        assert_eq!(storage.list().unwrap().len(), 1);

        storage.delete("del-001").unwrap();
        assert!(storage.list().unwrap().is_empty());
        assert!(storage.load("del-001").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_nonexistent() {
        let dir = std::env::temp_dir().join("k7s_sbom_test_notfound");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = SbomStorage::new(&dir);
        assert!(storage.load("does-not-exist").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
