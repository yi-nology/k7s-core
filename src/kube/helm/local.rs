//! Local chart library — the offline half of the Helm feature.
//!
//! ChartOps parity: scan a directory of `.tgz` packages / unpacked chart
//! dirs, parse their Chart.yaml, and expose entries for the UI. Pure
//! functions taking the library root as a parameter — the command layer
//! supplies `<data_dir>/charts`. tar entries are READ ONLY: we never
//! `unpack` onto disk, so a malicious archive has no filesystem surface.

use crate::error::{AppError, AppResult};
use k7s_deps::flate2::read::GzDecoder;
use k7s_deps::tar;
use k7s_deps::yaml_serde;
use std::io::Read;
use std::path::Path;

/// How a chart sits in the library: a `helm package` archive or an unpacked
/// chart dir. The kind decides how Chart.yaml is read and what `id` is.
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LocalChartKind {
    Tgz,
    Dir,
}

/// One chart in the local library, ready for the UI.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalChartEntry {
    /// "<name>-<version>"（tgz）or the directory's name.
    pub id: String,
    pub kind: LocalChartKind,
    pub name: String,
    pub version: String,
    pub app_version: String,
    pub description: String,
    pub icon: String,
    /// Absolute path, as a display string for the frontend.
    pub path: String,
    pub size_bytes: u64,
    /// RFC3339 mtime — the listing sorts on it, newest first.
    pub modified_at: String,
}

/// Chart.yaml fields we surface (everything else is ignored on purpose).
#[derive(Default, serde::Deserialize)]
struct ChartYaml {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default, rename = "appVersion")]
    app_version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    icon: String,
}

/// Assemble an entry from parsed metadata plus the file facts both parse
/// paths already have in hand.
fn entry_from_meta(
    kind: LocalChartKind,
    meta: ChartYaml,
    path: &Path,
    size_bytes: u64,
    modified: std::time::SystemTime,
    id: String,
) -> LocalChartEntry {
    LocalChartEntry {
        id,
        kind,
        name: meta.name,
        version: meta.version,
        app_version: meta.app_version,
        description: meta.description,
        icon: meta.icon,
        path: path.display().to_string(),
        size_bytes,
        modified_at: k7s_deps::chrono::DateTime::from_timestamp(
            modified
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            0,
        )
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default(),
    }
}

/// Read a `.tgz` chart's metadata by streaming its tar entries — never
/// unpacking to disk. A missing Chart.yaml is an error (the file is not a
/// chart package); bad YAML inside it degrades to empty fields, matching
/// the skip-don't-fail policy of the scan.
fn parse_tgz_metadata(path: &Path) -> AppResult<LocalChartEntry> {
    let file = std::fs::File::open(path)
        .map_err(|e| AppError::Other(format!("open {}: {e}", path.display())))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut meta: Option<ChartYaml> = None;
    for entry in archive
        .entries()
        .map_err(|e| AppError::Other(format!("tar entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| AppError::Other(format!("tar entry: {e}")))?;
        // Chart.yaml lives directly under the single top-level dir.
        if entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|f| f == "Chart.yaml"))
            .unwrap_or(false)
            && entry
                .path()
                .ok()
                .map(|p| p.components().count() == 2)
                .unwrap_or(false)
        {
            let mut yaml = String::new();
            entry
                .read_to_string(&mut yaml)
                .map_err(|e| AppError::Other(format!("read Chart.yaml: {e}")))?;
            meta = Some(yaml_serde::from_str::<ChartYaml>(&yaml).unwrap_or_default());
            break;
        }
    }
    let meta = meta.ok_or_else(|| AppError::Other("no Chart.yaml in archive".into()))?;
    let id = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let modified = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH);
    Ok(entry_from_meta(
        LocalChartKind::Tgz,
        meta,
        path,
        size,
        modified,
        id,
    ))
}

/// Read an unpacked chart dir's metadata. The caller (scan) has already
/// checked Chart.yaml exists; a read failure here still skips just this dir.
fn parse_dir_metadata(path: &Path) -> AppResult<LocalChartEntry> {
    let yaml = std::fs::read_to_string(path.join("Chart.yaml"))
        .map_err(|e| AppError::Other(format!("read Chart.yaml: {e}")))?;
    let meta: ChartYaml = yaml_serde::from_str(&yaml).unwrap_or_default();
    fn dir_size(p: &Path) -> u64 {
        std::fs::read_dir(p)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| {
                        let p = e.path();
                        if p.is_dir() {
                            dir_size(&p)
                        } else {
                            std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
                        }
                    })
                    .sum()
            })
            .unwrap_or(0)
    }
    let modified = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH);
    let id = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    Ok(entry_from_meta(
        LocalChartKind::Dir,
        meta,
        path,
        dir_size(path),
        modified,
        id,
    ))
}

/// Scan the library root: every `*.tgz` file and every dir containing a
/// Chart.yaml. Corrupt archives are skipped (logged), never fatal.
pub fn scan_local_charts(root: &Path) -> AppResult<Vec<LocalChartEntry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(root)
        .map_err(|e| AppError::Other(format!("read_dir {}: {e}", root.display())))?
        .filter_map(|e| e.ok())
    {
        let p = e.path();
        if p.extension().map(|x| x == "tgz").unwrap_or(false) {
            match parse_tgz_metadata(&p) {
                Ok(entry) => out.push(entry),
                Err(err) => k7s_deps::tracing::warn!("skip {}: {err}", p.display()),
            }
        } else if p.is_dir() && p.join("Chart.yaml").exists() {
            match parse_dir_metadata(&p) {
                Ok(entry) => out.push(entry),
                Err(err) => k7s_deps::tracing::warn!("skip {}: {err}", p.display()),
            }
        }
    }
    out.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::flate2::write::GzEncoder;
    use k7s_deps::flate2::Compression;
    use std::io::Write;

    /// Build an in-memory `.tgz` exactly like `helm package` produces:
    /// a single top-level `<name>/` dir containing Chart.yaml (+ extras).
    fn tgz_bytes(name: &str, version: &str, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let chart_yaml = format!(
            "apiVersion: v2\nname: {name}\nversion: {version}\ndescription: test chart\n"
        );
        let mut append = |path: String, data: &[u8]| {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, data).unwrap();
        };
        append(format!("{name}/Chart.yaml"), chart_yaml.as_bytes());
        for (p, d) in extra {
            append(format!("{name}/{p}"), d.as_bytes());
        }
        let tarball = builder.into_inner().unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tarball).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn scan_finds_tgz_and_dir_charts() {
        let tmp = std::env::temp_dir().join(format!("k7s-local-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // tgz chart
        std::fs::write(tmp.join("demo-app-1.0.0.tgz"), tgz_bytes("demo-app", "1.0.0", &[]))
            .unwrap();
        // dir chart
        let dir = tmp.join("my-chart");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Chart.yaml"),
            "apiVersion: v2\nname: my-chart\nversion: 2.0.0\n",
        )
        .unwrap();

        let mut entries = scan_local_charts(&tmp).unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "demo-app");
        assert_eq!(entries[0].version, "1.0.0");
        assert!(matches!(entries[0].kind, LocalChartKind::Tgz));
        assert_eq!(entries[1].name, "my-chart");
        assert!(matches!(entries[1].kind, LocalChartKind::Dir));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scan_skips_bad_tgz_rather_than_failing() {
        let tmp = std::env::temp_dir().join(format!("k7s-local-bad-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("garbage.tgz"), b"not a gzip at all").unwrap();
        // One corrupt file must not break the whole listing (mirrors
        // decode_release's skip-don't-fail policy in mod.rs).
        assert!(scan_local_charts(&tmp).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
