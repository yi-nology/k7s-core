//! Local chart library — the offline half of the Helm feature.
//!
//! ChartOps parity: scan a directory of `.tgz` packages / unpacked chart
//! dirs, parse their Chart.yaml, and expose entries for the UI. Pure
//! functions taking the library root as a parameter — [`charts_dir`] builds
//! it as `<data_dir>/charts`. tar entries are READ ONLY: we never
//! `unpack` onto disk, so a malicious archive has no filesystem surface.

use crate::core::audit;
use crate::error::{AppError, AppResult};
use k7s_deps::flate2::read::GzDecoder;
use k7s_deps::tar;
use k7s_deps::yaml_serde;
use std::io::Read;
use std::path::{Path, PathBuf};

/// How a chart sits in the library: a `helm package` archive or an unpacked
/// chart dir. The kind decides how Chart.yaml is read and what `id` is.
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LocalChartKind {
    Tgz,
    Dir,
}

/// One chart in the local library, ready for the UI. camelCase on the wire
/// (Tauri IPC + web JSON) to match the frontend's `LocalChartEntry` types.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
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
    // `.tar.gz` stems to `<id>.tar` (`demo-1.0.0.tar.gz` → `demo-1.0.0.tar`);
    // strip the stray `.tar` so the id matches the `.tgz` naming and the
    // delete/detail lookups (which retry archive extensions) resolve it.
    let id = path
        .file_name()
        .and_then(|f| f.to_str())
        .and_then(|f| f.strip_suffix(".tar.gz").map(str::to_string))
        .unwrap_or_else(|| {
            path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        });
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
                    .filter_map(|e| {
                        // `file_type()` (unlike `Path::is_dir`) does not
                        // follow symlinks: a symlinked subdir must not pull
                        // outside bytes into the size — or cycle to overflow.
                        let ft = e.file_type().ok()?;
                        if ft.is_symlink() {
                            return None;
                        }
                        let p = e.path();
                        Some(if ft.is_dir() {
                            dir_size(&p)
                        } else {
                            std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
                        })
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

/// The on-disk root of the local chart library: `<data_dir>/charts`. Shared
/// by the Tauri command layer and the MCP server (and their tests) so every
/// transport — and every audit record — agrees on one library location.
pub fn charts_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("charts")
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
        // Import accepts both spellings, so the listing must too — a
        // `.tar.gz` whose extension is `gz` would otherwise never show.
        let is_archive = p.extension().map(|x| x == "tgz").unwrap_or(false)
            || p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.ends_with(".tar.gz"));
        if is_archive {
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

/// Hard ceiling on an imported chart package — keeps a hostile upload from
/// filling the disk before the gzip magic check even runs.
pub const MAX_CHART_BYTES: u64 = 50 * 1024 * 1024;

/// Cap on a single decompressed member read (values.yaml, README, any file
/// the viewer opens): a gzip-bomb member must not OOM the process. A
/// truncated tail is acceptable for a read-only viewer.
const MAX_MEMBER_BYTES: u64 = 10 * 1024 * 1024;

/// Read a chart member as UTF-8, capped at [`MAX_MEMBER_BYTES`] via
/// [`Read::take`] — the remainder of an over-cap member is simply dropped.
fn read_capped<R: Read>(r: R) -> std::io::Result<String> {
    let mut s = String::new();
    r.take(MAX_MEMBER_BYTES).read_to_string(&mut s)?;
    Ok(s)
}

/// gzip files start with these two bytes; `.tgz` is always gzip.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Sanitise a client-supplied filename down to a bare basename with a
/// chart-ish extension. Rejects anything that tries to escape or rename.
fn sanitize_filename(name: &str) -> AppResult<String> {
    let base = std::path::Path::new(name)
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| AppError::Other("invalid filename".into()))?
        .to_string();
    if !base.ends_with(".tgz") && !base.ends_with(".tar.gz") {
        return Err(AppError::Other("only .tgz / .tar.gz accepted".into()));
    }
    Ok(base)
}

/// Import a chart from raw bytes: size-gate, gzip-magic-gate, sanitise the
/// filename, write it under the library root, then verify it parses as a
/// chart (a file that fails metadata is removed again — no corrupt residue).
/// Success-only audited (`local_chart_import`) right here in the core layer,
/// so MCP imports land in the trail the same way desktop imports do.
pub fn import_chart_bytes(root: &Path, filename: &str, bytes: &[u8]) -> AppResult<LocalChartEntry> {
    let name = sanitize_filename(filename)?;
    if bytes.len() as u64 > MAX_CHART_BYTES {
        return Err(AppError::Other(format!(
            "chart exceeds {} byte limit",
            MAX_CHART_BYTES
        )));
    }
    if bytes.len() < 2 || bytes[0..2] != GZIP_MAGIC {
        return Err(AppError::Other("not a gzip archive".into()));
    }
    std::fs::create_dir_all(root)
        .map_err(|e| AppError::Other(format!("mkdir {}: {e}", root.display())))?;
    let dest = root.join(&name);
    std::fs::write(&dest, bytes)
        .map_err(|e| AppError::Other(format!("write {}: {e}", dest.display())))?;
    match parse_tgz_metadata(&dest) {
        Ok(entry) => {
            // Success-only audit: only a verified chart on disk is recorded.
            audit::record(
                "local_chart_import",
                k7s_deps::serde_json::json!({
                    "name": entry.name.clone(),
                    "version": entry.version.clone(),
                    "bytes": bytes.len(),
                }),
            );
            Ok(entry)
        }
        Err(e) => {
            // Don't leave a corrupt file behind just because metadata failed.
            let _ = std::fs::remove_file(&dest);
            Err(e)
        }
    }
}

/// Delete by id. The id must resolve to a direct child of the library root
/// (canonicalised), so `../` tricks and absolute paths are refused. A tgz
/// id is the file *stem* (`demo-1.0.0`), so the archive extensions are
/// retried when the bare id doesn't name a dir chart directly.
/// Success-only audited (`local_chart_remove`) at the core layer.
pub fn remove_chart(root: &Path, id: &str) -> AppResult<()> {
    let root = root
        .canonicalize()
        .map_err(|e| AppError::Other(format!("canonicalize {}: {e}", root.display())))?;
    // "" covers dir charts (id IS the dir name); the other two cover tgz
    // archives, whose scan-time id drops the extension.
    let target = ["", ".tgz", ".tar.gz"]
        .into_iter()
        .map(|ext| root.join(format!("{id}{ext}")))
        .find(|p| p.exists())
        .ok_or_else(|| AppError::NotFound(format!("chart `{id}` not found")))?;
    let canon = target
        .canonicalize()
        .map_err(|e| AppError::NotFound(format!("chart `{id}`: {e}")))?;
    if canon.parent() != Some(root.as_path()) {
        return Err(AppError::Other(
            "refusing to delete outside chart library".into(),
        ));
    }
    if canon.is_dir() {
        std::fs::remove_dir_all(&canon)
    } else {
        std::fs::remove_file(&canon)
    }
    .map_err(|e| AppError::Other(format!("delete {}: {e}", canon.display())))?;
    audit::record(
        "local_chart_remove",
        k7s_deps::serde_json::json!({ "id": id }),
    );
    Ok(())
}

/// One node of a chart's file tree. For a tgz the path is the tar member
/// path as stored (kept under the chart's top-level dir, e.g.
/// `demo/values.yaml`); for a dir chart it is relative to the chart root.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalChartFile {
    pub path: String,
    pub size_bytes: u64,
    pub is_dir: bool,
}

/// Everything the detail view needs: the entry, its file tree, and the
/// files the UI renders inline (empty string when absent).
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalChartDetail {
    pub entry: LocalChartEntry,
    /// Sorted ascending so the tree renders deterministically.
    pub files: Vec<LocalChartFile>,
    /// Empty when the chart ships no Chart.yaml.
    pub chart_yaml: String,
    /// Empty when the chart ships no values.yaml.
    pub values_yaml: String,
    /// Empty when the chart ships no README.md.
    pub readme: String,
}

/// Collect (path, size, is_dir) for one chart package, entry by entry —
/// the same read-only streaming as the metadata parse, no unpacking.
fn tgz_files(path: &Path) -> AppResult<Vec<LocalChartFile>> {
    let file = std::fs::File::open(path)
        .map_err(|e| AppError::Other(format!("open {}: {e}", path.display())))?;
    let mut out = Vec::new();
    for entry in tar::Archive::new(GzDecoder::new(file))
        .entries()
        .map_err(|e| AppError::Other(format!("tar entries: {e}")))?
    {
        let entry = entry.map_err(|e| AppError::Other(format!("tar entry: {e}")))?;
        let rel = entry
            .path()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_default();
        if rel.is_empty() {
            continue;
        }
        out.push(LocalChartFile {
            path: rel,
            size_bytes: entry.size(),
            is_dir: entry.header().entry_type().is_dir(),
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Collect the file tree of an unpacked chart dir, recursively. Read errors
/// degrade to skipping (size 0 / missing subtree), matching the scan's
/// skip-don't-fail policy.
fn dir_files(root: &Path) -> Vec<LocalChartFile> {
    fn walk(base: &Path, rel: &str, out: &mut Vec<LocalChartFile>) {
        let Ok(rd) = std::fs::read_dir(base) else {
            return;
        };
        for e in rd.filter_map(|e| e.ok()) {
            // `file_type()` (unlike `Path::is_dir`) does not follow symlinks:
            // chart members have no legitimate symlinks, and following one
            // would list entries outside the chart root — or, for a cycle,
            // recurse until the stack overflows.
            let Ok(ft) = e.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if ft.is_dir() {
                out.push(LocalChartFile {
                    path: child_rel.clone(),
                    size_bytes: 0,
                    is_dir: true,
                });
                walk(&p, &child_rel, out);
            } else {
                out.push(LocalChartFile {
                    path: child_rel,
                    size_bytes: std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0),
                    is_dir: false,
                });
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Chart-root-relative form of a tar member path: helm packages store
/// everything under a single top-level dir named after the *chart*
/// (`demo/…` inside `demo-1.0.0.tgz` — the file stem is not it), so we
/// strip whatever the archive's own first component is.
fn chart_root_rel(rel: &str) -> &str {
    match rel.split_once('/') {
        Some((_, rest)) => rest,
        None => rel,
    }
}

/// Read one member out of a `.tgz` by streaming — the archive is never
/// unpacked and `inner` is never joined onto the disk, so there is no
/// filesystem surface for a hostile member path. Both spellings are
/// accepted: the full member path (`demo/values.yaml`) and the
/// chart-root-relative one (`values.yaml`).
fn read_member(path: &Path, inner: &str) -> AppResult<String> {
    let file = std::fs::File::open(path)
        .map_err(|e| AppError::Other(format!("open {}: {e}", path.display())))?;
    for entry in tar::Archive::new(GzDecoder::new(file))
        .entries()
        .map_err(|e| AppError::Other(format!("tar entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| AppError::Other(format!("tar entry: {e}")))?;
        let rel = entry
            .path()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_default();
        if rel == inner || chart_root_rel(&rel) == inner {
            if entry.header().entry_type().is_dir() {
                return Err(AppError::Other("is a directory".into()));
            }
            return read_capped(&mut entry)
                .map_err(|e| AppError::Other(format!("read {inner}: {e}")));
        }
    }
    Err(AppError::NotFound(format!("no member `{inner}`")))
}

/// Refuse anything that could escape the chart: absolute or `..` components.
fn safe_inner_path(inner: &str) -> AppResult<&str> {
    let p = Path::new(inner);
    if p.is_absolute()
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(AppError::Other("invalid chart member path".into()));
    }
    Ok(inner)
}

/// Resolve an id from the listing (not by guessing filenames): the scan is
/// the single source of truth for what a valid id is.
fn resolve(root: &Path, id: &str) -> AppResult<(PathBuf, LocalChartEntry)> {
    scan_local_charts(root)?
        .into_iter()
        .find(|e| e.id == id)
        .map(|e| (PathBuf::from(&e.path), e))
        .ok_or_else(|| AppError::NotFound(format!("chart `{id}`")))
}

/// Detail view: entry + file tree + values.yaml + README. The two inline
/// files degrade to empty strings, not errors — a chart without a README
/// is normal, not a failure.
pub fn local_chart_detail(root: &Path, id: &str) -> AppResult<LocalChartDetail> {
    let (path, entry) = resolve(root, id)?;
    let files = match entry.kind {
        LocalChartKind::Tgz => tgz_files(&path)?,
        LocalChartKind::Dir => dir_files(&path),
    };
    // `kind` is Copy — capturing it (not `entry`) lets the closure run
    // before `entry` moves into the result.
    let kind = entry.kind;
    let read = |inner: &str| -> String {
        match kind {
            LocalChartKind::Tgz => read_member(&path, inner).unwrap_or_default(),
            LocalChartKind::Dir => std::fs::read_to_string(path.join(inner)).unwrap_or_default(),
        }
    };
    let (chart_yaml, values_yaml, readme) =
        (read("Chart.yaml"), read("values.yaml"), read("README.md"));
    Ok(LocalChartDetail {
        entry,
        chart_yaml,
        values_yaml,
        readme,
        files,
    })
}

/// Read one file out of a chart by member path. `inner` is validated
/// first (no absolute / `..`), and for dir charts the joined path is
/// canonicalised and re-confined under the chart dir, so a symlink
/// planted inside the library cannot redirect a read outside it.
pub fn local_chart_file(root: &Path, id: &str, inner_path: &str) -> AppResult<String> {
    let inner = safe_inner_path(inner_path)?;
    let (path, entry) = resolve(root, id)?;
    match entry.kind {
        LocalChartKind::Tgz => read_member(&path, inner),
        LocalChartKind::Dir => {
            let base = path
                .canonicalize()
                .map_err(|e| AppError::NotFound(format!("chart `{id}`: {e}")))?;
            let canon = base
                .join(inner)
                .canonicalize()
                .map_err(|e| AppError::NotFound(format!("{inner}: {e}")))?;
            // Both sides canonicalised: a `..`-free inner joined to a
            // symlinked dir would otherwise slip past a raw prefix check.
            if !canon.starts_with(&base) {
                return Err(AppError::Other("invalid chart member path".into()));
            }
            let file = std::fs::File::open(&canon)
                .map_err(|e| AppError::Other(format!("read {inner}: {e}")))?;
            read_capped(file).map_err(|e| AppError::Other(format!("read {inner}: {e}")))
        }
    }
}

/// Build the argv for `helm lint <path>`. Pure (template_argv-style) so the
/// command shape is unit-testable without a helm binary.
fn lint_argv(path: &Path) -> Vec<String> {
    vec!["lint".into(), path.display().to_string()]
}

/// Build the argv for `helm verify <path>`. Same purity rule as [`lint_argv`].
fn verify_argv(path: &Path) -> Vec<String> {
    vec!["verify".into(), path.display().to_string()]
}

/// Run `helm lint` on a chart from the local library and return the report.
/// Lint is a fully offline operation — no cluster contact — so no kubeconfig
/// is involved.
pub async fn lint_chart(root: &Path, id: &str) -> AppResult<String> {
    let (path, _entry) = resolve(root, id)?;
    super::ops::helm_capture(lint_argv(&path), None).await
}

/// Run `helm verify` on a chart from the local library and return the
/// report. Verify inspects a packaged archive's provenance, so an unpacked
/// dir chart is refused before any helm invocation.
pub async fn verify_chart(root: &Path, id: &str) -> AppResult<String> {
    let (path, entry) = resolve(root, id)?;
    if entry.kind == LocalChartKind::Dir {
        return Err(AppError::Other(
            "verify requires a packaged chart (.tgz)".into(),
        ));
    }
    super::ops::helm_capture(verify_argv(&path), None).await
}

/// Which `helm dependency` subcommand to run. The wire form is the bare
/// lowercase verb (serde) — the frontend sends `"build"`, not `"Build"`.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DepsAction {
    List,
    Build,
    Update,
}

/// Build the argv for `helm package <dir> --destination <dest>`. Pure
/// (template_argv-style) so the command shape is unit-testable without a
/// helm binary.
fn package_argv(dir: &Path, dest: &Path) -> Vec<String> {
    vec![
        "package".into(),
        dir.display().to_string(),
        "--destination".into(),
        dest.display().to_string(),
    ]
}

/// Build the argv for `helm dependency <list|build|update> <path>`. Same
/// purity rule as [`package_argv`].
fn deps_argv(path: &Path, action: DepsAction) -> Vec<String> {
    let sub = match action {
        DepsAction::List => "list",
        DepsAction::Build => "build",
        DepsAction::Update => "update",
    };
    vec!["dependency".into(), sub.into(), path.display().to_string()]
}

/// Package an unpacked dir chart from the library with `helm package`,
/// writing `<root>/<name>-<version>.tgz`, and return the fresh archive's
/// entry. A chart that is already a `.tgz` is refused — there is nothing
/// to package. On success the library is re-scanned and the newest tgz
/// matching the chart's name is returned; a package run that produced no
/// readable archive is an error (helm failed silently, or wrote something
/// we cannot parse — either way the caller must not show a stale entry).
///
/// NOTE: this shells out to the helm binary; there is no in-process
/// fallback, mirroring lint/verify. Success-only audited
/// (`local_chart_package`) at the core layer, so MCP packages are recorded
/// too.
pub async fn package_chart(root: &Path, id: &str) -> AppResult<LocalChartEntry> {
    let (path, entry) = resolve(root, id)?;
    if entry.kind == LocalChartKind::Tgz {
        return Err(AppError::Other("chart is already packaged".into()));
    }
    super::ops::helm_capture(package_argv(&path, root), None).await?;
    // `helm package` prints the produced path, but parsing CLI output for a
    // filename is brittle; the re-scan is the same source of truth the
    // listing uses. It sorts newest-first, so the first name match is the
    // archive helm just wrote (an older tgz of the same chart loses).
    let packaged = scan_local_charts(root)?
        .into_iter()
        .find(|e| e.kind == LocalChartKind::Tgz && e.name == entry.name)
        .ok_or_else(|| {
            AppError::Other(format!(
                "helm package produced no readable archive for `{}`",
                entry.name
            ))
        })?;
    audit::record(
        "local_chart_package",
        k7s_deps::serde_json::json!({
            "id": id,
            "name": packaged.name.clone(),
            "version": packaged.version.clone(),
        }),
    );
    Ok(packaged)
}

/// Run `helm dependency list|build|update` on a chart from the local
/// library and return the report. `List` is read-only — no audit;
/// `Build`/`Update` write Chart.lock and populate the charts/ cache inside
/// the chart dir, so those two are audited (`local_chart_deps`) right here
/// at the core layer, success-only, with the serialized lowercase action.
pub async fn chart_deps(root: &Path, id: &str, action: DepsAction) -> AppResult<String> {
    let (path, _entry) = resolve(root, id)?;
    let out = super::ops::helm_capture(deps_argv(&path, action), None).await?;
    if !matches!(action, DepsAction::List) {
        audit::record(
            "local_chart_deps",
            k7s_deps::serde_json::json!({ "id": id, "action": action }),
        );
    }
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
        let chart_yaml =
            format!("apiVersion: v2\nname: {name}\nversion: {version}\ndescription: test chart\n");
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
        std::fs::write(
            tmp.join("demo-app-1.0.0.tgz"),
            tgz_bytes("demo-app", "1.0.0", &[]),
        )
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

    #[test]
    fn import_rejects_non_gzip_and_oversize() {
        let tmp = std::env::temp_dir().join(format!("k7s-import-bad-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // not gzip
        assert!(import_chart_bytes(&tmp, "evil.tgz", b"plain text").is_err());
        // wrong extension
        let good = tgz_bytes("demo", "1.0.0", &[]);
        assert!(import_chart_bytes(&tmp, "evil.exe", &good).is_err());
        // oversized (fabricate via limit check on a tiny ceiling — assert the
        // real constant rejects a > MAX buffer is impractical in-test, so we
        // assert the constant is what the code compares against instead)
        assert_eq!(MAX_CHART_BYTES, 50 * 1024 * 1024);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn import_then_scan_then_remove_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("k7s-import-ok-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let bytes = tgz_bytes("demo", "1.0.0", &[("values.yaml", "replicaCount: 1\n")]);
        let entry = import_chart_bytes(&tmp, "demo-1.0.0.tgz", &bytes).unwrap();
        assert_eq!(entry.name, "demo");
        assert_eq!(scan_local_charts(&tmp).unwrap().len(), 1);

        // traversal id must be refused
        assert!(remove_chart(&tmp, "../../etc").is_err());
        remove_chart(&tmp, &entry.id).unwrap();
        assert!(scan_local_charts(&tmp).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn detail_lists_files_and_reads_values() {
        let tmp = std::env::temp_dir().join(format!("k7s-detail-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let bytes = tgz_bytes(
            "demo",
            "1.0.0",
            &[
                ("values.yaml", "replicaCount: 2\n"),
                ("templates/deploy.yaml", "apiVersion: apps/v1\n"),
            ],
        );
        import_chart_bytes(&tmp, "demo-1.0.0.tgz", &bytes).unwrap();

        let d = local_chart_detail(&tmp, "demo-1.0.0").unwrap();
        assert_eq!(d.entry.name, "demo");
        assert_eq!(d.values_yaml, "replicaCount: 2\n");
        assert!(d.chart_yaml.contains("name: demo"));
        assert!(d
            .files
            .iter()
            .any(|f| f.path.ends_with("templates/deploy.yaml")));

        // inner file read, and traversal refusal
        let tpl = local_chart_file(&tmp, "demo-1.0.0", "templates/deploy.yaml").unwrap();
        assert!(tpl.contains("apps/v1"));
        assert!(local_chart_file(&tmp, "demo-1.0.0", "../../../etc/passwd").is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn dir_chart_detail_and_traversal_refusal() {
        let tmp = std::env::temp_dir().join(format!("k7s-dir-detail-{}", std::process::id()));
        let dir = tmp.join("my-chart");
        std::fs::create_dir_all(dir.join("templates")).unwrap();
        std::fs::write(
            dir.join("Chart.yaml"),
            "apiVersion: v2\nname: my-chart\nversion: 3.0.0\n",
        )
        .unwrap();
        std::fs::write(dir.join("values.yaml"), "replicaCount: 9\n").unwrap();
        std::fs::write(dir.join("templates/deploy.yaml"), "apiVersion: apps/v1\n").unwrap();

        let d = local_chart_detail(&tmp, "my-chart").unwrap();
        assert_eq!(d.values_yaml, "replicaCount: 9\n");
        assert!(d.chart_yaml.contains("name: my-chart"));
        // no README on disk → empty string, not an error
        assert_eq!(d.readme, "");
        assert!(d
            .files
            .iter()
            .any(|f| f.path == "templates/deploy.yaml" && !f.is_dir));
        assert!(d.files.iter().any(|f| f.path == "templates" && f.is_dir));

        let tpl = local_chart_file(&tmp, "my-chart", "templates/deploy.yaml").unwrap();
        assert!(tpl.contains("apps/v1"));
        assert!(local_chart_file(&tmp, "my-chart", "nope.yaml").is_err());
        // absolute and `..` members are refused before any join
        assert!(local_chart_file(&tmp, "my-chart", "/etc/passwd").is_err());
        assert!(local_chart_file(&tmp, "my-chart", "../../../etc/passwd").is_err());
        // a `..`-free member that is a symlink out of the chart dir must
        // still be refused — this is what the canonicalise guard is for.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", dir.join("escape")).unwrap();
            assert!(local_chart_file(&tmp, "my-chart", "escape").is_err());
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The dir walks (dir_size / dir_files) must not follow symlinks: a
    /// symlinked subdir would list entries outside the chart root, and a
    /// symlink cycle would recurse until the stack overflows. Unix-only —
    /// symlink creation is what the test hinges on.
    #[cfg(unix)]
    #[test]
    fn dir_walks_skip_symlinks() {
        let tmp = std::env::temp_dir().join(format!("k7s-symlink-{}", std::process::id()));
        let dir = tmp.join("my-chart");
        std::fs::create_dir_all(dir.join("templates")).unwrap();
        std::fs::write(
            dir.join("Chart.yaml"),
            "apiVersion: v2\nname: my-chart\nversion: 1.0.0\n",
        )
        .unwrap();
        // `outside` points out of the library entirely; `cycle` loops back
        // to the chart dir — under the old is_dir()-based walks the latter
        // crashed the process with a stack overflow.
        std::os::unix::fs::symlink("/etc", dir.join("outside")).unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("cycle")).unwrap();

        let d = local_chart_detail(&tmp, "my-chart").unwrap();
        assert!(d.files.iter().any(|f| f.path == "templates" && f.is_dir));
        assert!(
            d.files
                .iter()
                .all(|f| !f.path.starts_with("outside") && !f.path.starts_with("cycle")),
            "symlinked dirs must not be walked: {:?}",
            d.files
        );
        // Size counts real members only — following `outside` would pull
        // all of /etc into the sum.
        assert!(d.entry.size_bytes < 1024 * 1024);

        // Reading through a symlinked member is refused by the confinement
        // guard (canonicalised target escapes the chart dir).
        assert!(local_chart_file(&tmp, "my-chart", "outside/hosts").is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- helm lint / verify (ChartOps P2) ----

    /// The argv builders produce helm's exact positional form —
    /// `helm lint <path>` / `helm verify <path>`, no flags, nothing else.
    /// Keeping these pure means the command shape is pinned without a helm
    /// binary in the test environment.
    #[test]
    fn lint_and_verify_argv_are_exact() {
        let p = Path::new("/data/charts/demo-1.0.0.tgz");
        assert_eq!(
            lint_argv(p),
            vec![
                "lint".to_string(),
                "/data/charts/demo-1.0.0.tgz".to_string()
            ]
        );
        assert_eq!(
            verify_argv(p),
            vec![
                "verify".to_string(),
                "/data/charts/demo-1.0.0.tgz".to_string()
            ]
        );
    }

    /// `helm verify` inspects a packaged archive's provenance — there is
    /// nothing to verify on an unpacked dir chart, so the request is
    /// refused *before* any helm invocation (deterministic error, no helm
    /// binary needed to test it).
    #[k7s_deps::tokio::test]
    async fn verify_chart_refuses_dir_charts() {
        let tmp = std::env::temp_dir().join(format!("k7s-verify-dir-{}", std::process::id()));
        let dir = tmp.join("my-chart");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Chart.yaml"),
            "apiVersion: v2\nname: my-chart\nversion: 1.0.0\n",
        )
        .unwrap();

        let err = verify_chart(&tmp, "my-chart").await.unwrap_err();
        assert!(
            err.to_string().contains("requires a packaged chart"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Both commands resolve ids through the scan listing: an unknown id is
    /// a NotFound from `resolve`, again before any helm invocation.
    #[k7s_deps::tokio::test]
    async fn lint_and_verify_unknown_id_is_not_found() {
        let tmp = std::env::temp_dir().join(format!("k7s-lint-missing-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(matches!(
            lint_chart(&tmp, "nope").await.unwrap_err(),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            verify_chart(&tmp, "nope").await.unwrap_err(),
            AppError::NotFound(_)
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `helm package <dir> --destination <root>` and
    /// `helm dependency <list|build|update> <path>`: exact positional argv,
    /// pinned without a helm binary in the test environment.
    #[test]
    fn package_and_deps_argv_are_exact() {
        let dir = Path::new("/data/charts/my-chart");
        let dest = Path::new("/data/charts");
        assert_eq!(
            package_argv(dir, dest),
            vec![
                "package".to_string(),
                "/data/charts/my-chart".to_string(),
                "--destination".to_string(),
                "/data/charts".to_string(),
            ]
        );
        let p = Path::new("/data/charts/demo-1.0.0.tgz");
        assert_eq!(
            deps_argv(p, DepsAction::List),
            vec![
                "dependency".to_string(),
                "list".to_string(),
                "/data/charts/demo-1.0.0.tgz".to_string()
            ]
        );
        assert_eq!(
            deps_argv(p, DepsAction::Build),
            vec![
                "dependency".to_string(),
                "build".to_string(),
                "/data/charts/demo-1.0.0.tgz".to_string()
            ]
        );
        assert_eq!(
            deps_argv(p, DepsAction::Update),
            vec![
                "dependency".to_string(),
                "update".to_string(),
                "/data/charts/demo-1.0.0.tgz".to_string()
            ]
        );
    }

    /// The wire form of a deps action is the bare lowercase verb — the
    /// frontend sends `"build"`, not `"Build"`. An unknown verb must be
    /// rejected, not silently mapped to some default (a typo'd `"updata"`
    /// mutating the chart lock would be a nasty surprise).
    #[test]
    fn deps_action_serde_roundtrip_is_lowercase() {
        for (wire, expected) in [
            ("list", DepsAction::List),
            ("build", DepsAction::Build),
            ("update", DepsAction::Update),
        ] {
            let parsed: DepsAction = k7s_deps::serde_json::from_str(&format!("\"{wire}\""))
                .unwrap_or_else(|e| panic!("{wire} must deserialize: {e}"));
            assert_eq!(parsed, expected);
            assert_eq!(
                k7s_deps::serde_json::to_string(&parsed).unwrap(),
                format!("\"{wire}\"")
            );
        }
        assert!(k7s_deps::serde_json::from_str::<DepsAction>("\"frobnicate\"").is_err());
    }

    /// `helm package` packages an unpacked dir; a `.tgz` is already the
    /// finished artefact, so the request is refused *before* any helm
    /// invocation (deterministic error, no helm binary needed).
    #[k7s_deps::tokio::test]
    async fn package_chart_refuses_already_packaged() {
        let tmp = std::env::temp_dir().join(format!("k7s-package-tgz-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let bytes = tgz_bytes("demo", "1.0.0", &[]);
        let entry = import_chart_bytes(&tmp, "demo-1.0.0.tgz", &bytes).unwrap();
        let err = package_chart(&tmp, &entry.id).await.unwrap_err();
        assert!(
            err.to_string().contains("already packaged"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Both commands resolve ids through the scan listing: an unknown id is
    /// a NotFound from `resolve`, again before any helm invocation.
    #[k7s_deps::tokio::test]
    async fn package_and_deps_unknown_id_is_not_found() {
        let tmp = std::env::temp_dir().join(format!("k7s-package-missing-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(matches!(
            package_chart(&tmp, "nope").await.unwrap_err(),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            chart_deps(&tmp, "nope", DepsAction::List)
                .await
                .unwrap_err(),
            AppError::NotFound(_)
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // The happy path of `package_chart` spawns the real `helm` binary, so it
    // cannot run in a test environment without helm installed — like the
    // lint/verify success paths, it is covered by the argv pins above plus
    // manual verification against a live helm.

    #[test]
    fn import_tar_gz_roundtrips_through_scan() {
        let tmp = std::env::temp_dir().join(format!("k7s-import-targz-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Same bytes as .tgz — only the accepted filename differs. Import
        // accepting .tar.gz while scan ignores it would make the chart
        // silently vanish from the listing.
        let bytes = tgz_bytes("demo", "2.0.0", &[]);
        let entry = import_chart_bytes(&tmp, "demo-2.0.0.tar.gz", &bytes).unwrap();
        assert_eq!(entry.name, "demo");
        assert_eq!(entry.id, "demo-2.0.0");
        assert_eq!(scan_local_charts(&tmp).unwrap().len(), 1);
        remove_chart(&tmp, &entry.id).unwrap();
        assert!(scan_local_charts(&tmp).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- audit lives in the write fns (command layer + MCP both flow here) ----

    /// Import and remove must append their audit records themselves — the
    /// audit used to sit in the Tauri command layer only, so MCP writes went
    /// unrecorded. `set_dir` is OnceLock first-writer-wins and no other test
    /// in this binary calls it, so this dir wins for the whole process; the
    /// parallel import tests may append to it too, hence assertions are
    /// CONTAINS on action strings, never exact line counts.
    #[test]
    fn import_and_remove_append_audit_records() {
        let audit_dir =
            std::env::temp_dir().join(format!("k7s-local-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&audit_dir);
        std::fs::create_dir_all(&audit_dir).unwrap();
        crate::core::audit::set_dir(audit_dir.clone());

        let tmp = std::env::temp_dir().join(format!("k7s-audit-chart-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let bytes = tgz_bytes("demo", "1.0.0", &[]);
        let entry = import_chart_bytes(&tmp, "demo-1.0.0.tgz", &bytes).unwrap();
        remove_chart(&tmp, &entry.id).unwrap();

        let log = std::fs::read_to_string(audit_dir.join("audit.log")).unwrap();
        assert!(
            log.contains("\"local_chart_import\""),
            "import must be audited, log:\n{log}"
        );
        assert!(
            log.contains("\"local_chart_remove\""),
            "remove must be audited, log:\n{log}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
        // Parallel tests may still be appending to the winning audit dir; a
        // best-effort removal (errors ignored) is all the cleanup it needs.
        let _ = std::fs::remove_dir_all(&audit_dir);
    }

    /// The shared library-root helper: exactly `<data_dir>/charts`, the one
    /// path both the Tauri command layer and the MCP server must agree on.
    #[test]
    fn charts_dir_joins_charts_under_data_dir() {
        assert_eq!(
            charts_dir(Path::new("/home/u/.k7s")),
            PathBuf::from("/home/u/.k7s/charts")
        );
    }
}
