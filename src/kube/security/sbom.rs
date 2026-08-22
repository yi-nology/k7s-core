//! SBOM (Software Bill of Materials) generation and management.
//!
//! Supports three-tier fallback: trivy -> grype -> native parser.
//! Outputs CycloneDX and SPDX formats.

use k7s_deps::chrono::{DateTime, Utc};
use k7s_deps::uuid::Uuid;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use k7s_deps::tokio::process::Command;

/// SBOM generation source
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum SbomSource {
    Image {
        image_ref: String,
        namespace: String,
        pod: Option<String>,
    },
    Cluster {
        context: String,
    },
}

/// SBOM output format
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

impl SbomFormat {
    pub fn as_str(&self) -> &str {
        match self {
            Self::CycloneDx => "cyclonedx",
            Self::Spdx => "spdx",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cyclonedx" | "cyclone-dx" => Some(Self::CycloneDx),
            "spdx" => Some(Self::Spdx),
            _ => None,
        }
    }
}

/// A component in the SBOM
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub component_type: String,
    pub licenses: Vec<String>,
    pub supplier: Option<String>,
    pub hashes: Vec<String>,
}

/// Dependency relationship
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomDependency {
    pub ref_id: String,
    pub depends_on: Vec<String>,
}

/// Vulnerability associated with SBOM components
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomVulnerability {
    pub id: String,
    pub severity: String,
    pub affected_components: Vec<String>,
    pub description: Option<String>,
    pub fixed_version: Option<String>,
}

/// Metadata about the SBOM generation
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomMetadata {
    pub tool: String,
    pub tool_version: String,
    pub scan_duration_ms: u64,
}

/// Complete SBOM result
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomResult {
    pub id: String,
    pub source: SbomSource,
    pub format: SbomFormat,
    pub spec_version: String,
    pub metadata: SbomMetadata,
    pub components: Vec<SbomComponent>,
    pub dependencies: Vec<SbomDependency>,
    pub vulnerabilities: Vec<SbomVulnerability>,
    pub raw_output: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Summary for history listing
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomSummary {
    pub id: String,
    pub source: SbomSource,
    pub format: SbomFormat,
    pub component_count: usize,
    pub vulnerability_count: usize,
    pub tool: String,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tool detection — re-export from image_scan to avoid duplication
// ---------------------------------------------------------------------------

/// Re-export trivy/grype detection from image_scan module.
pub use crate::kube::image::scan::{which_grype, which_trivy};

// ---------------------------------------------------------------------------
// SBOM generation
// ---------------------------------------------------------------------------

/// Generate SBOM via trivy.
pub async fn generate_via_trivy(
    trivy_path: &str,
    image_ref: &str,
    format: &SbomFormat,
    timeout: &str,
) -> AppResult<SbomResult> {
    let start = std::time::Instant::now();
    let format_flag = match format {
        SbomFormat::CycloneDx => "cyclonedx",
        SbomFormat::Spdx => "spdx-json",
    };

    let output = Command::new(trivy_path)
        .args([
            "image",
            "--format",
            format_flag,
            "--output",
            "/dev/stdout",
            "--quiet",
            "--timeout",
            timeout,
            image_ref,
        ])
        .output()
        .await
        .map_err(|e| AppError::Other(format!("Failed to run trivy: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Other(format!("trivy failed: {stderr}")));
    }

    let raw = String::from_utf8(output.stdout)
        .map_err(|e| AppError::Other(format!("Invalid UTF-8 from trivy: {e}")))?;
    let elapsed = start.elapsed().as_millis() as u64;

    parse_trivy_sbom(&raw, image_ref, format, elapsed)
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse trivy JSON output into SbomResult.
fn parse_trivy_sbom(
    raw: &str,
    image_ref: &str,
    format: &SbomFormat,
    elapsed_ms: u64,
) -> AppResult<SbomResult> {
    let value: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(raw)
        .map_err(|e| AppError::Other(format!("Failed to parse trivy output: {e}")))?;

    let spec_version = match format {
        SbomFormat::CycloneDx => value["specVersion"].as_str().unwrap_or("1.5").to_string(),
        SbomFormat::Spdx => value["spdxVersion"]
            .as_str()
            .unwrap_or("SPDX-2.3")
            .to_string(),
    };

    let tool_version = value["metadata"]["tools"]["components"]
        .as_array()
        .and_then(|t| t.first())
        .and_then(|t| t["version"].as_str())
        .unwrap_or("unknown")
        .to_string();

    let components = parse_trivy_components(&value, format);

    Ok(SbomResult {
        id: Uuid::new_v4().to_string(),
        source: SbomSource::Image {
            image_ref: image_ref.to_string(),
            namespace: String::new(),
            pod: None,
        },
        format: format.clone(),
        spec_version,
        metadata: SbomMetadata {
            tool: "trivy".to_string(),
            tool_version,
            scan_duration_ms: elapsed_ms,
        },
        components,
        dependencies: vec![],
        vulnerabilities: vec![],
        raw_output: Some(raw.to_string()),
        created_at: k7s_deps::chrono::Utc::now(),
    })
}

/// Extract components from trivy output.
fn parse_trivy_components(
    value: &k7s_deps::serde_json::Value,
    format: &SbomFormat,
) -> Vec<SbomComponent> {
    match format {
        SbomFormat::CycloneDx => value["components"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|c| SbomComponent {
                        name: c["name"].as_str().unwrap_or("").to_string(),
                        version: c["version"].as_str().unwrap_or("").to_string(),
                        purl: c["purl"].as_str().map(String::from),
                        cpe: c["cpe"].as_str().map(String::from),
                        component_type: c["type"].as_str().unwrap_or("library").to_string(),
                        licenses: c["licenses"]
                            .as_array()
                            .map(|l| {
                                l.iter()
                                    .filter_map(|v| v["id"].as_str().or(v["name"].as_str()))
                                    .map(String::from)
                                    .collect()
                            })
                            .unwrap_or_default(),
                        supplier: c["supplier"]["name"].as_str().map(String::from),
                        hashes: c["hashes"]
                            .as_array()
                            .map(|h| {
                                h.iter()
                                    .filter_map(|v| v["content"].as_str())
                                    .map(String::from)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        SbomFormat::Spdx => value["packages"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|p| SbomComponent {
                        name: p["name"].as_str().unwrap_or("").to_string(),
                        version: p["versionInfo"].as_str().unwrap_or("").to_string(),
                        purl: p["externalRefs"]
                            .as_array()
                            .and_then(|refs| {
                                refs.iter()
                                    .find(|r| r["referenceType"].as_str() == Some("purl"))
                                    .and_then(|r| r["referenceLocator"].as_str())
                            })
                            .map(String::from),
                        cpe: None,
                        component_type: "library".to_string(),
                        licenses: p["licenseDeclared"]
                            .as_str()
                            .map(|l| vec![l.to_string()])
                            .unwrap_or_default(),
                        supplier: p["supplier"].as_str().map(String::from),
                        hashes: vec![],
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Generate SBOM via grype
// ---------------------------------------------------------------------------

/// Generate SBOM via grype.
pub async fn generate_via_grype(
    grype_path: &str,
    image_ref: &str,
    format: &SbomFormat,
) -> AppResult<SbomResult> {
    let start = std::time::Instant::now();
    let format_flag = match format {
        SbomFormat::CycloneDx => "cyclonedx",
        SbomFormat::Spdx => "spdx-json",
    };

    let output = Command::new(grype_path)
        .args([image_ref, "-o", format_flag])
        .output()
        .await
        .map_err(|e| AppError::Other(format!("Failed to run grype: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Other(format!("grype failed: {stderr}")));
    }

    let raw = String::from_utf8(output.stdout)
        .map_err(|e| AppError::Other(format!("Invalid UTF-8 from grype: {e}")))?;
    let elapsed = start.elapsed().as_millis() as u64;

    parse_grype_sbom(&raw, image_ref, format, elapsed)
}

/// Parse grype JSON output into SbomResult.
fn parse_grype_sbom(
    raw: &str,
    image_ref: &str,
    format: &SbomFormat,
    elapsed_ms: u64,
) -> AppResult<SbomResult> {
    let value: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(raw)
        .map_err(|e| AppError::Other(format!("Failed to parse grype output: {e}")))?;

    let spec_version = match format {
        SbomFormat::CycloneDx => value["specVersion"].as_str().unwrap_or("1.5").to_string(),
        SbomFormat::Spdx => value["spdxVersion"]
            .as_str()
            .unwrap_or("SPDX-2.3")
            .to_string(),
    };

    let components = parse_trivy_components(&value, format);

    // grype SBOM output includes vulnerabilities in a separate array
    let vulnerabilities = value["vulnerabilities"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|v| SbomVulnerability {
                    id: v["id"].as_str().unwrap_or("").to_string(),
                    severity: v["severity"].as_str().unwrap_or("unknown").to_string(),
                    affected_components: v["artifacts"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|art| art["name"].as_str())
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default(),
                    description: v["description"].as_str().map(String::from),
                    fixed_version: v["fix"]["versions"]
                        .as_array()
                        .and_then(|v| v.first())
                        .and_then(|v| v.as_str())
                        .map(String::from),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(SbomResult {
        id: Uuid::new_v4().to_string(),
        source: SbomSource::Image {
            image_ref: image_ref.to_string(),
            namespace: String::new(),
            pod: None,
        },
        format: format.clone(),
        spec_version,
        metadata: SbomMetadata {
            tool: "grype".to_string(),
            tool_version: "unknown".to_string(),
            scan_duration_ms: elapsed_ms,
        },
        components,
        dependencies: vec![],
        vulnerabilities,
        raw_output: Some(raw.to_string()),
        created_at: k7s_deps::chrono::Utc::now(),
    })
}

// ---------------------------------------------------------------------------
// Native fallback: basic SBOM generation without external tools
// ---------------------------------------------------------------------------

/// Native fallback: basic SBOM generation without external tools.
/// Uses `docker inspect` to extract basic image metadata.
/// Only supports CycloneDX format. Returns a minimal SBOM.
pub async fn generate_native(image_ref: &str, format: &SbomFormat) -> AppResult<SbomResult> {
    let start = std::time::Instant::now();

    if *format == SbomFormat::Spdx {
        return Err(AppError::Other(
            "SPDX format not supported in native fallback mode. Install trivy or grype for full format support.".to_string(),
        ));
    }

    let config_json = get_image_config(image_ref).await?;
    let elapsed = start.elapsed().as_millis() as u64;
    let components = extract_components_from_config(&config_json);

    Ok(SbomResult {
        id: Uuid::new_v4().to_string(),
        source: SbomSource::Image {
            image_ref: image_ref.to_string(),
            namespace: String::new(),
            pod: None,
        },
        format: SbomFormat::CycloneDx,
        spec_version: "1.5".to_string(),
        metadata: SbomMetadata {
            tool: "native".to_string(),
            tool_version: "0.1.0".to_string(),
            scan_duration_ms: elapsed,
        },
        components,
        dependencies: vec![],
        vulnerabilities: vec![],
        raw_output: None,
        created_at: k7s_deps::chrono::Utc::now(),
    })
}

/// Try to get image config via docker inspect.
async fn get_image_config(image_ref: &str) -> AppResult<k7s_deps::serde_json::Value> {
    let output = Command::new("docker")
        .args(["inspect", image_ref])
        .output()
        .await
        .map_err(|e| AppError::Other(format!("Failed to run docker inspect: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Other(format!(
            "docker inspect failed (is docker installed and running?): {stderr}"
        )));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let arr: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(&raw)
        .map_err(|e| AppError::Other(format!("Failed to parse docker inspect output: {e}")))?;

    arr.as_array()
        .and_then(|a| a.first())
        .cloned()
        .ok_or_else(|| AppError::Other("Empty docker inspect output".to_string()))
}

/// Extract basic components from image config.
fn extract_components_from_config(config: &k7s_deps::serde_json::Value) -> Vec<SbomComponent> {
    let mut components = vec![];

    // Extract OS info
    if let Some(os) = config["Os"].as_str().or(config["os"].as_str()) {
        components.push(SbomComponent {
            name: os.to_string(),
            version: config["OsVersion"]
                .as_str()
                .or(config["os_version"].as_str())
                .unwrap_or("unknown")
                .to_string(),
            purl: None,
            cpe: None,
            component_type: "operating-system".to_string(),
            licenses: vec![],
            supplier: None,
            hashes: vec![],
        });
    }

    // Extract from history (package installations)
    if let Some(history) = config["History"]
        .as_array()
        .or(config["history"].as_array())
    {
        for entry in history {
            if let Some(created_by) = entry["created_by"].as_str() {
                let packages = parse_packages_from_history(created_by);
                components.extend(packages);
            }
        }
    }

    components
}

/// Parse package names from Dockerfile history commands.
fn parse_packages_from_history(cmd: &str) -> Vec<SbomComponent> {
    let mut packages = vec![];
    let make_component = |name: &str| SbomComponent {
        name: name.to_string(),
        version: "unknown".to_string(),
        purl: None,
        cpe: None,
        component_type: "library".to_string(),
        licenses: vec![],
        supplier: None,
        hashes: vec![],
    };

    // apt-get install / apt install — state machine after "install" keyword
    if cmd.contains("apt-get install") || cmd.contains("apt install") {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let mut after_install = false;
        for part in parts {
            if part == "install" {
                after_install = true;
                continue;
            }
            if after_install {
                // Stop at shell operators
                if part == "&&" || part == ";" || part == "|" {
                    break;
                }
                // Skip flags (e.g. -y, --no-install-recommends)
                if part.starts_with('-') {
                    continue;
                }
                if !part.is_empty() {
                    packages.push(make_component(part));
                }
            }
        }
    }

    // apk add — state machine after "add" keyword
    if cmd.contains("apk add") {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let mut after_add = false;
        for part in parts {
            if part == "add" {
                after_add = true;
                continue;
            }
            if after_add {
                // Stop at shell operators
                if part == "&&" || part == ";" || part == "|" {
                    break;
                }
                // Skip flags
                if part.starts_with('-') {
                    continue;
                }
                if !part.is_empty() {
                    packages.push(make_component(part));
                }
            }
        }
    }

    packages
}

// ---------------------------------------------------------------------------
// SBOM Engine: three-tier fallback orchestration
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

/// Cached tool detection results to avoid spawning processes on every call.
static TRIVY_PATH: OnceLock<Option<String>> = OnceLock::new();
static GRYPE_PATH: OnceLock<Option<String>> = OnceLock::new();

/// Get cached trivy path, detecting once per process lifetime.
fn cached_trivy_path() -> &'static Option<String> {
    TRIVY_PATH.get_or_init(which_trivy)
}

/// Get cached grype path, detecting once per process lifetime.
fn cached_grype_path() -> &'static Option<String> {
    GRYPE_PATH.get_or_init(which_grype)
}

/// If `custom` is a non-empty string and the path exists on disk, use it;
/// otherwise fall back to the auto-detected cached value.
fn resolve_path_or_auto(custom: Option<&str>, auto: &'static Option<String>) -> Option<String> {
    if let Some(p) = custom {
        let trimmed = p.trim();
        if !trimmed.is_empty() && std::path::Path::new(trimmed).is_file() {
            return Some(trimmed.to_string());
        }
    }
    auto.clone()
}

/// SBOM generation engine with three-tier fallback.
pub struct SbomEngine {
    trivy_path: Option<String>,
    grype_path: Option<String>,
    /// Timeout string passed to trivy (e.g. "5m", "300s").
    timeout: String,
}

impl Default for SbomEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomEngine {
    /// Create a new engine, using cached tool detection results.
    pub fn new() -> Self {
        Self {
            trivy_path: cached_trivy_path().clone(),
            grype_path: cached_grype_path().clone(),
            timeout: "5m".to_string(),
        }
    }

    /// Create an engine with custom binary paths and timeout from user prefs.
    /// Each path, if non-empty, overrides the auto-detected value.
    pub fn with_prefs(
        custom_trivy_path: Option<&str>,
        custom_grype_path: Option<&str>,
        timeout: Option<&str>,
    ) -> Self {
        let trivy_path = resolve_path_or_auto(custom_trivy_path, cached_trivy_path());
        let grype_path = resolve_path_or_auto(custom_grype_path, cached_grype_path());
        let timeout = timeout
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("5m")
            .to_string();
        Self {
            trivy_path,
            grype_path,
            timeout,
        }
    }

    /// Generate SBOM for a single image with three-tier fallback.
    /// Falls through to the next tier on execution failure, not just missing binary.
    pub async fn generate_image_sbom(
        &self,
        image_ref: &str,
        format: &SbomFormat,
    ) -> AppResult<SbomResult> {
        // Tier 1: trivy
        if let Some(ref path) = self.trivy_path {
            match generate_via_trivy(path, image_ref, format, &self.timeout).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    k7s_deps::tracing::warn!("trivy SBOM generation failed, falling back: {e}")
                }
            }
        }
        // Tier 2: grype
        if let Some(ref path) = self.grype_path {
            match generate_via_grype(path, image_ref, format).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    k7s_deps::tracing::warn!("grype SBOM generation failed, falling back: {e}")
                }
            }
        }
        // Tier 3: native fallback
        generate_native(image_ref, format).await
    }

    /// Generate SBOM with vulnerability correlation via trivy.
    pub async fn generate_with_vulns(
        &self,
        image_ref: &str,
        format: &SbomFormat,
    ) -> AppResult<SbomResult> {
        let mut sbom = self.generate_image_sbom(image_ref, format).await?;

        if let Some(ref path) = self.trivy_path {
            let vulns = scan_vulnerabilities(path, image_ref, &self.timeout).await?;
            sbom.vulnerabilities = vulns;
        }

        Ok(sbom)
    }

    /// Check which tools are available.
    pub fn available_tools(&self) -> Vec<&str> {
        let mut tools = vec![];
        if self.trivy_path.is_some() {
            tools.push("trivy");
        }
        if self.grype_path.is_some() {
            tools.push("grype");
        }
        tools.push("native");
        tools
    }
}

/// Run trivy vulnerability scan and return findings.
async fn scan_vulnerabilities(
    trivy_path: &str,
    image_ref: &str,
    timeout: &str,
) -> AppResult<Vec<SbomVulnerability>> {
    let output = Command::new(trivy_path)
        .args([
            "image",
            "--format",
            "json",
            "--quiet",
            "--timeout",
            timeout,
            image_ref,
        ])
        .output()
        .await
        .map_err(|e| AppError::Other(format!("trivy vuln scan failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        k7s_deps::tracing::warn!("trivy vulnerability scan failed for {image_ref}: {stderr}");
        return Err(AppError::Other(format!(
            "trivy vulnerability scan failed: {stderr}"
        )));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let value: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(&raw)
        .map_err(|e| AppError::Other(format!("Failed to parse trivy vuln output: {e}")))?;

    let vulns = value["Results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r["Vulnerabilities"].as_array().into_iter().flatten())
                .map(|v| SbomVulnerability {
                    id: v["VulnerabilityID"].as_str().unwrap_or("").to_string(),
                    severity: v["Severity"].as_str().unwrap_or("unknown").to_string(),
                    affected_components: vec![v["PkgName"].as_str().unwrap_or("").to_string()],
                    description: v["Description"].as_str().map(String::from),
                    fixed_version: v["FixedVersion"].as_str().map(String::from),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(vulns)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SbomFormat
    // -----------------------------------------------------------------------

    #[test]
    fn sbom_format_from_str_cyclonedx() {
        assert_eq!(SbomFormat::parse("cyclonedx"), Some(SbomFormat::CycloneDx));
        assert_eq!(SbomFormat::parse("CycloneDX"), Some(SbomFormat::CycloneDx));
        assert_eq!(SbomFormat::parse("cyclone-dx"), Some(SbomFormat::CycloneDx));
    }

    #[test]
    fn sbom_format_from_str_spdx() {
        assert_eq!(SbomFormat::parse("spdx"), Some(SbomFormat::Spdx));
        assert_eq!(SbomFormat::parse("SPDX"), Some(SbomFormat::Spdx));
    }

    #[test]
    fn sbom_format_from_str_unknown() {
        assert_eq!(SbomFormat::parse("unknown"), None);
        assert_eq!(SbomFormat::parse(""), None);
    }

    #[test]
    fn sbom_format_as_str_roundtrip() {
        assert_eq!(SbomFormat::CycloneDx.as_str(), "cyclonedx");
        assert_eq!(SbomFormat::Spdx.as_str(), "spdx");
        // Roundtrip
        for fmt in [SbomFormat::CycloneDx, SbomFormat::Spdx] {
            assert_eq!(SbomFormat::parse(fmt.as_str()), Some(fmt));
        }
    }

    // -----------------------------------------------------------------------
    // SbomSource serialization
    // -----------------------------------------------------------------------

    #[test]
    fn sbom_source_image_serde_roundtrip() {
        let source = SbomSource::Image {
            image_ref: "nginx:1.25".to_string(),
            namespace: "default".to_string(),
            pod: Some("nginx-abc123".to_string()),
        };
        let json = k7s_deps::serde_json::to_string(&source).unwrap();
        let deserialized: SbomSource = k7s_deps::serde_json::from_str(&json).unwrap();
        match deserialized {
            SbomSource::Image {
                image_ref,
                namespace,
                pod,
            } => {
                assert_eq!(image_ref, "nginx:1.25");
                assert_eq!(namespace, "default");
                assert_eq!(pod, Some("nginx-abc123".to_string()));
            }
            _ => panic!("Expected Image variant"),
        }
    }

    #[test]
    fn sbom_source_cluster_serde_roundtrip() {
        let source = SbomSource::Cluster {
            context: "production".to_string(),
        };
        let json = k7s_deps::serde_json::to_string(&source).unwrap();
        let deserialized: SbomSource = k7s_deps::serde_json::from_str(&json).unwrap();
        match deserialized {
            SbomSource::Cluster { context } => {
                assert_eq!(context, "production");
            }
            _ => panic!("Expected Cluster variant"),
        }
    }

    // -----------------------------------------------------------------------
    // SbomResult serialization
    // -----------------------------------------------------------------------

    #[test]
    fn sbom_result_serde_roundtrip() {
        let result = SbomResult {
            id: "test-id-001".to_string(),
            source: SbomSource::Image {
                image_ref: "alpine:3.19".to_string(),
                namespace: "default".to_string(),
                pod: None,
            },
            format: SbomFormat::CycloneDx,
            spec_version: "1.5".to_string(),
            metadata: SbomMetadata {
                tool: "trivy".to_string(),
                tool_version: "0.52.0".to_string(),
                scan_duration_ms: 1234,
            },
            components: vec![SbomComponent {
                name: "musl".to_string(),
                version: "1.2.5".to_string(),
                purl: Some("pkg:apk/alpine/musl@1.2.5".to_string()),
                cpe: None,
                component_type: "library".to_string(),
                licenses: vec!["MIT".to_string()],
                supplier: None,
                hashes: vec![],
            }],
            dependencies: vec![],
            vulnerabilities: vec![SbomVulnerability {
                id: "CVE-2024-TEST".to_string(),
                severity: "high".to_string(),
                affected_components: vec!["musl".to_string()],
                description: Some("Test vulnerability".to_string()),
                fixed_version: Some("1.2.6".to_string()),
            }],
            raw_output: None,
            created_at: k7s_deps::chrono::Utc::now(),
        };

        let json = k7s_deps::serde_json::to_string_pretty(&result).unwrap();
        let deserialized: SbomResult = k7s_deps::serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, "test-id-001");
        assert_eq!(deserialized.format, SbomFormat::CycloneDx);
        assert_eq!(deserialized.spec_version, "1.5");
        assert_eq!(deserialized.metadata.tool, "trivy");
        assert_eq!(deserialized.components.len(), 1);
        assert_eq!(deserialized.components[0].name, "musl");
        assert_eq!(deserialized.vulnerabilities.len(), 1);
        assert_eq!(deserialized.vulnerabilities[0].id, "CVE-2024-TEST");
    }

    // -----------------------------------------------------------------------
    // parse_packages_from_history
    // -----------------------------------------------------------------------

    #[test]
    fn parse_apt_get_install() {
        let cmd = "RUN /bin/sh -c apt-get update && apt-get install -y curl wget ca-certificates";
        let packages = parse_packages_from_history(cmd);
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["curl", "wget", "ca-certificates"]);
    }

    #[test]
    fn parse_apt_get_no_false_positives() {
        // Must NOT include "RUN", "update", "rm", etc.
        let cmd = "RUN /bin/sh -c apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*";
        let packages = parse_packages_from_history(cmd);
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["curl"]);
    }

    #[test]
    fn parse_apt_install_short_form() {
        let cmd = "RUN apt install -y vim";
        let packages = parse_packages_from_history(cmd);
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["vim"]);
    }

    #[test]
    fn parse_apk_add() {
        let cmd = "/bin/sh -c apk add --no-cache openssl libssl3";
        let packages = parse_packages_from_history(cmd);
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["openssl", "libssl3"]);
    }

    #[test]
    fn parse_apk_add_no_false_positives() {
        // Must NOT include "rm" after "&&"
        let cmd = "/bin/sh -c apk add --no-cache openssl && rm -rf /var/cache/apk/*";
        let packages = parse_packages_from_history(cmd);
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["openssl"]);
    }

    #[test]
    fn parse_history_no_packages() {
        let cmd = "RUN /bin/sh -c echo hello";
        let packages = parse_packages_from_history(cmd);
        assert!(packages.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_trivy_components (CycloneDX)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_trivy_components_cyclonedx() {
        let json = k7s_deps::serde_json::json!({
            "components": [
                {
                    "name": "openssl",
                    "version": "3.1.4",
                    "purl": "pkg:apk/alpine/openssl@3.1.4",
                    "type": "library",
                    "licenses": [{"id": "Apache-2.0"}]
                },
                {
                    "name": "zlib",
                    "version": "1.3",
                    "type": "library"
                }
            ]
        });
        let components = parse_trivy_components(&json, &SbomFormat::CycloneDx);
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].name, "openssl");
        assert_eq!(components[0].version, "3.1.4");
        assert_eq!(
            components[0].purl,
            Some("pkg:apk/alpine/openssl@3.1.4".to_string())
        );
        assert_eq!(components[0].licenses, vec!["Apache-2.0"]);
        assert_eq!(components[1].name, "zlib");
        assert!(components[1].licenses.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_trivy_components (SPDX)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_trivy_components_spdx() {
        let json = k7s_deps::serde_json::json!({
            "packages": [
                {
                    "name": "bash",
                    "versionInfo": "5.2.15",
                    "licenseDeclared": "GPL-3.0"
                }
            ]
        });
        let components = parse_trivy_components(&json, &SbomFormat::Spdx);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "bash");
        assert_eq!(components[0].version, "5.2.15");
        assert_eq!(components[0].licenses, vec!["GPL-3.0"]);
    }

    #[test]
    fn parse_trivy_components_empty() {
        let json = k7s_deps::serde_json::json!({});
        let components = parse_trivy_components(&json, &SbomFormat::CycloneDx);
        assert!(components.is_empty());
    }

    // -----------------------------------------------------------------------
    // SbomSummary
    // -----------------------------------------------------------------------

    #[test]
    fn sbom_summary_serde() {
        let summary = SbomSummary {
            id: "sum-001".to_string(),
            source: SbomSource::Image {
                image_ref: "node:20".to_string(),
                namespace: "prod".to_string(),
                pod: None,
            },
            format: SbomFormat::Spdx,
            component_count: 150,
            vulnerability_count: 5,
            tool: "trivy".to_string(),
            created_at: k7s_deps::chrono::Utc::now(),
        };
        let json = k7s_deps::serde_json::to_string(&summary).unwrap();
        let deserialized: SbomSummary = k7s_deps::serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "sum-001");
        assert_eq!(deserialized.component_count, 150);
        assert_eq!(deserialized.vulnerability_count, 5);
        assert_eq!(deserialized.format, SbomFormat::Spdx);
    }
}
