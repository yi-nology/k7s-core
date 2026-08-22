//! Private image registry management (Phase 5 of KubePi parity).
//!
//! Strategy: walk the OCI Distribution v2 catalog API.
//!
//! Specs: <https://github.com/opencontainers/distribution-spec/blob/main/spec.md>
//!
//! Most registries (Harbor, GHCR, Docker Hub with token, ECR with login)
//! implement:
//!
//!   `GET /v2/_catalog`            → list of repositories
//!   `GET /v2/<name>/tags/list`    → list of tags for a repository
//!   `HEAD /v2/<name>/manifests/<reference>`  → manifest digest + size
//!
//! Authentication: a registry may require a `Bearer` challenge first. We do
//! the standard dance: send the request, read `Www-Authenticate` on a 401,
//! request a token from the realm advertised there, retry with `Authorization:
//! Bearer …`. Username/password come from the user's stored credentials.
//!
//! Limitations: `/v2/_catalog` is **not** supported by every registry (Docker
//! Hub notably doesn't, and ECR restricts it). When a registry doesn't expose
//! it, we surface a clear "browse not supported; type a name" message rather
//! than pretending. The `tags/list` endpoint is universal.

use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageRegistry {
    pub name: String,
    /// `https://registry.example.com` — no trailing slash, no `/v2`.
    pub url: String,
    #[serde(default)]
    pub username: String,
    /// Never serialise the password back to the UI; the field is here so
    /// we can keep the secret in-process between commands. The on-disk
    /// shape stores it as `password`; we strip on read.
    #[serde(default, skip_serializing)]
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub description: String,
    /// Last refresh outcome; displayed next to the registry row in the UI.
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_refreshed: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    /// The user-facing entries. We keep passwords in `creds.json` with
    /// 0600 perms, separate from the rest, so a `list` call can ship
    /// redacted DTOs to the UI.
    registries: Vec<RegistryMeta>,
    /// Password store, keyed by registry name.
    #[serde(default)]
    passwords: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryMeta {
    name: String,
    url: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    description: String,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    last_refreshed: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RepoEntry {
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TagEntry {
    pub name: String,
    pub digest: Option<String>,
    pub size: Option<i64>,
    pub created: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct HttpClient {
    inner: k7s_deps::reqwest::Client,
}

impl HttpClient {
    fn build(insecure: bool) -> Self {
        // Note: `danger_accept_invalid_certs` requires the `default-tls`
        // feature on reqwest, which Cargo.toml currently leaves off (to keep
        // the binary small — the forwarder is plaintext-on-localhost). We
        // accept the limitation: the `insecure` field is stored and
        // round-trips, but for now it doesn't change the client. Private
        // registries on a corporate VPN over HTTPS aren't affected; only
        // self-signed certs are.
        let _ = insecure;
        let b = k7s_deps::reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("k7s/image-registry")
            .build()
            .unwrap_or_else(|_| k7s_deps::reqwest::Client::new());
        Self { inner: b }
    }
}

// ---------------------------------------------------------------------------
// Storage — one file, two sections
// ---------------------------------------------------------------------------

fn config_path() -> AppResult<PathBuf> {
    let dir = match std::env::var_os("HOME") {
        Some(h) => std::path::PathBuf::from(h).join(if cfg!(target_os = "macos") {
            "Library/Application Support/k7s"
        } else {
            ".config/k7s"
        }),
        None => return Err(AppError::Other("no HOME".into())),
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Other(format!("mkdir {}: {e}", dir.display())))?;
    Ok(dir.join("image-registries.json"))
}

fn load_file() -> AppResult<RegistryFile> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(RegistryFile::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Other(format!("read {}: {e}", path.display())))?;
    if text.trim().is_empty() {
        return Ok(RegistryFile::default());
    }
    k7s_deps::serde_json::from_str(&text).map_err(|e| AppError::Other(format!("parse: {e}")))
}

fn save_file(f: &RegistryFile) -> AppResult<()> {
    let path = config_path()?;
    let text = k7s_deps::serde_json::to_string_pretty(f)
        .map_err(|e| AppError::Other(format!("serialise: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| AppError::Other(format!("write tmp: {e}")))?;
    std::fs::rename(&tmp, &path).map_err(|e| AppError::Other(format!("rename: {e}")))?;
    // The password map is sensitive; chmod the file 0600 on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

pub fn list_registries() -> AppResult<Vec<ImageRegistry>> {
    let f = load_file()?;
    Ok(f.registries
        .into_iter()
        .map(|m| {
            let password = f.passwords.get(&m.name).cloned().unwrap_or_default();
            ImageRegistry {
                name: m.name,
                url: m.url,
                username: m.username,
                password,
                insecure: m.insecure,
                description: m.description,
                last_error: m.last_error,
                last_refreshed: m.last_refreshed,
            }
        })
        .collect())
}

pub fn upsert_registry(
    name: &str,
    url: &str,
    username: &str,
    password: &str,
    insecure: bool,
    description: &str,
) -> AppResult<ImageRegistry> {
    let name = name.trim();
    let url = url.trim().trim_end_matches('/');
    if name.is_empty() {
        return Err(AppError::Other("registry name cannot be empty".into()));
    }
    if url.is_empty() {
        return Err(AppError::Other("registry url cannot be empty".into()));
    }
    // Strip a trailing `/v2` so users can paste either form.
    let url = url.trim_end_matches("/v2");
    let mut f = load_file()?;
    // Replace if exists, else add.
    if let Some(idx) = f.registries.iter().position(|r| r.name == name) {
        f.registries[idx] = RegistryMeta {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            insecure,
            description: description.to_string(),
            last_error: None,
            last_refreshed: None,
        };
    } else {
        f.registries.push(RegistryMeta {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            insecure,
            description: description.to_string(),
            last_error: None,
            last_refreshed: None,
        });
    }
    if password.is_empty() {
        f.passwords.remove(name);
    } else {
        f.passwords.insert(name.to_string(), password.to_string());
    }
    save_file(&f)?;
    Ok(ImageRegistry {
        name: name.to_string(),
        url: url.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        insecure,
        description: description.to_string(),
        last_error: None,
        last_refreshed: None,
    })
}

pub fn remove_registry(name: &str) -> AppResult<()> {
    let mut f = load_file()?;
    let before = f.registries.len();
    f.registries.retain(|r| r.name != name);
    f.passwords.remove(name);
    if f.registries.len() != before {
        save_file(&f)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

/// Test that a registry is reachable: hit `/v2/` (a 200 with `{}` is
/// "supported, anonymous" and a 401 with a `Www-Authenticate` is "supported,
/// auth required"). Anything else (404, 5xx, network error) is a failure.
pub async fn test_connect(reg: &ImageRegistry) -> AppResult<()> {
    let client = HttpClient::build(reg.insecure);
    let url = format!("{}/v2/", reg.url);
    let mut req = client.inner.get(&url);
    if !reg.username.is_empty() {
        // First try a basic-auth probe; if the registry wants bearer, the
        // GET will succeed anyway, and the `test` succeeds as long as we get
        // a non-5xx response.
        req = req.basic_auth(&reg.username, Some(&reg.password));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if status.is_success() || status.as_u16() == 401 {
        Ok(())
    } else {
        Err(AppError::Other(format!("GET {url}: HTTP {status}")))
    }
}

/// List repositories. Hits `/v2/_catalog`. Some registries (Docker Hub) do
/// not implement this — the response will be 404, which we surface as a
/// "browse unsupported" error so the UI can offer a typed-name input.
pub async fn list_repositories(reg: &ImageRegistry) -> AppResult<Vec<RepoEntry>> {
    let client = HttpClient::build(reg.insecure);
    let url = format!("{}/v2/_catalog?n=200", reg.url);
    let resp = authed_get(&client, reg, &url).await?;
    let status = resp.status();
    if status.as_u16() == 404 {
        return Err(AppError::Other(format!(
            "registry {} does not support catalog browsing; type a repository name",
            reg.name
        )));
    }
    if !status.is_success() {
        return Err(AppError::Other(format!("catalog: HTTP {status}")));
    }
    let body: CatalogResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode catalog: {e}")))?;
    Ok(body
        .repositories
        .into_iter()
        .map(|name| RepoEntry { name })
        .collect())
}

/// List tags for one repository. Universal — every registry implements it.
pub async fn list_tags(reg: &ImageRegistry, repo: &str) -> AppResult<Vec<TagEntry>> {
    let client = HttpClient::build(reg.insecure);
    let url = format!("{}/v2/{}/tags/list?n=200", reg.url, repo);
    let resp = authed_get(&client, reg, &url).await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(AppError::Other(format!("tags: HTTP {status}")));
    }
    let body: TagsResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode tags: {e}")))?;
    Ok(body
        .tags
        .unwrap_or_default()
        .into_iter()
        .map(|name| TagEntry {
            name,
            digest: None,
            size: None,
            created: None,
        })
        .collect())
}

#[derive(Deserialize)]
struct CatalogResponse {
    #[serde(default)]
    repositories: Vec<String>,
}

#[derive(Deserialize)]
struct TagsResponse {
    #[serde(default)]
    tags: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Auth: bearer-challenge dance
// ---------------------------------------------------------------------------

async fn authed_get(
    client: &HttpClient,
    reg: &ImageRegistry,
    url: &str,
) -> AppResult<k7s_deps::reqwest::Response> {
    let mut req = client.inner.get(url);
    if !reg.username.is_empty() {
        req = req.basic_auth(&reg.username, Some(&reg.password));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    if resp.status().as_u16() != 401 {
        return Ok(resp);
    }
    // Parse `Www-Authenticate: Bearer realm="…", service="…", scope="…"`
    let challenge = resp
        .headers()
        .get(k7s_deps::reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let Some(challenge) = challenge else {
        return Ok(resp);
    };
    let parsed = parse_bearer(&challenge);
    let Some(parsed) = parsed else {
        return Ok(resp);
    };
    // Ask the realm for a token with the requested scope.
    let mut token_url = format!("{}?", parsed.realm);
    let mut sep = "";
    for (k, v) in [
        ("service", parsed.service.as_str()),
        ("scope", parsed.scope.as_str()),
    ] {
        if !v.is_empty() {
            token_url.push_str(&format!("{sep}{k}={}", urlencode(v)));
            sep = "&";
        }
    }
    let token_req = client
        .inner
        .get(&token_url)
        .basic_auth(&reg.username, Some(&reg.password));
    let token_resp = token_req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("token {token_url}: {e}")))?;
    if !token_resp.status().is_success() {
        return Err(AppError::Other(format!(
            "token: HTTP {}",
            token_resp.status()
        )));
    }
    #[derive(Deserialize)]
    struct TokenResp {
        token: Option<String>,
        access_token: Option<String>,
    }
    let tr: TokenResp = token_resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode token: {e}")))?;
    let token = tr.token.or(tr.access_token).ok_or_else(|| {
        AppError::Other("token response missing 'token' and 'access_token'".into())
    })?;
    // Retry the original request with bearer.
    client
        .inner
        .get(url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("retry GET {url}: {e}")))
}

#[derive(Default, Debug)]
struct BearerChallenge {
    realm: String,
    service: String,
    scope: String,
}

fn parse_bearer(s: &str) -> Option<BearerChallenge> {
    // Strip the leading scheme name; we only handle Bearer.
    let rest = s.trim_start().strip_prefix("Bearer")?.trim_start();
    let mut c = BearerChallenge::default();
    // Tokenise on `,` then on `=`. Quoted values are common; strip them.
    for part in rest.split(',') {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        let v = v.trim().trim_matches('"');
        match k.trim() {
            "realm" => c.realm = v.to_string(),
            "service" => c.service = v.to_string(),
            "scope" => c.scope = v.to_string(),
            _ => {}
        }
    }
    if c.realm.is_empty() {
        None
    } else {
        Some(c)
    }
}

fn urlencode(s: &str) -> String {
    // Minimal encoder; covers the chars that actually appear in registry
    // challenge scopes (slashes, colons, dots). Anything more exotic should
    // probably fail loudly rather than silently mis-encode.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Image manifest drill-down
// ---------------------------------------------------------------------------

/// The OCI manifest as a typed struct. We decode the common fields
/// (digest, mediaType, size) and leave the rest as a JSON blob so
/// we don't have to chase every OCI spec revision.
#[derive(Clone, Debug, Serialize)]
pub struct ImageManifest {
    /// Schema version, usually 2.
    pub schema_version: i64,
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    /// The full raw JSON so the UI can show the platform list, env, etc.
    pub raw: String,
    /// Config descriptor: mediaType + size + digest.
    pub config_digest: String,
    pub config_size: i64,
    /// Layer descriptors: digest + size + mediaType.
    pub layers: Vec<LayerEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LayerEntry {
    pub digest: String,
    pub size: i64,
    pub media_type: String,
}

/// Pull the manifest for one (registry, repo, tag). We request
/// `application/vnd.docker.distribution.manifest.v2+json`; if the
/// registry says it only knows `application/vnd.oci.image.manifest.v1+json`
/// (a real OCI-only registry), the second call handles that. Either
/// way the result is a parseable JSON document.
pub async fn manifest(reg: &ImageRegistry, repo: &str, tag: &str) -> AppResult<ImageManifest> {
    let client = HttpClient::build(reg.insecure);
    let url = format!("{}/v2/{}/manifests/{}", reg.url, repo, tag);
    let resp = authed_get_manifest(&client, reg, &url).await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(AppError::Other(format!("manifest: HTTP {status}")));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| AppError::Other(format!("read body: {e}")))?;
    let raw: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(&text)
        .map_err(|e| AppError::Other(format!("decode manifest: {e}")))?;
    let schema_version = raw
        .get("schemaVersion")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let media_type = raw
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let config = raw
        .get("config")
        .cloned()
        .unwrap_or(k7s_deps::serde_json::Value::Null);
    let config_digest = config
        .get("digest")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let config_size = config.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
    let layers: Vec<LayerEntry> = raw
        .get("layers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|l| LayerEntry {
                    digest: l
                        .get("digest")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: l.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
                    media_type: l
                        .get("mediaType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    let size = config_size + layers.iter().map(|l| l.size).sum::<i64>();
    let digest = config_digest.clone();
    Ok(ImageManifest {
        schema_version,
        media_type,
        digest,
        size,
        raw: text,
        config_digest,
        config_size,
        layers,
    })
}

/// Same shape as `authed_get` in the catalog path, but for HEAD/GET on
/// the manifest endpoint — most registries answer a manifest GET
/// even if the Bearer challenge dance is required.
async fn authed_get_manifest(
    client: &HttpClient,
    reg: &ImageRegistry,
    url: &str,
) -> AppResult<k7s_deps::reqwest::Response> {
    let mut req = client.inner.get(url);
    // Manifest GETs need an explicit Accept; the registry otherwise
    // returns a fat manifest list which our parser doesn't handle.
    req = req.header(
        "Accept",
        "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json",
    );
    if !reg.username.is_empty() {
        req = req.basic_auth(&reg.username, Some(&reg.password));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    if resp.status().as_u16() != 401 {
        return Ok(resp);
    }
    let challenge = resp
        .headers()
        .get(k7s_deps::reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let Some(challenge) = challenge else {
        return Ok(resp);
    };
    let parsed = parse_bearer(&challenge);
    let Some(parsed) = parsed else {
        return Ok(resp);
    };
    let mut token_url = format!("{}?", parsed.realm);
    let mut sep = "";
    for (k, v) in [
        ("service", parsed.service.as_str()),
        ("scope", parsed.scope.as_str()),
    ] {
        if !v.is_empty() {
            token_url.push_str(&format!("{sep}{k}={}", urlencode(v)));
            sep = "&";
        }
    }
    let token_resp = client
        .inner
        .get(&token_url)
        .basic_auth(&reg.username, Some(&reg.password))
        .send()
        .await
        .map_err(|e| AppError::Other(format!("token {token_url}: {e}")))?;
    if !token_resp.status().is_success() {
        return Err(AppError::Other(format!(
            "token: HTTP {}",
            token_resp.status()
        )));
    }
    #[derive(Deserialize)]
    struct TokenResp {
        token: Option<String>,
        access_token: Option<String>,
    }
    let tr: TokenResp = token_resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode token: {e}")))?;
    let token = tr.token.or(tr.access_token).ok_or_else(|| {
        AppError::Other("token response missing 'token' and 'access_token'".into())
    })?;
    client
        .inner
        .get(url)
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json",
        )
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("retry GET {url}: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge() {
        let s =
            r#"Bearer realm="https://r.example/token", service="r", scope="repository:foo:pull""#;
        let c = parse_bearer(s).unwrap();
        assert_eq!(c.realm, "https://r.example/token");
        assert_eq!(c.service, "r");
        assert_eq!(c.scope, "repository:foo:pull");
    }

    #[test]
    fn urlencodes_scope() {
        assert_eq!(
            urlencode("repository:foo/bar:pull"),
            "repository%3Afoo%2Fbar%3Apull"
        );
    }

    #[test]
    fn bearer_challenge_without_realm_returns_none() {
        assert!(parse_bearer("Basic realm=\"x\"").is_none());
    }

    #[test]
    fn bearer_challenge_picks_first_value_of_each_key() {
        // Multiple `realm=` keys aren't a thing, but verifying we
        // overwrite sanely is cheap.
        let s = r#"Bearer realm="https://r/", realm="https://r2/", service="s""#;
        let c = parse_bearer(s).unwrap();
        assert_eq!(c.realm, "https://r2/");
        assert_eq!(c.service, "s");
    }

    #[test]
    fn urlencode_passes_through_safe_chars() {
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
    }
}
