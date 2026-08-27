//! Helm releases (B26), read from the cluster rather than from the `helm` CLI.
//!
//! Helm stores each release as a Secret of type `helm.sh/release.v1`, whose
//! `release` key holds the release JSON gzipped and base64'd. (Kubernetes then
//! base64s the whole thing again for transport, which the client undoes — so what
//! we get handed is still base64 *text*.) Decoding that is the whole feature:
//! everything Lens shows for a release is in there, including the rendered
//! manifest.
//!
//! Two things the storage format makes easy to get wrong:
//!
//!   - **Every revision is its own Secret.** A release upgraded five times has
//!     `…v1` through `…v5`, of which four are `superseded`. `helm list` shows only
//!     the latest, and so must we, or an upgraded release appears five times.
//!   - **The rendered manifest can contain Secrets**, with their values in the
//!     clear. The app redacts Secret values everywhere else (see
//!     docs/verification.md), so it redacts them here too rather than leaving a
//!     hole behind a different door.
//!
//! Module layout: marketplace in [`market`], repo/rollback ops in [`ops`].

// market shells out to the helm binary via ops — desktop/web only, like ops.
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod market;

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod ops;

use crate::kube::dto::{Cell, Row, Tone};
use k7s_deps::base64::Engine;
use k7s_deps::flate2::read::GzDecoder;
use k7s_deps::k8s_openapi::api::core::v1::Secret;
use k7s_deps::kube::ResourceExt;
use serde::Deserialize;
use std::io::Read;

/// The Secret type Helm uses for release storage.
pub const RELEASE_SECRET_TYPE: &str = "helm.sh/release.v1";

/// A decoded Helm release.
pub struct Release {
    pub name: String,
    pub namespace: String,
    /// Chart name and version, as `helm list` renders it ("traefik-27.0.2").
    pub chart: String,
    pub app_version: String,
    pub revision: i64,
    /// deployed | superseded | failed | pending-install | …
    pub status: String,
    /// RFC3339 last-deployed time, or empty.
    pub updated: String,
    /// e.g. "Install complete", "Upgrade complete".
    pub description: String,
    /// RFC3339 first-deployed time (the release's creation), or empty.
    pub first_deployed: String,
    /// The user-supplied values overrides (Helm's `config`); an object, possibly
    /// empty. Chart defaults live under `chart.values` and are deliberately not
    /// surfaced — "what did *I* set" is the question this answers (B35).
    pub config: k7s_deps::serde_json::Value,
    /// The rendered manifest, with any Secret values redacted.
    pub manifest: String,
}

// ---------------------------------------------------------------------------
// The on-disk shape (only the parts we use; Helm's JSON is much larger)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ReleaseJson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: String,
    /// The revision number. Helm calls it "version"; the CLI shows "REVISION".
    #[serde(default)]
    version: i64,
    #[serde(default)]
    info: InfoJson,
    #[serde(default)]
    chart: ChartJson,
    /// User-supplied values overrides.
    #[serde(default)]
    config: k7s_deps::serde_json::Value,
    #[serde(default)]
    manifest: String,
}

#[derive(Deserialize, Default)]
struct InfoJson {
    #[serde(default)]
    status: String,
    #[serde(default)]
    first_deployed: String,
    #[serde(default)]
    last_deployed: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Default)]
struct ChartJson {
    #[serde(default)]
    metadata: ChartMeta,
}

#[derive(Deserialize, Default)]
struct ChartMeta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default, rename = "appVersion")]
    app_version: String,
}

/// Placeholder for an unset value.
const DASH: &str = "—";

fn or_dash(s: String) -> String {
    if s.is_empty() {
        DASH.into()
    } else {
        s
    }
}

/// Decode a Helm release Secret, or None if it isn't one / can't be read.
///
/// Undecodable releases are skipped rather than surfaced: a release written by a
/// future Helm, or a truncated Secret, shouldn't put a broken row in the table.
pub fn decode_release(secret: &Secret) -> Option<Release> {
    if secret.type_.as_deref() != Some(RELEASE_SECRET_TYPE) {
        return None;
    }
    let raw = &secret.data.as_ref()?.get("release")?.0;

    // base64 text → gzip bytes → JSON. Helm's own encoding, on top of the
    // transport base64 the client already undid.
    let gz = k7s_deps::base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| {
            k7s_deps::tracing::warn!("helm release {}: bad base64: {e}", secret.name_any())
        })
        .ok()?;

    let mut json = String::new();
    GzDecoder::new(&gz[..])
        .read_to_string(&mut json)
        .map_err(|e| k7s_deps::tracing::warn!("helm release {}: bad gzip: {e}", secret.name_any()))
        .ok()?;

    let r: ReleaseJson = k7s_deps::serde_json::from_str(&json)
        .map_err(|e| k7s_deps::tracing::warn!("helm release {}: bad json: {e}", secret.name_any()))
        .ok()?;

    // Chart is "name-version", the form `helm list` prints.
    let chart = match (
        r.chart.metadata.name.as_str(),
        r.chart.metadata.version.as_str(),
    ) {
        ("", _) => DASH.to_string(),
        (n, "") => n.to_string(),
        (n, v) => format!("{n}-{v}"),
    };

    Some(Release {
        // Prefer the release's own namespace; fall back to the Secret's.
        namespace: if r.namespace.is_empty() {
            secret.namespace().unwrap_or_default()
        } else {
            r.namespace
        },
        name: r.name,
        chart,
        app_version: or_dash(r.chart.metadata.app_version),
        revision: r.version,
        status: or_dash(r.info.status),
        updated: r.info.last_deployed,
        first_deployed: r.info.first_deployed,
        description: or_dash(r.info.description),
        config: r.config,
        manifest: redact_secret_manifests(&r.manifest),
    })
}

/// Fetch the rendered manifest for a specific revision of a Helm release.
///
/// Unlike `shell_common::helm_manifest()` which always returns the latest
/// revision, this queries by revision number. Every revision is its own
/// Secret (`sh.helm.release.v1.<name>.v<revision>`), so we list by label
/// and match on `release.revision`.
pub async fn helm_manifest_revision(
    client: k7s_deps::kube::Client,
    namespace: &str,
    name: &str,
    revision: i64,
) -> crate::error::AppResult<String> {
    use k7s_deps::kube::api::{Api, ListParams};

    let api: Api<Secret> = if namespace.is_empty() {
        Api::all(client)
    } else {
        Api::namespaced(client, namespace)
    };

    let lp = ListParams::default()
        .fields(&format!("type={}", RELEASE_SECRET_TYPE))
        .labels(&format!("owner=helm,name={name}"));
    let list = api.list(&lp).await?;

    for secret in &list {
        if let Some(release) = decode_release(secret) {
            if release.revision == revision {
                if release.manifest.trim().is_empty() {
                    return Err(crate::error::AppError::Other(format!(
                        "revision {revision} of {name} has no rendered manifest"
                    )));
                }
                return Ok(release.manifest);
            }
        }
    }

    Err(crate::error::AppError::NotFound(format!(
        "revision {revision} of Helm release {name} not found in {namespace}"
    )))
}

/// Fetch the user-supplied values for a specific revision of a Helm release.
///
/// Returns the `config` field (Helm's user-supplied value overrides) for the
/// requested revision, as a JSON value. Sensitive keys are redacted by
/// `flatten_values` on the caller side, but the raw JSON is returned here so
/// the caller can choose how to present it.
pub async fn helm_values_revision(
    client: k7s_deps::kube::Client,
    namespace: &str,
    name: &str,
    revision: i64,
) -> crate::error::AppResult<k7s_deps::serde_json::Value> {
    use k7s_deps::kube::api::{Api, ListParams};

    let api: Api<Secret> = if namespace.is_empty() {
        Api::all(client)
    } else {
        Api::namespaced(client, namespace)
    };

    let lp = ListParams::default()
        .fields(&format!("type={}", RELEASE_SECRET_TYPE))
        .labels(&format!("owner=helm,name={name}"));
    let list = api.list(&lp).await?;

    for secret in &list {
        if let Some(release) = decode_release(secret) {
            if release.revision == revision {
                return Ok(release.config);
            }
        }
    }

    Err(crate::error::AppError::NotFound(format!(
        "revision {revision} of Helm release {name} not found in {namespace}"
    )))
}

/// Tone for a release status, matching how the statuses actually read:
/// `deployed` is the healthy resting state, `superseded` is normal history, and
/// anything failed or stuck mid-operation wants attention.
pub fn status_tone(status: &str) -> Tone {
    match status {
        "deployed" => Tone::Good,
        "superseded" | "uninstalled" => Tone::Muted,
        "failed" => Tone::Bad,
        // pending-install / pending-upgrade / pending-rollback / uninstalling:
        // an operation is in flight, or died holding the lock.
        _ => Tone::Warn,
    }
}

/// Whether a values key names a credential, and so must be redacted (B35). Matches
/// the substrings the manifest/secret stance already treats as sensitive; a values
/// blob is exactly where a `dbPassword` or `apiToken` ends up.
fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_lowercase();
    ["password", "secret", "token", "key"]
        .iter()
        .any(|p| k.contains(p))
}

/// Flatten a release's values into sorted `dotted.path` → value pairs, redacting
/// any value under a sensitive key (B35). A sensitive key's whole subtree is
/// replaced by `<redacted>` — the value string never reaches the caller, so it
/// can't reach the frontend payload.
///
/// Nested objects dot together (`resources.limits.cpu`); arrays index
/// (`hosts.0`). Scalars render as their JSON text without quotes.
pub fn flatten_values(config: &k7s_deps::serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Values is an object (or absent/null); a top-level scalar isn't a real Helm
    // config, so it yields nothing rather than a nameless row.
    if config.is_object() || config.is_array() {
        flatten_into("", config, &mut out);
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn flatten_into(
    prefix: &str,
    value: &k7s_deps::serde_json::Value,
    out: &mut Vec<(String, String)>,
) {
    match value {
        k7s_deps::serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                if is_sensitive_key(k) {
                    // Redact the whole subtree — never descend into a credential.
                    out.push((path, "<redacted>".to_string()));
                } else {
                    flatten_into(&path, v, out);
                }
            }
        }
        k7s_deps::serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let path = if prefix.is_empty() {
                    i.to_string()
                } else {
                    format!("{prefix}.{i}")
                };
                flatten_into(&path, v, out);
            }
        }
        k7s_deps::serde_json::Value::String(s) => out.push((prefix.to_string(), s.clone())),
        k7s_deps::serde_json::Value::Null => out.push((prefix.to_string(), DASH.to_string())),
        other => out.push((prefix.to_string(), other.to_string())),
    }
}

/// Map a release Secret to a table row: NAME, NAMESPACE, CHART, APP VERSION,
/// REVISION, STATUS, UPDATED. None for anything that isn't a readable release.
pub fn map_release(secret: &Secret) -> Option<Row> {
    let r = decode_release(secret)?;
    let cells = vec![
        Cell::new(r.name.clone(), Tone::Primary),
        Cell::new(r.namespace.clone(), Tone::Muted),
        Cell::new(r.chart, Tone::Secondary),
        Cell::new(r.app_version, Tone::Secondary),
        // The revision carries a numeric sort key: `latest_only` uses it, and it
        // stops "10" sorting before "9" in the column.
        Cell::new(r.revision.to_string(), Tone::Secondary).with_sort(r.revision as f64),
        Cell::status(r.status.clone(), status_tone(&r.status)),
        Cell::age(Some(r.updated.clone()).filter(|u| !u.is_empty())),
    ];
    Some(Row {
        // Identity is the release, not the Secret: the row for a release should
        // keep its selection across an upgrade rather than being a new row.
        uid: format!("helm:{}/{}", r.namespace, r.name),
        name: r.name,
        namespace: Some(r.namespace),
        cells,
        ..Default::default()
    })
}

/// Keep only each release's newest revision, newest release first.
///
/// Helm never deletes old revision Secrets (it keeps ten by default), so without
/// this an upgraded release would appear once per revision — mostly as
/// `superseded` rows nobody asked for. This is what `helm list` shows.
pub fn latest_only(rows: Vec<Row>) -> Vec<Row> {
    use std::collections::HashMap;

    let revision = |r: &Row| r.cells.get(4).and_then(|c| c.sort).unwrap_or(0.0);

    // uid is already "helm:namespace/name" — the release's identity.
    let mut newest: HashMap<String, Row> = HashMap::new();
    for row in rows {
        match newest.get(&row.uid) {
            Some(existing) if revision(existing) >= revision(&row) => {}
            _ => {
                newest.insert(row.uid.clone(), row);
            }
        }
    }

    let mut out: Vec<Row> = newest.into_values().collect();
    // Most recently updated first: what you just deployed is what you're looking
    // for. Ties (and undated releases) fall back to name for a stable order.
    out.sort_by(|a, b| {
        let updated = |r: &Row| r.cells.get(6).map(|c| c.text.clone()).unwrap_or_default();
        updated(b)
            .cmp(&updated(a))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

// ---------------------------------------------------------------------------
// Manifest redaction
// ---------------------------------------------------------------------------

/// Redact Secret values inside a rendered manifest.
///
/// A chart that ships a Secret renders it with its values in the clear. The app
/// redacts Secret values in every other view, so showing them here would just be
/// the same leak through a different door.
///
/// Works line-wise on the specific documents that are Secrets, rather than
/// parsing and re-emitting the YAML: Helm's output carries `# Source:` comments
/// that say which template produced each document, and a round-trip through a
/// YAML parser would throw them away.
fn redact_secret_manifests(manifest: &str) -> String {
    if manifest.is_empty() {
        return String::new();
    }
    manifest
        .split("\n---")
        .map(|doc| {
            if is_secret_doc(doc) {
                redact_doc(doc)
            } else {
                doc.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n---")
}

/// True when a manifest document declares a core/v1 Secret.
fn is_secret_doc(doc: &str) -> bool {
    let mut kind_is_secret = false;
    for line in doc.lines() {
        let t = line.trim();
        // Only top-level keys count: a Deployment mounting a secret has
        // "kind: Secret" nested under a volume, and that's not a Secret document.
        if !line.starts_with("kind:") {
            continue;
        }
        if t == "kind: Secret" {
            kind_is_secret = true;
        }
    }
    kind_is_secret
}

/// Replace the values under `data:` / `stringData:` with a placeholder.
fn redact_doc(doc: &str) -> String {
    let mut out = Vec::new();
    // Indentation of the data block we're inside, if any.
    let mut in_data_block = false;

    for line in doc.lines() {
        let trimmed = line.trim_end();
        if trimmed == "data:" || trimmed == "stringData:" {
            in_data_block = true;
            out.push(line.to_string());
            continue;
        }
        if in_data_block {
            let indent = line.len() - line.trim_start().len();
            // A non-indented, non-empty line ends the block.
            if !line.trim().is_empty() && indent == 0 {
                in_data_block = false;
            } else if let Some((key, _)) = line.split_once(':') {
                if !line.trim().is_empty() {
                    out.push(format!("{key}: <redacted>"));
                    continue;
                }
            }
        }
        out.push(line.to_string());
    }
    let mut s = out.join("\n");
    // `lines()` drops a trailing newline; keep the document's shape.
    if doc.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::flate2::write::GzEncoder;
    use k7s_deps::flate2::Compression;
    use k7s_deps::serde_json::json;
    use std::io::Write;

    /// Build a release Secret exactly as the cluster hands one to us.
    ///
    /// The double encoding is the point, and it's easy to get wrong: Helm writes
    /// `base64(gzip(json))` as the *value*, and Kubernetes then base64s every
    /// Secret value again for transport — which `ByteString`'s deserializer
    /// undoes. So the bytes our code receives are still base64 text, and a
    /// fixture that encodes only once tests a decoder no cluster will ever feed.
    fn release_secret(name: &str, ns: &str, revision: i64, status: &str, updated: &str) -> Secret {
        let body = json!({
            "name": name,
            "namespace": ns,
            "version": revision,
            "info": { "status": status, "last_deployed": updated, "description": "Install complete" },
            "chart": { "metadata": { "name": "traefik", "version": "27.0.2", "appVersion": "v3.0.0" } },
            "manifest": "# Source: traefik/templates/svc.yaml\napiVersion: v1\nkind: Service\n",
        });
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(body.to_string().as_bytes()).unwrap();
        // What Helm stores in the value: base64 text.
        let helm_value =
            k7s_deps::base64::engine::general_purpose::STANDARD.encode(gz.finish().unwrap());
        // What the API serialises: that text, base64'd again for transport.
        let transport =
            k7s_deps::base64::engine::general_purpose::STANDARD.encode(helm_value.as_bytes());

        k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": format!("sh.helm.release.v1.{name}.v{revision}"), "namespace": ns },
            "type": RELEASE_SECRET_TYPE,
            "data": { "release": transport },
        }))
        .unwrap()
    }

    /// The full Helm encoding chain round-trips into the columns we show.
    #[test]
    fn decodes_a_release() {
        let s = release_secret(
            "traefik",
            "kube-system",
            1,
            "deployed",
            "2026-06-28T09:30:13Z",
        );
        let r = decode_release(&s).expect("should decode");
        assert_eq!(r.name, "traefik");
        assert_eq!(r.namespace, "kube-system");
        assert_eq!(
            r.chart, "traefik-27.0.2",
            "chart reads as helm list prints it"
        );
        assert_eq!(r.app_version, "v3.0.0");
        assert_eq!(r.revision, 1);
        assert_eq!(r.status, "deployed");
    }

    /// Non-Helm Secrets are not releases, and must not be decoded or shown.
    #[test]
    fn ignores_ordinary_secrets() {
        let s: Secret = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "db-creds", "namespace": "prod" },
            "type": "Opaque",
            "data": { "password": "aHVudGVyMg==" },
        }))
        .unwrap();
        assert!(decode_release(&s).is_none());
    }

    /// Garbage in the release key is skipped, not surfaced as a broken row.
    #[test]
    fn undecodable_release_is_skipped() {
        let s: Secret = k7s_deps::serde_json::from_value(json!({
            "metadata": { "name": "sh.helm.release.v1.x.v1", "namespace": "prod" },
            "type": RELEASE_SECRET_TYPE,
            // Transport-decodes to "not-gzip", which is valid base64 of nothing useful.
            "data": { "release": "Ym0keUxXZDZhWEE9" },
        }))
        .unwrap();
        assert!(decode_release(&s).is_none());
        assert!(map_release(&s).is_none());
    }

    // ---- values flattening & redaction (B35) ----

    /// A credential value is redacted by key name, and the value string never
    /// appears in the output at all — not just hidden behind a placeholder.
    #[test]
    fn flatten_redacts_credentials() {
        let cfg = json!({
            "dbPassword": "hunter2",
            "api": { "token": "t0psecret", "url": "https://x" },
            "tls": { "key": "PRIVATE", "crt": "public-cert" },
            "clientSecret": "shh",
        });
        let flat = flatten_values(&cfg);
        let dumped = format!("{flat:?}");
        for leaked in ["hunter2", "t0psecret", "PRIVATE", "shh"] {
            assert!(
                !dumped.contains(leaked),
                "credential '{leaked}' must not survive flattening"
            );
        }
        // The keys are still listed, as <redacted>, so the shape stays visible.
        let redacted: Vec<_> = flat
            .iter()
            .filter(|(_, v)| v == "<redacted>")
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(redacted.contains(&"dbPassword"));
        assert!(redacted.contains(&"api.token"));
        assert!(redacted.contains(&"tls.key"));
        assert!(redacted.contains(&"clientSecret"));
        // A non-sensitive sibling under the same parent is untouched.
        assert!(flat.iter().any(|(k, v)| k == "api.url" && v == "https://x"));
        assert!(flat
            .iter()
            .any(|(k, v)| k == "tls.crt" && v == "public-cert"));
    }

    /// Nested objects dot together, arrays index, and the output is sorted.
    #[test]
    fn flatten_paths_and_order() {
        let cfg = json!({
            "replicaCount": 2,
            "resources": { "limits": { "cpu": "500m" } },
            "hosts": ["a.example", "b.example"],
        });
        let flat = flatten_values(&cfg);
        assert_eq!(
            flat,
            vec![
                ("hosts.0".to_string(), "a.example".to_string()),
                ("hosts.1".to_string(), "b.example".to_string()),
                ("replicaCount".to_string(), "2".to_string()),
                ("resources.limits.cpu".to_string(), "500m".to_string()),
            ]
        );
    }

    /// No overrides → no rows; the caller renders "chart defaults" instead.
    #[test]
    fn flatten_empty_config_is_empty() {
        assert!(flatten_values(&json!({})).is_empty());
        assert!(flatten_values(&k7s_deps::serde_json::Value::Null).is_empty());
    }

    /// Status colouring: deployed is healthy, superseded is just history, failed
    /// is red, and anything pending is an operation in flight.
    #[test]
    fn status_tones() {
        assert_eq!(status_tone("deployed"), Tone::Good);
        assert_eq!(status_tone("superseded"), Tone::Muted);
        assert_eq!(status_tone("failed"), Tone::Bad);
        assert_eq!(status_tone("pending-upgrade"), Tone::Warn);
    }

    /// The headline behaviour: an upgraded release is one row, at its newest
    /// revision — not one row per revision Secret.
    #[test]
    fn keeps_only_the_newest_revision() {
        let rows: Vec<Row> = vec![
            map_release(&release_secret(
                "traefik",
                "kube-system",
                1,
                "superseded",
                "2026-06-01T00:00:00Z",
            ))
            .unwrap(),
            map_release(&release_secret(
                "traefik",
                "kube-system",
                3,
                "deployed",
                "2026-06-03T00:00:00Z",
            ))
            .unwrap(),
            map_release(&release_secret(
                "traefik",
                "kube-system",
                2,
                "superseded",
                "2026-06-02T00:00:00Z",
            ))
            .unwrap(),
        ];
        let out = latest_only(rows);
        assert_eq!(out.len(), 1, "three revision secrets are one release");
        assert_eq!(
            out[0].cells[4].text, "3",
            "and it shows the newest revision"
        );
        assert_eq!(out[0].cells[5].text, "deployed");
    }

    /// Releases in different namespaces with the same name are different releases.
    #[test]
    fn same_name_in_two_namespaces_stays_two_rows() {
        let rows = vec![
            map_release(&release_secret(
                "redis",
                "prod",
                1,
                "deployed",
                "2026-06-01T00:00:00Z",
            ))
            .unwrap(),
            map_release(&release_secret(
                "redis",
                "staging",
                1,
                "deployed",
                "2026-06-02T00:00:00Z",
            ))
            .unwrap(),
        ];
        assert_eq!(latest_only(rows).len(), 2);
    }

    /// Newest deployment first.
    #[test]
    fn sorts_newest_first() {
        let rows = vec![
            map_release(&release_secret(
                "old",
                "prod",
                1,
                "deployed",
                "2026-06-01T00:00:00Z",
            ))
            .unwrap(),
            map_release(&release_secret(
                "new",
                "prod",
                1,
                "deployed",
                "2026-06-09T00:00:00Z",
            ))
            .unwrap(),
        ];
        let out = latest_only(rows);
        assert_eq!(out[0].name, "new");
    }

    /// Revisions sort numerically, so 10 beats 9.
    #[test]
    fn revision_ordering_is_numeric_not_lexical() {
        let rows = vec![
            map_release(&release_secret(
                "app",
                "prod",
                9,
                "superseded",
                "2026-06-01T00:00:00Z",
            ))
            .unwrap(),
            map_release(&release_secret(
                "app",
                "prod",
                10,
                "deployed",
                "2026-06-02T00:00:00Z",
            ))
            .unwrap(),
        ];
        assert_eq!(latest_only(rows)[0].cells[4].text, "10");
    }

    // ---- manifest redaction ----

    /// A Secret rendered by a chart doesn't get to show its values here when
    /// every other view redacts them.
    #[test]
    fn redacts_secret_values_in_the_manifest() {
        let m = "# Source: c/templates/secret.yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: creds\ndata:\n  password: aHVudGVyMg==\n  token: c2VjcmV0\n";
        let out = redact_secret_manifests(m);
        assert!(
            !out.contains("aHVudGVyMg=="),
            "secret value must not survive"
        );
        assert!(!out.contains("c2VjcmV0"));
        assert!(out.contains("password: <redacted>"));
        assert!(out.contains("token: <redacted>"));
        // The provenance comment is why this is line-wise rather than a YAML
        // round-trip; losing it would make the manifest much harder to read.
        assert!(out.contains("# Source: c/templates/secret.yaml"));
    }

    /// stringData too — same values, different key.
    #[test]
    fn redacts_string_data() {
        let m = "kind: Secret\nstringData:\n  password: hunter2\n";
        assert!(redact_secret_manifests(m).contains("password: <redacted>"));
    }

    /// Non-Secret documents are passed through untouched — a ConfigMap's data is
    /// exactly what you opened the manifest to read.
    #[test]
    fn leaves_other_documents_alone() {
        let m = "kind: ConfigMap\ndata:\n  log_level: debug\n";
        assert!(redact_secret_manifests(m).contains("log_level: debug"));
    }

    /// Only the Secret document in a multi-document manifest is touched.
    #[test]
    fn redacts_only_the_secret_document() {
        let m = "kind: ConfigMap\ndata:\n  keep: yes\n---\nkind: Secret\ndata:\n  hide: c2VjcmV0\n";
        let out = redact_secret_manifests(m);
        assert!(out.contains("keep: yes"));
        assert!(out.contains("hide: <redacted>"));
        assert!(!out.contains("c2VjcmV0"));
    }

    /// "kind: Secret" nested inside a pod spec's volume doesn't make the document
    /// a Secret, and must not trigger redaction of a Deployment.
    #[test]
    fn nested_secret_reference_is_not_a_secret_document() {
        let m = "kind: Deployment\nspec:\n  template:\n    spec:\n      volumes:\n        - secret:\n            kind: Secret\n";
        assert!(!is_secret_doc(m));
    }
}
