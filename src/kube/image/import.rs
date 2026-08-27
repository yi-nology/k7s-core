//! Import a local `.tar` image archive into a cluster node's container runtime.
//!
//! Air-gapped (intranet, no public internet) clusters can't pull images from
//! public registries. The standard offline workflow is: `docker save`/`ctr
//! images export` the image to a `.tar` on an internet-connected machine, move
//! the file to the cluster network, then `docker load`/`ctr images import` it
//! on the node. This module is the k7s UI's answer to the second half of that.
//!
//! ## How it differs from `image_sync`
//!
//! [`image_sync`](crate::kube::image::sync) copies an image into a *private
//! registry* via `skopeo` — that needs a registry running in the cluster and
//! `skopeo` on the host. This module loads the tar *directly into a node's
//! container runtime* via a privileged debug pod — no registry required, which
//! is the right tool for clusters that have no internal registry at all.
//!
//! ## Mechanism
//!
//! There is no Kubernetes API for "load this image onto that node", so this
//! reuses the node-shell trick: create a privileged pod pinned to the node
//! ([`nodeshell::debug_pod_spec`]), `nsenter` into PID 1's namespaces (so we
//! land on the host, not in the container), and pipe the tar over the pod's
//! exec stdin into the runtime's load command. The pod is created for the one
//! exec and deleted immediately after — it never lingers.
//!
//! Runtime detection reads `Node.status.nodeInfo.containerRuntimeVersion`
//! (`containerd://…` / `docker://…`) and dispatches:
//!   - containerd → `ctr --address /run/containerd/containerd.sock images import --no-unpack -`
//!   - docker     → `docker load`
//!
//! `--no-unpack` on containerd skips snapshot unpacking (slower, can fail on
//! edge cases); the image is still usable because kubelet pulls from the
//! content store and unpack happens lazily on first run.

use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::core::v1::{Node, Pod};
use k7s_deps::kube::api::{Api, AttachParams, PostParams};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::kube::nodeshell;

/// Result of an image import: what ran, what the runtime said, and the image
/// refs we parsed out of the output. Returned to the UI verbatim.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    /// Detected runtime family: "containerd" | "docker".
    pub runtime: String,
    /// Raw stdout from the load command (the "Loaded image: …" / ref lines).
    pub output: String,
    /// Image refs parsed out of `output` (e.g. "nginx:1.25").
    pub images: Vec<String>,
    /// `None` on success; the failure reason on error.
    pub error: Option<String>,
}

/// Monotonic sequence so two concurrent imports on different nodes don't
/// collide on the pod name. (v1 is single-import, but the guard is cheap and
/// keeps the name unique across retries too.)
static IMPORT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Detect the runtime family from `containerRuntimeVersion`.
///
/// The string on a real node looks like `containerd://1.7.22` or
/// `docker://20.10.24`. The scheme prefix is authoritative for which load
/// command to run; cri-o (`cri-o://…`) has no native tar-load, so it's a
/// clear error rather than a guess.
pub fn detect_runtime(version: &str) -> AppResult<String> {
    let v = version.trim();
    if v.starts_with("containerd://") {
        return Ok("containerd".into());
    }
    if v.starts_with("docker://") {
        return Ok("docker".into());
    }
    Err(AppError::Other(format!(
        "unsupported container runtime '{v}' — image import supports containerd and docker"
    )))
}

/// Build the `nsenter … /bin/sh -c "<load-cmd>"` argv that reads the tar from
/// stdin and loads it into the host's container runtime.
///
/// The `nsenter` prefix mirrors [`nodeshell::nsenter_cmd`] exactly — same
/// namespaces, same target (PID 1) — only the final `/bin/sh -c <cmd>`
/// differs. The load command reads the tar from stdin (`-` for ctr, the
/// implicit stdin for `docker load`).
pub fn load_command(runtime: &str) -> AppResult<Vec<String>> {
    let inner = match runtime {
        "containerd" => "ctr --address /run/containerd/containerd.sock images import --no-unpack -",
        "docker" => "docker load",
        other => return Err(AppError::Other(format!("unsupported runtime '{other}'"))),
    };
    Ok(vec![
        "nsenter".into(),
        "--target".into(),
        "1".into(),
        "--mount".into(),
        "--uts".into(),
        "--ipc".into(),
        "--net".into(),
        "--pid".into(),
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        inner.into(),
    ])
}

/// Parse image refs out of a load command's stdout.
///
/// The two runtimes print recognisable lines:
///   - docker:     `Loaded image: nginx:1.25` / `Loaded image ID: sha256:…`
///   - containerd: bare refs like `docker.io/library/nginx:1.25`, plus
///     progress noise (`unpacking …`, `elapsed …`, percentages with `%`).
///
/// We keep the docker `Loaded image:` line's tail verbatim, and for containerd
/// keep lines that look like an image ref (contain `:` for a tag or
/// `@sha256:` for a digest) while excluding obvious progress noise. Dedup at
/// the end because containerd sometimes repeats the ref.
pub fn parse_loaded_images(output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in output.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("Loaded image:") {
            let img = rest.trim();
            if !img.is_empty() {
                out.push(img.to_string());
            }
            continue;
        }
        // `Loaded image ID: sha256:…` — keep the digest so the user at least
        // sees *something* was loaded, even though it's not a ref.
        if let Some(rest) = l.strip_prefix("Loaded image ID:") {
            let img = rest.trim();
            if !img.is_empty() {
                out.push(img.to_string());
            }
            continue;
        }
        // containerd prints refs without a prefix. Keep lines that look like a
        // ref and aren't progress noise.
        let looks_like_ref = (l.contains(':') || l.contains("@sha256:"))
            && !l.contains('%')
            && !l.starts_with("unpacking")
            && !l.starts_with("elapsed")
            && !l.starts_with("importing")
            && !l.starts_with("done");
        if looks_like_ref && !l.is_empty() {
            out.push(l.to_string());
        }
    }
    out.dedup();
    out
}

/// The full one-shot import: detect runtime → create debug pod → await Running
/// → exec(nsenter, tar→stdin) → parse output → delete pod (always).
///
/// Pod cleanup is **unconditional**: a `?` short-circuit mid-way would strand
/// a privileged pod on the node, so every error path funnels through the same
/// teardown. The pod also carries `activeDeadlineSeconds` (from the spec) as a
/// server-side kill switch that outlives this process.
pub async fn import_to_node(
    client: k7s_deps::kube::Client,
    node: &str,
    tar_bytes: &[u8],
) -> AppResult<ImportResult> {
    // 1. Detect runtime from the node's status.
    let node_api: Api<Node> = Api::all(client.clone());
    let node_obj = node_api.get(node).await?;
    let version = node_obj
        .status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.container_runtime_version.clone())
        .unwrap_or_default();
    let runtime = match detect_runtime(&version) {
        Ok(r) => r,
        Err(e) => {
            return Ok(ImportResult {
                runtime: String::new(),
                output: String::new(),
                images: Vec::new(),
                error: Some(e.to_string()),
            });
        }
    };
    let argv = load_command(&runtime)?;

    // 2. Create the privileged debug pod on the node.
    let pod_api: Api<Pod> = Api::namespaced(client.clone(), nodeshell::DEBUG_NAMESPACE);
    let seq = IMPORT_SEQ.fetch_add(1, Ordering::Relaxed);
    let pod_name = format!("k7s-imgimp-{}-{}", sanitize_for_name(node), seq);
    // Reuse the node-shell image (it's already pulled if the user has used the
    // node shell; netshoot has /bin/sh + nsenter, which is all we need).
    let image = std::env::var("K7S_NODE_SHELL_IMAGE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| nodeshell::DEFAULT_IMAGE.to_string());
    let pod_spec = nodeshell::debug_pod_spec(node, &image, &pod_name);

    // From here the pod exists — every subsequent error must clean it up.
    if let Err(e) = pod_api.create(&PostParams::default(), &pod_spec).await {
        return Err(AppError::Other(format!("create debug pod: {e}")));
    }

    // Guard: run the exec, then always delete the pod. Using a closure so the
    // `?` operator short-circuits into `res` and cleanup still runs.
    let res: AppResult<(String, Vec<String>)> = async {
        // 3. Wait for Running.
        nodeshell::await_debug_pod(&pod_api, &pod_name).await?;

        // 4. exec: nsenter into host, run the load command, stream tar stdin.
        let mut ap = AttachParams::default()
            .stdin(true)
            .stdout(true)
            .stderr(false)
            .tty(false);
        // The debug pod spec pins its single container to "debug"; passing the
        // pod name here made the exec attach to a non-existent container.
        ap = ap.container("debug");
        let mut proc = pod_api.exec(&pod_name, argv, &ap).await?;
        use k7s_deps::tokio::io::{AsyncReadExt, AsyncWriteExt};
        if let Some(mut stdin) = proc.stdin() {
            stdin
                .write_all(tar_bytes)
                .await
                .map_err(|e| AppError::Other(format!("exec stdin: {e}")))?;
            // EOF so the load command finishes reading.
            stdin.shutdown().await.ok();
        }
        let mut out = Vec::new();
        if let Some(mut stdout) = proc.stdout() {
            stdout.read_to_end(&mut out).await.ok();
        }
        let status_opt = proc
            .take_status()
            .ok_or_else(|| AppError::Other("no status channel".into()))?
            .await;
        let succeeded = status_opt
            .as_ref()
            .and_then(|s| s.status.as_deref())
            .map(|s| s == "Success")
            .unwrap_or(true);
        let output = String::from_utf8_lossy(&out).to_string();
        if !succeeded {
            return Err(AppError::Other(format!(
                "image load failed: {:?} (output: {})",
                status_opt.and_then(|s| s.message),
                output,
            )));
        }
        Ok((output.clone(), parse_loaded_images(&output)))
    }
    .await;

    // 5. Unconditional pod cleanup — success or failure.
    nodeshell::delete_debug_pod(&pod_api, &pod_name).await;

    match res {
        Ok((output, images)) => Ok(ImportResult {
            runtime,
            output,
            images,
            error: None,
        }),
        Err(e) => Ok(ImportResult {
            runtime,
            output: String::new(),
            images: Vec::new(),
            error: Some(e.to_string()),
        }),
    }
}

/// Reduce a node name to a legal DNS-1035 label fragment for a pod name.
/// Mirrors the sanitisation `nodeshell::pod_name` does, but inline because we
/// compose a different prefix (`k7s-imgimp-`).
fn sanitize_for_name(node: &str) -> String {
    node.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- detect_runtime ----

    #[test]
    fn detect_containerd() {
        assert_eq!(detect_runtime("containerd://1.7.22").unwrap(), "containerd");
    }

    #[test]
    fn detect_docker() {
        assert_eq!(detect_runtime("docker://20.10.24").unwrap(), "docker");
    }

    #[test]
    fn detect_trims_whitespace() {
        assert_eq!(
            detect_runtime("  containerd://1.6  ").unwrap(),
            "containerd"
        );
    }

    #[test]
    fn detect_crio_is_unsupported() {
        let err = detect_runtime("cri-o://1.29.0").unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn detect_empty_is_unsupported() {
        assert!(detect_runtime("").is_err());
    }

    // ---- load_command ----

    #[test]
    fn load_command_containerd_uses_ctr_and_nsenter() {
        let argv = load_command("containerd").unwrap();
        // nsenter prefix mirrors the node-shell exactly.
        assert_eq!(argv[0], "nsenter");
        assert_eq!(argv[1], "--target");
        assert_eq!(argv[2], "1");
        let cmd = argv.join(" ");
        assert!(cmd.contains("ctr --address /run/containerd/containerd.sock"));
        assert!(cmd.contains("images import --no-unpack -"));
    }

    #[test]
    fn load_command_docker_uses_docker_load() {
        let argv = load_command("docker").unwrap();
        let cmd = argv.join(" ");
        assert!(cmd.contains("docker load"));
    }

    #[test]
    fn load_command_unknown_runtime_errors() {
        assert!(load_command("cri-o").is_err());
    }

    // ---- parse_loaded_images ----

    #[test]
    fn parse_docker_loaded_image_lines() {
        let out = "Loaded image: nginx:1.25\nLoaded image: busybox:latest\n";
        let imgs = parse_loaded_images(out);
        assert_eq!(imgs, vec!["nginx:1.25", "busybox:latest"]);
    }

    #[test]
    fn parse_docker_loaded_image_id() {
        let out = "Loaded image ID: sha256:abc123def456\n";
        let imgs = parse_loaded_images(out);
        assert_eq!(imgs, vec!["sha256:abc123def456"]);
    }

    #[test]
    fn parse_containerd_bare_refs() {
        let out = "docker.io/library/nginx:1.25\ndocker.io/library/busybox:latest\n";
        let imgs = parse_loaded_images(out);
        assert_eq!(
            imgs,
            vec![
                "docker.io/library/nginx:1.25",
                "docker.io/library/busybox:latest"
            ]
        );
    }

    #[test]
    fn parse_filters_progress_noise() {
        let out = "\
unpacking sha256:abc (7.3MB)…
elapsed: 2.3s
done. | eff40ce |
docker.io/library/nginx:1.25";
        let imgs = parse_loaded_images(out);
        // Only the bare ref survives; the unpacking/elapsed/done lines are noise.
        assert_eq!(imgs, vec!["docker.io/library/nginx:1.25"]);
    }

    #[test]
    fn parse_dedups_repeated_refs() {
        let out = "docker.io/library/nginx:1.25\ndocker.io/library/nginx:1.25\n";
        let imgs = parse_loaded_images(out);
        assert_eq!(imgs, vec!["docker.io/library/nginx:1.25"]);
    }

    #[test]
    fn parse_empty_output() {
        assert!(parse_loaded_images("").is_empty());
    }

    #[test]
    fn parse_keeps_digest_refs() {
        let out = "nginx@sha256:abcdef0123456789\n";
        let imgs = parse_loaded_images(out);
        assert_eq!(imgs, vec!["nginx@sha256:abcdef0123456789"]);
    }

    // ---- sanitize_for_name ----

    #[test]
    fn sanitize_replaces_dots_and_uppercase() {
        assert_eq!(
            sanitize_for_name("Host.DC1.Example.COM"),
            "host-dc1-example-com"
        );
    }

    #[test]
    fn sanitize_trims_leading_trailing_dashes() {
        assert_eq!(sanitize_for_name("---node-1---"), "node-1");
    }
}
