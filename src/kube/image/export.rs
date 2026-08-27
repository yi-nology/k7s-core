//! Export a container image from a cluster node's container runtime to a local
//! `.tar` file. This is the reverse of [`imageimport`] — instead of piping a tar
//! into the runtime's load command, we run the runtime's export command and
//! stream the tar bytes back through exec stdout.
//!
//! ## Mechanism
//!
//! Same privileged debug pod trick as `imageimport`: create a pod pinned to the
//! node, `nsenter` into PID 1's namespaces, run the export command. The tar
//! bytes come back over exec stdout and are written directly to a local file.
//!
//! Runtime-specific commands:
//!   - containerd → `ctr --address /run/containerd/containerd.sock images export --output - <image-ref>`
//!   - docker     → `docker save <image-ref>`

use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::core::v1::{Node, Pod};
use k7s_deps::kube::api::{Api, AttachParams, PostParams};
use k7s_deps::tokio::io::AsyncReadExt;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::kube::{image::import, nodeshell};

/// Result of exporting an image from a node.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    /// Detected runtime: "containerd" | "docker".
    pub runtime: String,
    /// Raw stdout from the export command (usually empty on success — tar goes to file).
    pub output: String,
    /// Exported image refs (echoed from the input).
    pub images: Vec<String>,
    /// Local file path the tar was saved to.
    pub saved_path: String,
    /// None on success; failure reason on error.
    pub error: Option<String>,
}

static EXPORT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Validate an image reference before it reaches a container runtime. A
/// legitimate image ref (`repo/name:tag`, `repo@sha256:…`, with optional
/// `host:port/` prefix and `/` separators) only contains alphanumerics,
/// `.`, `-`, `_`, `:`, `/`, `@`, and hex digits for digests. Any shell
/// metacharacter here means someone is trying to break out of the arg list
/// — reject it outright rather than relying on quoting.
///
/// This is defense in depth on top of passing `image_ref` as a discrete argv
/// element (no shell), so even a ref that somehow contained a metacharacter
/// could not execute a separate command — but we reject it anyway to fail
/// fast and avoid surprising the runtime with malformed input.
fn validate_image_ref(image_ref: &str) -> AppResult<()> {
    if image_ref.is_empty() {
        return Err(AppError::Other("image reference is empty".into()));
    }
    if image_ref
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '-' | '_' | ':' | '/' | '@'))
    {
        return Err(AppError::Other(format!(
            "image reference '{image_ref}' contains forbidden characters (allowed: A-Z a-z 0-9 . - _ : / @)"
        )));
    }
    Ok(())
}

/// Validate a caller-supplied local file path that the runtime will write to
/// (image export `.tar` save locations). Guards against path traversal and
/// writes to system-critical directories. The desktop UI picks `save_path`
/// via a native save dialog, but the Tauri command (and any future web/MCP
/// bridge) takes the string from the caller, so this is the trust boundary.
pub(crate) fn validate_save_path(save_path: &str) -> AppResult<()> {
    use std::path::{Component, Path};

    if save_path.is_empty() {
        return Err(AppError::Other("save path is empty".into()));
    }
    let path = Path::new(save_path);

    // Must be absolute — a relative path is ambiguous about where it lands
    // and is a classic traversal vector.
    if !path.is_absolute() {
        return Err(AppError::Other(format!(
            "save path '{save_path}' must be absolute"
        )));
    }

    // Reject any component that escapes normalisation (`..` / root / prefix).
    for comp in path.components() {
        if !matches!(
            comp,
            Component::Normal(_) | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(AppError::Other(format!(
                "save path '{save_path}' contains a forbidden component (parent-dir or cur-dir reference)"
            )));
        }
    }

    // Refuse to clobber system-critical locations. A user exporting an image
    // tar has no reason to write under /etc, /usr, /bin, … — and doing so
    // would be destructive. Match by the first real path segment.
    const FORBIDDEN_ROOT_DIRS: &[&str] = &[
        "etc", "usr", "bin", "sbin", "boot", "lib", "lib64", "proc", "sys", "dev",
    ];
    let first_seg = path
        .components()
        .find_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .unwrap_or("");
    if FORBIDDEN_ROOT_DIRS.contains(&first_seg) {
        return Err(AppError::Other(format!(
            "save path '{save_path}' is inside a system directory ('/{first_seg}') and is refused"
        )));
    }

    Ok(())
}

/// Build the `nsenter … <runtime> …` argv that writes the tar to stdout. The
/// caller reads stdout and writes it to a local file.
///
/// `image_ref` is passed as a **discrete argv element**, never interpolated
/// into a shell string — the K8s exec API takes a vector of args, so no
/// `/bin/sh -c` wrapper is needed. `validate_image_ref` rejects anything that
/// is not a plausible image ref before it gets here.
pub fn export_command(runtime: &str, image_ref: &str) -> AppResult<Vec<String>> {
    validate_image_ref(image_ref)?;
    let mut argv = nsenter_prefix();
    match runtime {
        "containerd" => {
            argv.extend([
                "ctr".into(),
                "--address".into(),
                "/run/containerd/containerd.sock".into(),
                "images".into(),
                "export".into(),
                "--output".into(),
                "-".into(),
                image_ref.into(),
            ]);
        }
        "docker" => {
            argv.extend(["docker".into(), "save".into(), image_ref.into()]);
        }
        other => return Err(AppError::Other(format!("unsupported runtime '{other}'"))),
    }
    Ok(argv)
}

/// Build the argv to list images on a node.
fn list_command(runtime: &str) -> AppResult<Vec<String>> {
    let mut argv = nsenter_prefix();
    match runtime {
        "containerd" => {
            argv.extend([
                "ctr".into(),
                "--address".into(),
                "/run/containerd/containerd.sock".into(),
                "images".into(),
                "list".into(),
                "-q".into(),
            ]);
        }
        "docker" => {
            argv.extend([
                "docker".into(),
                "images".into(),
                "--format".into(),
                "json".into(),
            ]);
        }
        other => return Err(AppError::Other(format!("unsupported runtime '{other}'"))),
    }
    Ok(argv)
}

/// The fixed `nsenter … --` prefix shared by every command we run inside the
/// debug pod to reach the host's container runtime via PID 1's namespaces.
fn nsenter_prefix() -> Vec<String> {
    vec![
        "nsenter".into(),
        "--target".into(),
        "1".into(),
        "--mount".into(),
        "--uts".into(),
        "--ipc".into(),
        "--net".into(),
        "--pid".into(),
        "--".into(),
    ]
}

/// Parse image refs from `docker images --format json` or `ctr images list -q` output.
pub fn parse_listed_images(output: &str, runtime: &str) -> Vec<String> {
    match runtime {
        "docker" => {
            // `docker images --format json` outputs one JSON object per line.
            output
                .lines()
                .filter_map(|line| {
                    let v: k7s_deps::serde_json::Value =
                        k7s_deps::serde_json::from_str(line.trim()).ok()?;
                    let repo = v.get("Repository")?.as_str()?;
                    let tag = v.get("Tag")?.as_str()?;
                    if repo == "<none>" || tag == "<none>" {
                        return None;
                    }
                    Some(format!("{repo}:{tag}"))
                })
                .collect()
        }
        "containerd" => {
            // `ctr images list -q` outputs one ref per line.
            output
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        }
        _ => Vec::new(),
    }
}

/// List container images present on a node.
pub async fn list_node_images(
    client: k7s_deps::kube::Client,
    node: &str,
) -> AppResult<Vec<String>> {
    let node_api: Api<Node> = Api::all(client.clone());
    let node_obj = node_api.get(node).await?;
    let version = node_obj
        .status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.container_runtime_version.clone())
        .unwrap_or_default();
    let runtime = import::detect_runtime(&version)?;
    let argv = list_command(&runtime)?;

    let image = std::env::var("K7S_NODE_SHELL_IMAGE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| nodeshell::DEFAULT_IMAGE.to_string());
    let pod_name = format!("k7s-imgls-{}-0", sanitize_for_name(node));
    let pod_spec = nodeshell::debug_pod_spec(node, &image, &pod_name);

    let pod_api: Api<Pod> = Api::namespaced(client.clone(), nodeshell::DEBUG_NAMESPACE);
    if let Err(e) = pod_api.create(&PostParams::default(), &pod_spec).await {
        return Err(AppError::Other(format!("create debug pod: {e}")));
    }

    let res: AppResult<Vec<String>> = async {
        nodeshell::await_debug_pod(&pod_api, &pod_name).await?;
        let mut ap = AttachParams::default()
            .stdin(false)
            .stdout(true)
            .stderr(false)
            .tty(false);
        // The debug pod spec pins its single container to "debug"; passing the
        // pod name here made the exec attach to a non-existent container.
        ap = ap.container("debug");
        // One-shot privileged host exec — audit namespace/pod + the command
        // argv (identifiers only, no command output).
        crate::core::audit::record(
            "exec.run",
            k7s_deps::serde_json::json!({
                "namespace": nodeshell::DEBUG_NAMESPACE,
                "pod": &pod_name,
                "command": argv,
            }),
        );
        let mut proc = pod_api.exec(&pod_name, argv, &ap).await?;
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
                "list images failed: {:?} (output: {})",
                status_opt.and_then(|s| s.message),
                output,
            )));
        }
        Ok(parse_listed_images(&output, &runtime))
    }
    .await;

    nodeshell::delete_debug_pod(&pod_api, &pod_name).await;
    res
}

/// Export an image from a node to a local .tar file.
pub async fn export_from_node(
    client: k7s_deps::kube::Client,
    node: &str,
    image_ref: &str,
    save_path: &str,
) -> AppResult<ExportResult> {
    validate_save_path(save_path)?;
    let node_api: Api<Node> = Api::all(client.clone());
    let node_obj = node_api.get(node).await?;
    let version = node_obj
        .status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.container_runtime_version.clone())
        .unwrap_or_default();
    let runtime = match import::detect_runtime(&version) {
        Ok(r) => r,
        Err(e) => {
            return Ok(ExportResult {
                runtime: String::new(),
                output: String::new(),
                images: Vec::new(),
                saved_path: save_path.to_string(),
                error: Some(e.to_string()),
            });
        }
    };
    let argv = export_command(&runtime, image_ref)?;

    let pod_api: Api<Pod> = Api::namespaced(client.clone(), nodeshell::DEBUG_NAMESPACE);
    let seq = EXPORT_SEQ.fetch_add(1, Ordering::Relaxed);
    let pod_name = format!("k7s-imgexp-{}-{}", sanitize_for_name(node), seq);
    let image = std::env::var("K7S_NODE_SHELL_IMAGE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| nodeshell::DEFAULT_IMAGE.to_string());
    let pod_spec = nodeshell::debug_pod_spec(node, &image, &pod_name);

    if let Err(e) = pod_api.create(&PostParams::default(), &pod_spec).await {
        return Err(AppError::Other(format!("create debug pod: {e}")));
    }

    let res: AppResult<(String, Vec<String>)> = async {
        nodeshell::await_debug_pod(&pod_api, &pod_name).await?;

        let mut ap = AttachParams::default()
            .stdin(false)
            .stdout(true)
            .stderr(false)
            .tty(false);
        // The debug pod spec pins its single container to "debug"; passing the
        // pod name here made the exec attach to a non-existent container.
        ap = ap.container("debug");
        // One-shot privileged host exec — audit namespace/pod + the command
        // argv (identifiers only, no command output).
        crate::core::audit::record(
            "exec.run",
            k7s_deps::serde_json::json!({
                "namespace": nodeshell::DEBUG_NAMESPACE,
                "pod": &pod_name,
                "command": argv,
            }),
        );
        let mut proc = pod_api.exec(&pod_name, argv, &ap).await?;

        // Stream stdout to the local file.
        let mut file = k7s_deps::tokio::fs::File::create(save_path)
            .await
            .map_err(|e| AppError::Other(format!("create file '{save_path}': {e}")))?;
        let mut total_bytes: u64 = 0;
        if let Some(mut stdout) = proc.stdout() {
            let mut buf = vec![0u8; 256 * 1024]; // 256 KB chunks
            loop {
                let n = stdout.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                k7s_deps::tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n])
                    .await
                    .map_err(|e| AppError::Other(format!("write file: {e}")))?;
                total_bytes += n as u64;
            }
        }
        k7s_deps::tokio::io::AsyncWriteExt::flush(&mut file)
            .await
            .map_err(|e| AppError::Other(format!("flush file: {e}")))?;

        let status_opt = proc
            .take_status()
            .ok_or_else(|| AppError::Other("no status channel".into()))?
            .await;
        let succeeded = status_opt
            .as_ref()
            .and_then(|s| s.status.as_deref())
            .map(|s| s == "Success")
            .unwrap_or(true);
        let output = format!("exported {total_bytes} bytes to {save_path}");
        if !succeeded {
            // Clean up the partial file.
            k7s_deps::tokio::fs::remove_file(save_path).await.ok();
            return Err(AppError::Other(format!(
                "image export failed: {:?}",
                status_opt.and_then(|s| s.message),
            )));
        }
        Ok((output, vec![image_ref.to_string()]))
    }
    .await;

    nodeshell::delete_debug_pod(&pod_api, &pod_name).await;

    match res {
        Ok((output, images)) => Ok(ExportResult {
            runtime,
            output,
            images,
            saved_path: save_path.to_string(),
            error: None,
        }),
        Err(e) => Ok(ExportResult {
            runtime,
            output: String::new(),
            images: Vec::new(),
            saved_path: save_path.to_string(),
            error: Some(e.to_string()),
        }),
    }
}

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

    #[test]
    fn export_command_containerd() {
        let argv = export_command("containerd", "nginx:1.25").unwrap();
        let cmd = argv.join(" ");
        assert!(cmd.contains("ctr --address /run/containerd/containerd.sock"));
        assert!(cmd.contains("images export"));
        assert!(cmd.contains("nginx:1.25"));
        assert_eq!(argv[0], "nsenter");
        // image_ref must be a discrete argv element (no /bin/sh -c wrapper),
        // so it cannot break out into a separate command.
        assert!(!argv.iter().any(|a| a == "/bin/sh" || a == "-c"));
        assert_eq!(argv.last().unwrap(), "nginx:1.25");
    }

    #[test]
    fn export_command_docker() {
        let argv = export_command("docker", "nginx:1.25").unwrap();
        let cmd = argv.join(" ");
        assert!(cmd.contains("docker save"));
        assert!(cmd.contains("nginx:1.25"));
        assert_eq!(argv[0], "nsenter");
        assert!(!argv.iter().any(|a| a == "/bin/sh" || a == "-c"));
        assert_eq!(argv.last().unwrap(), "nginx:1.25");
    }

    #[test]
    fn export_command_unknown_runtime_errors() {
        assert!(export_command("cri-o", "nginx:1.25").is_err());
    }

    #[test]
    fn export_command_rejects_shell_metacharacters() {
        // A ref containing shell metacharacters must be rejected before it
        // ever reaches the runtime — defense in depth against command
        // injection, even though image_ref is now a discrete argv element.
        for evil in [
            "nginx; id",
            "nginx && cat /etc/shadow",
            "nginx`id`",
            "nginx$(id)",
            "nginx|sh",
        ] {
            assert!(
                export_command("containerd", evil).is_err(),
                "expected '{evil}' to be rejected"
            );
            assert!(
                export_command("docker", evil).is_err(),
                "expected '{evil}' to be rejected"
            );
        }
    }

    #[test]
    fn export_command_allows_digest_refs() {
        // @sha256:… digest refs are legitimate and must pass validation.
        let argv = export_command(
            "containerd",
            "registry.example.com/library/nginx@sha256:abcdef1234567890",
        )
        .unwrap();
        assert_eq!(
            argv.last().unwrap(),
            "registry.example.com/library/nginx@sha256:abcdef1234567890"
        );
    }

    #[test]
    fn validate_save_path_accepts_normal_absolute() {
        assert!(validate_save_path("/home/user/exports/nginx.tar").is_ok());
        assert!(validate_save_path("/tmp/img.tar").is_ok());
        assert!(validate_save_path("/Users/me/Downloads/img.tar").is_ok());
    }

    #[test]
    fn validate_save_path_rejects_traversal_and_relative() {
        assert!(validate_save_path("").is_err());
        assert!(validate_save_path("relative/img.tar").is_err());
        assert!(validate_save_path("/home/../etc/passwd").is_err());
        assert!(validate_save_path("/home/./x/../y/img.tar").is_err());
    }

    #[test]
    fn validate_save_path_rejects_system_dirs() {
        assert!(validate_save_path("/etc/x/img.tar").is_err());
        assert!(validate_save_path("/usr/local/img.tar").is_err());
        assert!(validate_save_path("/bin/img.tar").is_err());
        assert!(validate_save_path("/boot/img.tar").is_err());
    }

    #[test]
    fn list_command_unknown_runtime_errors() {
        assert!(list_command("cri-o").is_err());
    }

    #[test]
    fn parse_docker_images_list() {
        let output = r#"{"Repository":"nginx","Tag":"1.25","ID":"sha256:abc123","Size":"12345678"}
{"Repository":"busybox","Tag":"latest","ID":"sha256:def456","Size":"1234567"}"#;
        let images = parse_listed_images(output, "docker");
        assert_eq!(images, vec!["nginx:1.25", "busybox:latest"]);
    }

    #[test]
    fn parse_containerd_images_list() {
        // `ctr images list -q` outputs bare refs, one per line.
        let output = "docker.io/library/nginx:1.25\ndocker.io/library/busybox:latest\n";
        let images = parse_listed_images(output, "containerd");
        assert_eq!(
            images,
            vec![
                "docker.io/library/nginx:1.25",
                "docker.io/library/busybox:latest"
            ]
        );
    }
}
