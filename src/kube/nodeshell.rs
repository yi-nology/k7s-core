//! Node debug shell (B53): a root shell on a node's host OS.
//!
//! There is no Kubernetes API for "give me a shell on this machine", so this does
//! what `kubectl debug node/...` and Lens do — runs a privileged pod pinned to the
//! node, then `nsenter`s out of every namespace into PID 1's. What you get is not
//! a shell in a container that can see the host; it is the host's own shell, with
//! the host's filesystem, processes, and network.
//!
//! That is a full privilege escalation to root on the machine, and it is the point
//! of the feature. So the design is built around the two ways it can go wrong:
//!
//! **Leaving a privileged pod running.** The session deletes its pod on close, but
//! "on close" is a promise the app can only keep while it's alive — a crash, a
//! kill -9, or a laptop lid closing at the wrong moment would strand a root-capable
//! pod on a node indefinitely. So the pod also carries `activeDeadlineSeconds`,
//! which makes the *API server* terminate it regardless of what happened here.
//! That's the guarantee that survives us; the explicit delete is just the tidy path.
//! On top of that, every start sweeps the node's leftovers first (see `LABEL_NODE`),
//! so a previous crash is cleaned up by the next session rather than accumulating.
//!
//! **Starting one by accident.** Not this module's job — the pod is only created
//! when the user explicitly asks (see the Shell tab for nodes), never by navigating.
//!
//! The spec-building here is deliberately pure and heavily tested: it's the part
//! that decides how much privilege gets handed out, and it should be reviewable
//! without a cluster.

use k7s_deps::k8s_openapi::api::core::v1::{Container, Pod, PodSpec, SecurityContext, Toleration};
use k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

/// Namespace the debug pod is created in.
///
/// `default` matches `kubectl debug node/...`, which matters more than it looks:
/// anyone auditing the cluster will find these where they already expect
/// short-lived debug workloads, not tucked away somewhere that looks deliberate.
pub const DEBUG_NAMESPACE: &str = "default";

/// Marks every pod this feature creates, for the orphan sweep and for humans
/// grepping a cluster wondering what made a privileged pod.
pub const LABEL_MANAGED: &str = "app.kubernetes.io/managed-by";
pub const LABEL_MANAGED_VALUE: &str = "k7s";
/// Which node a debug pod belongs to — the selector the sweep uses.
pub const LABEL_NODE: &str = "k7s.dev/debug-node";

/// Default image. Overridable in settings.
///
/// Multi-arch matters here and is easy to get wrong: a single-arch image works on
/// an amd64 node and dies in ImagePullBackOff on an arm64 one, which reads as "the
/// feature is broken" rather than "wrong image". netshoot publishes both, and
/// carries a real `nsenter` (busybox's applet is missing options we use).
pub const DEFAULT_IMAGE: &str = "nicolaka/netshoot";

/// Server-side kill switch: how long a debug pod may live, whatever happens here.
///
/// An hour is long enough that nobody loses a real debugging session to it, and
/// short enough that a stranded root pod is a footnote rather than an incident.
pub const MAX_LIFETIME_SECS: i64 = 3600;

/// The pod name for a session. Includes the node so a stray pod is self-describing.
///
/// Node names can be up to 253 chars and contain dots (they're often FQDNs), while
/// a pod name must be a DNS *label*: ≤63 chars, no dots. Truncating and
/// substituting keeps a readable name without generating one the API server will
/// reject on a cluster whose nodes are named `host.dc1.example.com`.
pub fn pod_name(node: &str, seq: u64) -> String {
    let sanitized: String = node
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let suffix = format!("-{seq}");
    // "k7s-debug-" + node + "-<seq>" must fit in 63.
    let room = 63 - "k7s-debug-".len() - suffix.len();
    let short: String = sanitized.chars().take(room).collect();
    // A trailing '-' from truncation or substitution is not a legal name ending.
    format!("k7s-debug-{}{}", short.trim_matches('-'), suffix)
}

/// The command that escapes into the host's namespaces.
///
/// `--target 1 --mount --uts --ipc --net --pid` is the whole trick: entering PID
/// 1's mount namespace is what makes `/` the *host's* root rather than the image's,
/// so the tools you get are the node's own.
///
/// The bash-or-sh probe mirrors the pod shell (kube/exec.rs) for the same reason it
/// exists there: a failed `exec` would kill the shell before any fallback could
/// run, so we only exec what we've confirmed is present. Here it's doubly true —
/// this runs against whatever distro the node happens to be.
pub fn nsenter_cmd() -> Vec<String> {
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
        "/bin/sh".into(),
        "-c".into(),
        "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi".into(),
    ]
}

/// Build the debug pod for `node`.
///
/// Every privileged bit below is load-bearing; none is defensive copy-paste:
///   - `node_name` pins the pod *and* bypasses the scheduler, which is what lets
///     this work on a node that is cordoned or tainted — usually exactly the node
///     you need a shell on.
///   - `host_pid` is what makes `--target 1` mean the host's init rather than the
///     container's.
///   - `host_network`/`host_ipc` complete the picture, so `ss`, `ip`, and friends
///     report the node's reality.
///   - `privileged` is required to enter another namespace at all.
///   - tolerations accept *everything*, for the same reason as `node_name`: a node
///     under `NoExecute` pressure is a node worth looking at.
///   - `restart_policy: Never` — if the shell exits, the session is over. Restarting
///     it would silently hand out a fresh root shell nobody asked for.
pub fn debug_pod_spec(node: &str, image: &str, name: &str) -> Pod {
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_MANAGED.to_string(), LABEL_MANAGED_VALUE.to_string());
    labels.insert(LABEL_NODE.to_string(), node.to_string());

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "k7s.dev/description".to_string(),
        format!("Interactive debug shell on node {node}, created by k7s. Safe to delete."),
    );

    Pod {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(DEBUG_NAMESPACE.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(PodSpec {
            node_name: Some(node.to_string()),
            host_pid: Some(true),
            host_network: Some(true),
            host_ipc: Some(true),
            restart_policy: Some("Never".into()),
            // The backstop that outlives this process. See MAX_LIFETIME_SECS.
            active_deadline_seconds: Some(MAX_LIFETIME_SECS),
            // Nothing to flush; waiting 30s to reap a shell that has already exited
            // just leaves the privileged pod around longer.
            termination_grace_period_seconds: Some(0),
            tolerations: Some(vec![Toleration {
                operator: Some("Exists".into()),
                ..Default::default()
            }]),
            containers: vec![Container {
                name: "debug".into(),
                image: Some(image.to_string()),
                // Hold the container open; the shell arrives later over exec. Without
                // this the container would run its entrypoint and exit before anyone
                // could attach.
                command: Some(vec!["sleep".into(), MAX_LIFETIME_SECS.to_string()]),
                tty: Some(true),
                stdin: Some(true),
                // IfNotPresent (not the default Always for a :latest tag) so the pod
                // reuses a pre-loaded image instead of re-pulling. Air-gapped clusters
                // pre-load netshoot onto nodes; a forced pull there fails with
                // ImagePullBackOff and the shell never starts. IfNotPresent still pulls
                // when the image is absent, so connected clusters are unaffected.
                image_pull_policy: Some("IfNotPresent".into()),
                security_context: Some(SecurityContext {
                    privileged: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Label selector matching this node's debug pods (for the orphan sweep).
pub fn node_selector(node: &str) -> String {
    format!("{LABEL_MANAGED}={LABEL_MANAGED_VALUE},{LABEL_NODE}={node}")
}

/// Explain why a debug pod isn't running yet, as something a human can act on.
///
/// The two cases that actually happen are worth distinguishing by name: a NotReady
/// node leaves the pod `Pending` forever (nothing is wrong with the manifest — the
/// kubelet simply isn't listening), and a wrong or single-arch image shows up as a
/// container waiting reason. Reporting a bare timeout for either sends people
/// looking in the wrong place.
pub fn pending_reason(phase: &str, waiting: Option<(&str, &str)>) -> String {
    if let Some((reason, message)) = waiting {
        let detail = if message.is_empty() {
            String::new()
        } else {
            format!(" — {message}")
        };
        return format!("the debug container is stuck in {reason}{detail}");
    }
    match phase {
        "Pending" => "the pod is still Pending. If the node is NotReady its kubelet can't \
             start the pod, and no amount of waiting will change that."
            .to_string(),
        other => format!("the debug pod is {other}, not Running"),
    }
}

/// How long to wait for the debug pod to reach Running before giving up. Mirrors
/// the worst-case scheduling + image-pull time observed in the field; long
/// enough for a slow registry, short enough that a stuck pod doesn't hang the
/// caller indefinitely. Shared by the interactive node shell and the one-shot
/// image-import path, so it lives here alongside the pod spec.
pub const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Wait for the debug pod to reach Running, or explain what it's stuck on.
///
/// Shared by `start_node_shell` (interactive) and `import::import_to_node`
/// (one-shot). Both need the same "wait, then surface the actionable reason"
/// behaviour, so it lives with the pod spec rather than in either caller.
pub async fn await_debug_pod(api: &k7s_deps::kube::Api<Pod>, name: &str) -> crate::error::AppResult<()> {
    let deadline = k7s_deps::tokio::time::Instant::now() + READY_TIMEOUT;
    let mut last = String::from("the pod was never observed");
    while k7s_deps::tokio::time::Instant::now() < deadline {
        let pod = match api.get(name).await {
            Ok(p) => p,
            // Transient 404 right after create is expected: the API server's
            // read cache may lag behind etcd by a few hundred ms. Keep polling;
            // any other error (auth, network) is real and should fail fast.
            // kube-rs 0.99 wraps 404 differently across code paths — match
            // on the status code broadly rather than assuming the Api variant.
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("404") || msg.contains("not found") || msg.contains("NotFound") {
                    last = format!("pod {name} not yet visible (API cache lag)");
                    k7s_deps::tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                    continue;
                }
                return Err(e.into());
            }
        };
        let status = pod.status.unwrap_or_default();
        let phase = status.phase.clone().unwrap_or_default();
        if phase == "Running" {
            return Ok(());
        }
        // A container waiting reason (ImagePullBackOff, CreateContainerError) is far
        // more actionable than the phase, so prefer it when there is one.
        let waiting = status
            .container_statuses
            .as_ref()
            .and_then(|cs| cs.first())
            .and_then(|c| c.state.as_ref())
            .and_then(|s| s.waiting.as_ref())
            .map(|w| {
                (
                    w.reason.clone().unwrap_or_default(),
                    w.message.clone().unwrap_or_default(),
                )
            });
        last = pending_reason(
            &phase,
            waiting.as_ref().map(|(r, m)| (r.as_str(), m.as_str())),
        );
        k7s_deps::tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    }
    Err(crate::error::AppError::Other(format!(
        "timed out starting the debug pod: {last}"
    )))
}

/// Delete a debug pod, best effort. Used by both the orphan sweep and session
/// teardown, and by image import's unconditional cleanup.
pub async fn delete_debug_pod(api: &k7s_deps::kube::Api<Pod>, name: &str) {
    use k7s_deps::kube::api::DeleteParams;
    // Grace period 0: there is nothing to flush, and every second it lingers is a
    // second a privileged pod is still on the node.
    let dp = DeleteParams {
        grace_period_seconds: Some(0),
        ..Default::default()
    };
    if let Err(e) = api.delete(name, &dp).await {
        k7s_deps::tracing::warn!("failed to delete debug pod {name}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_name_is_a_legal_dns_label() {
        let n = pod_name("murphy-yi", 7);
        assert_eq!(n, "k7s-debug-murphy-yi-7");
        assert!(n.len() <= 63);
    }

    /// Nodes are routinely named as FQDNs, and a dot is illegal in a pod name.
    #[test]
    fn pod_name_replaces_illegal_characters() {
        let n = pod_name("host.dc1.example.com", 1);
        assert!(
            !n.contains('.'),
            "dots must not survive into a pod name: {n}"
        );
        assert_eq!(n, "k7s-debug-host-dc1-example-com-1");
    }

    /// A 253-char node name must not produce a pod the API server rejects.
    #[test]
    fn pod_name_stays_within_the_limit() {
        let n = pod_name(&"a".repeat(253), 999);
        assert!(n.len() <= 63, "got {} chars: {n}", n.len());
        assert!(n.ends_with("-999"));
    }

    /// Truncation must not leave a trailing dash — also not a legal name.
    #[test]
    fn pod_name_never_ends_with_a_dash_before_the_sequence() {
        let n = pod_name("node--------------", 3);
        assert!(!n.contains("--3"), "trailing dash survived: {n}");
    }

    #[test]
    fn uppercase_node_names_are_lowercased() {
        assert_eq!(pod_name("MURPHY-YI", 1), "k7s-debug-murphy-yi-1");
    }

    /// The privileges below are the entire security surface of this feature. If one
    /// of them changes, it should be a deliberate edit to this test too.
    #[test]
    fn spec_requests_exactly_the_privileges_the_shell_needs() {
        let pod = debug_pod_spec("murphy-yi", DEFAULT_IMAGE, "k7s-debug-murphy-yi-1");
        let spec = pod.spec.unwrap();

        assert_eq!(spec.node_name.as_deref(), Some("murphy-yi"));
        assert_eq!(
            spec.host_pid,
            Some(true),
            "nsenter --target 1 needs the host PID namespace"
        );
        assert_eq!(spec.host_network, Some(true));
        assert_eq!(spec.host_ipc, Some(true));
        assert_eq!(spec.restart_policy.as_deref(), Some("Never"));
        assert_eq!(
            spec.containers[0]
                .security_context
                .as_ref()
                .unwrap()
                .privileged,
            Some(true)
        );
    }

    /// The one guarantee that survives the app being killed.
    #[test]
    fn spec_always_carries_a_server_side_deadline() {
        let spec = debug_pod_spec("n", DEFAULT_IMAGE, "p").spec.unwrap();
        assert_eq!(spec.active_deadline_seconds, Some(MAX_LIFETIME_SECS));
        assert_eq!(spec.termination_grace_period_seconds, Some(0));
    }

    /// Debugging a cordoned or NoExecute-tainted node is the common case, not the
    /// exotic one — a spec that can't land there is much less useful.
    #[test]
    fn spec_tolerates_every_taint() {
        let spec = debug_pod_spec("n", DEFAULT_IMAGE, "p").spec.unwrap();
        let tol = &spec.tolerations.as_ref().unwrap()[0];
        assert_eq!(tol.operator.as_deref(), Some("Exists"));
        assert!(
            tol.key.is_none(),
            "a keyed toleration would only match some taints"
        );
        assert!(tol.effect.is_none(), "no effect means all effects");
    }

    /// The pod is labelled so orphans are findable — by the sweep and by a human.
    #[test]
    fn spec_is_labelled_for_cleanup() {
        let pod = debug_pod_spec("murphy-yi", DEFAULT_IMAGE, "p");
        let labels = pod.metadata.labels.unwrap();
        assert_eq!(
            labels.get(LABEL_MANAGED).map(String::as_str),
            Some(LABEL_MANAGED_VALUE)
        );
        assert_eq!(
            labels.get(LABEL_NODE).map(String::as_str),
            Some("murphy-yi")
        );
        assert!(node_selector("murphy-yi").contains("k7s.dev/debug-node=murphy-yi"));
    }

    /// The container must outlive its own entrypoint, or exec has nothing to attach
    /// to — but not outlive the deadline, which would be a confusing double timeout.
    #[test]
    fn container_sleeps_for_exactly_the_pod_lifetime() {
        let spec = debug_pod_spec("n", DEFAULT_IMAGE, "p").spec.unwrap();
        assert_eq!(
            spec.containers[0].command.as_ref().unwrap(),
            &vec!["sleep".to_string(), MAX_LIFETIME_SECS.to_string()]
        );
    }

    #[test]
    fn nsenter_enters_every_host_namespace() {
        let cmd = nsenter_cmd().join(" ");
        for flag in ["--target 1", "--mount", "--uts", "--ipc", "--net", "--pid"] {
            assert!(cmd.contains(flag), "missing {flag} in: {cmd}");
        }
    }

    /// Same reasoning as the pod shell: only exec a binary we've confirmed exists.
    #[test]
    fn nsenter_probes_before_exec_ing_bash() {
        let cmd = nsenter_cmd().join(" ");
        assert!(cmd.contains("command -v bash"));
        assert!(cmd.contains("exec sh"));
    }

    /// A NotReady node is the single most likely reason this hangs, so it must not
    /// be reported as a generic timeout.
    #[test]
    fn pending_reason_calls_out_a_dead_kubelet() {
        let msg = pending_reason("Pending", None);
        assert!(msg.contains("NotReady"), "got: {msg}");
    }

    /// A single-arch image on a mixed-arch cluster surfaces here.
    #[test]
    fn pending_reason_prefers_the_container_waiting_reason() {
        let msg = pending_reason(
            "Pending",
            Some(("ImagePullBackOff", "no match for platform")),
        );
        assert!(msg.contains("ImagePullBackOff"));
        assert!(msg.contains("no match for platform"));
    }

    #[test]
    fn pending_reason_handles_an_empty_waiting_message() {
        let msg = pending_reason("Pending", Some(("CreateContainerError", "")));
        assert!(msg.contains("CreateContainerError"));
        assert!(!msg.contains(" — "), "no dangling separator: {msg}");
    }
}
