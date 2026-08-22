//! Interactive shell (exec) into a pod container (B4).
//!
//! Each session runs `exec` with a TTY and pumps three channels:
//!   - container stdout  → emitted as `shell-out:{id}` (text chunks)
//!   - frontend stdin    → written to the container (via `shell_input`)
//!   - terminal resize   → forwarded to the container (via `shell_resize`)
//!
//! On exit/error it emits `shell-closed:{id}`. The pump task owns the
//! AttachedProcess, so aborting the task (on stop / disconnect) tears down the
//! exec connection.

use crate::core::events::EventSink;
use crate::error::AppError;
use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::api::{Api, AttachParams, TerminalSize};
use k7s_deps::kube::Client;
use k7s_deps::tokio::io::{AsyncReadExt, AsyncWriteExt};
use k7s_deps::tokio::sync::mpsc;
use serde::Serialize;

/// Prefix for stdout chunk events (`shell-out:{stream_id}`).
pub const SHELL_OUT_PREFIX: &str = "shell-out:";
/// Prefix for session-closed events (`shell-closed:{stream_id}`).
pub const SHELL_CLOSED_PREFIX: &str = "shell-closed:";

/// A stdout chunk sent to the frontend.
#[derive(Serialize, Clone)]
struct ShellOut {
    data: String,
}

/// Try bash, fall back to sh — gives a nicer prompt where bash exists. We probe
/// with `command -v` first: a *failed* `exec` would terminate the POSIX shell
/// before any `||` fallback could run, so we must only exec a binary we know
/// exists (many images, e.g. redis, have no /bin/bash).
const SHELL_CMD: [&str; 3] = [
    "/bin/sh",
    "-c",
    "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi",
];

/// The command to exec, honouring the user's override (B23).
///
/// An override still runs through `/bin/sh -c` rather than being exec'd directly:
/// people type things like `env TERM=xterm bash -l`, and running that as a bare
/// argv would look for a binary with spaces in its name. It also keeps the same
/// shape as the default, whose whole job is to be a shell snippet.
pub fn shell_cmd(override_cmd: &str) -> Vec<String> {
    let trimmed = override_cmd.trim();
    if trimmed.is_empty() {
        return SHELL_CMD.iter().map(|s| s.to_string()).collect();
    }
    vec!["/bin/sh".into(), "-c".into(), format!("exec {trimmed}")]
}

/// Run a shell session until the process exits or the task is aborted.
#[allow(clippy::too_many_arguments)]
pub async fn run_shell(
    client: Client,
    sink: EventSink,
    stream_id: String,
    namespace: String,
    pod: String,
    container: String,
    // The user's shell override, or empty for the default probe (B23).
    command: String,
    input_rx: mpsc::Receiver<Vec<u8>>,
    resize_rx: mpsc::Receiver<(u16, u16)>,
) {
    run_argv(
        client,
        sink,
        stream_id,
        namespace,
        pod,
        container,
        shell_cmd(&command),
        input_rx,
        resize_rx,
    )
    .await
}

/// Run an explicit argv until it exits or the task is aborted.
///
/// Split out from `run_shell` for the node debug shell (B53), whose command is an
/// `nsenter` invocation rather than a shell snippet. Wrapping that in `sh -c`
/// the way `shell_cmd` does would mean quoting a command line that itself ends in
/// a quoted shell snippet — so it passes argv straight through instead.
#[allow(clippy::too_many_arguments)]
pub async fn run_argv(
    client: Client,
    sink: EventSink,
    stream_id: String,
    namespace: String,
    pod: String,
    container: String,
    argv: Vec<String>,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    mut resize_rx: mpsc::Receiver<(u16, u16)>,
) {
    let closed_event = format!("{}{}", SHELL_CLOSED_PREFIX, stream_id);
    // Give the frontend time to attach its `shell-out` listener after the
    // `start_shell` invoke resolves. Without this, the container's first
    // output (the shell prompt) can be emitted before the async Tauri
    // `listen()` call attaches, and the prompt is silently dropped — the
    // terminal stays blank and the shell looks dead even though it's alive.
    k7s_deps::tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let reason = match exec_pump(
        client,
        &sink,
        &stream_id,
        &namespace,
        &pod,
        &container,
        argv,
        &mut input_rx,
        &mut resize_rx,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => e.to_string(),
    };
    sink.emit(&closed_event, &reason);
}

#[allow(clippy::too_many_arguments)]
async fn exec_pump(
    client: Client,
    sink: &EventSink,
    stream_id: &str,
    namespace: &str,
    pod: &str,
    container: &str,
    argv: Vec<String>,
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_rx: &mut mpsc::Receiver<(u16, u16)>,
) -> Result<String, AppError> {
    let api: Api<Pod> = Api::namespaced(client, namespace);
    let ap = AttachParams::default()
        .stdin(true)
        .stdout(true)
        .stderr(false) // tty merges stderr into stdout
        .tty(true)
        .container(container.to_string());

    let mut proc = api
        .exec(pod, argv, &ap)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;

    let mut stdout = proc
        .stdout()
        .ok_or_else(|| AppError::Other("no stdout".into()))?;
    let mut stdin = proc
        .stdin()
        .ok_or_else(|| AppError::Other("no stdin".into()))?;
    // terminal_size() is a futures mpsc Sender (bounded); use try_send (non-async).
    let mut ts_tx = proc.terminal_size();

    let out_event = format!("{}{}", SHELL_OUT_PREFIX, stream_id);
    let mut buf = [0u8; 8192];

    loop {
        k7s_deps::tokio::select! {
            // Container output → frontend.
            read = stdout.read(&mut buf) => match read {
                Ok(0) => return Ok("session ended".into()),
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                    sink.emit(&out_event, &ShellOut { data });
                }
                Err(e) => return Err(AppError::Other(e.to_string())),
            },
            // Frontend keystrokes → container stdin.
            input = input_rx.recv() => match input {
                Some(bytes) => {
                    if stdin.write_all(&bytes).await.is_err() || stdin.flush().await.is_err() {
                        return Ok("stdin closed".into());
                    }
                }
                None => return Ok("input closed".into()),
            },
            // Terminal resize → container.
            size = resize_rx.recv() => {
                if let Some((cols, rows)) = size {
                    if let Some(tx) = ts_tx.as_mut() {
                        let _ = tx.try_send(TerminalSize { width: cols, height: rows });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No override → the bash-or-sh probe, unchanged.
    #[test]
    fn empty_override_uses_the_default_probe() {
        assert_eq!(shell_cmd(""), SHELL_CMD.to_vec());
        assert_eq!(shell_cmd("   "), SHELL_CMD.to_vec());
    }

    /// An override runs through `sh -c`, not as a bare argv: people type command
    /// lines ("env TERM=xterm bash -l"), and exec'ing that directly would look for
    /// a binary whose name contains spaces.
    #[test]
    fn override_runs_through_a_shell() {
        assert_eq!(
            shell_cmd("/bin/zsh"),
            vec!["/bin/sh", "-c", "exec /bin/zsh"]
        );
        assert_eq!(
            shell_cmd("env TERM=xterm bash -l"),
            vec!["/bin/sh", "-c", "exec env TERM=xterm bash -l"]
        );
    }

    /// `exec` replaces the shell, so the session ends when the command does —
    /// without it, an extra /bin/sh would linger between the user and their shell.
    #[test]
    fn override_is_exec_ed() {
        let cmd = shell_cmd("bash");
        assert!(
            cmd[2].starts_with("exec "),
            "override must replace the wrapping shell"
        );
    }

    /// Surrounding whitespace from the settings field doesn't reach the container.
    #[test]
    fn override_is_trimmed() {
        assert_eq!(shell_cmd("  bash  "), vec!["/bin/sh", "-c", "exec bash"]);
    }
}
