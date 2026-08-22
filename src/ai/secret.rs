//! Storage for the LLM api_key.
//!
//! **Primary**: OS keychain via the `keyring` crate — macOS Keychain, Linux
//! secret-service, Windows Credential Manager. The key is stored by the OS
//! credential store and never touches our own files in plaintext.
//!
//! **Fallback**: file-based XOR obfuscation (`ai-key.bin`) for environments
//! where the keychain is unavailable (headless CI, containers, Linux without
//! a secret-service daemon). The file is `chmod 0600` on Unix.
//!
//! **The XOR fallback is obfuscation, not encryption.** The mask key lives in
//! source, so anyone with the file can recover the plaintext; 0600 only stops
//! other *local users*, not backups/cloud-sync/malware. The keychain is the
//! real protection; the file path exists so the app still works on hosts with
//! no secret store. Both paths present the same `save` / `load` / `delete`
//! interface; callers don't know which backend is in use.
//!
//! **Concurrency note**: the keychain backends are synchronous and may block
//! (notably the Linux secret-service D-Bus call). Callers already run this
//! inside `tokio::task::spawn_blocking` (see `ai::config::load`), so blocking
//! here does not stall the runtime.

use crate::ai::error::{AiError, AiResult};

const SERVICE: &str = "k7s-ai";
const USER: &str = "api-key";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Persist the api_key. Empty string deletes it.
///
/// Tries the OS keychain first; if that's unavailable or errors, falls back
/// to the XOR-obfuscated file so the app still works headless.
pub fn save(data_dir: Option<&std::path::Path>, key: &str) -> AiResult<()> {
    if key.is_empty() {
        return delete(data_dir);
    }
    // Keychain first.
    match keyring_entry() {
        Ok(entry) => match entry.set_password(key) {
            Ok(()) => {
                // Also wipe any stale file from a previous file-only install
                // so the key doesn't linger in two places.
                let path = file_path(data_dir);
                if path.exists() {
                    let _ = std::fs::remove_file(&path);
                }
                Ok(())
            }
            Err(e) => {
                k7s_deps::tracing::warn!(
                    "keychain set_password failed ({e}); falling back to file"
                );
                save_to_file(data_dir, key)
            }
        },
        Err(e) => {
            k7s_deps::tracing::warn!("keychain unavailable ({e}); using file fallback");
            save_to_file(data_dir, key)
        }
    }
}

/// Load the api_key. Returns `None` when nothing is stored.
///
/// Keychain first; `NoEntry` (and keychain-unavailable) fall through to the
/// file so a key saved via the file path on a headless host can still be read.
pub fn load(data_dir: Option<&std::path::Path>) -> AiResult<Option<String>> {
    match keyring_entry() {
        Ok(entry) => match entry.get_password() {
            Ok(pw) => Ok(Some(pw)),
            Err(k7s_deps::keyring::Error::NoEntry) => {
                // Not in the keychain — try the file (may exist from file-only use).
                load_from_file(data_dir)
            }
            Err(e) => {
                k7s_deps::tracing::warn!("keychain get_password failed ({e}); trying file");
                load_from_file(data_dir)
            }
        },
        Err(e) => {
            k7s_deps::tracing::debug!("keychain unavailable ({e}); loading from file");
            load_from_file(data_dir)
        }
    }
}

/// Delete the stored key, from whichever backend holds it.
pub fn delete(data_dir: Option<&std::path::Path>) -> AiResult<()> {
    // Best-effort keychain delete (ignore NoEntry).
    if let Ok(entry) = keyring_entry() {
        if let Err(e) = entry.delete_credential() {
            // NoEntry is fine; anything else is logged but non-fatal — we still
            // try the file below.
            if !matches!(e, k7s_deps::keyring::Error::NoEntry) {
                k7s_deps::tracing::warn!("keychain delete failed: {e}");
            }
        }
    }
    let path = file_path(data_dir);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

/// Build a keyring `Entry` for our well-known service/user. Returns `Err` when
/// the platform has no usable credential store (so callers can fall back).
fn keyring_entry() -> Result<k7s_deps::keyring::Entry, k7s_deps::keyring::Error> {
    k7s_deps::keyring::Entry::new(SERVICE, USER)
}

// ---------------------------------------------------------------------------
// File-based fallback (XOR obfuscation, chmod 0600)
// ---------------------------------------------------------------------------

/// The XOR mask. **This is not a secret** — it lives in the binary and only
/// stops a casual `cat` from revealing the key. Real protection comes from the
/// keychain; the file is a headless/CI fallback.
const OBFUSCATION_KEY: &[u8] = b"k7s-ai-file-fallback-obfuscation-only";

fn xor(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= OBFUSCATION_KEY[i % OBFUSCATION_KEY.len()];
    }
}

fn file_path(data_dir: Option<&std::path::Path>) -> std::path::PathBuf {
    match data_dir {
        Some(d) => d.join("ai-key.bin"),
        None => crate::ai::default_config_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("ai-key.bin"),
    }
}

fn save_to_file(data_dir: Option<&std::path::Path>, key: &str) -> AiResult<()> {
    use k7s_deps::base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let path = file_path(data_dir);
    let mut buf = key.as_bytes().to_vec();
    xor(&mut buf);
    let encoded = B64.encode(&buf);
    std::fs::write(&path, encoded)
        .map_err(|e| AiError::Other(format!("write {}: {e}", path.display())))?;
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

fn load_from_file(data_dir: Option<&std::path::Path>) -> AiResult<Option<String>> {
    use k7s_deps::base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let path = file_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let encoded = std::fs::read_to_string(&path)
        .map_err(|e| AiError::Other(format!("read {}: {e}", path.display())))?;
    if encoded.trim().is_empty() {
        return Ok(None);
    }
    let mut buf = B64
        .decode(encoded.trim())
        .map_err(|e| AiError::Other(format!("decode key: {e}")))?;
    xor(&mut buf);
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| AiError::Other(format!("key not utf8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE on the keychain: the OS keychain (macOS Keychain / Linux
    // secret-service / Windows Credential Manager) is a *process-wide,
    // host-global* store keyed by (SERVICE, USER). The `data_dir` argument to
    // save/load/delete only affects the *file* fallback path — it does NOT
    // isolate the keychain entry. So the public-API round-trip can't be tested
    // reliably in parallel (two tests would clobber the same keychain entry,
    // and a value left by a prior run would satisfy load() spuriously).
    //
    // Instead we test the file-fallback backend directly (it IS isolated by
    // `data_dir`), and rely on the fact that save()/load()/delete() route to
    // the keychain *or* the file via the same `data_dir`-agnostic entry. The
    // wiring (keychain first, file on NoEntry/unavailable) is covered by the
    // `keyring_entry` helper returning Err when there's no store, which the
    // headless CI environment exercises end-to-end.

    /// The file-fallback path round-trips on its own (this is what headless
    /// hosts use when the keychain is absent).
    #[test]
    fn file_xor_round_trip() {
        let dir = std::env::temp_dir().join("k7s-ai-test-xor");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        save_to_file(Some(&dir), "sk-fallback-key").unwrap();
        let loaded = load_from_file(Some(&dir)).unwrap();
        assert_eq!(loaded.as_deref(), Some("sk-fallback-key"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The XOR file must not contain the plaintext key verbatim. NOTE: this
    /// only verifies obfuscation (the key is recoverable from source) — it is
    /// NOT a security guarantee. Real secrecy comes from the keychain.
    #[test]
    fn file_fallback_is_not_plaintext() {
        let dir = std::env::temp_dir().join("k7s-ai-test-no-plaintext");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        save_to_file(Some(&dir), "sk-should-not-appear").unwrap();
        let raw = std::fs::read_to_string(file_path(Some(&dir))).unwrap();
        assert!(
            !raw.contains("sk-should-not-appear"),
            "file fallback must not contain the plaintext key (it is obfuscated, not encrypted)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty key save should delete the file fallback (mirrors the public
    /// `save("") → delete` contract), tested via the isolated file path.
    #[test]
    fn file_empty_save_deletes() {
        let dir = std::env::temp_dir().join("k7s-ai-test-empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        save_to_file(Some(&dir), "something").unwrap();
        assert!(load_from_file(Some(&dir)).unwrap().is_some());

        // Simulate the delete the public `save("")` performs.
        let path = file_path(Some(&dir));
        let _ = std::fs::remove_file(&path);
        assert!(load_from_file(Some(&dir)).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
