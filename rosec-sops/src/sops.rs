//! The `sops` command wrapper.
//!
//! Every file operation shells out to the real `sops` binary:
//!
//! ```text
//! sops --encrypt [--age <recipients>] --input-type yaml --output-type yaml <plain>
//! sops --decrypt --input-type yaml --output-type yaml <cipher>
//! ```
//!
//! with `SOPS_AGE_KEY_FILE=<key_file>` in the environment, so the age identity
//! (on this host a YubiKey identity in `~/.config/sops/age/keys.txt`) decides
//! what can be read. No GPG, no age key in the provider, no network call.
//!
//! Writes are atomic from a syncing peer's point of view: the ciphertext goes
//! to a hidden temporary file in the target directory, is fsynced, then
//! renamed over the target, and the directory is fsynced.
//!
//! **No raw sops output in errors.** `sops` quotes document content in its
//! stderr, and a malformed document can make it quote plaintext. Every error
//! in this module and in [`crate::error`] therefore carries a *classified*
//! summary — the error class, the exit code and whether an `ENC[` marker
//! appears — never the stderr text itself.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::error::SopsError;

/// Default upper bound for the `unlock` probe.
///
/// Generous enough for one unattended YubiKey decrypt (well under a second on
/// this host) and for the age plugin's own startup, short enough that an
/// unplugged token cannot hang `rosec unlock`.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Prefix of every age secret key.
pub const AGE_SECRET_PREFIX: &str = "AGE-SECRET-KEY-1";

/// File name an item write tells sops to pretend it reads, so that an item
/// creation rule matches. Public: the identity migration uses the same name for
/// the destination store.
pub const ENCRYPT_NAME: &str = "rosec-encrypt-input.sops.yaml";

/// A configured `sops` binary plus the age identity file it must use.
///
/// The identity file is **mutable**: `unlock` replaces it with the runtime file
/// of the unwrapped derived identity for the session, `lock` resets it. The
/// handle is cheap to clone and every clone sees the same value.
#[derive(Debug, Clone)]
pub struct SopsCommand {
    binary: PathBuf,
    key_file: Arc<RwLock<PathBuf>>,
    probe_timeout: Duration,
}

impl SopsCommand {
    /// Create a wrapper for `binary` that always passes `key_file`.
    pub fn new(binary: impl Into<PathBuf>, key_file: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            key_file: Arc::new(RwLock::new(key_file.into())),
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
        }
    }

    /// Bound the decrypt probe used by [`SopsCommand::probe_decrypt`].
    pub fn with_probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// The identity file this wrapper exports as `SOPS_AGE_KEY_FILE`.
    pub fn key_file(&self) -> PathBuf {
        self.key_file
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Point every later operation at another identity file.
    ///
    /// `unlock` sets the runtime file of the derived identity, `lock` sets the
    /// configured `key_file` back.
    pub fn set_key_file(&self, path: impl Into<PathBuf>) {
        *self.key_file.write().unwrap_or_else(|e| e.into_inner()) = path.into();
    }

    /// The configured `sops` executable.
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Check that the binary runs and that `key_file` (when given) exists.
    ///
    /// Runs `sops --version`, which reads neither the key nor any store file.
    /// Both failures are reported as [`SopsError::Unavailable`] so `unlock` can
    /// name the missing piece. This proves nothing about readability — see
    /// [`SopsCommand::probe_decrypt`].
    ///
    /// `key_file` is `None` when a session already has its derived identity in
    /// `runtime_identity_file`: the store then unlocks without the YubiKey.
    pub async fn probe(&self, key_file: Option<&Path>) -> Result<String, SopsError> {
        if let Some(key_file) = key_file
            && !key_file.is_file()
        {
            return Err(SopsError::Unavailable(format!(
                "age identity file `{}` does not exist (set `options.key_file`)",
                key_file.display()
            )));
        }
        let mut command = Command::new(&self.binary);
        command.args(["--version", "--check-for-updates=false"]);
        if let Some(key_file) = key_file {
            command.env("SOPS_AGE_KEY_FILE", key_file);
        }
        let output = command.stdin(Stdio::null()).output().await.map_err(|e| {
            SopsError::Unavailable(format!(
                "cannot run `{}`: {e} (set `options.sops_binary`)",
                self.binary.display()
            ))
        })?;
        if !output.status.success() {
            return Err(SopsError::SopsFailed {
                args: "--version".into(),
                status: describe_status(output.status),
                reason: classify_stderr(&output.stderr),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Prove that `path` can be decrypted with the configured identity.
    ///
    /// Returns the plaintext length on success, so the caller can check that a
    /// document was really produced. A failure is reported as
    /// [`SopsError::Unreadable`], which maps to [`ProviderError::AuthFailed`]:
    /// the store is present but this identity cannot open it (wrong YubiKey
    /// slot, revoked recipient, or a `keys.txt` holding another identity).
    ///
    /// [`ProviderError::AuthFailed`]: rosec_core::ProviderError::AuthFailed
    pub async fn probe_decrypt(&self, path: &Path) -> Result<usize, SopsError> {
        let plain = self.decrypt_timed(path, self.probe_timeout).await?;
        Ok(plain.len())
    }

    /// Encrypt one plaintext document.
    ///
    /// `recipients` is `None` when no `age_recipient` is configured: sops then
    /// runs without `--age` and the creation rules of the nearest `.sops.yaml`
    /// (from the current directory upwards) choose the recipients. When no
    /// rule matches, sops fails with "no keys provided", which comes back as
    /// [`SopsError::SopsFailed`].
    ///
    /// `cwd` is the directory sops runs in — the store root — so its
    /// `.sops.yaml` is found. The plaintext is piped on stdin. `sops` needs at
    /// least one file argument even when it reads stdin, so `/dev/stdin` is
    /// passed as the input file; `--filename-override` keeps YAML the effective
    /// type for that pseudo-path.
    pub async fn encrypt(
        &self,
        plaintext: &[u8],
        recipients: Option<&str>,
        cwd: &Path,
    ) -> Result<Vec<u8>, SopsError> {
        self.encrypt_as(plaintext, recipients, cwd, ENCRYPT_NAME)
            .await
    }

    /// Encrypt to explicit age recipients, ignoring every creation rule.
    ///
    /// Used by the master file and by the identity migration: the recipient
    /// set is decided by the caller, so no `.sops.yaml` rule can widen or
    /// narrow it.
    pub async fn encrypt_to(
        &self,
        plaintext: &[u8],
        recipients: &str,
        cwd: &Path,
    ) -> Result<Vec<u8>, SopsError> {
        self.encrypt_as(plaintext, Some(recipients), cwd, ENCRYPT_NAME)
            .await
    }

    /// Encrypt one document, naming the file sops must pretend to read.
    ///
    /// `filename_override` is what the creation rules of `.sops.yaml` are
    /// matched against, so the caller decides which rule applies — an item
    /// rule for an item, the master rule for the master file.
    pub async fn encrypt_as(
        &self,
        plaintext: &[u8],
        recipients: Option<&str>,
        cwd: &Path,
        filename_override: &str,
    ) -> Result<Vec<u8>, SopsError> {
        let mut args = vec!["--encrypt".to_string()];
        // sops keeps only the last of repeated `--age` flags; a comma-joined
        // list in one flag encrypts to every recipient.
        if let Some(list) = recipients {
            let joined = crate::config::split_recipients(list)
                .collect::<Vec<_>>()
                .join(",");
            if !joined.is_empty() {
                args.push("--age".to_string());
                args.push(joined);
            }
        }
        args.extend([
            "--input-type".to_string(),
            "yaml".to_string(),
            "--output-type".to_string(),
            "yaml".to_string(),
            // The override name decides which `.sops.yaml` creation rules
            // match, so it must look like an item file — a bare
            // `rosec-item.yaml` matches `.sops.yaml` rules only by accident.
            "--filename-override".to_string(),
            filename_override.to_string(),
            "/dev/stdin".to_string(),
        ]);
        let output = self.run(&args, Some(plaintext), Some(cwd), None).await?;
        if !output.status.success() {
            return Err(SopsError::SopsFailed {
                args: join_args(&args),
                status: describe_status(output.status),
                reason: classify_stderr(&output.stderr),
            });
        }
        Ok(output.stdout)
    }

    /// Decrypt one YAML file and return the selected field.
    ///
    /// `--extract` runs inside sops, so the rest of the document never reaches
    /// this process. Used to read `identity:` out of the master file.
    pub async fn decrypt_field(&self, path: &Path, extract: &str) -> Result<Vec<u8>, SopsError> {
        let args = vec![
            "--decrypt".to_string(),
            "--extract".to_string(),
            extract.to_string(),
            "--input-type".to_string(),
            "yaml".to_string(),
            "--output-type".to_string(),
            "yaml".to_string(),
            "--filename-override".to_string(),
            "rosec-item.sops.yaml".to_string(),
            path.display().to_string(),
        ];
        let output = self
            .run(&args, None, path.parent(), Some(self.probe_timeout))
            .await?;
        if !output.status.success() {
            return Err(SopsError::SopsFailed {
                args: join_args(&args),
                status: describe_status(output.status),
                reason: classify_stderr(&output.stderr),
            });
        }
        Ok(output.stdout)
    }

    /// Re-encrypt the file header to the recipients of the current rule.
    ///
    /// Runs `sops updatekeys --yes <path>` with `cwd`, so the store's
    /// `.sops.yaml` decides the new recipient set: a key added to the rule is
    /// added to the file, a key removed from the rule is removed from the
    /// file. The payload is decrypted with the key file of this wrapper, so
    /// the operation needs one identity that is still in the file.
    pub async fn update_keys(&self, path: &Path, cwd: &Path) -> Result<(), SopsError> {
        let args = vec![
            "updatekeys".to_string(),
            "--yes".to_string(),
            path.display().to_string(),
        ];
        let output = self.run(&args, None, Some(cwd), None).await?;
        if !output.status.success() {
            return Err(SopsError::SopsFailed {
                args: join_args(&args),
                status: describe_status(output.status),
                reason: classify_stderr(&output.stderr),
            });
        }
        Ok(())
    }

    /// Decrypt one file into plaintext bytes.
    pub async fn decrypt(&self, path: &Path) -> Result<Vec<u8>, SopsError> {
        self.decrypt_timed(path, Duration::from_secs(300)).await
    }

    /// Decrypt one file, aborting the child after `timeout`.
    ///
    /// Used by the unlock probe with a short timeout; the read path uses a long
    /// one so a YubiKey touch prompt is never cut short.
    pub async fn decrypt_timed(
        &self,
        path: &Path,
        timeout: Duration,
    ) -> Result<Vec<u8>, SopsError> {
        let args = vec![
            "--decrypt".to_string(),
            "--input-type".to_string(),
            "yaml".to_string(),
            "--output-type".to_string(),
            "yaml".to_string(),
            "--filename-override".to_string(),
            "rosec-item.sops.yaml".to_string(),
            path.display().to_string(),
        ];
        let output = self
            .run(&args, None, path.parent(), Some(timeout))
            .await
            .map_err(|e| match e {
                SopsError::Unavailable(_) => e,
                SopsError::SopsFailed {
                    args,
                    status,
                    reason,
                } if status == TIMEOUT_STATUS => SopsError::Unreadable {
                    path: path.display().to_string(),
                    reason: format!("`sops {args}` did not finish within {timeout:?}: {reason}"),
                },
                other => other,
            })?;
        if !output.status.success() {
            return Err(SopsError::SopsFailed {
                args: join_args(&args),
                status: describe_status(output.status),
                reason: classify_stderr(&output.stderr),
            });
        }
        Ok(output.stdout)
    }

    async fn run(
        &self,
        args: &[String],
        stdin: Option<&[u8]>,
        cwd: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<std::process::Output, SopsError> {
        let key_file = self.key_file();
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env("SOPS_AGE_KEY_FILE", &key_file)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(cwd) = cwd.filter(|dir| dir.is_dir()) {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().map_err(|e| {
            SopsError::Unavailable(format!("cannot run `{}`: {e}", self.binary.display()))
        })?;

        if let Some(bytes) = stdin {
            let mut handle = child
                .stdin
                .take()
                .expect("stdin is piped when a payload is given");
            handle
                .write_all(bytes)
                .await
                .map_err(|e| SopsError::io(format!("stdin of `{}`", self.binary.display()), e))?;
            handle
                .shutdown()
                .await
                .map_err(|e| SopsError::io(format!("stdin of `{}`", self.binary.display()), e))?;
        }

        match timeout {
            None => child
                .wait_with_output()
                .await
                .map_err(|e| SopsError::io(format!("`{}`", self.binary.display()), e)),
            Some(limit) => match tokio::time::timeout(limit, child.wait_with_output()).await {
                Ok(result) => {
                    result.map_err(|e| SopsError::io(format!("`{}`", self.binary.display()), e))
                }
                Err(_) => {
                    // `kill_on_drop` reaps the child when the handle drops.
                    Err(SopsError::SopsFailed {
                        args: join_args(args),
                        status: TIMEOUT_STATUS.to_owned(),
                        reason: format!("no result within {limit:?}"),
                    })
                }
            },
        }
    }
}

/// Status text used when a child was killed for running too long.
const TIMEOUT_STATUS: &str = "timeout";

fn join_args(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.contains(' ') {
                format!("'{a}'")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn describe_status(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit {code}"),
        None => "terminated by signal".to_owned(),
    }
}

/// Reduce sops stderr to a fixed vocabulary.
///
/// sops quotes the offending part of a document in its errors, and a malformed
/// document can make it quote plaintext. The raw text is therefore never
/// forwarded: the result names the error class only, plus whether an `ENC[`
/// marker was present. Every branch is a constant string, so nothing derived
/// from document content can reach a log.
pub fn classify_stderr(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lower = text.to_lowercase();
    let mut class = if lower.contains("no keys provided") || lower.contains("no master key") {
        "no encryption keys: neither `age_recipient` nor a matching creation rule"
    } else if lower.contains("multiple data keys") || lower.contains("data key") {
        "data key is not readable by this identity"
    } else if lower.contains("identity did not match")
        || lower.contains("no identity matched")
        || lower.contains("could not decrypt")
        || lower.contains("failed to decrypt")
        || lower.contains("decryption failed")
    {
        "decryption failed: the identity in `key_file` cannot open this file"
    } else if lower.contains("failed to get the data key") {
        "cannot obtain the data key"
    } else if lower.contains("mac mismatch") || lower.contains("integrity") {
        "integrity check failed: the ciphertext looks tampered with"
    } else if lower.contains("config file") || lower.contains("creation rules") {
        "sops configuration error"
    } else if lower.contains("yaml") || lower.contains("parse") || lower.contains("unmarshal") {
        "document could not be parsed"
    } else if text.trim().is_empty() {
        "no stderr output"
    } else {
        "unclassified sops failure (stderr redacted)"
    }
    .to_owned();
    if text.contains("ENC[") {
        class.push_str("; sops quoted ciphertext");
    }
    class
}

/// age recipients recorded in a sops ciphertext header.
///
/// The header is public, so this needs no key and starts no subprocess. The
/// formats sops writes are
/// `sops.age[].recipient` (shredded trees) and `sops.age[].enc` plus
/// `sops.age[].recipient` in the flat variant; both carry the `age1…` string.
pub fn header_recipients(cipher: &[u8]) -> Vec<String> {
    let Ok(document) = serde_yaml::from_slice::<serde_yaml::Value>(cipher) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let Some(entries) = document
        .get("sops")
        .and_then(|sops| sops.get("age"))
        .and_then(|age| age.as_sequence())
    else {
        return out;
    };
    for entry in entries {
        for key in ["recipient", "enc"] {
            if let Some(value) = entry.get(key).and_then(|v| v.as_str())
                && value.starts_with("age1")
                && !out.iter().any(|seen| seen == value)
            {
                out.push(value.to_owned());
            }
        }
    }
    out
}

/// Union of `configured` and `existing`, order-stable and de-duplicated.
///
/// An empty `configured` list keeps `existing` untouched, so an unconfigured
/// provider rewrites a file to exactly the recipients it already had.
pub fn union_recipients(configured: &[String], existing: &[String]) -> Vec<String> {
    let mut out: Vec<String> = configured.to_vec();
    for recipient in existing {
        if !out.contains(recipient) {
            out.push(recipient.clone());
        }
    }
    out
}

/// Write `bytes` to `target` through a temporary file in the same directory.
///
/// Sequence: create `<dir>/.<name>.<pid>.<counter>.tmp` with mode 0600, write,
/// fsync the file, rename over the target, fsync the directory. A reader (or a
/// syncing peer) sees either the old file or the whole new file.
///
/// The temporary file is removed on every error path, so a crashed write never
/// leaves a `.tmp` in a synced tree. A best-effort drop guard covers early
/// returns; the explicit cleanups cover the ordinary failures.
pub async fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), SopsError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let dir = target.parent().ok_or_else(|| {
        SopsError::Config(format!("`{}` has no parent directory", target.display()))
    })?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "item".into());
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = dir.join(format!(".{name}.{}.{unique}.tmp", std::process::id()));

    // Drop guard: whatever path returns, the temporary file does not survive.
    struct Cleanup(Option<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let mut cleanup = Cleanup(Some(temp.clone()));

    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode_private()
            .open(&temp)
            .map_err(|e| SopsError::io(temp.display(), e))?;
        file.write_all(bytes)
            .map_err(|e| SopsError::io(temp.display(), e))?;
        file.sync_all()
            .map_err(|e| SopsError::io(temp.display(), e))?;
    }

    std::fs::rename(&temp, target).map_err(|e| SopsError::io(target.display(), e))?;
    // The rename consumed the temporary name; disarm the guard.
    cleanup.0 = None;

    // Persist the rename itself. Best effort: some filesystems (and some
    // network mounts) refuse to fsync a directory; the rename is already
    // visible either way.
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    Ok(())
}

/// Blocking [`write_atomic`] with an explicit file mode.
///
/// The CLI and the unlock path are short-lived and synchronous around these
/// writes, so they call this from a plain function. `mode` is `0600` for a
/// secret file and `0644` for a public one; the temporary file always starts
/// private and is widened to `mode` after the write, before the rename, so the
/// target never exists with wider permissions than requested.
pub fn write_atomic_mode(target: &Path, bytes: &[u8], mode: u32) -> Result<(), SopsError> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let dir = target.parent().ok_or_else(|| {
        SopsError::Config(format!("`{}` has no parent directory", target.display()))
    })?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = dir.join(format!(".{name}.{}.{unique}.tmp", std::process::id()));
    struct Cleanup(Option<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let mut cleanup = Cleanup(Some(temp.clone()));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_private()
        .open(&temp)
        .map_err(|e| SopsError::io(temp.display(), e))?;
    file.write_all(bytes)
        .map_err(|e| SopsError::io(temp.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| SopsError::io(temp.display(), e))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    file.sync_all()
        .map_err(|e| SopsError::io(temp.display(), e))?;
    drop(file);

    std::fs::rename(&temp, target).map_err(|e| SopsError::io(target.display(), e))?;
    cleanup.0 = None;
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    Ok(())
}

/// Blocking [`write_atomic_mode`] with mode `0600`, for private files.
pub fn write_atomic_sync(target: &Path, bytes: &[u8]) -> Result<(), SopsError> {
    write_atomic_mode(target, bytes, 0o600)
}

/// `OpenOptionsExt::mode(0o600)` without importing the trait in every caller.
trait ModePrivate {
    fn mode_private(&mut self) -> &mut Self;
}

impl ModePrivate for std::fs::OpenOptions {
    fn mode_private(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600)
        }
        #[cfg(not(unix))]
        {
            self
        }
    }
}

/// True when `text` holds an age secret key line.
pub fn is_age_identity_text(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .any(|line| line.starts_with(AGE_SECRET_PREFIX))
}

/// Run `age-keygen` and return `(secret key, public recipient)`.
///
/// Both values are secrets-adjacent: the caller must never print the secret.
/// The pair is written to a private temporary file and read back, so a
/// passphrase prompt cannot hang the call (there is no tty to prompt on).
pub fn generate_age_identity() -> Result<(String, String), SopsError> {
    let dir = std::env::temp_dir().join(format!(
        "rosec-agegen-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| SopsError::io(dir.display(), e))?;
    let result = (|| {
        let key_path = dir.join("identity.txt");
        let output = std::process::Command::new("age-keygen")
            .arg("-o")
            .arg(&key_path)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| SopsError::Unavailable(format!("cannot run `age-keygen`: {e}")))?;
        if !output.status.success() {
            return Err(SopsError::Unavailable(
                "`age-keygen` failed; install the `age` package".into(),
            ));
        }
        let text =
            std::fs::read_to_string(&key_path).map_err(|e| SopsError::io(key_path.display(), e))?;
        let secret = text
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(AGE_SECRET_PREFIX))
            .ok_or_else(|| SopsError::Unavailable("`age-keygen` printed no identity".into()))?
            .to_owned();
        let recipient = public_recipient_for(&secret)?;
        Ok((secret, recipient))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The public age recipient of a secret key, via `age-keygen -y`.
///
/// The secret goes over the child's stdin, never through a command line or an
/// environment variable, so it cannot be seen in `ps` or `/proc`.
pub fn public_recipient_for(secret: &str) -> Result<String, SopsError> {
    use std::io::Write;
    let mut child = std::process::Command::new("age-keygen")
        .arg("-y")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SopsError::Unavailable(format!("cannot run `age-keygen -y`: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{secret}\n").as_bytes())
            .map_err(|e| SopsError::io("stdin of `age-keygen -y`", e))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| SopsError::io("`age-keygen -y`", e))?;
    if !output.status.success() {
        return Err(SopsError::Unavailable(
            "`age-keygen -y` rejected the derived identity".into(),
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("age1"))
        .map(str::to_owned)
        .ok_or_else(|| SopsError::Unavailable("`age-keygen -y` printed no recipient".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_atomic_replaces_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("item.sops.yaml");
        write_atomic(&target, b"first").await.unwrap();
        write_atomic(&target, b"second").await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
    }

    #[test]
    fn classifies_without_echoing_stderr() {
        let secret = "hunter2-SUPER-SECRET-VALUE";
        let crafted = format!(
            "Error getting data key: 0 successful groups required, got 0\n\
             while parsing line 4: secrets: password: {secret}\nENC[AES256_GCM,data:AAAA]"
        );
        let class = classify_stderr(crafted.as_bytes());
        assert!(
            !class.contains(secret),
            "secret leaked into the class: {class}"
        );
        assert!(!class.contains("password"), "field leaked: {class}");
        assert!(
            class.contains("sops quoted ciphertext"),
            "the marker is reported: {class}"
        );
        assert!(class.is_ascii(), "{class}");

        assert!(classify_stderr(b"Error: no keys provided\n").contains("no encryption keys"));
        assert!(classify_stderr(b"").contains("no stderr output"));
        assert!(
            classify_stderr(b"something odd happened: /home/u/secret.txt").contains("unclassified")
        );
        assert!(
            !classify_stderr(b"something odd happened: /home/u/secret.txt").contains("secret.txt"),
            "paths from stderr must not be echoed"
        );
    }

    #[test]
    fn reads_recipients_from_a_header() {
        // Shape of a real sops header, abbreviated.
        let cipher = b"sops:\n  age:\n    - recipient: age1aaaa\n    - recipient: age1bbbb\n\
                       lastmodified: '2026-11-14T19:16:17Z'\n";
        assert_eq!(
            header_recipients(cipher),
            vec!["age1aaaa".to_string(), "age1bbbb".to_string()]
        );
        // Duplicates and non-age keys are not reported twice.
        let cipher = b"sops:\n  age:\n    - recipient: age1aaaa\n    - recipient: age1aaaa\n";
        assert_eq!(header_recipients(cipher), vec!["age1aaaa".to_string()]);
        assert!(header_recipients(b"not: sops\n").is_empty());
        assert!(header_recipients(b"\x00\xff garbage").is_empty());
    }

    #[test]
    fn unions_recipients_without_narrowing() {
        let configured = vec!["age1new".to_string()];
        let existing = vec!["age1old1".to_string(), "age1old2".to_string()];
        assert_eq!(
            union_recipients(&configured, &existing),
            vec![
                "age1new".to_string(),
                "age1old1".to_string(),
                "age1old2".to_string()
            ]
        );
        // No configured list: the file keeps exactly what it had.
        assert_eq!(union_recipients(&[], &existing), existing);
        // Duplicates collapse.
        assert_eq!(
            union_recipients(&configured, &configured),
            vec!["age1new".to_string()]
        );
    }
}
