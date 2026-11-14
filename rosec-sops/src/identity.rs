//! The derived sops identity: unwrap once per session.
//!
//! # Two layers
//!
//! A `derived` store has two layers of encryption:
//!
//! 1. **The store identity** — a plain age identity (a `AGE-SECRET-KEY-1…`
//!    line). Every item file is encrypted to its **public** recipient, which
//!    is recorded in plaintext in
//!    `<store>/.rosec-store-identity.recipient`.
//! 2. **The master file** — `<store>/.rosec-store-identity.sops.yaml`, a
//!    sops-encrypted YAML with exactly one field:
//!
//!    ```yaml
//!    identity: AGE-SECRET-KEY-1…
//!    ```
//!
//!    Its recipients are the **unlock group**, chosen by the creation rule that
//!    matches `.rosec-store-identity.sops.yaml` in the store's `.sops.yaml`.
//!    That rule may name age/YubiKey recipients, PGP keys, a KMS key or a
//!    vault, so any sops mode can unlock the store. Adding or removing an
//!    unlock key is `sops updatekeys` on this one file — it never touches an
//!    item.
//!
//! `unlock` therefore costs **one** YubiKey operation per session: it decrypts
//! the master once, writes the identity to a private runtime file, and every
//! item read in that session uses the runtime file. A read costs no token
//! operation at all.
//!
//! # What this module does not do
//!
//! It never prints a secret. Every public function returns the derived
//! **recipient** (public) or a path; the identity itself only ever travels
//! between the master file, the runtime file and a `sops` child process.

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::config::SopsConfig;
use crate::error::SopsError;
use crate::sops::{AGE_SECRET_PREFIX, SopsCommand, is_age_identity_text, write_atomic_sync};
use crate::store_mode::{STORE_IDENTITY_FILE, STORE_IDENTITY_RECIPIENT_FILE, StoreMode, read_meta};

/// The one field the master file holds.
pub const IDENTITY_FIELD: &str = "identity";

/// The `--extract` argument that selects it.
const IDENTITY_EXTRACT: &str = r#"["identity"]"#;

/// Path of the master file inside a store root.
pub fn master_path(store: &Path) -> PathBuf {
    store.join(STORE_IDENTITY_FILE)
}

/// Path of the plaintext recipient sidecar inside a store root.
pub fn sidecar_path(store: &Path) -> PathBuf {
    store.join(STORE_IDENTITY_RECIPIENT_FILE)
}

/// The derived public recipient recorded in the sidecar, if it is readable.
pub fn read_sidecar(store: &Path) -> Option<String> {
    let text = std::fs::read_to_string(sidecar_path(store)).ok()?;
    let first = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    first.starts_with("age1").then(|| first.to_owned())
}

/// What the master file currently resolves to, without unwrapping it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterState {
    /// The master file is there.
    Present,
    /// No master file: `identity init` has not run.
    Missing,
}

/// Inspect the master file.
pub fn master_state(store: &Path) -> MasterState {
    if master_path(store).is_file() {
        MasterState::Present
    } else {
        MasterState::Missing
    }
}

/// Refuse anything on a store whose metadata mode is not `derived`.
pub fn require_derived(store: &Path, action: &str) -> Result<(), SopsError> {
    let meta = read_meta(store)?;
    if meta.mode != StoreMode::Derived {
        return Err(SopsError::Config(format!(
            "`{action}` needs a `derived` store, but `{}` is `{}`; the mode never changes in \
             place — migrate into a new store instead (`rosec-sops store migrate`)",
            store.display(),
            meta.mode
        )));
    }
    Ok(())
}

/// True when `path` holds a usable runtime identity.
///
/// Three conditions: the file exists, it is not empty, and it carries an
/// `AGE-SECRET-KEY-1` line. A truncated or empty file is treated as absent, so
/// a crash during `unlock` cannot wedge the session.
pub fn runtime_identity_is_valid(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(text) => !text.trim().is_empty() && is_age_identity_text(&text),
        Err(_) => false,
    }
}

/// Write the derived identity to the runtime file: 0600 below a 0700 directory.
pub fn write_runtime_identity(path: &Path, identity: &str) -> Result<(), SopsError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| SopsError::io(dir.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| SopsError::io(dir.display(), e))?;
        }
    }
    write_atomic_sync(path, ensure_trailing_newline(identity.trim()).as_bytes())
}

/// Remove the runtime identity file, if any.
pub fn remove_runtime_identity(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => debug!(runtime = %path.display(), "removed the runtime store identity"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            warn!(runtime = %path.display(), error = %e, "cannot remove the runtime store identity")
        }
    }
}

fn ensure_trailing_newline(text: &str) -> String {
    if text.ends_with('\n') {
        text.to_owned()
    } else {
        format!("{text}\n")
    }
}

/// Decrypt the master file once and return the derived identity.
///
/// Runs `sops --decrypt --extract '["identity"]'` with `SOPS_AGE_KEY_FILE` set
/// to the identity that opens the master (`identity_key_file`, else
/// `key_file`), bounded by `probe_timeout`. The value is trimmed and must start
/// with `AGE-SECRET-KEY-1`; it is never logged and never put in an error.
pub async fn unwrap_master(config: &SopsConfig) -> Result<String, SopsError> {
    let master = master_path(&config.path);
    if !master.is_file() {
        return Err(SopsError::Unavailable(format!(
            "store `{}` is `derived` but has no master file `{}`; run \
             `rosec-sops identity init` in that store",
            config.path.display(),
            master.display()
        )));
    }
    let sops = SopsCommand::new(&config.sops_binary, config.master_key_file())
        .with_probe_timeout(config.probe_timeout);
    let raw = sops.decrypt_field(&master, IDENTITY_EXTRACT).await?;
    let text = String::from_utf8(raw).map_err(|_| SopsError::Unreadable {
        path: master.display().to_string(),
        reason: "the decrypted identity is not UTF-8".into(),
    })?;
    let identity = text.trim().to_owned();
    if !identity.starts_with(AGE_SECRET_PREFIX) {
        return Err(SopsError::Unreadable {
            path: master.display().to_string(),
            reason: "the master file does not hold an `AGE-SECRET-KEY-1` identity".into(),
        });
    }
    Ok(identity)
}

/// Unwrap the master into the runtime file, unless the session already has it.
///
/// Returns `true` when a decrypt happened (the caller then resets the runtime
/// file on a failed probe, because a bad unwrap must not be reused).
pub async fn ensure_runtime_identity(config: &SopsConfig) -> Result<bool, SopsError> {
    let runtime = &config.runtime_identity_file;
    if runtime_identity_is_valid(runtime) {
        debug!(runtime = %runtime.display(), "reusing the session store identity");
        return Ok(false);
    }
    let identity = unwrap_master(config).await?;
    write_runtime_identity(runtime, &identity)?;
    info!(
        runtime = %runtime.display(),
        master = %master_path(&config.path).display(),
        "unwrapped the store identity for this session",
    );
    Ok(true)
}

/// Paths that matter to the identity CLI for one store.
#[derive(Debug, Clone)]
pub struct IdentityPaths {
    /// Store root.
    pub store: PathBuf,
    /// The master file.
    pub master: PathBuf,
    /// The plaintext recipient sidecar.
    pub sidecar: PathBuf,
    /// The session runtime file.
    pub runtime: PathBuf,
}

impl IdentityPaths {
    /// Collect the paths for `store` under `config`.
    pub fn new(config: &SopsConfig) -> Self {
        Self {
            store: config.path.clone(),
            master: master_path(&config.path),
            sidecar: sidecar_path(&config.path),
            runtime: config.runtime_identity_file.clone(),
        }
    }
}

/// The `.sops.yaml` snippet the user must paste so both rules are present.
///
/// The **master rule comes first**: sops applies the first matching creation
/// rule, and the item rule (`.*\.sops\.yaml$`) also matches the master file
/// name. With the order reversed, an `identity init` would encrypt the master
/// to the YubiKey recipients the item rule names instead of the unlock group.
pub fn sops_yaml_snippet(derived_recipient: &str, unlock_recipients: &str) -> String {
    let unlock = if unlock_recipients.trim().is_empty() {
        "age1…   # the unlock group: age/YubiKey, pgp:, kms:, hc_vault:"
    } else {
        unlock_recipients
    };
    format!(
        "creation_rules:\n\
         \x20 # 1. the store master file: its recipients are the unlock group.\n\
         \x20 #    Keep this rule FIRST; it also matches the item rule below.\n\
         \x20 - path_regex: ^\\.rosec-store-identity\\.sops\\.yaml$\n\
         \x20   age: {unlock}\n\
         \x20 # 2. the items: encrypted to the derived identity only.\n\
         \x20 - path_regex: .*\\.sops\\.yaml$\n\
         \x20   age: {derived_recipient}\n"
    )
}

/// The hint printed when no creation rule matches the master file name.
pub fn missing_master_rule_hint(store: &Path) -> String {
    format!(
        "sops found no creation rule for `{STORE_IDENTITY_FILE}` in `{}/.sops.yaml`. Add the \
         master rule FIRST (it also matches the item rule):\n\n{}",
        store.display(),
        sops_yaml_snippet("age1…   # the derived recipient", "")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_file_must_hold_an_age_identity() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("nested").join("store-identity.age");
        assert!(!runtime_identity_is_valid(&runtime), "absent");
        write_runtime_identity(&runtime, "AGE-SECRET-KEY-1TEST\n").unwrap();
        assert!(runtime_identity_is_valid(&runtime), "written");

        std::fs::write(&runtime, "").unwrap();
        assert!(!runtime_identity_is_valid(&runtime), "empty");

        std::fs::write(&runtime, "age1recipient\n").unwrap();
        assert!(
            !runtime_identity_is_valid(&runtime),
            "a public recipient is not an identity"
        );

        // The parent directory is private.
        std::fs::write(&runtime, "AGE-SECRET-KEY-1TEST").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(runtime.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "the parent directory must be private");
            let mode = std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the identity file must be private");
        }
    }

    #[test]
    fn the_snippet_puts_the_master_rule_first() {
        let snippet = sops_yaml_snippet("age1derived", "age1a,age1b");
        let master = snippet.find("rosec-store-identity").unwrap();
        let items = snippet.find(r".*\.sops\.yaml$").unwrap();
        assert!(
            master < items,
            "the master rule must come first:\n{snippet}"
        );
        assert!(snippet.contains("age1a,age1b"), "{snippet}");
        assert!(snippet.contains("age1derived"), "{snippet}");
    }

    #[test]
    fn a_missing_master_rule_hint_names_the_file() {
        let hint = missing_master_rule_hint(Path::new("/store"));
        assert!(hint.contains(STORE_IDENTITY_FILE), "{hint}");
        assert!(hint.contains("/store/.sops.yaml"), "{hint}");
    }

    #[test]
    fn a_missing_store_mode_is_named_by_the_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let error = require_derived(dir.path(), "identity init").unwrap_err();
        assert!(error.to_string().contains("store init --mode"), "{error}");
    }
}
