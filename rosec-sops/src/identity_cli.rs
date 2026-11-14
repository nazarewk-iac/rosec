//! `rosec-sops identity …`: create, inspect and rotate the derived identity.
//!
//! Every command works on one store and never prints a secret. The derived
//! **recipient** is public and is printed; the derived **identity** travels
//! only between the master file, the runtime file and a `sops` child process.
//!
//! ```text
//! rosec-sops identity init    [--force]   create the master + sidecar
//! rosec-sops identity show                print the paths and the recipient
//! rosec-sops identity rewrap              re-wrap the master to the current rule
//! rosec-sops identity rekey   [--force]   new derived identity, re-encrypt every item
//! rosec-sops identity migrate             one-time: direct items -> derived
//! ```
//!
//! The store mode is **not** touched by any of them: it is set by
//! `store init --mode`, and the only supported mode change is a migration into
//! a new store (`store migrate`).

use std::path::{Path, PathBuf};

use crate::config::SopsConfig;
use crate::error::SopsError;
use crate::identity::{
    MasterState, master_path, master_state, missing_master_rule_hint, read_sidecar,
    require_derived, runtime_identity_is_valid, sidecar_path, sops_yaml_snippet, unwrap_master,
    write_runtime_identity,
};
use crate::sops::{
    AGE_SECRET_PREFIX, DEFAULT_PROBE_TIMEOUT, SopsCommand, generate_age_identity,
    public_recipient_for, write_atomic_mode, write_atomic_sync,
};
use crate::store::ITEM_SUFFIX;
use crate::store_mode::STORE_IDENTITY_FILE;

/// What one item operation produced, used for the summary lines.
#[derive(Debug, Default, Clone)]
pub struct ItemReport {
    /// Files rewritten.
    pub rewritten: usize,
    /// Files that could not be decrypted with the old identity.
    pub skipped: Vec<PathBuf>,
}

/// Every item file below `store`, recursively, excluding the master file.
///
/// Item files are `*.sops.yaml` that are not dotfiles, plus the collection meta
/// names (`_meta.meta.yaml`, `_meta.sops.yaml`, which do not end in the item
/// suffix). Archive dotfiles and `.conflicts` markers are not items and are
/// never touched.
pub fn item_files(store: &Path) -> Result<Vec<PathBuf>, SopsError> {
    let mut out = Vec::new();
    let mut stack = vec![store.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let reader = match std::fs::read_dir(&dir) {
            Ok(reader) => reader,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(SopsError::io(dir.display(), e)),
        };
        for entry in reader {
            let entry = entry.map_err(|e| SopsError::io(dir.display(), e))?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = entry
                .file_type()
                .map_err(|e| SopsError::io(path.display(), e))?;
            if file_type.is_dir() {
                // Hidden directories hold syncing metadata and conflict
                // markers, never items.
                if !name.starts_with('.') {
                    stack.push(path);
                }
                continue;
            }
            if !file_type.is_file() || name.starts_with('.') {
                continue;
            }
            if name == STORE_IDENTITY_FILE {
                continue;
            }
            if name.ends_with(ITEM_SUFFIX) || name.ends_with(".meta.yaml") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The store `.sops.yaml`, which decides the unlock group of the master file.
fn sops_yaml_path(store: &Path) -> PathBuf {
    store.join(".sops.yaml")
}

/// The age recipients of the rule that matches the master file name.
///
/// Read from `.sops.yaml` only to build the hint the user pastes back; the
/// authoritative decision is made by `sops` itself.
pub fn master_rule_recipients(store: &Path) -> Option<String> {
    let text = std::fs::read_to_string(sops_yaml_path(store)).ok()?;
    let document: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let rules = document.get("creation_rules")?.as_sequence()?;
    for rule in rules {
        let matches = rule
            .get("path_regex")
            .and_then(|v| v.as_str())
            .map(|pattern| {
                regex_matches(pattern, STORE_IDENTITY_FILE)
                    || regex_matches(pattern, &format!("./{STORE_IDENTITY_FILE}"))
            })
            .unwrap_or(true);
        if !matches {
            continue;
        }
        if let Some(age) = rule.get("age").and_then(|v| v.as_str()) {
            return Some(age.to_owned());
        }
        // A rule with pgp/kms/vault and no age: name that instead of nothing.
        for key in [
            "pgp",
            "kms",
            "hc_vault",
            "gcp_kms",
            "azure_kv",
            "aliyun_kms",
        ] {
            if rule.get(key).is_some() {
                return Some(format!("<{key} recipients>"));
            }
        }
    }
    None
}

/// A small matcher for the `path_regex` shapes a store config uses.
///
/// Full regex support is not needed: the two shapes are the master rule
/// (`^\.rosec-store-identity\.sops\.yaml$` or a longer `.*` variant) and the
/// item rule (`.*\.sops\.yaml$`). Anything else is treated as a match, which is
/// what `sops` does for a rule without `path_regex`.
fn regex_matches(pattern: &str, name: &str) -> bool {
    let anchored_start = pattern.starts_with('^');
    let anchored_end = pattern.ends_with('$');
    let core = pattern
        .trim_start_matches('^')
        .trim_end_matches('$')
        .replace("\\.", ".")
        .replace(".*", "\u{0}");
    let parts: Vec<&str> = core.split('\u{0}').collect();
    let mut rest = name;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 && anchored_start {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
            continue;
        }
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    if anchored_end {
        let last = parts.iter().rev().find(|p| !p.is_empty());
        return match last {
            Some(last) => name.ends_with(last),
            None => true,
        };
    }
    true
}

/// Run `sops --encrypt` for the master YAML with cwd = store root.
async fn encrypt_master(config: &SopsConfig, identity: &str) -> Result<Vec<u8>, SopsError> {
    let plain = format!("identity: {identity}\n");
    let sops = SopsCommand::new(&config.sops_binary, config.master_key_file())
        .with_probe_timeout(config.probe_timeout);
    sops.encrypt_as(plain.as_bytes(), None, &config.path, STORE_IDENTITY_FILE)
        .await
        .map_err(|e| match e {
            SopsError::SopsFailed { .. } => SopsError::Config(format!(
                "sops could not encrypt the master file. {}",
                missing_master_rule_hint(&config.path)
            )),
            other => other,
        })
}

/// `identity init [--force]`
pub async fn init(config: &SopsConfig, force: bool) -> Result<(), String> {
    let store = &config.path;
    require_derived(store, "identity init").map_err(|e| e.to_string())?;
    let master = master_path(store);
    if master.is_file() && !force {
        return Err(format!(
            "`{}` already exists; `identity init --force` overwrites it, and every existing item \
             file becomes unreadable because they are encrypted to the OLD derived identity. Use \
             `identity rekey` to rotate without losing items",
            master.display()
        ));
    }
    if master.is_file() {
        println!(
            "warning: overwriting `{}`; item files encrypted to the previous derived identity \
             stay unreadable until they are re-encrypted",
            master.display()
        );
    }
    std::fs::create_dir_all(store).map_err(|e| SopsError::io(store.display(), e).to_string())?;
    let (identity, recipient) = generate_age_identity().map_err(|e| e.to_string())?;
    let cipher = encrypt_master(config, &identity)
        .await
        .map_err(|e| e.to_string())?;
    write_atomic_sync(&master, &cipher).map_err(|e| e.to_string())?;
    write_atomic_mode(
        &sidecar_path(store),
        format!("{recipient}\n").as_bytes(),
        0o644,
    )
    .map_err(|e| e.to_string())?;

    println!("wrote master file: {}", master.display());
    println!(
        "public sidecar:    {} ({recipient})",
        sidecar_path(store).display()
    );
    println!();
    println!("derived recipient: {recipient}");
    println!();
    println!(
        "Add these rules to `{}` (the master rule FIRST):",
        sops_yaml_path(store).display()
    );
    println!();
    print!(
        "{}",
        sops_yaml_snippet(
            &recipient,
            &master_rule_recipients(store).unwrap_or_default()
        )
    );
    println!();
    println!("Then set `age_recipient = \"{recipient}\"` in the provider options of the daemon.");
    Ok(())
}

/// `identity show`
pub async fn show(config: &SopsConfig) -> Result<(), String> {
    let store = &config.path;
    let meta = crate::store_mode::read_meta(store).map_err(|e| e.to_string())?;
    let recipient = read_sidecar(store).unwrap_or_else(|| "<no sidecar>".to_owned());
    println!("store:             {}", store.display());
    println!("mode:              {}", meta.mode);
    println!("derived recipient: {recipient}");
    println!("master file:       {}", master_path(store).display());
    println!(
        "master state:      {}",
        match master_state(store) {
            MasterState::Present => "present",
            MasterState::Missing => "MISSING (run `rosec-sops identity init`)",
        }
    );
    println!("unlock key file:   {}", config.master_key_file().display());
    println!(
        "runtime file:      {}",
        config.runtime_identity_file.display()
    );
    println!(
        "runtime identity:  {}",
        if runtime_identity_is_valid(&config.runtime_identity_file) {
            "present (this session is unlocked)"
        } else {
            "absent (the next unlock unwraps the master)"
        }
    );
    println!("sops binary:       {}", config.sops_binary.display());
    Ok(())
}

/// `identity rewrap`: make the master file match the current creation rule.
pub async fn rewrap(config: &SopsConfig) -> Result<(), String> {
    let store = &config.path;
    require_derived(store, "identity rewrap").map_err(|e| e.to_string())?;
    let master = master_path(store);
    if !master.is_file() {
        return Err(format!(
            "`{}` does not exist; run `identity init` first",
            master.display()
        ));
    }
    let sops = SopsCommand::new(&config.sops_binary, config.master_key_file())
        .with_probe_timeout(config.probe_timeout);
    sops.update_keys(&master, store).await.map_err(|e| {
        format!(
            "`sops updatekeys` failed for `{}`: {e}. The master file is unchanged. Order \
                 matters: ADD the new key to the rule first, rewrap, THEN remove the old key and \
                 rewrap again — a rewrap with no intersection between the rule and the file \
                 would leave the master readable by nobody",
            master.display()
        )
    })?;
    // The recipient sidecar and the runtime file are unaffected: the derived
    // identity did not change, only who can unlock it.
    let recipients = master_rule_recipients(store);
    println!("re-wrapped master file: {}", master.display());
    match recipients {
        Some(list) => println!("unlock group now: {list}"),
        None => println!(
            "unlock group: as decided by `{}`",
            sops_yaml_path(store).display()
        ),
    }
    println!("the derived identity is unchanged: item files need no re-encryption");
    Ok(())
}

/// `identity rekey`: new derived identity, every item re-encrypted.
///
/// Needs a master file that still opens: the rotation decrypts every item with
/// the old identity first. `force` only skips the sidecar/recipient agreement
/// check, which a hand-edited store can break.
pub async fn rekey(config: &SopsConfig, force: bool) -> Result<(), String> {
    let store = &config.path;
    require_derived(store, "identity rekey").map_err(|e| e.to_string())?;
    let master = master_path(store);
    let old_sidecar = read_sidecar(store);
    if !master.is_file() && !runtime_identity_is_valid(&config.runtime_identity_file) {
        return Err(format!(
            "no old identity: `{}` is missing and `{}` holds no valid identity, so the items \
             cannot be re-encrypted. Use `identity init` for a fresh store",
            master.display(),
            config.runtime_identity_file.display()
        ));
    }

    // The old identity: the runtime file when it is valid, else the master.
    let old_identity = if runtime_identity_is_valid(&config.runtime_identity_file) {
        std::fs::read_to_string(&config.runtime_identity_file)
            .map_err(|e| SopsError::io(config.runtime_identity_file.display(), e).to_string())?
            .trim()
            .to_owned()
    } else {
        unwrap_master(config).await.map_err(|e| e.to_string())?
    };
    if !old_identity.starts_with(AGE_SECRET_PREFIX) {
        return Err("no readable old identity: cannot rotate".into());
    }
    let old_recipient = public_recipient_for(&old_identity).map_err(|e| e.to_string())?;
    if let Some(sidecar) = &old_sidecar
        && *sidecar != old_recipient
        && master.is_file()
        && !force
    {
        return Err(format!(
            "the sidecar names `{sidecar}` but the master file holds `{old_recipient}`; refuse to \
             rotate on an inconsistent store (check `.rosec-store-identity.recipient`), or pass \
             `--force` to trust the master"
        ));
    }

    let (new_identity, new_recipient) = generate_age_identity().map_err(|e| e.to_string())?;
    let temp_old = temp_identity_file(&old_identity)?;
    let report = reencrypt_items(config, &temp_old, Some(&old_recipient), &new_recipient)
        .await
        .map_err(|e| e.to_string())?;
    remove_temp(&temp_old);

    let cipher = encrypt_master(config, &new_identity)
        .await
        .map_err(|e| e.to_string())?;
    write_atomic_sync(&master, &cipher).map_err(|e| e.to_string())?;
    write_atomic_mode(
        &sidecar_path(store),
        format!("{new_recipient}\n").as_bytes(),
        0o644,
    )
    .map_err(|e| e.to_string())?;
    write_runtime_identity(&config.runtime_identity_file, &new_identity)
        .map_err(|e| e.to_string())?;

    println!("re-encrypted items: {}", report.rewritten);
    if !report.skipped.is_empty() {
        println!(
            "WARNING: {} item file(s) could not be decrypted with the old identity:",
            report.skipped.len()
        );
        for path in &report.skipped {
            println!("  {}", path.display());
        }
    }
    println!("new derived recipient: {new_recipient}");
    println!("master file rewritten: {}", master.display());
    println!(
        "runtime identity replaced: {}",
        config.runtime_identity_file.display()
    );
    println!();
    println!(
        "Next: set the item rule of `{}` to `age: {new_recipient}` and the nix module's \
         `age_recipient` to the same value, then re-run `rosec-sops identity rewrap` if the \
         unlock group changed too",
        sops_yaml_path(store).display()
    );
    Ok(())
}

/// `identity migrate`: move a `direct` store's items onto the derived identity.
pub async fn migrate(config: &SopsConfig) -> Result<(), String> {
    let store = &config.path;
    require_derived(store, "identity migrate").map_err(|e| e.to_string())?;
    let recipient = read_sidecar(store).ok_or_else(|| {
        format!(
            "no derived recipient sidecar at `{}`; run `identity init` first",
            sidecar_path(store).display()
        )
    })?;
    if let Some(recorded) = config.identity_file.as_ref()
        && *recorded != master_path(store)
    {
        return Err(format!(
            "this command works on `{}`, but the configuration names `{}`; drop `--store` or fix \
             `identity_file`",
            master_path(store).display(),
            recorded.display()
        ));
    }
    // The unlock identity (`key_file`, the YubiKey) opens the direct items.
    let sops = SopsCommand::new(&config.sops_binary, &config.key_file)
        .with_probe_timeout(config.probe_timeout);
    let report = reencrypt_with(&sops, store, None, &recipient)
        .await
        .map_err(|e| e.to_string())?;
    println!("migrated items: {}", report.rewritten);
    if !report.skipped.is_empty() {
        println!(
            "WARNING: {} item file(s) could not be decrypted with `{}`, so they were left as they \
             are. That is expected when they are already on the derived identity; otherwise the \
             unlock key file is not the one that encrypted them (with `--store`, the identity is \
             the `--store` default unless a `--config` entry says otherwise):",
            report.skipped.len(),
            config.key_file.display()
        );
        for path in &report.skipped {
            println!("  {}", path.display());
        }
    }
    println!("derived recipient: {recipient}");
    println!(
        "Next: set the provider's `identity_file` to `{}` and restart the daemon",
        master_path(store).display()
    );
    Ok(())
}

/// Re-encrypt every item with `sops`, decrypting through `key_file`.
async fn reencrypt_items(
    config: &SopsConfig,
    key_file: &Path,
    _old: Option<&str>,
    new_recipient: &str,
) -> Result<ItemReport, SopsError> {
    let sops =
        SopsCommand::new(&config.sops_binary, key_file).with_probe_timeout(DEFAULT_PROBE_TIMEOUT);
    reencrypt_with(&sops, &config.path, None, new_recipient).await
}

/// Decrypt then re-encrypt one store's items, atomically replacing each file.
///
/// `source_recipient` is informational and not used: the recipient information
/// needed for the re-encryption is the *new* one.
async fn reencrypt_with(
    sops: &SopsCommand,
    store: &Path,
    _source_recipient: Option<&str>,
    new_recipient: &str,
) -> Result<ItemReport, SopsError> {
    let mut report = ItemReport::default();
    for path in item_files(store)? {
        let plain = match sops.decrypt(&path).await {
            Ok(plain) => plain,
            Err(_) => {
                report.skipped.push(path);
                continue;
            }
        };
        let cipher = sops.encrypt_to(&plain, new_recipient, store).await?;
        write_atomic_sync(&path, &cipher)?;
        report.rewritten += 1;
    }
    Ok(report)
}

/// Write the old identity to a private temporary file for a `sops` child.
fn temp_identity_file(identity: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("rosec-rekey-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| SopsError::io(dir.display(), e).to_string())?;
    let path = dir.join("old-store-identity.age");
    write_atomic_sync(&path, format!("{identity}\n").as_bytes()).map_err(|e| e.to_string())?;
    Ok(path)
}

fn remove_temp(path: &Path) {
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

/// The `.sops.yaml` item rule currently in force, for the `store init` hint.
pub fn item_rule_recipients(store: &Path) -> Option<String> {
    master_rule_recipients(store)
}

/// Required by [`crate::cli`] when it prints an init-time reminder.
pub fn item_suffix() -> &'static str {
    ITEM_SUFFIX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_master_rule_matcher_handles_the_two_shapes() {
        assert!(regex_matches(
            r"^\.rosec-store-identity\.sops\.yaml$",
            STORE_IDENTITY_FILE
        ));
        assert!(!regex_matches(
            r"^\.rosec-store-identity\.sops\.yaml$",
            "item-abc.sops.yaml"
        ));
        assert!(regex_matches(r".*\.sops\.yaml$", "item-abc.sops.yaml"));
        assert!(regex_matches(r".*\.sops\.yaml$", STORE_IDENTITY_FILE));
        assert!(!regex_matches(r".*\.sops\.yaml$", "notes.txt"));
    }
}
