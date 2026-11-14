//! `rosec-sops store migrate`: copy a store into a new one.
//!
//! The store mode **never changes in place**. To move a `direct` store to
//! `derived`, or to rotate the derived identity onto new unlock keys, the user
//! creates a second store, initialises it with the wanted mode and identity,
//! and migrates the items into it.
//!
//! What is copied: item files (decrypted with the source key/identity and
//! re-encrypted for the destination), collection meta files, and therefore the
//! item ids, collections, labels, timestamps and revisions that live inside
//! those documents.
//!
//! What is **not** copied: `.superseded-*` archives and `.conflicts/` markers.
//! An unresolved conflict is a decision the user still owes, and copying it
//! would either smuggle a losing value along or silently drop it — the command
//! refuses and asks for a resolution first.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::config::SopsConfig;
use crate::error::SopsError;
use crate::identity::{master_path, read_sidecar, require_derived};
use crate::sops::{SopsCommand, write_atomic_sync};
use crate::store_mode::{StoreMeta, StoreMode, read_mode, write_meta};

/// What [`migrate_store`] did.
#[derive(Debug, Clone)]
pub struct MigrationReport {
    /// Source store root.
    pub from: PathBuf,
    /// Destination store root.
    pub to: PathBuf,
    /// Source mode.
    pub from_mode: Option<StoreMode>,
    /// Destination mode.
    pub to_mode: StoreMode,
    /// Item files written (item files plus collection meta files).
    pub items: usize,
    /// Collections created.
    pub collections: BTreeSet<String>,
    /// Files skipped because the source key could not read them.
    pub skipped: Vec<PathBuf>,
}

/// Options of one migration.
#[derive(Debug, Clone)]
pub struct MigrationOptions {
    /// Source store root.
    pub from: PathBuf,
    /// Destination store root.
    pub to: PathBuf,
    /// The identity that opens the source items (usually the source `key_file`).
    pub source_key_file: PathBuf,
    /// The `sops` binary.
    pub sops_binary: PathBuf,
    /// Mode to write into the destination when it has no metadata yet.
    pub mode: Option<StoreMode>,
    /// Allow an existing destination.
    pub force: bool,
    /// Copy into a destination that already holds items.
    pub overwrite: bool,
}

/// Run a migration.
///
/// The destination must be new or empty unless `force` is set, and it must
/// carry a valid mode either way — a `--mode` writes it, otherwise
/// `<dst>/.rosec-store.yaml` must already exist.
pub async fn migrate_store(
    options: &MigrationOptions,
    derive_config: impl Fn(&Path) -> SopsConfig,
) -> Result<MigrationReport, SopsError> {
    if options.from == options.to {
        return Err(SopsError::Config(
            "source and destination are the same directory".into(),
        ));
    }
    if !options.from.is_dir() {
        return Err(SopsError::Unavailable(format!(
            "source store `{}` does not exist",
            options.from.display()
        )));
    }

    // Destination state: must be new/empty, or explicitly forced. The check
    // runs before anything is written, so a refusal leaves no trace: the
    // authorised destination files are its metadata, its master identity and
    // its recipient sidecar.
    let stray = stray_entries(&options.to)?;
    if !stray.is_empty() && !options.force {
        return Err(SopsError::Config(format!(
            "destination `{}` is not empty ({}); pass `--force` to write into it anyway",
            options.to.display(),
            stray
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let mut report = MigrationReport {
        from: options.from.clone(),
        to: options.to.clone(),
        from_mode: read_mode(&options.from).ok(),
        to_mode: StoreMode::Direct,
        items: 0,
        collections: BTreeSet::new(),
        skipped: Vec::new(),
    };

    // Refuse an unresolved conflict before touching anything.
    let unresolved = unresolved_conflicts(&options.from)?;
    if !unresolved.is_empty() {
        let names = unresolved
            .iter()
            .map(|(collection, id)| format!("{collection}/{id}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(SopsError::Config(format!(
            "the source store has {} unresolved conflict(s): {names}. Resolve them first \
             (`rosec-sops conflicts resolve <item> --keep winner|loser`), then migrate",
            unresolved.len()
        )));
    }

    // Destination mode: explicit, never guessed.
    let to_mode = match (options.mode, read_mode(&options.to)) {
        (Some(mode), Ok(existing)) if existing != mode => {
            return Err(SopsError::Config(format!(
                "destination `{}` is already `{existing}`, not `{mode}`; the mode never changes \
                 in place",
                options.to.display()
            )));
        }
        (Some(mode), _) => mode,
        (None, Ok(mode)) => mode,
        (None, Err(_)) => {
            return Err(crate::store_mode::missing_mode_error(&options.to));
        }
    };
    report.to_mode = to_mode;
    std::fs::create_dir_all(&options.to).map_err(|e| SopsError::io(options.to.display(), e))?;
    // A destination that already has its metadata is reused as it is; a
    // destination without metadata gets one from `--mode`.
    if read_mode(&options.to).is_err() {
        write_meta(&options.to, &StoreMeta::new(to_mode))?;
    }

    // Destination identity: the derived recipient, or the destination
    // config's own recipients (creation rules / age_recipient).
    let dest_config = derive_config(&options.to);
    let dest_recipient = if to_mode == StoreMode::Derived {
        read_sidecar(&options.to).ok_or_else(|| {
            SopsError::Config(format!(
                "destination `{}` is `derived` but has no derived recipient yet; run \
                 `rosec-sops --store {} identity init` first",
                options.to.display(),
                options.to.display()
            ))
        })?
    } else {
        String::new()
    };

    let source_sops = SopsCommand::new(&options.sops_binary, &options.source_key_file)
        .with_probe_timeout(crate::sops::DEFAULT_PROBE_TIMEOUT);
    let dest_sops = SopsCommand::new(&options.sops_binary, &dest_config.key_file)
        .with_probe_timeout(crate::sops::DEFAULT_PROBE_TIMEOUT);

    for path in files_to_copy(&options.from)? {
        let relative = path
            .strip_prefix(&options.from)
            .unwrap_or(&path)
            .to_path_buf();
        let target = options.to.join(&relative);
        if target.exists() && !options.overwrite {
            return Err(SopsError::Config(format!(
                "destination file `{}` exists; pass `--overwrite` to replace it",
                target.display()
            )));
        }
        let plain = match source_sops.decrypt(&path).await {
            Ok(plain) => plain,
            Err(_) => {
                report.skipped.push(path);
                continue;
            }
        };
        let cipher = if to_mode == StoreMode::Derived {
            dest_sops
                .encrypt_to(&plain, &dest_recipient, &options.to)
                .await
                .map_err(|e| destination_encrypt_error(e, &options.to))?
        } else {
            // The destination's own rules decide: `age_recipient` or the
            // item rule of its `.sops.yaml`.
            let recipients = (!dest_config.age_recipient.is_empty())
                .then_some(dest_config.age_recipient.as_str());
            dest_sops
                .encrypt_as(&plain, recipients, &options.to, crate::sops::ENCRYPT_NAME)
                .await?
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SopsError::io(parent.display(), e))?;
        }
        write_atomic_sync(&target, &cipher)?;
        report.items += 1;
        if let Some(collection) = relative
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_string_lossy().into_owned())
        {
            report.collections.insert(collection);
        }
    }

    // A `derived` destination needs its master file; a `direct` one must not
    // have one.
    if to_mode == StoreMode::Derived && !master_path(&options.to).is_file() {
        return Err(SopsError::Config(format!(
            "destination `{}` is `derived` but has no master file; run `identity init` first",
            master_path(&options.to).display()
        )));
    }
    if to_mode == StoreMode::Direct && master_path(&options.to).is_file() {
        return Err(SopsError::Config(format!(
            "destination `{}` is `direct` but holds `{}`; remove that file",
            options.to.display(),
            master_path(&options.to).display()
        )));
    }
    Ok(report)
}

/// Turn a destination encryption failure into a message with the next step.
fn destination_encrypt_error(error: SopsError, destination: &Path) -> SopsError {
    match error {
        SopsError::SopsFailed { .. } => SopsError::Config(format!(
            "cannot encrypt for destination `{}`: {error}. A `direct` destination needs a \
             creation rule or `age_recipient` naming its recipients — add the item rule to \
             `{}/.sops.yaml`, or migrate into a `derived` destination",
            destination.display(),
            destination.display()
        )),
        other => other,
    }
}

/// Item and meta files of a store, recursively, without identity secrets.
fn files_to_copy(store: &Path) -> Result<Vec<PathBuf>, SopsError> {
    crate::identity_cli::item_files(store)
}

/// Entries of the destination that a migration would collide with.
///
/// The store metadata, the master file and the recipient sidecar are part of a
/// destination that was deliberately set up (`store init`, `identity init`),
/// so they do not count. Anything else — an item directory, a foreign file —
/// means the destination is already in use.
fn stray_entries(store: &Path) -> Result<Vec<PathBuf>, SopsError> {
    let allowed = [
        crate::store_mode::STORE_META_FILE,
        crate::STORE_IDENTITY_FILE,
        crate::STORE_IDENTITY_RECIPIENT_FILE,
        ".sops.yaml",
    ];
    let mut out = Vec::new();
    let reader = match std::fs::read_dir(store) {
        Ok(reader) => reader,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(SopsError::io(store.display(), e)),
    };
    for entry in reader {
        let entry = entry.map_err(|e| SopsError::io(store.display(), e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if allowed.contains(&name.as_str()) {
            continue;
        }
        out.push(entry.path());
    }
    Ok(out)
}

/// `(collection, id)` pairs that still have a conflict marker.
fn unresolved_conflicts(store: &Path) -> Result<Vec<(String, String)>, SopsError> {
    let set = crate::conflicts::conflicted_ids_blocking(store)?;
    Ok(set.into_iter().collect())
}

/// Refuse a source that is `derived` without a readable master.
pub fn check_source_mode(store: &Path) -> Result<StoreMode, SopsError> {
    let mode = read_mode(store)?;
    if mode == StoreMode::Derived {
        require_derived(store, "store migrate")?;
    }
    Ok(mode)
}

/// Parse `--mode` for `store init` / `store migrate`.
pub fn parse_mode(raw: &str) -> Result<StoreMode, SopsError> {
    StoreMode::parse(raw)
}
