//! The store mode: how item files are encrypted.
//!
//! Two modes exist, and the mode is always **explicit**:
//!
//! - `direct` — every item file is encrypted to the unlock keys themselves
//!   (the YubiKey recipient in the item rule of `.sops.yaml`). This is the
//!   original behaviour: one YubiKey operation per decrypt.
//! - `derived` — every item file is encrypted to a **derived sops identity**,
//!   a plain age identity that is itself stored as a sops-encrypted master file
//!   whose recipients are the unlock group. The master is unwrapped once per
//!   session, so the item reads in that session cost no YubiKey operation.
//!
//! The mode is recorded in plaintext at `<store>/.rosec-store.yaml`:
//!
//! ```yaml
//! version: 1
//! mode: derived
//! ```
//!
//! **There is no default.** A store without this file, or with a missing or
//! unknown `mode`, is refused: guessing would silently encrypt new item files
//! to the wrong recipient set, which is unrecoverable. The mode never changes
//! in place; the only supported change is a migration into a new store (see
//! `rosec-sops store migrate`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::SopsError;

/// Plaintext metadata file that records the store mode.
pub const STORE_META_FILE: &str = ".rosec-store.yaml";

/// The sops-encrypted master file that holds the derived sops identity.
///
/// A dotfile without `.sops.yaml` as its final suffix would be read as an item
/// by some scanners; this name ends in `.sops.yaml` but starts with a dot, and
/// the item scanner only reads `<collection>/*.sops.yaml`, so it is ignored as
/// an item either way.
pub const STORE_IDENTITY_FILE: &str = ".rosec-store-identity.sops.yaml";

/// Plaintext sidecar holding the derived **public** age recipient.
pub const STORE_IDENTITY_RECIPIENT_FILE: &str = ".rosec-store-identity.recipient";

/// The `version` this build writes.
pub const STORE_META_VERSION: u32 = 1;

/// How item files are encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreMode {
    /// Item files are encrypted to the unlock keys directly.
    Direct,
    /// Item files are encrypted to a derived sops identity.
    Derived,
}

impl StoreMode {
    /// Parse the command-line/text spelling.
    pub fn parse(raw: &str) -> Result<Self, SopsError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "direct" => Ok(StoreMode::Direct),
            "derived" => Ok(StoreMode::Derived),
            other => Err(SopsError::Config(format!(
                "unknown store mode `{other}`; use `direct` or `derived`"
            ))),
        }
    }

    /// The spelling written to the metadata file and printed to the user.
    pub fn as_str(self) -> &'static str {
        match self {
            StoreMode::Direct => "direct",
            StoreMode::Derived => "derived",
        }
    }
}

impl std::fmt::Display for StoreMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The content of `<store>/.rosec-store.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreMeta {
    /// Format version. An unknown version is refused.
    pub version: u32,
    /// The store mode. No `#[serde(default)]`: a missing key is an error.
    pub mode: StoreMode,
}

impl StoreMeta {
    /// The metadata for a fresh store.
    pub fn new(mode: StoreMode) -> Self {
        Self {
            version: STORE_META_VERSION,
            mode,
        }
    }

    /// Path of the metadata file inside a store root.
    pub fn path(store: &Path) -> PathBuf {
        store.join(STORE_META_FILE)
    }
}

/// The message every refusal carries, so a user always sees the next step.
pub fn missing_mode_error(store: &Path) -> SopsError {
    SopsError::Config(format!(
        "store `{}` has no mode: `{}` is missing or has no valid `mode`. The store mode is \
         always explicit — run `rosec-sops --store {} store init --mode direct|derived`",
        store.display(),
        STORE_META_FILE,
        store.display()
    ))
}

/// Read and validate the store metadata.
///
/// A missing file, a missing `mode`, an unknown `mode` and an unknown
/// `version` are all refused with [`missing_mode_error`] or a sibling message.
/// Nothing is inferred and nothing is written here.
pub fn read_meta(store: &Path) -> Result<StoreMeta, SopsError> {
    let path = StoreMeta::path(store);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(missing_mode_error(store));
        }
        Err(e) => return Err(SopsError::io(path.display(), e)),
    };
    let meta: StoreMeta = serde_yaml::from_slice(&bytes).map_err(|_| missing_mode_error(store))?;
    if meta.version != STORE_META_VERSION {
        return Err(SopsError::Config(format!(
            "store `{}` has metadata version {}, this build understands version {}",
            store.display(),
            meta.version,
            STORE_META_VERSION
        )));
    }
    Ok(meta)
}

/// The mode of an existing store, or the refusal when there is none.
pub fn read_mode(store: &Path) -> Result<StoreMode, SopsError> {
    read_meta(store).map(|meta| meta.mode)
}

/// Write the metadata file atomically.
pub fn write_meta(store: &Path, meta: &StoreMeta) -> Result<(), SopsError> {
    let text = serde_yaml::to_string(meta).map_err(|e| SopsError::Malformed {
        path: STORE_META_FILE.to_owned(),
        reason: e.to_string(),
    })?;
    crate::sops::write_atomic_sync(&StoreMeta::path(store), text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_modes_and_refuses_anything_else() {
        assert_eq!(StoreMode::parse("direct").unwrap(), StoreMode::Direct);
        assert_eq!(StoreMode::parse(" Derived ").unwrap(), StoreMode::Derived);
        assert!(StoreMode::parse("auto").is_err());
        assert!(StoreMode::parse("").is_err());
    }

    #[test]
    fn a_missing_or_incomplete_metadata_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let error = read_mode(root).expect_err("a store without metadata has no mode");
        assert!(error.to_string().contains("store init --mode"), "{error}");

        std::fs::write(StoreMeta::path(root), b"version: 1\n").unwrap();
        assert!(read_mode(root).is_err(), "a missing mode must be refused");

        std::fs::write(StoreMeta::path(root), b"version: 1\nmode: auto\n").unwrap();
        assert!(read_mode(root).is_err(), "an unknown mode must be refused");

        std::fs::write(StoreMeta::path(root), b"version: 9\nmode: direct\n").unwrap();
        assert!(
            read_mode(root).is_err(),
            "an unknown version must be refused"
        );

        write_meta(root, &StoreMeta::new(StoreMode::Derived)).unwrap();
        assert_eq!(read_mode(root).unwrap(), StoreMode::Derived);
        let text = std::fs::read_to_string(StoreMeta::path(root)).unwrap();
        assert!(text.contains("mode: derived"), "{text}");
    }
}
