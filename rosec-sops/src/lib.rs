//! A native rosec provider whose store is a **sops-encrypted file tree**.
//!
//! One file per item, encrypted by the external `sops` binary. Recipients are
//! either configured directly or taken from the store's own `.sops.yaml`
//! creation rules. On this host the recipient is a YubiKey identity and the age
//! identity file is `~/.config/sops/age/keys.txt`, so the hardware token is the
//! unlock — and [`Provider::unlock`] proves it by decrypting a store file.
//!
//! # Layout
//!
//! ```text
//! <root>/.sops.yaml                          optional sops creation rules
//! <root>/<collection>/<item-id>.sops.yaml    one sops-encrypted YAML document
//! <root>/<collection>/_meta.meta.yaml        collection label (optional)
//! <root>/<collection>/.superseded-…          archived, superseded copy
//! <root>/.conflicts/<collection>/<id>.md     plaintext conflict marker
//! ```
//!
//! The plaintext document inside each file:
//!
//! ```yaml
//! label: github.com
//! attributes:
//!   rosec:type: login
//!   username: kdn
//! secrets:
//!   password: hunter2
//! binary_secrets:          # only when a value is not UTF-8, standard base64
//!   blob: AP+AQQ==
//! created: 2026-11-14T18:02:11.000000000Z
//! modified: 2026-11-14T18:41:09.417000000Z
//! host: oams
//! revision: 7
//! ```
//!
//! `created` and `modified` are RFC 3339 on write; a bare Unix epoch is
//! accepted on read. `revision` counts writes and `host` names the writer.
//! `secrets` holds UTF-8 text; `binary_secrets` holds standard base64, so a
//! value that is not UTF-8 survives a round trip byte for byte.
//!
//! **Collection labels.** A collection is a directory and its directory name is
//! its label. Only a collection whose label differs from the directory name
//! gets a meta file, written by [`Store::write_collection_meta`]; an ordinary
//! store holds item files only. An unreadable meta file only makes the label
//! fall back to the directory name. The `_meta.sops.yaml` name an earlier build
//! wrote is still read, never treated as an item.
//!
//! **Item ids.** A file name is the item id plus `.sops.yaml`. New ids are
//! randomly generated (`item-` and 16 random bytes in hex) and carry no
//! information about the secret: the store is synced as plaintext file names, so
//! a hash of the secret would be an offline verifier for a guess. The daemon
//! sees bare ids for the collection that owns most items (ties broken by name)
//! and `<collection>/<id>` for the rest. Aliases are the daemon's concern.
//!
//! # Encryption
//!
//! All encryption is done by the `sops` command:
//!
//! ```text
//! SOPS_AGE_KEY_FILE=<key_file> sops --encrypt [--age <recipients>] \
//!     --input-type yaml --output-type yaml
//! SOPS_AGE_KEY_FILE=<key_file> sops --decrypt \
//!     --input-type yaml --output-type yaml <file>
//! ```
//!
//! There is no GPG step, no network access, and no age key inside the process.
//! Writes go to a hidden temporary file in the same directory, are fsynced,
//! then renamed over the target, so a syncing peer or a reader sees the old
//! file or the whole new one.
//!
//! ## Recipients, two modes
//!
//! - **`age_recipient` unset** — `--encrypt` runs without `--age`, and the
//!   creation rules of the `.sops.yaml` in the store root choose the recipients.
//!   A store without a matching rule fails cleanly (`no encryption keys`).
//!   An update keeps the recipients already recorded in the file header.
//! - **`age_recipient` set** — a new file is encrypted to that list, and an
//!   **update** is encrypted to the **union** of that list and the recipients
//!   already in the file's header. A configured list can therefore add access,
//!   never remove it: rewriting a three-recipient file through a provider that
//!   lists one recipient keeps all three.
//!
//! Reads are cached by `(mtime, size, sha256)` of the ciphertext. A rewrite
//! that keeps the timestamp and the length is still detected, because the hash
//! is computed on every read. Decryption — the step that may need the YubiKey
//! — runs only when that key changes.
//!
//! # Conflict rule (placeholder)
//!
//! For one item id the provider considers the canonical `<id>.sops.yaml` and
//! every Syncthing conflict copy of the same id in the same collection
//! (`<id>.sops.yaml.sync-conflict-*` or `<id>.sync-conflict-*.sops.yaml`).
//! **The copy with the latest `modified` wins.** A conflict copy therefore wins
//! over the canonical file whenever its `modified` is later. On a full tie —
//! equal `modified`, equal `host`, equal `revision` — the canonical file wins.
//! A file that fails to decrypt is skipped.
//!
//! A read never changes the store. A **write** is different:
//!
//! 1. the merged document is written to the **canonical** `<id>.sops.yaml`,
//!    whatever copy was served;
//! 2. every other copy of that id — including the served copy when it was a
//!    conflict copy — is renamed to
//!    `.superseded-<id>.<nanos>-<host>.sops.yaml`. A dotfile, and not a valid
//!    item name, so the copy stops participating in resolution;
//! 3. the archive path is logged at `warn`;
//! 4. a plaintext, secret-free marker `<root>/.conflicts/<collection>/<id>.md`
//!    records the winner, the archived losers and their
//!    `modified`/`host`/`revision`, so the conflict is visible to a user, a
//!    script or a host-side watcher without a key (see
//!    [`crate::conflicts`] and the `rosec-sops conflicts` CLI).
//!
//! The archived copy is **never deleted** by a write: it keeps the value that
//! lost, for review. [`Provider::delete_item`][rosec_core::Provider::delete_item]
//! removes every copy and archive of an id, and its marker, because the user
//! asked for the item to disappear.
//!
//! This rule is a placeholder. It can lose a secret when two hosts edit at
//! once, and it relies on wall-clock agreement. Hashing out a real merge is
//! the follow-up task in the nix-configs repository:
//! `docs/tasks/2026-11/rosec-conflict-resolution/definition.md`.
//!
//! # Locked behaviour
//!
//! `unlock` verifies three things: the `sops` binary runs, the age identity file
//! exists, and one store file actually **decrypts**. The decrypt probe uses a
//! collection meta file when present, else the smallest item file, and it is
//! bounded by `probe_timeout_seconds` (default 30 s). A failure is reported as
//! [`ProviderError::AuthFailed`] — a wrong YubiKey slot, a revoked recipient or
//! a `keys.txt` with another identity fails at unlock, not on the first read.
//! An empty store has nothing to prove and unlocks after the two checks.
//!
//! `lock` drops the decrypted-document cache and the default collection.
//! While locked, `list_items`, `search`, `get_item_attributes`,
//! `get_secret_attr` and every write return [`ProviderError::Locked`]. The
//! daemon maps that to `RefreshOutcome::Locked` and keeps its previous view —
//! an empty list would be a complete refresh of zero items and would wipe every
//! sops item from the cache.
//!
//! # Attributes
//!
//! `rosec:type` and `rosec:totp` are reserved by [`rosec_core`], and this
//! provider also manages `collection`, `rosec:collection-dir`,
//! `rosec:sops-conflict` and `rosec:sops-unresolved-conflict`. None of them may
//! come from a client:
//! [`NewItem::validate`] rejects the reserved names, and this provider **strips**
//! [`INTERNAL_ATTRIBUTES`] from `attributes` on create and update instead of
//! rejecting them, so the Secret Service layer can echo a full attribute map
//! back on a read-modify-write. The provider stamps the values itself.
//!
//! # Configuration
//!
//! ```toml
//! [[provider]]
//! id   = "sops"
//! kind = "sops"
//! path = "~/Nextcloud/drag0nius@nc.nazarewk.pw/important/rosec-storage"
//!
//! [provider.options]
//! key_file      = "~/.config/sops/age/keys.txt"   # default
//! age_recipient = "age1yubikey1…"                 # optional
//! sops_binary   = "sops"                          # default
//! probe_timeout_seconds = 30                      # default
//! ```
//!
//! `age_recipient` may list several recipients, comma-separated. All paths
//! accept a `~/` prefix and must be absolute after expansion.
//!
//! # Value mapping
//!
//! rosec secrets are bytes. A UTF-8 value is stored as text under `secrets` and
//! a non-UTF-8 value as base64 under `binary_secrets`, so both round-trip
//! exactly. Only [`Capability::Write`] is declared: SSH keys and TOTP seeds in
//! the store are not turned into an agent or TOTP files.

pub mod cli;
pub mod config;
pub mod conflicts;
pub mod document;
pub mod error;
pub mod provider;
pub mod sops;
pub mod store;

pub use config::{DEFAULT_KEY_FILE, DEFAULT_SOPS_BINARY, SopsConfig};
pub use conflicts::{CONFLICTS_DIR, ConflictMarker, CopyMeta, StoredMarker};
pub use document::{CollectionMeta, SecretDecodeError, SopsDocument, Timestamp};
pub use error::SopsError;
pub use provider::{
    ATTR_COLLECTION, ATTR_COLLECTION_DIR, ATTR_CONFLICT, ATTR_UNRESOLVED_CONFLICT,
    DEFAULT_COLLECTION, INTERNAL_ATTRIBUTES, SopsProvider, new_id,
};
pub use sops::SopsCommand;
pub use store::{
    COLLECTION_META, ITEM_SUFFIX, Keep, LEGACY_COLLECTION_META, Resolution, SUPERSEDED_PREFIX,
    SYNCTHING_CONFLICT_MARKER, Store, StoreCache, StoreItem,
};

#[cfg(test)]
mod tests;
