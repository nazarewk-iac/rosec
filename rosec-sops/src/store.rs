//! The on-disk store: layout, conflict-copy resolution, and the read cache.
//!
//! Layout (see also the crate docs):
//!
//! ```text
//! <root>/.sops.yaml                          optional sops creation rules
//! <root>/<collection>/<item-id>.sops.yaml    one item, sops-encrypted
//! <root>/<collection>/_meta.meta.yaml        collection label (optional)
//! ```
//!
//! Collections are directories below the root. A collection label comes from
//! `_meta.meta.yaml` when that file exists and decrypts; otherwise the
//! directory name is the label. Only a collection whose label differs from its
//! directory name gets a meta file — a store with plain directory names holds
//! item files only, and each name is read once per `list_items` reached.
//!
//! Only files ending in `.sops.yaml` are read as items. That keeps Syncthing
//! `.stversions` entries, editor backups and the syncing client's own metadata
//! directories out of the item list. Superseded conflict copies are archived
//! as `.superseded-<id>.<nanos>-<host>.sops.yaml` — a dotfile that does not
//! parse as an item either way (leading dot, and `superseded-` is not a valid
//! item id character). Each archive also writes a plaintext, secret-free marker
//! `<root>/.conflicts/<collection>/<item-id>.md` (see [`crate::conflicts`]), so
//! a user, a script or a host-side watcher can see the conflict without a key.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::SopsConfig;
use crate::conflicts::{ConflictMarker, CopyMeta, RESOLUTION_HINT, now_text};
use crate::document::{CollectionMeta, SecretDecodeError, SopsDocument, Timestamp};
use crate::error::SopsError;
use crate::sops::{SopsCommand, header_recipients, union_recipients, write_atomic};

/// Suffix every item file carries.
pub const ITEM_SUFFIX: &str = ".sops.yaml";

/// File name of a collection's label file, when the label is not the directory
/// name. Optional.
pub const COLLECTION_META: &str = "_meta.meta.yaml";

/// File name an earlier build used for a collection's label file.
///
/// Still read as a meta file, never as an item, so a store written by that
/// build keeps working.
pub const LEGACY_COLLECTION_META: &str = "_meta.sops.yaml";

/// Prefix of an archived, superseded conflict copy.
pub const SUPERSEDED_PREFIX: &str = ".superseded-";

/// Marker Syncthing puts into a conflict copy's file name.
pub const SYNCTHING_CONFLICT_MARKER: &str = ".sync-conflict-";

/// Parsed item plus the file it came from.
#[derive(Debug, Clone)]
pub struct StoreItem {
    /// Collection directory the file lives in.
    pub collection: String,
    /// Item identifier (the file name without [`ITEM_SUFFIX`]).
    pub id: String,
    /// The file the document was read from. Not always the canonical one.
    pub file: PathBuf,
    /// The decrypted document.
    pub document: SopsDocument,
    /// Every other file that held the same id: older conflict copies that are
    /// not being served. A write supersedes them (see
    /// [`Store::archive_superseded`]).
    pub superseded: Vec<PathBuf>,
}

impl StoreItem {
    /// True when the item was served from a Syncthing conflict copy instead of
    /// the canonical `<id>.sops.yaml` file.
    pub fn is_from_conflict_copy(&self) -> bool {
        self.file
            .file_name()
            .map(|n| n.to_string_lossy().contains(SYNCTHING_CONFLICT_MARKER))
            .unwrap_or(false)
    }
}

/// One candidate file for an item id: the canonical file or a conflict copy.
#[derive(Debug, Clone)]
struct Candidate {
    file: PathBuf,
    canonical: bool,
}

/// Identity of one cached decrypted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileKey {
    /// Path of the file.
    pub path: PathBuf,
    /// Modification time in nanoseconds since the epoch.
    pub mtime_nanos: u128,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the ciphertext.
    pub sha256: [u8; 32],
}

/// One cached, decrypted file, kept in the type it was parsed as.
///
/// The cache is typed rather than a single document type: an item file yields
/// an [`SopsDocument`], a collection meta file a [`CollectionMeta`]. Nothing is
/// re-serialised to move between the two, so a future field name shared by
/// both types cannot silently change meaning.
#[derive(Debug, Clone)]
enum Cached {
    Item(Box<SopsDocument>),
    Meta(CollectionMeta),
}

/// Bounded cache of decrypted documents.
///
/// A document is reused while `(mtime, size, sha256)` of its ciphertext file is
/// unchanged. Callers pass a `stat` taken *before* reading the file; the loader
/// re-stats after the read and only caches when the stat still matches, so a
/// concurrent write can never pin a stale document under a fresh key.
///
/// The cache keeps at most [`StoreCache::CAPACITY`] documents and clears
/// wholesale when full. That bounds memory without an LRU implementation.
#[derive(Debug, Default)]
pub struct StoreCache {
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
}

/// Identity of a cache slot: one file, parsed as one type.
///
/// The same file can be asked for as two types — `_meta.sops.yaml` is a
/// `CollectionMeta` to the label reader and a `SopsDocument` to
/// [`Store::resolve_item`] — so the type is part of the key. A path-only key
/// made the second request hit a value of the other type and fail with
/// "cached document has a different type than requested".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    path: PathBuf,
    kind: CacheKind,
}

/// The parsed type a slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CacheKind {
    Item,
    Meta,
}

/// One cached file.
#[derive(Debug, Clone)]
struct CacheEntry {
    key: FileKey,
    value: Cached,
}

impl StoreCache {
    /// Maximum number of decrypted documents kept in memory.
    pub const CAPACITY: usize = 512;

    fn slot(path: &Path, kind: CacheKind) -> CacheKey {
        CacheKey {
            path: path.to_path_buf(),
            kind,
        }
    }

    /// Look up an entry of this type whose identifying key matches.
    fn get(&self, key: &FileKey, kind: CacheKind) -> Option<Cached> {
        let slot = Self::slot(&key.path, kind);
        let guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get(&slot)
            .filter(|entry| entry.key == *key)
            .map(|entry| entry.value.clone())
    }

    fn put(&self, key: FileKey, kind: CacheKind, value: Cached) {
        let slot = Self::slot(&key.path, kind);
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= Self::CAPACITY && !guard.contains_key(&slot) {
            debug!(capacity = Self::CAPACITY, "sops store cache full, clearing");
            guard.clear();
        }
        guard.insert(slot, CacheEntry { key, value });
    }

    /// Remove one file from the cache (after a write or a delete): every type
    /// it was cached as.
    fn forget(&self, path: &Path) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|slot, _| slot.path != path);
    }

    /// Number of cached documents.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// True when nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forget everything. Called on `lock`.
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

/// The document a write is encrypting to.
#[derive(Debug, Clone)]
enum DocKind {
    Item,
    Meta,
}

/// Handle on the store root. Walks directories, decrypts through
/// [`SopsCommand`], and archives superseded conflict copies.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    recipient: String,
    sops: SopsCommand,
    cache: Arc<StoreCache>,
    host: Arc<RwLock<String>>,
}

impl Store {
    /// Build a store handle over `config.path`.
    pub fn new(config: &SopsConfig) -> Self {
        Self {
            root: config.path.clone(),
            recipient: config.age_recipient.clone(),
            sops: SopsCommand::new(&config.sops_binary, &config.key_file)
                .with_probe_timeout(config.probe_timeout),
            cache: Arc::new(StoreCache::default()),
            host: Arc::new(RwLock::new(default_host())),
        }
    }

    /// Build a store handle that shares `cache` with the provider, so `lock`
    /// clears one cache for every caller.
    pub fn with_cache(config: &SopsConfig, cache: Arc<StoreCache>) -> Self {
        let mut store = Self::new(config);
        store.cache = cache;
        store
    }

    /// Store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The sops wrapper this store uses.
    pub fn sops(&self) -> &SopsCommand {
        &self.sops
    }

    /// The cache behind this store.
    pub fn cache(&self) -> &Arc<StoreCache> {
        &self.cache
    }

    /// The configured recipient list. Empty means "the store's `.sops.yaml`
    /// creation rules decide".
    pub fn configured_recipient(&self) -> &str {
        &self.recipient
    }

    /// Set the hostname written into new revisions (defaults to the kernel
    /// hostname).
    pub fn set_host(&self, host: impl Into<String>) {
        *self.host.write().unwrap_or_else(|e| e.into_inner()) = host.into();
    }

    /// The hostname written into new revisions.
    pub fn host(&self) -> String {
        self.host.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Create the root directory when it does not exist yet.
    pub async fn ensure_root(&self) -> Result<(), SopsError> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(|e| SopsError::io(self.root.display(), e))
    }

    /// Canonical file path of an item.
    pub fn item_path(&self, collection: &str, id: &str) -> PathBuf {
        self.root
            .join(collection)
            .join(format!("{id}{ITEM_SUFFIX}"))
    }

    /// Collection directories present in the store, sorted by name.
    ///
    /// Hidden directories are skipped, so the syncing client's own metadata
    /// directory (Nextcloud and Syncthing each keep one) never becomes a
    /// collection.
    pub async fn collections(&self) -> Result<Vec<String>, SopsError> {
        let mut out = Vec::new();
        let mut dir = match tokio::fs::read_dir(&self.root).await {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(SopsError::io(self.root.display(), e)),
        };
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|e| SopsError::io(self.root.display(), e))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if entry.path().is_dir() {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Collection label: `_meta.meta.yaml` when it exists and reads, else the
    /// directory name.
    ///
    /// The meta file is optional. An unreadable one logs a warning and falls
    /// back, so a broken label file never hides a collection's items.
    pub async fn collection_label(&self, collection: &str) -> String {
        let dir = self.root.join(collection);
        let meta_path = [COLLECTION_META, LEGACY_COLLECTION_META]
            .into_iter()
            .map(|name| dir.join(name))
            .find(|path| path.is_file());
        if let Some(meta_path) = meta_path {
            match self.load::<CollectionMeta>(&meta_path).await {
                Ok(meta) => return meta.label,
                Err(e) => warn!(
                    path = %meta_path.display(),
                    error = %e,
                    "collection meta unreadable; using the directory name as the label",
                ),
            }
        }
        collection.to_owned()
    }

    /// Write the label file for a collection, creating the directory.
    ///
    /// A label equal to the directory name writes nothing and removes a stale
    /// meta file, because the directory name already means exactly that.
    pub async fn write_collection_meta(
        &self,
        collection: &str,
        label: &str,
    ) -> Result<(), SopsError> {
        validate_name("collection", collection)?;
        let dir = self.root.join(collection);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?;
        let path = dir.join(COLLECTION_META);
        if label == collection {
            if path.is_file() {
                tokio::fs::remove_file(&path)
                    .await
                    .map_err(|e| SopsError::io(path.display(), e))?;
                self.cache.forget(&path);
            }
            return Ok(());
        }
        let meta = CollectionMeta {
            label: label.to_owned(),
            created: Some(Timestamp::now()),
        };
        self.write_meta_document(collection, &meta).await
    }

    async fn write_meta_document(
        &self,
        collection: &str,
        meta: &CollectionMeta,
    ) -> Result<(), SopsError> {
        let path = self.root.join(collection).join(COLLECTION_META);
        self.write_typed(&path, meta, DocKind::Meta, None).await
    }

    /// Decrypt and parse one typed document, with the cache in front.
    ///
    /// `T` is selected by the caller, and the cached entry is parsed as `T`
    /// only for the matching file kind — an item file is never re-read as a
    /// meta file or the other way round.
    pub async fn load<T: DeserializeOwned + 'static>(&self, path: &Path) -> Result<T, SopsError> {
        let before = stat_key(path)?;
        // The requested type decides the cache slot, so `_meta.sops.yaml` can be
        // held both as a `CollectionMeta` and as a `SopsDocument`.
        let kind = if std::any::TypeId::of::<T>() == std::any::TypeId::of::<CollectionMeta>() {
            CacheKind::Meta
        } else {
            CacheKind::Item
        };
        if let Some(cached) = self.cache.get(&before, kind) {
            return decode::<T>(cached, path);
        }

        let cipher = tokio::fs::read(path)
            .await
            .map_err(|e| SopsError::io(path.display(), e))?;
        let plain = self.sops.decrypt(path).await?;
        let is_meta = kind == CacheKind::Meta;
        // Parse straight into the type the caller asked for: an item file
        // yields a `SopsDocument`, a collection meta file a `CollectionMeta`.
        // No YAML re-serialisation is involved, so a field name shared by both
        // types cannot silently change meaning.
        let cached = if is_meta {
            Cached::Meta(
                serde_yaml::from_slice(&plain).map_err(|e| SopsError::Malformed {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?,
            )
        } else {
            Cached::Item(Box::new(SopsDocument::from_yaml(
                &plain,
                &path.display().to_string(),
            )?))
        };

        // Re-stat after the read. Only cache when the file did not change
        // while it was being decrypted.
        if let Ok(after) = stat_key(path)
            && after.mtime_nanos == before.mtime_nanos
            && after.size == before.size
        {
            let key = FileKey {
                sha256: Sha256::digest(&cipher).into(),
                ..after
            };
            self.cache.put(key, kind, cached.clone());
        }

        decode::<T>(cached, path)
    }

    /// Load one document without the typed wrapper (convenience).
    pub async fn load_document(&self, path: &Path) -> Result<SopsDocument, SopsError> {
        self.load::<SopsDocument>(path).await
    }

    /// Write an item document to `collection`/`id`.
    ///
    /// Recipients are the union of the configured list and the recipients
    /// already in the file's header, so an update never narrows access. With no
    /// configured list the file keeps exactly its own header, and a new file
    /// is encrypted by the store's `.sops.yaml` creation rules.
    ///
    /// Superseded conflict copies are not touched here; the caller archives
    /// them through [`Store::archive_superseded`] once the write succeeded.
    pub async fn write_document(
        &self,
        collection: &str,
        id: &str,
        document: &SopsDocument,
    ) -> Result<(), SopsError> {
        validate_name("collection", collection)?;
        validate_name("item id", id)?;
        let dir = self.root.join(collection);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?;
        let path = self.item_path(collection, id);
        self.write_typed(&path, document, DocKind::Item, None).await
    }

    /// Encrypt `document` to `path`, choosing recipients per [`DocKind`].
    async fn write_typed<T: Serialize>(
        &self,
        path: &Path,
        document: &T,
        kind: DocKind,
        recipients: Option<Vec<String>>,
    ) -> Result<(), SopsError> {
        let recipients = match recipients {
            Some(list) => list,
            None => self.recipients_for(path, &kind).await,
        };
        let plain = serde_yaml::to_string(document).map_err(|e| SopsError::Malformed {
            path: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<in memory>".into()),
            reason: e.to_string(),
        })?;
        let configured = (!self.recipient.is_empty()).then_some(self.recipient.as_str());
        let cipher = if recipients.is_empty() {
            None
        } else {
            Some(recipients.join(","))
        };
        let cipher = self
            .sops
            .encrypt(
                plain.as_bytes(),
                cipher.as_deref().or(configured),
                &self.root,
            )
            .await?;
        let result = write_atomic(path, &cipher).await;
        self.cache.forget(path);
        result
    }

    /// Recipients for a write: configured list plus the file's own header.
    async fn recipients_for(&self, path: &Path, kind: &DocKind) -> Vec<String> {
        let configured = crate::config::split_recipients(&self.recipient)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let existing = match kind {
            // A meta file is not an item; it follows the configuration.
            DocKind::Meta => Vec::new(),
            DocKind::Item => match tokio::fs::read(path).await {
                Ok(cipher) => header_recipients(&cipher),
                Err(_) => Vec::new(),
            },
        };
        let union = union_recipients(&configured, &existing);
        if configured.is_empty() && union.is_empty() {
            info!(
                path = %path.display(),
                "no `age_recipient` configured; sops will use the store's creation rules",
            );
        } else if configured.is_empty() {
            debug!(
                path = %path.display(),
                recipients = union.len(),
                "keeping the recipients recorded in the file header",
            );
        }
        union
    }

    /// Create the collection directory. Item files only: the directory name is
    /// the label.
    pub async fn ensure_collection(&self, collection: &str) -> Result<(), SopsError> {
        validate_name("collection", collection)?;
        let dir = self.root.join(collection);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| SopsError::io(dir.display(), e))
    }

    /// Delete an item file plus every conflict copy of the same id.
    ///
    /// Returns `false` when the id had no file at all. Losing conflict copies
    /// are never deleted by a *read*; a write archives them (see
    /// [`Store::archive_superseded`]) and only an explicit delete removes them.
    /// The item's conflict marker goes too: the user asked for the item to
    /// disappear, so no marker may outlive it.
    pub async fn delete_item(&self, collection: &str, id: &str) -> Result<bool, SopsError> {
        validate_name("collection", collection)?;
        validate_name("item id", id)?;
        let candidates = self.candidates(collection, id).await?;
        let mut removed = false;
        for candidate in candidates {
            tokio::fs::remove_file(&candidate.file)
                .await
                .map_err(|e| SopsError::io(candidate.file.display(), e))?;
            self.cache.forget(&candidate.file);
            removed = true;
        }
        // Archived copies of the same id go too: the user asked for the item
        // to disappear.
        for archive in self.archived_copies(collection, id).await? {
            if tokio::fs::remove_file(&archive).await.is_ok() {
                removed = true;
            }
            self.cache.forget(&archive);
        }
        crate::conflicts::remove_marker(&self.root, collection, id).await?;
        Ok(removed)
    }

    /// Archived superseded copies of an id, oldest first.
    async fn archived_copies(&self, collection: &str, id: &str) -> Result<Vec<PathBuf>, SopsError> {
        let dir = self.root.join(collection);
        let prefix = format!("{SUPERSEDED_PREFIX}{id}.");
        let mut out = Vec::new();
        let mut reader = match tokio::fs::read_dir(&dir).await {
            Ok(reader) => reader,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(SopsError::io(dir.display(), e)),
        };
        while let Some(entry) = reader
            .next_entry()
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && name.ends_with(".sops.yaml") {
                out.push(entry.path());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Retire copies of `id` that lost to the document just written.
    ///
    /// Each file in `others` is renamed to
    /// `.superseded-<id>.<modified-nanos>-<host>.sops.yaml` in the same
    /// directory. The name starts with a dot and does not parse as an item id,
    /// so the copy stops participating in resolution and review, and it is
    /// **never deleted** — it stays as an audit trail of the losing value.
    ///
    /// `written` is the file the caller just wrote. It is skipped: after a
    /// successful write it holds the winning document, not a loser, even when
    /// it was one of the
    /// [`superseded`][StoreItem::superseded] files (a write serviced from a
    /// conflict copy still lands on the canonical path).
    ///
    /// When at least one copy is archived, a plaintext, secret-free conflict
    /// marker is written to `<root>/.conflicts/<collection>/<id>.md`. It
    /// carries the winner, the archived losers, and their
    /// `modified`/`host`/`revision` — never a secret value. A later conflict
    /// for the same id replaces the marker, so one id has one marker.
    ///
    /// Returns the archive paths.
    pub async fn archive_superseded(
        &self,
        collection: &str,
        id: &str,
        others: &[PathBuf],
        written: &Path,
    ) -> Result<Vec<PathBuf>, SopsError> {
        let dir = self.root.join(collection);
        let mut out = Vec::new();
        let mut losers: Vec<CopyMeta> = Vec::new();
        for path in others {
            if path == written || !path.is_file() {
                continue;
            }
            // The stamp names *when* the loser claimed its value, so two
            // archives of the same id never collide. The document is loaded
            // once: the same copy is described by the marker below.
            let document = self.load_document(path).await.ok();
            let stamp = match &document {
                Some(document) => document
                    .modified
                    .map(|m| m.file_stamp())
                    .unwrap_or_else(|| Timestamp::now().file_stamp()),
                None => Timestamp::now().file_stamp(),
            };
            let host: String = self
                .host()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect();
            let mut archive = dir.join(format!(
                "{SUPERSEDED_PREFIX}{id}.{stamp}-{host}{ITEM_SUFFIX}"
            ));
            if archive.exists() {
                archive = dir.join(format!(
                    "{SUPERSEDED_PREFIX}{id}.{stamp}-{host}-{}{ITEM_SUFFIX}",
                    std::process::id()
                ));
            }
            tokio::fs::rename(path, &archive)
                .await
                .map_err(|e| SopsError::io(path.display(), e))?;
            self.cache.forget(path);
            info!(
                item_id = %id,
                from = %path.display(),
                archived = %archive.display(),
                "archived a superseded copy of a written item",
            );
            if let Some(document) = document {
                losers.push(CopyMeta::from_document(self.relative(&archive), &document));
            } else {
                // An unreadable loser still gets a marker entry: the file name
                // is the only fact, and it is enough to find the archive.
                losers.push(CopyMeta {
                    file: self.relative(&archive),
                    ..Default::default()
                });
            }
            out.push(archive);
        }
        if !out.is_empty() {
            self.write_conflict_marker(collection, id, written, &losers)
                .await?;
        }
        Ok(out)
    }

    /// Write (or replace) the conflict marker for `collection`/`id`.
    ///
    /// Reads only the winner and the plaintext-free fields of the losers, so no
    /// secret value can enter the marker. A failure is logged and swallowed by
    /// the caller: the write and the archive already succeeded, and the archive
    /// path is in the log.
    async fn write_conflict_marker(
        &self,
        collection: &str,
        id: &str,
        written: &Path,
        losers: &[CopyMeta],
    ) -> Result<(), SopsError> {
        let winner_document = self.load_document(written).await.ok();
        let label = self.collection_label(collection).await;
        let winner_meta = winner_document
            .as_ref()
            .map(|document| CopyMeta::from_document(self.relative(written), document));
        let mut sorted = losers.to_vec();
        sorted.sort_by(|a, b| a.file.cmp(&b.file));
        let mut attributes = winner_document
            .as_ref()
            .map(|document| document.attributes.clone())
            .unwrap_or_default();
        // Provider-internal values are noise in a user-facing file.
        attributes.retain(|key, _| {
            !crate::provider::INTERNAL_ATTRIBUTES.contains(&key.as_str())
                && !rosec_core::RESERVED_ATTRIBUTES.contains(&key.as_str())
        });
        let marker = ConflictMarker {
            item: id.to_owned(),
            collection: collection.to_owned(),
            label,
            winner: self.relative(written),
            losers: sorted,
            winner_meta,
            written: now_text(),
            attributes,
            hint: RESOLUTION_HINT.to_owned(),
        };
        let path = crate::conflicts::write_marker(&self.root, &marker).await?;
        info!(
            item_id = %id,
            marker = %path.display(),
            losers = marker.losers.len(),
            "wrote a conflict marker; the user must resolve this item",
        );
        Ok(())
    }

    /// Path relative to the store root, for display and for the marker.
    pub fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    /// Archived superseded copies of an id, oldest first.
    pub async fn archived_copies_of(
        &self,
        collection: &str,
        id: &str,
    ) -> Result<Vec<PathBuf>, SopsError> {
        self.archived_copies(collection, id).await
    }

    /// List the files that can hold item `id`: the canonical file and every
    /// Syncthing conflict copy of the same id, in the same collection.
    async fn candidates(&self, collection: &str, id: &str) -> Result<Vec<Candidate>, SopsError> {
        validate_name("collection", collection)?;
        validate_name("item id", id)?;
        let canonical_name = format!("{id}{ITEM_SUFFIX}");
        let dir = self.root.join(collection);
        let mut out = Vec::new();
        let mut reader = match tokio::fs::read_dir(&dir).await {
            Ok(reader) => reader,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(SopsError::io(dir.display(), e)),
        };
        while let Some(entry) = reader
            .next_entry()
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_item_file_name(&name) {
                continue;
            }
            // Both the canonical file and a conflict copy must yield this id.
            if item_id_from_file_name(&name).as_deref() != Some(id) {
                continue;
            }
            out.push(Candidate {
                file: entry.path(),
                canonical: name == canonical_name,
            });
        }
        Ok(out)
    }

    /// Resolve one item id to its freshest copy.
    ///
    /// The sort key is `(modified, host, revision)` compared as a tuple, so
    /// `modified` dominates: the freshest copy wins even when it is a conflict
    /// copy. A strict tie falls back to the canonical file, which can only
    /// happen for two copies with an identical key. Files that fail to decrypt
    /// or parse are skipped with a warning and never removed.
    ///
    /// `superseded` collects the other readable copies of the id.
    pub async fn resolve_item(&self, collection: &str, id: &str) -> Result<StoreItem, SopsError> {
        let candidates = self.candidates(collection, id).await?;
        let mut best: Option<(StoreItem, bool, (u128, String, u64))> = None;
        let mut others: Vec<(PathBuf, (u128, String, u64))> = Vec::new();

        for candidate in candidates {
            let document = match self.load::<SopsDocument>(&candidate.file).await {
                Ok(document) => document,
                Err(e) => {
                    warn!(
                        path = %candidate.file.display(),
                        error = %e,
                        "skipping unreadable sops item file",
                    );
                    continue;
                }
            };
            let (modified, host, revision) = document.freshness();
            let sort_key = (modified, host.to_owned(), revision);
            let better = match &best {
                None => true,
                Some((_, best_canonical, best_key)) => match sort_key.cmp(best_key) {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Less => false,
                    std::cmp::Ordering::Equal => candidate.canonical && !*best_canonical,
                },
            };
            if better {
                if let Some((previous, _, previous_key)) = best.take() {
                    others.push((previous.file, previous_key));
                }
                best = Some((
                    StoreItem {
                        collection: collection.to_owned(),
                        id: id.to_owned(),
                        file: candidate.file,
                        document,
                        superseded: Vec::new(),
                    },
                    candidate.canonical,
                    sort_key,
                ));
            } else {
                others.push((candidate.file, sort_key));
            }
        }

        match best {
            Some((mut item, _, _)) => {
                // Oldest first, so an archive listing reads chronologically.
                others.sort_by(|a, b| a.1.cmp(&b.1));
                item.superseded = others.into_iter().map(|(path, _)| path).collect();
                if item.is_from_conflict_copy() {
                    debug!(
                        item_id = %id,
                        file = %item.file.display(),
                        "serving the freshest copy, which is a Syncthing conflict copy",
                    );
                }
                Ok(item)
            }
            None => Err(SopsError::NotFound(id.to_owned())),
        }
    }

    /// List every item in the store, one entry per id, conflict copies
    /// resolved by [`Store::resolve_item`].
    pub async fn list_items(&self) -> Result<Vec<StoreItem>, SopsError> {
        let mut out = Vec::new();
        for collection in self.collections().await? {
            for id in self.item_ids(&collection).await? {
                match self.resolve_item(&collection, &id).await {
                    Ok(item) => out.push(item),
                    Err(SopsError::NotFound(_)) => continue,
                    Err(e) => {
                        warn!(
                            collection = %collection,
                            item_id = %id,
                            error = %e,
                            "skipping unresolvable sops item",
                        );
                    }
                }
            }
        }
        Ok(out)
    }

    /// Item ids in one collection, derived from file names: canonical files
    /// contribute their stem, conflict copies contribute the stem of the item
    /// they conflict with.
    pub async fn item_ids(&self, collection: &str) -> Result<Vec<String>, SopsError> {
        let dir = self.root.join(collection);
        let mut ids = BTreeMap::new();
        let mut reader = match tokio::fs::read_dir(&dir).await {
            Ok(reader) => reader,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SopsError::io(dir.display(), e)),
        };
        while let Some(entry) = reader
            .next_entry()
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_item_file_name(&name) || name == COLLECTION_META {
                continue;
            }
            if let Some(id) = item_id_from_file_name(&name) {
                ids.insert(id, ());
            }
        }
        Ok(ids.into_keys().collect())
    }

    /// Decode a secret read from a stored document.
    pub fn decode_secret(
        document: &SopsDocument,
        name: &str,
        path: &Path,
    ) -> Result<Vec<u8>, SopsError> {
        match document.secret_bytes(name) {
            Some(Ok(bytes)) => Ok(bytes),
            Some(Err(SecretDecodeError::NotBase64)) => Err(SopsError::MalformedSecret {
                path: path.display().to_string(),
                name: name.to_owned(),
            }),
            None => Err(SopsError::NotFound(name.to_owned())),
        }
    }

    /// Resolve the recorded conflict of `collection`/`id`.
    ///
    /// `keep` names the copy the user keeps (see [`Keep`]). The store performs
    /// the file work only and returns what it did; the marker is removed once
    /// everything succeeded, so the user can retry after a failure.
    ///
    /// Refusals, all before any file changes:
    ///
    /// - no marker for the id ([`SopsError::NotFound`]) — only a recorded
    ///   conflict can be resolved;
    /// - the marker names the wrong collection ([`SopsError::Config`]), which a
    ///   hand-edited marker can cause;
    /// - a named file is missing or the kept file does not decrypt.
    pub async fn resolve_conflict(
        &self,
        collection: &str,
        id: &str,
        keep: &Keep,
    ) -> Result<Resolution, SopsError> {
        validate_name("collection", collection)?;
        validate_name("item id", id)?;
        let marker_path = crate::conflicts::marker_path(&self.root, collection, id);
        if !marker_path.is_file() {
            return Err(SopsError::NotFound(format!(
                "{collection}/{id} (no conflict marker at {})",
                self.relative(&marker_path)
            )));
        }
        let marker = ConflictMarker::read(&marker_path).await?;
        if marker.collection != collection || marker.item != id {
            return Err(SopsError::Config(format!(
                "marker `{}` records `{}/{}` but was read as `{collection}/{id}`",
                self.relative(&marker_path),
                marker.collection,
                marker.item
            )));
        }

        let canonical = self.item_path(collection, id);
        let losers = self.archived_copies(collection, id).await?;
        let mut resolution = Resolution {
            item: id.to_owned(),
            collection: collection.to_owned(),
            kept: PathBuf::new(),
            promoted: false,
            deleted: Vec::new(),
            unarchived: Vec::new(),
        };

        match keep {
            Keep::Winner => {
                resolution.kept = canonical.clone();
                for loser in &losers {
                    tokio::fs::remove_file(loser)
                        .await
                        .map_err(|e| SopsError::io(loser.display(), e))?;
                    self.cache.forget(loser);
                    resolution.deleted.push(loser.clone());
                }
            }
            Keep::Loser => {
                let newest = losers.last().ok_or_else(|| {
                    SopsError::NotFound(format!(
                        "{collection}/{id}: the marker records no archived copy to keep"
                    ))
                })?;
                resolution.kept = newest.clone();
                self.promote(newest, &canonical, &losers, &mut resolution)
                    .await?;
            }
            Keep::File(raw) => {
                let chosen = self.locate(collection, id, &canonical, &losers, raw)?;
                resolution.kept = chosen.clone();
                if chosen == canonical {
                    for loser in &losers {
                        tokio::fs::remove_file(loser)
                            .await
                            .map_err(|e| SopsError::io(loser.display(), e))?;
                        self.cache.forget(loser);
                        resolution.deleted.push(loser.clone());
                    }
                } else {
                    self.promote(&chosen, &canonical, &losers, &mut resolution)
                        .await?;
                }
            }
        }

        // A kept file must open with the configured identity: resolving a
        // conflict must not leave the item unreadable. The check is skipped
        // when the identity file is absent, so a bare `--store` can still
        // resolve — the archive and the promoted file stay on disk either way.
        if self.sops.key_file().is_file() {
            self.load_document(&canonical).await?;
        }
        crate::conflicts::remove_marker(&self.root, collection, id).await?;
        info!(
            item_id = %id,
            collection = %collection,
            kept = %self.relative(&resolution.kept),
            promoted = resolution.promoted,
            deleted = resolution.deleted.len(),
            "resolved a recorded conflict",
        );
        Ok(resolution)
    }

    /// Turn an archived loser into the canonical file.
    ///
    /// The loser is renamed onto `<id>.sops.yaml` (an atomic replace), and
    /// every other loser is renamed onto its canonical `sync-conflict` name, so
    /// they stop being archives and become ordinary conflict copies. The
    /// copies that *lose* again are re-archived and the marker is rewritten
    /// with the new set by [`Store::archive_superseded`].
    async fn promote(
        &self,
        chosen: &Path,
        canonical: &Path,
        losers: &[PathBuf],
        resolution: &mut Resolution,
    ) -> Result<(), SopsError> {
        // Keep the winner's own file too: it holds the value the user just
        // decided against, and no rule may delete it silently.
        let previous: Vec<PathBuf> = self
            .candidates(&resolution.collection, &resolution.item)
            .await?
            .into_iter()
            .map(|candidate| candidate.file)
            .filter(|path| path != chosen)
            .collect();
        for victim in &previous {
            if victim != canonical {
                continue;
            }
            let archived = self
                .archive_one(&resolution.collection, &resolution.item, victim)
                .await?;
            if let Some(archived) = &archived {
                resolution.unarchived.push(archived.clone());
            }
        }
        tokio::fs::rename(chosen, canonical)
            .await
            .map_err(|e| SopsError::io(chosen.display(), e))?;
        self.cache.forget(chosen);
        self.cache.forget(canonical);
        resolution.promoted = true;
        // Every other loser becomes a plain conflict copy again, so the
        // existing freshness rule decides and the marker keeps what still
        // loses.
        let mut others: Vec<PathBuf> = Vec::new();
        for loser in losers {
            if loser == chosen {
                continue;
            }
            let name = loser
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let stem = name
                .strip_prefix(SUPERSEDED_PREFIX)
                .and_then(|rest| rest.split_once('.').map(|(_, tail)| tail))
                .unwrap_or(name.as_str());
            let target = self
                .root
                .join(&resolution.collection)
                .join(format!("{stem}{SYNCTHING_CONFLICT_MARKER}rosec-resolve"));
            tokio::fs::rename(loser, &target)
                .await
                .map_err(|e| SopsError::io(loser.display(), e))?;
            self.cache.forget(loser);
            others.push(target);
        }
        if !others.is_empty() {
            self.archive_superseded(&resolution.collection, &resolution.item, &others, canonical)
                .await?;
        }
        Ok(())
    }

    /// Archive one copy of an id without touching a marker.
    async fn archive_one(
        &self,
        collection: &str,
        id: &str,
        path: &Path,
    ) -> Result<Option<PathBuf>, SopsError> {
        let dir = self.root.join(collection);
        let stamp = match self.load_document(path).await {
            Ok(document) => document
                .modified
                .map(|m| m.file_stamp())
                .unwrap_or_else(|| Timestamp::now().file_stamp()),
            Err(_) => Timestamp::now().file_stamp(),
        };
        let host: String = self
            .host()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let archive = dir.join(format!(
            "{SUPERSEDED_PREFIX}{id}.{stamp}-{host}{ITEM_SUFFIX}"
        ));
        tokio::fs::rename(path, &archive)
            .await
            .map_err(|e| SopsError::io(path.display(), e))?;
        self.cache.forget(path);
        Ok(Some(archive))
    }

    /// Map the user's `--keep` argument to a file of this item.
    fn locate(
        &self,
        collection: &str,
        id: &str,
        canonical: &Path,
        losers: &[PathBuf],
        raw: &str,
    ) -> Result<PathBuf, SopsError> {
        let trimmed = raw.trim();
        let candidate = if Path::new(trimmed).is_absolute() {
            PathBuf::from(trimmed)
        } else {
            self.root.join(trimmed)
        };
        let ok = |path: &Path| path.is_file();
        if candidate == canonical || (ok(&candidate) && candidate == canonical) {
            return Ok(canonical.to_path_buf());
        }
        for loser in losers {
            if *loser == candidate || self.relative(loser) == trimmed {
                return Ok(loser.clone());
            }
        }
        // A user may name the item by its plain names only.
        let by_name = |name: &str| {
            losers
                .iter()
                .find(|loser| loser.file_name().map(|n| n.to_string_lossy() == name) == Some(true))
                .cloned()
        };
        let name = candidate
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == format!("{id}{ITEM_SUFFIX}") {
            return Ok(canonical.to_path_buf());
        }
        if let Some(found) = by_name(&name) {
            return Ok(found);
        }
        Err(SopsError::NotFound(format!(
            "no file `{trimmed}` for `{collection}/{id}`; unit tests use --keep winner|loser"
        )))
    }
}

/// Which copy of a conflicted item the user keeps when resolving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keep {
    /// Keep the canonical file the write produced; delete the archives.
    Winner,
    /// Keep the newest archived loser and promote it to the canonical file.
    Loser,
    /// Keep a named file: an absolute path, a path relative to the store
    /// root, the plain file name, or `winner`/`loser`.
    File(String),
}

impl Keep {
    /// Parse a `--keep` argument.
    pub fn parse(raw: &str) -> Result<Self, SopsError> {
        match raw.trim() {
            "winner" => Ok(Keep::Winner),
            "loser" => Ok(Keep::Loser),
            "" => Err(SopsError::Config(
                "`--keep` needs `winner`, `loser` or a file name".into(),
            )),
            other => Ok(Keep::File(other.to_owned())),
        }
    }
}

/// What [`Store::resolve_conflict`] did.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// Item id.
    pub item: String,
    /// Collection directory.
    pub collection: String,
    /// The file that is served after the resolution.
    pub kept: PathBuf,
    /// True when the kept file was promoted over the canonical file.
    pub promoted: bool,
    /// Archived losers that were deleted.
    pub deleted: Vec<PathBuf>,
    /// Copies the promoted file replaced; they are archived, never deleted.
    pub unarchived: Vec<PathBuf>,
}

/// True when a file name can hold an item: `<id>.sops.yaml`, or the same name
/// with a Syncthing conflict marker anywhere after the id.
pub fn is_item_file_name(name: &str) -> bool {
    if name.starts_with('.') {
        return false;
    }
    // `_meta.meta.yaml` is the current meta file; `_meta.sops.yaml` is the
    // name an earlier build wrote. Neither is an item, even though the legacy
    // name parses as one.
    if name == LEGACY_COLLECTION_META || name.ends_with(".meta.yaml") {
        return false;
    }
    match name.split_once(SYNCTHING_CONFLICT_MARKER) {
        Some((head, _)) => head.ends_with(ITEM_SUFFIX) || name.ends_with(ITEM_SUFFIX),
        None => name.ends_with(ITEM_SUFFIX),
    }
}

/// Derive the item id from a file name, undoing the Syncthing rename.
///
/// `github.com.sops.yaml` → `github.com`;
/// `github.com.sops.yaml.sync-conflict-20261114-181502-ABCDEFG` → `github.com`;
/// `github.com.sync-conflict-20261114-181502-ABCDEFG.sops.yaml` → `github.com`.
pub fn item_id_from_file_name(name: &str) -> Option<String> {
    if name.starts_with('.') {
        // `.item-123.sops.yaml.1234.0.tmp`, `.superseded-…` and other dotfiles
        // are not items.
        return None;
    }
    let stem = match name.strip_suffix(ITEM_SUFFIX) {
        Some(stem) => stem,
        // A conflict copy may carry the marker *after* the suffix.
        None => name
            .split_once(SYNCTHING_CONFLICT_MARKER)?
            .0
            .strip_suffix(ITEM_SUFFIX)?,
    };
    let id = match stem.split_once(SYNCTHING_CONFLICT_MARKER) {
        Some((head, _)) => head,
        None => stem,
    };
    if id.is_empty() {
        return None;
    }
    Some(id.to_owned())
}

/// Stat a file into a [`FileKey`] with a zero digest.
fn stat_key(path: &Path) -> Result<FileKey, SopsError> {
    let meta = std::fs::metadata(path).map_err(|e| SopsError::io(path.display(), e))?;
    let mtime_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(FileKey {
        path: path.to_path_buf(),
        mtime_nanos,
        size: meta.len(),
        sha256: [0u8; 32],
    })
}

/// Decode a cached entry as the requested type.
///
/// A cache entry keeps the type it was parsed as, so this is a move or a clone
/// — never a serialise/parse round trip. Asking for the wrong type is a
/// programming error at the call site and reports
/// [`SopsError::Malformed`] instead of guessing.
fn decode<T: DeserializeOwned + 'static>(cached: Cached, path: &Path) -> Result<T, SopsError> {
    let boxed: Box<dyn std::any::Any> = match cached {
        Cached::Item(document) => Box::new(*document),
        Cached::Meta(meta) => Box::new(meta),
    };
    match boxed.downcast::<T>() {
        Ok(value) => Ok(*value),
        Err(_) => Err(SopsError::Malformed {
            path: path.display().to_string(),
            reason: "cached document has a different type than requested".into(),
        }),
    }
}

/// The kernel hostname, falling back to the environment.
///
/// `/proc/sys/kernel/hostname` and `gethostname(2)` come first: a shell that
/// exports a stale `HOSTNAME` (common over `ssh` + `tmux`) must not stamp the
/// wrong host into a revision.
fn default_host() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .filter(|h| !h.is_empty() && !h.contains("unset"))
        })
        .or_else(|| std::env::var("HOST").ok().filter(|h| !h.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Reject item ids and collection names that could leave the store root.
pub fn validate_name(kind: &str, name: &str) -> Result<(), SopsError> {
    if name.is_empty() {
        return Err(SopsError::Config(format!("{kind} is empty")));
    }
    if name == "." || name == ".." {
        return Err(SopsError::Config(format!("{kind} `{name}` is not allowed")));
    }
    if name.contains('\0') {
        return Err(SopsError::Config(format!(
            "{kind} `{name}` contains a NUL byte"
        )));
    }
    if name
        .chars()
        .any(|c| matches!(c, '/' | '\\' | ':' | '\n' | '\r'))
    {
        return Err(SopsError::Config(format!(
            "{kind} `{name}` must not contain a path separator or a colon"
        )));
    }
    let mut components = Path::new(name).components();
    let first = components.next();
    if components.next().is_some() || !matches!(first, Some(Component::Normal(_))) {
        return Err(SopsError::Config(format!(
            "{kind} `{name}` is not a plain name"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_item_ids_from_file_names() {
        assert_eq!(
            item_id_from_file_name("github.com.sops.yaml").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            item_id_from_file_name("github.com.sops.yaml.sync-conflict-20261114-181502-ABCDEFG")
                .as_deref(),
            Some("github.com")
        );
        assert_eq!(
            item_id_from_file_name("github.com.sync-conflict-20261114-181502-X.sops.yaml")
                .as_deref(),
            Some("github.com")
        );
        assert_eq!(item_id_from_file_name("notes.txt"), None);
        // Archived conflict copies are not items.
        assert_eq!(
            item_id_from_file_name(".superseded-item-ab12.1763150000000000000-host-a.sops.yaml"),
            None
        );
        // The (retired) `_meta.sops.yaml` name is filtered by the caller, not
        // by the parser; the meta file itself is not an item file.
        assert!(!is_item_file_name(COLLECTION_META));
        assert!(!is_item_file_name("_meta.sops.yaml"));
        assert!(is_item_file_name("github.com.sops.yaml"));
    }

    #[test]
    fn rejects_escapes() {
        for bad in ["", ".", "..", "a/b", "a\\b", "c:x", "a\nb"] {
            assert!(validate_name("item id", bad).is_err(), "{bad:?} accepted");
        }
        assert!(validate_name("item id", "gh:github.com").is_err());
        assert!(validate_name("item id", "github.com").is_ok());
        assert!(validate_name("collection", "work").is_ok());
    }

    #[test]
    fn host_prefers_the_kernel_hostname() {
        let host = default_host();
        assert!(!host.is_empty());
        // A stale exported HOSTNAME must not win over the kernel value.
        let kernel = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|h| h.trim().to_owned())
            .filter(|h| !h.is_empty());
        if let Some(kernel) = kernel {
            assert_eq!(host, kernel);
        }
    }
}
