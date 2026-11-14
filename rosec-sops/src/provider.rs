//! `Provider` implementation over the sops file tree.
//!
//! The provider is deliberately thin: it owns the lock flag, maps store items
//! to rosec's item model, and implements the write capability. All file and
//! `sops` work lives in [`crate::store`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use rosec_core::{
    ATTR_TOTP, ATTR_TYPE, AttributeDescriptor, Attributes, AuthField, AuthFieldKind, Capability,
    ItemAttributes, ItemMeta, ItemType, ItemUpdate, NewItem, Provider, ProviderCallbacks,
    ProviderError, ProviderStatus, RESERVED_ATTRIBUTES, SecretBytes, SecretValue, UnlockInput,
    attributes_match,
};
use tracing::{debug, info, warn};

use crate::config::SopsConfig;
use crate::document::{DOCUMENT_VERSION, SopsDocument, Timestamp};
use crate::error::SopsError;
use crate::identity::runtime_identity_is_valid;
use crate::store::{COLLECTION_META, Store, StoreCache, StoreItem, validate_name};
use crate::store_mode::{StoreMode, read_mode};

/// Attribute name carrying the collection of an item.
pub const ATTR_COLLECTION: &str = "collection";

/// Attribute name carrying the store-relative collection directory.
///
/// Equals [`ATTR_COLLECTION`] unless the collection `_meta.meta.yaml` renames
/// the label; the directory is what the provider needs for its write paths.
pub const ATTR_COLLECTION_DIR: &str = "rosec:collection-dir";

/// Attribute stamped on items served from a Syncthing conflict copy.
pub const ATTR_CONFLICT: &str = "rosec:sops-conflict";

/// Attribute stamped on an item that has an unresolved conflict marker.
///
/// Set from `<root>/.conflicts/<collection>/<id>.md`, so a client can find
/// every conflicted item with one search — a marker is the provider's record
/// that a write archived a divergent copy and the user has not decided yet.
/// Independent of [`ATTR_CONFLICT`]: the freshest file of a two-file conflict
/// already wins on read, and the marker outlives that moment until a write.
pub const ATTR_UNRESOLVED_CONFLICT: &str = "rosec:sops-unresolved-conflict";

/// Attribute names this provider manages itself.
///
/// Like [`RESERVED_ATTRIBUTES`], these are never taken from client input: they
/// are stamped by the provider (and the service layer) and would otherwise let
/// a client forge a collection or a conflict flag. They are stripped from a
/// create or an update instead of being rejected, because the Secret Service
/// layer echoes the full attribute map back on a read-modify-write — rejecting
/// would break every such round trip.
pub const INTERNAL_ATTRIBUTES: &[&str] = &[
    ATTR_COLLECTION,
    ATTR_COLLECTION_DIR,
    ATTR_CONFLICT,
    ATTR_UNRESOLVED_CONFLICT,
];

/// Collection directory used by a store that does not have one yet.
pub const DEFAULT_COLLECTION: &str = "default";

/// Length in bytes of the random part of a generated item id.
const ID_RANDOM_BYTES: usize = 16;

/// One sops-backed provider instance.
///
/// Multiple collections of the same store root are served by one instance.
/// The item id is unique across the store: plain `<id>` for items in the
/// largest collection and `<collection>/<id>` otherwise (see
/// [`SopsProvider::qualified_id`]).
pub struct SopsProvider {
    id: String,
    config: SopsConfig,
    store: Store,
    cache: Arc<StoreCache>,
    unlocked: AtomicBool,
    callbacks: RwLock<ProviderCallbacks>,
    /// Collection directory that owns the plain ids, decided at unlock.
    default_collection: RwLock<Option<String>>,
}

impl SopsProvider {
    /// Build a provider from validated options.
    pub fn new(id: impl Into<String>, config: SopsConfig) -> Self {
        let cache = Arc::new(StoreCache::default());
        let store = Store::with_cache(&config, Arc::clone(&cache));
        Self {
            id: id.into(),
            config,
            store,
            cache,
            unlocked: AtomicBool::new(false),
            callbacks: RwLock::new(ProviderCallbacks::default()),
            default_collection: RwLock::new(None),
        }
    }

    /// Build a provider straight from the provider entry's raw fields.
    pub fn from_entry(
        id: impl Into<String>,
        provider_path: Option<&str>,
        options: &HashMap<String, serde_json::Value>,
    ) -> Result<Self, ProviderError> {
        let config = SopsConfig::from_options(provider_path, options)?;
        Ok(Self::new(id, config))
    }

    /// The validated configuration.
    pub fn config(&self) -> &SopsConfig {
        &self.config
    }

    /// The store handle (tests and tooling use it directly).
    pub fn store(&self) -> &Store {
        &self.store
    }

    fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::Acquire)
    }

    fn ensure_unlocked(&self) -> Result<(), ProviderError> {
        if self.is_unlocked() {
            Ok(())
        } else {
            Err(ProviderError::Locked)
        }
    }

    fn default_collection(&self) -> Option<String> {
        self.default_collection
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Queue time taken from the store item.
    fn times(item: &StoreItem) -> (Option<SystemTime>, Option<SystemTime>) {
        (
            item.document.created.map(|t| t.0),
            item.document.modified.map(|t| t.0),
        )
    }

    /// Item id as exposed over D-Bus.
    ///
    /// Items in the default collection keep their bare id so that ordinary
    /// single-collection stores look exactly like before. Items in other
    /// collections use `<collection>/<id>`.
    pub fn qualified_id(&self, collection: &str, id: &str) -> String {
        match self.default_collection() {
            Some(ref default) if default == collection => id.to_owned(),
            _ => format!("{collection}/{id}"),
        }
    }

    /// Split an item id back into `(collection, id)`.
    async fn resolve_id(&self, id: &str) -> Result<(String, String), ProviderError> {
        let default = self.default_collection();
        if let Some(default) = default {
            if self.store.item_path(&default, id).is_file() {
                return Ok((default, id.to_owned()));
            }
            if let Ok(item) = self.store.resolve_item(&default, id).await {
                return Ok((item.collection, item.id));
            }
        }
        // Qualified form `<collection>/<id>`.
        if let Some((collection, rest)) = id.split_once('/') {
            let collection = collection.to_owned();
            let rest = rest.to_owned();
            validate_name("collection", &collection).map_err(SopsError::into_provider_error)?;
            validate_name("item id", &rest).map_err(SopsError::into_provider_error)?;
            return Ok((collection, rest));
        }
        // A store with no collections yet, or an id that only exists in a
        // non-default collection.
        Err(ProviderError::NotFound)
    }

    /// Strip provider-managed and reserved attribute names from client input.
    ///
    /// Returns the accepted map and whether anything was dropped, so the caller
    /// can log the drop at debug level. See [`INTERNAL_ATTRIBUTES`].
    fn strip_internal(
        attrs: impl IntoIterator<Item = (String, String)>,
    ) -> (HashMap<String, String>, Vec<String>) {
        let mut kept = HashMap::new();
        let mut dropped = Vec::new();
        for (key, value) in attrs {
            if INTERNAL_ATTRIBUTES.contains(&key.as_str())
                || RESERVED_ATTRIBUTES.contains(&key.as_str())
            {
                dropped.push(key);
                continue;
            }
            kept.insert(key, value);
        }
        (kept, dropped)
    }

    /// Build the daemon-facing metadata for a store item.
    fn to_meta(&self, item: &StoreItem, collection_label: &str, unresolved: bool) -> ItemMeta {
        let mut attributes = item
            .document
            .attributes
            .iter()
            .filter(|(key, _)| !INTERNAL_ATTRIBUTES.contains(&key.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Attributes>();
        attributes.insert(ATTR_COLLECTION.into(), collection_label.to_owned());
        attributes.insert(ATTR_COLLECTION_DIR.into(), item.collection.clone());
        if item.document.has_secret("totp") {
            attributes.insert(ATTR_TOTP.into(), "true".into());
        }
        if item.is_from_conflict_copy() {
            attributes.insert(ATTR_CONFLICT.into(), "true".into());
        }
        if unresolved {
            attributes.insert(ATTR_UNRESOLVED_CONFLICT.into(), "true".into());
        }
        let (created, modified) = Self::times(item);
        ItemMeta {
            id: self.qualified_id(&item.collection, &item.id),
            provider_id: self.id.clone(),
            label: item.document.label.clone(),
            attributes,
            created,
            modified,
            locked: false,
            attribute_hashes: None,
        }
    }

    /// Turn a [`NewItem`] into a store document.
    fn document_from_new(
        &self,
        item: &NewItem,
        attributes: HashMap<String, String>,
    ) -> SopsDocument {
        let now = Timestamp::now();
        let mut attributes = attributes;
        if let Some(ref item_type) = item.item_type {
            attributes.insert(ATTR_TYPE.into(), item_type.to_string());
        }
        let mut document = SopsDocument {
            label: item.label.clone(),
            attributes: attributes.into_iter().collect(),
            secrets: Default::default(),
            binary_secrets: Default::default(),
            created: Some(now),
            modified: Some(now),
            host: Some(self.store.host()),
            revision: 1,
            version: DOCUMENT_VERSION,
        };
        for (name, value) in &item.secrets {
            document.set_secret(name, value.as_slice());
        }
        document
    }

    /// Write `document` to `collection`/`id` and retire any copy that lost.
    ///
    /// The merged document goes to the **canonical** file. Every conflict copy
    /// that `resolve_item` reported as superseded is archived under a name that
    /// no longer resolves, and the archive path is logged at `warn` — a write is
    /// exactly when a user must learn that two copies had diverged.
    async fn save(&self, item: &StoreItem, document: &SopsDocument) -> Result<(), ProviderError> {
        self.store
            .ensure_collection(&item.collection)
            .await
            .map_err(SopsError::into_provider_error)?;
        self.store
            .write_document(&item.collection, &item.id, document)
            .await
            .map_err(SopsError::into_provider_error)?;
        let written = self.store.item_path(&item.collection, &item.id);
        // Archive every other copy of this id. The served copy comes first:
        // when the merge was built from a conflict copy, that copy holds the
        // value this write replaced, and the canonical now holds the merge.
        let mut stale: Vec<std::path::PathBuf> = Vec::new();
        if item.is_from_conflict_copy() && item.file != written {
            stale.push(item.file.clone());
        }
        for path in &item.superseded {
            if *path != written && !stale.contains(path) {
                stale.push(path.clone());
            }
        }
        if stale.is_empty() {
            return Ok(());
        }
        match self
            .store
            .archive_superseded(&item.collection, &item.id, &stale, &written)
            .await
        {
            Ok(archives) => {
                if archives.is_empty() {
                    return Ok(());
                }
                warn!(
                    provider_id = %self.id,
                    item_id = %item.id,
                    served_from = %item.file.display(),
                    written = %written.display(),
                    archived = ?archives,
                    marker = %self
                        .store
                        .relative(&crate::conflicts::marker_path(
                            self.store.root(),
                            &item.collection,
                            &item.id
                        )),
                    "a write superseded a divergent conflict copy; the copy is archived, not \
                     deleted, and a conflict marker asks the user to resolve it",
                );
            }
            Err(e) => {
                // The write succeeded; a copy that cannot be archived does not
                // undo it, but it must be visible.
                warn!(
                    provider_id = %self.id,
                    item_id = %item.id,
                    error = %e,
                    "could not archive a superseded conflict copy",
                );
            }
        }
        Ok(())
    }

    /// Pick the collection for a new item.
    fn write_collection(&self) -> String {
        match self.default_collection() {
            Some(collection) => collection,
            None => DEFAULT_COLLECTION.to_owned(),
        }
    }

    /// True when the existing item has this label (decrypts only that item).
    async fn label_matches(
        &self,
        collection: &str,
        candidate: &str,
        label: &str,
    ) -> Result<bool, ProviderError> {
        match self.store.resolve_item(collection, candidate).await {
            Ok(item) => Ok(item.document.label == label),
            Err(_) => Ok(false),
        }
    }

    /// True when the existing item holds every given attribute value.
    async fn attributes_match(
        &self,
        collection: &str,
        candidate: &str,
        attributes: &std::collections::BTreeMap<String, String>,
    ) -> Result<bool, ProviderError> {
        match self.store.resolve_item(collection, candidate).await {
            Ok(item) => Ok(attributes
                .iter()
                .all(|(k, v)| item.document.attributes.get(k) == Some(v))),
            Err(_) => Ok(false),
        }
    }

    /// `(collection, item)` pairs that have an unresolved conflict marker.
    ///
    /// The markers are plaintext, so this costs no decryption. A store whose
    /// `.conflicts` directory cannot be read is treated as conflict-free and
    /// logged: a listing must not fail because a marker is unreadable.
    fn conflicted(&self) -> std::collections::BTreeSet<(String, String)> {
        match crate::conflicts::conflicted_ids_blocking(self.store.root()) {
            Ok(set) => set,
            Err(e) => {
                warn!(
                    provider_id = %self.id,
                    error = %e,
                    "cannot read the conflict markers; listing without conflict flags",
                );
                Default::default()
            }
        }
    }

    /// A decryptable store file to use as the unlock probe, if any.
    ///
    /// Prefers a collection meta file (tiny, proves the identity), then the
    /// smallest item file by ciphertext size (also tiny, and it exercises the
    /// same code path as a real read).
    async fn probe_candidate(&self) -> Result<Option<std::path::PathBuf>, SopsError> {
        let mut best: Option<(u64, std::path::PathBuf)> = None;
        for collection in self.store.collections().await? {
            let meta = self.store.root().join(&collection).join(COLLECTION_META);
            if meta.is_file() {
                return Ok(Some(meta));
            }
            for id in self.store.item_ids(&collection).await? {
                let path = self.store.item_path(&collection, &id);
                let Ok(metadata) = tokio::fs::metadata(&path).await else {
                    continue;
                };
                let size = metadata.len();
                if best.as_ref().map(|(best_size, _)| size < *best_size) != Some(false) {
                    best = Some((size, path));
                }
            }
        }
        Ok(best.map(|(_, path)| path))
    }
}

#[async_trait]
impl Provider for SopsProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        "sops store"
    }

    fn kind(&self) -> &str {
        "sops"
    }

    fn capabilities(&self) -> &'static [Capability] {
        &[Capability::Write]
    }

    fn supported_item_types(&self) -> &'static [ItemType] {
        &[
            ItemType::Generic,
            ItemType::Login,
            ItemType::SshKey,
            ItemType::Note,
            ItemType::Card,
            ItemType::Identity,
        ]
    }

    fn available_attributes(&self) -> &'static [AttributeDescriptor] {
        const ATTRS: &[AttributeDescriptor] = &[
            AttributeDescriptor {
                name: ATTR_COLLECTION,
                sensitive: false,
                item_types: &[],
                description: "Collection label of the item (provider-managed)",
            },
            AttributeDescriptor {
                name: ATTR_COLLECTION_DIR,
                sensitive: false,
                item_types: &[],
                description: "Collection directory that holds the item's file (provider-managed)",
            },
            AttributeDescriptor {
                name: ATTR_CONFLICT,
                sensitive: false,
                item_types: &[],
                description: "Present when the served copy is a Syncthing conflict copy (provider-managed)",
            },
        ];
        ATTRS
    }

    fn needs_new_password_confirmation(&self) -> bool {
        false
    }

    /// The unlock "password" is optional and ignored.
    ///
    /// The daemon's unlock flow always collects the password field first, so
    /// this field exists only to satisfy that flow. Marking it optional lets
    /// `rosec unlock` proceed on an empty answer — the age identity (on this
    /// host the YubiKey) is the real credential, and there is no password to
    /// ask for.
    fn password_field(&self) -> AuthField {
        AuthField {
            id: "password",
            label: "No password needed",
            placeholder: "Press Enter — the age identity unlocks this store",
            required: false,
            kind: AuthFieldKind::Password,
        }
    }

    fn set_event_callbacks(&self, callbacks: ProviderCallbacks) -> Result<(), ProviderError> {
        *self.callbacks.write().unwrap_or_else(|e| e.into_inner()) = callbacks;
        Ok(())
    }

    async fn status(&self) -> Result<ProviderStatus, ProviderError> {
        Ok(ProviderStatus {
            locked: !self.is_unlocked(),
            last_sync: None,
            cached: false,
            offline_cache: false,
            last_cache_write: None,
        })
    }

    /// Check the mode and the environment, then **prove** the store is readable.
    ///
    /// Steps, in this order:
    ///
    /// 0. the store metadata must name a mode, and the mode must match the
    ///    configuration (`derived` ⇔ `identity_file`);
    /// 1. the `sops` binary must run and the age identity file must exist —
    ///    unless this session already holds the runtime identity, so an
    ///    unlocked session keeps working with the YubiKey unplugged;
    /// 2. the store root is created when missing;
    /// 3. for a `derived` store the master file is unwrapped **once** into the
    ///    runtime file, and every later item operation uses that file;
    /// 4. one store file is decrypted under a bounded timeout — a collection
    ///    meta file when present, else the smallest item file.
    ///
    /// Step 4 is what makes "the YubiKey is the unlock" a verified claim: a
    /// token in the wrong slot, a revoked recipient, or a `keys.txt` holding
    /// another identity fails here with [`ProviderError::AuthFailed`] instead of
    /// unlocking and failing on every read with a generic fault. A store with no
    /// files has nothing to prove, so it unlocks after step 2.
    async fn unlock(&self, _input: UnlockInput) -> Result<(), ProviderError> {
        if self.is_unlocked() {
            debug!(provider_id = %self.id, "already unlocked");
            return Ok(());
        }

        let mode = read_mode(&self.config.path).map_err(SopsError::into_provider_error)?;
        if let Err(e) = self.config.check_mode(mode) {
            warn!(provider_id = %self.id, error = %e, "sops provider refuses to unlock");
            return Err(e);
        }

        // The runtime identity makes the token optional: an unlocked session
        // must survive the YubiKey being unplugged.
        let runtime = self.config.runtime_identity_file.clone();
        let runtime_ready = mode == StoreMode::Derived && runtime_identity_is_valid(&runtime);
        let probe_key_file = if runtime_ready {
            None
        } else {
            Some(self.config.key_file.as_path())
        };
        let version = self.store.sops().probe(probe_key_file).await.map_err(|e| {
            warn!(provider_id = %self.id, error = %e, "sops provider cannot unlock");
            e.into_provider_error()
        })?;
        debug!(
            sops = %version,
            key_file = %self.config.key_file.display(),
            mode = %mode,
            "sops available",
        );

        self.store
            .ensure_root()
            .await
            .map_err(SopsError::into_provider_error)?;

        // Unlock once: the derived identity lands in the runtime file, and
        // every item operation then costs no token operation.
        let mut unwrapped = false;
        if mode == StoreMode::Derived {
            unwrapped = match crate::identity::ensure_runtime_identity(&self.config).await {
                Ok(unwrapped) => unwrapped,
                Err(e) => {
                    warn!(provider_id = %self.id, error = %e, "cannot unwrap the store identity");
                    return Err(e.into_provider_error());
                }
            };
            self.store.sops().set_key_file(runtime.clone());
            debug!(runtime = %runtime.display(), unwrapped, "derived identity in use");
        }

        let mut counts: Vec<(String, usize)> = Vec::new();
        for collection in self
            .store
            .collections()
            .await
            .map_err(SopsError::into_provider_error)?
        {
            let count = self
                .store
                .item_ids(&collection)
                .await
                .map_err(SopsError::into_provider_error)?
                .len();
            counts.push((collection, count));
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        // An empty store gets a `default` collection up front, so the first
        // item created on this host has a bare id and a second host that
        // syncs the same item cannot elect a different collection.
        let default = match counts.first() {
            Some((name, _)) => Some(name.clone()),
            None => Some(DEFAULT_COLLECTION.to_owned()),
        };

        // Readability probe. Bounded, and reported as `AuthFailed` because the
        // store is present but this identity cannot open it.
        if let Some(path) = self
            .probe_candidate()
            .await
            .map_err(SopsError::into_provider_error)?
        {
            let timeout = self.config.probe_timeout;
            match self.store.sops().probe_decrypt(&path).await {
                Ok(bytes) => debug!(
                    path = %path.display(),
                    plaintext_bytes = bytes,
                    timeout = ?timeout,
                    "unlock probe decrypted a store file",
                ),
                Err(e) => {
                    let provider_error = SopsError::Unreadable {
                        path: path.display().to_string(),
                        reason: e.to_string(),
                    }
                    .into_provider_error();
                    warn!(
                        provider_id = %self.id,
                        path = %path.display(),
                        error = %e,
                        timeout = ?timeout,
                        "unlock probe failed: the identity cannot read this store",
                    );
                    // A runtime file that was just written must not survive a
                    // failed probe: the next unlock must unwrap again.
                    if mode == StoreMode::Derived && unwrapped {
                        crate::identity::remove_runtime_identity(&runtime);
                        self.store.sops().set_key_file(self.config.key_file.clone());
                    }
                    return Err(provider_error);
                }
            }
        }

        *self
            .default_collection
            .write()
            .unwrap_or_else(|e| e.into_inner()) = default.clone();
        self.unlocked.store(true, Ordering::Release);
        let callbacks = self
            .callbacks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(cb) = callbacks.on_unlocked {
            cb();
        }
        info!(
            provider_id = %self.id,
            root = %self.config.path.display(),
            mode = %mode,
            default_collection = ?default,
            "sops provider unlocked",
        );
        Ok(())
    }

    /// Drop all decrypted documents.
    async fn lock(&self) -> Result<(), ProviderError> {
        if !self.unlocked.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        self.cache.clear();
        *self
            .default_collection
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;

        // A locked session must not keep the unwrapped identity: the runtime
        // file is the secret, and the effective identity goes back to the
        // configured `key_file` so a later read cannot slip through.
        if self.config.identity_file.is_some() {
            crate::identity::remove_runtime_identity(&self.config.runtime_identity_file);
            self.store.sops().set_key_file(self.config.key_file.clone());
        }

        let callbacks = self
            .callbacks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(cb) = callbacks.on_locked {
            cb();
        }
        info!(provider_id = %self.id, "sops provider locked");
        Ok(())
    }

    /// List every item.
    ///
    /// While locked this returns [`ProviderError::Locked`], the state the
    /// daemon handles explicitly (`RefreshOutcome::Locked`): it keeps its
    /// previous view. Returning an empty list would be reported as a *complete*
    /// refresh of zero items and would wipe every sops item from the cache.
    ///
    /// A file whose secrets cannot be decrypted is skipped with a warning; one
    /// unreadable file never breaks the whole listing.
    async fn list_items(&self) -> Result<Vec<ItemMeta>, ProviderError> {
        self.ensure_unlocked()?;
        let items = self
            .store
            .list_items()
            .await
            .map_err(SopsError::into_provider_error)?;
        let conflicted = self.conflicted();

        let mut labels: HashMap<String, String> = HashMap::new();
        let mut out = Vec::with_capacity(items.len());
        for item in &items {
            let label = match labels.get(&item.collection) {
                Some(label) => label.clone(),
                None => {
                    let label = self.store.collection_label(&item.collection).await;
                    labels.insert(item.collection.clone(), label.clone());
                    label
                }
            };
            let unresolved = conflicted.contains(&(item.collection.clone(), item.id.clone()));
            out.push(self.to_meta(item, &label, unresolved));
        }
        Ok(out)
    }

    /// Search by attribute subset.
    ///
    /// Provider-managed attributes are stripped from the query, so a client
    /// that echoes an item's full attribute map back does not filter on a
    /// value the provider just stamped for one specific collection
    /// (`rosec:collection-dir`). Like [`Provider::list_items`], this returns
    /// [`ProviderError::Locked`] while locked.
    async fn search(&self, attrs: &Attributes) -> Result<Vec<ItemMeta>, ProviderError> {
        self.ensure_unlocked()?;
        let (query, dropped) = Self::strip_internal(attrs.clone());
        if !dropped.is_empty() {
            debug!(
                provider_id = %self.id,
                dropped = ?dropped,
                "ignoring provider-managed attributes in a search query",
            );
        }
        let items = self.list_items().await?;
        Ok(items
            .into_iter()
            .filter(|meta| attributes_match(&meta.attributes, &query))
            .collect())
    }

    async fn get_item_attributes(&self, id: &str) -> Result<ItemAttributes, ProviderError> {
        self.ensure_unlocked()?;
        let (collection, local_id) = self.resolve_id(id).await?;
        let item = self
            .store
            .resolve_item(&collection, &local_id)
            .await
            .map_err(SopsError::into_provider_error)?;
        let label = self.store.collection_label(&collection).await;
        let unresolved =
            crate::conflicts::marker_path(self.store.root(), &collection, &local_id).is_file();
        let meta = self.to_meta(&item, &label, unresolved);
        Ok(ItemAttributes {
            public: meta.attributes,
            secret_names: item.document.secret_names().cloned().collect(),
        })
    }

    async fn get_secret_attr(&self, id: &str, attr: &str) -> Result<SecretBytes, ProviderError> {
        self.get_secret_value(id, attr)
            .await
            .map(|value| value.bytes)
    }

    async fn get_secret_value(&self, id: &str, attr: &str) -> Result<SecretValue, ProviderError> {
        self.ensure_unlocked()?;
        let (collection, local_id) = self.resolve_id(id).await?;
        let item = self
            .store
            .resolve_item(&collection, &local_id)
            .await
            .map_err(SopsError::into_provider_error)?;
        let bytes = Store::decode_secret(&item.document, attr, &item.file)
            .map_err(SopsError::into_provider_error)?;
        Ok(SecretValue::text(SecretBytes::new(bytes)))
    }

    /// Create an item, or update the item that already holds the same secrets.
    ///
    /// The id is **random** (`item-<64 hex chars>`), never derived from the
    /// secret. A derived id would be an offline verifier — the store is
    /// plaintext-synced, so any observer could confirm a guess of a
    /// low-entropy secret by hashing it — and it would change on every write.
    ///
    /// Matching an existing item therefore follows identity, not content: an
    /// item with client attributes matches by attribute subset, an item
    /// without attributes matches by label. A match is an update when
    /// `replace` is set and [`ProviderError::AlreadyExists`] otherwise, which is
    /// what makes two hosts that write the same `key=value` converge on one
    /// file. Only candidates whose identity matches are decrypted, so a create
    /// does not cost one YubiKey operation per item in the store.
    async fn create_item(&self, item: NewItem, replace: bool) -> Result<String, ProviderError> {
        self.ensure_unlocked()?;
        item.validate()?;
        let (attributes, dropped) = Self::strip_internal(item.attributes.clone());
        if !dropped.is_empty() {
            debug!(
                provider_id = %self.id,
                dropped = ?dropped,
                "dropping provider-managed attributes from item input",
            );
        }

        let document = self.document_from_new(&item, attributes);
        // A binary-only item has an empty text map, so both maps count.
        if document.secret_names().next().is_none() {
            return Err(ProviderError::InvalidInput(
                "at least one secret required".into(),
            ));
        }

        let collection = self.write_collection();
        for candidate in self
            .store
            .item_ids(&collection)
            .await
            .map_err(SopsError::into_provider_error)?
        {
            // Identity first: a cheap filename/attribute guess filters the list
            // before anything is decrypted.
            let matches = if document.attributes.is_empty() {
                self.label_matches(&collection, &candidate, &document.label)
                    .await?
            } else {
                self.attributes_match(&collection, &candidate, &document.attributes)
                    .await?
            };
            if !matches {
                continue;
            }
            let Ok(existing) = self.store.resolve_item(&collection, &candidate).await else {
                continue;
            };
            if !existing.document.secrets_equal(&document) {
                continue;
            }
            if !replace {
                return Err(ProviderError::AlreadyExists);
            }
            let mut merged = existing.document.clone();
            merged.label = document.label.clone();
            merged.attributes = document.attributes.clone();
            merged.revision = merged.revision.saturating_add(1);
            merged.modified = Some(Timestamp::now());
            merged.host = Some(self.store.host());
            self.save(&existing, &merged).await?;
            return Ok(self.qualified_id(&existing.collection, &existing.id));
        }

        let id = new_id();
        let fresh = StoreItem {
            collection: collection.clone(),
            id: id.clone(),
            file: self.store.item_path(&collection, &id),
            document: document.clone(),
            superseded: Vec::new(),
        };
        self.save(&fresh, &document).await?;
        info!(provider_id = %self.id, item_id = %id, "created sops item");
        Ok(self.qualified_id(&collection, &id))
    }

    async fn update_item(&self, id: &str, update: ItemUpdate) -> Result<(), ProviderError> {
        self.ensure_unlocked()?;
        let (attributes, dropped) = match update.attributes {
            Some(attrs) => {
                let (kept, dropped) = Self::strip_internal(attrs);
                (Some(kept), dropped)
            }
            None => (None, Vec::new()),
        };
        if !dropped.is_empty() {
            debug!(
                provider_id = %self.id,
                dropped = ?dropped,
                "dropping provider-managed attributes from an update",
            );
        }

        let (collection, local_id) = self.resolve_id(id).await?;
        let existing = self
            .store
            .resolve_item(&collection, &local_id)
            .await
            .map_err(SopsError::into_provider_error)?;

        let mut document = existing.document.clone();
        if let Some(label) = update.label {
            document.label = label;
        }
        if let Some(attrs) = attributes {
            // Keep the provider-stamped type across an attribute replacement.
            let stored_type = existing.document.attributes.get(ATTR_TYPE).cloned();
            document.attributes = attrs.into_iter().collect();
            if let Some(stored_type) = stored_type {
                document.attributes.insert(ATTR_TYPE.into(), stored_type);
            }
        }
        if let Some(item_type) = update.item_type {
            document
                .attributes
                .insert(ATTR_TYPE.into(), item_type.to_string());
        }
        if let Some(secrets) = update.secrets {
            for (key, value) in secrets {
                document.set_secret(&key, value.as_slice());
            }
        }
        document.revision = document.revision.saturating_add(1);
        document.modified = Some(Timestamp::now());
        document.host = Some(self.store.host());

        // The canonical file receives the merged document; `existing` may have
        // been a conflict copy, and the copy that loses is archived (never
        // deleted) by `save`, which also warns with the archive path.
        self.save(&existing, &document).await?;
        debug!(
            provider_id = %self.id,
            item_id = %local_id,
            revision = document.revision,
            "updated sops item",
        );
        Ok(())
    }

    async fn delete_item(&self, id: &str) -> Result<(), ProviderError> {
        self.ensure_unlocked()?;
        let (collection, local_id) = self.resolve_id(id).await?;
        let deleted = self
            .store
            .delete_item(&collection, &local_id)
            .await
            .map_err(SopsError::into_provider_error)?;
        if deleted {
            info!(provider_id = %self.id, item_id = %local_id, "deleted sops item");
            Ok(())
        } else {
            Err(ProviderError::NotFound)
        }
    }
}

/// An opaque item id: `item-` plus 16 random bytes in hex.
///
/// Random ids carry no information about the secret and never change when the
/// secret does, so the id is neither an offline verifier nor a moving target
/// for a client that keeps it. Collisions are not a practical concern (128
/// bits); a clash would be an `AlreadyExists` on the next write.
///
/// The trade-off is metadata: the id no longer says what the item contains, so
/// the label and the public attribute map are the only human-readable hints in
/// a synced tree.
pub fn new_id() -> String {
    let mut bytes = [0u8; ID_RANDOM_BYTES];
    // `age` pulls `getrandom` in for the workspace, so the dependency is
    // already present.
    getrandom::fill(&mut bytes).expect("the OS random source is available");
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("item-{hex}")
}

impl std::fmt::Debug for SopsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SopsProvider")
            .field("id", &self.id)
            .field("root", &self.config.path)
            .field("unlocked", &self.is_unlocked())
            .finish()
    }
}
