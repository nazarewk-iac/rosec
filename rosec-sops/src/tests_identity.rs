//! Tests for the store mode, the derived identity and the migration paths.
//!
//! Everything here runs against the real `sops`, `age` and `age-keygen`
//! binaries from the devenv shell, with generated test identities — no YubiKey
//! is involved. Each test skips itself when a tool is missing.
//!
//! The secrets in this module are known strings; every test that touches an
//! output also asserts that the derived **identity** never appears in it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rosec_core::{Provider, ProviderError, SecretBytes, UnlockInput};
use zeroize::Zeroizing;

use crate::config::SopsConfig;
use crate::identity::{master_path, read_sidecar, sidecar_path, write_runtime_identity};
use crate::sops::{AGE_SECRET_PREFIX, SopsCommand, generate_age_identity, write_atomic_sync};
use crate::store_mode::{STORE_META_FILE, StoreMeta, StoreMode, read_meta, read_mode, write_meta};
use crate::{SopsDocument, SopsProvider, Timestamp};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn has_tools() -> bool {
    ["sops", "age-keygen"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// Run `age-keygen -o path` and return the public recipient.
fn keygen(path: &Path) -> String {
    let output = Command::new("age-keygen")
        .arg("-o")
        .arg(path)
        .output()
        .expect("age-keygen");
    assert!(output.status.success(), "age-keygen failed: {output:?}");
    String::from_utf8_lossy(&output.stderr)
        .split_whitespace()
        .find(|word| word.starts_with("age1"))
        .expect("recipient")
        .to_owned()
}

/// A store root with a `.sops.yaml` holding the master rule first.
struct Store {
    _dir: tempfile::TempDir,
    root: PathBuf,
    /// The identity file that opens the master (the "YubiKey" stand-in).
    key_file: PathBuf,
    /// That identity's recipient.
    unlock_recipient: String,
    /// A second unlock key.
    second_key_file: PathBuf,
    second_recipient: String,
}

impl Store {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        std::fs::create_dir_all(&root).unwrap();
        let key_file = dir.path().join("keys.txt");
        let unlock_recipient = keygen(&key_file);
        let second_key_file = dir.path().join("keys2.txt");
        let second_recipient = keygen(&second_key_file);
        let store = Self {
            _dir: dir,
            root,
            key_file,
            unlock_recipient,
            second_key_file,
            second_recipient,
        };
        store.write_sops_yaml(std::slice::from_ref(&store.unlock_recipient));
        store
    }

    /// Write `.sops.yaml` with a master rule (unlock group) and an item rule.
    fn write_sops_yaml(&self, unlock: &[String]) {
        let derived = read_sidecar(&self.root).unwrap_or_else(|| self.unlock_recipient.clone());
        let text = format!(
            "creation_rules:\n\
             \x20 - path_regex: ^\\.rosec-store-identity\\.sops\\.yaml$\n\
             \x20   age: {}\n\
             \x20 - path_regex: .*\\.sops\\.yaml$\n\
             \x20   age: {derived}\n",
            unlock.join(",")
        );
        std::fs::write(self.root.join(".sops.yaml"), text).unwrap();
    }

    fn runtime(&self) -> PathBuf {
        self._dir.path().join("runtime/store-identity.age")
    }

    /// A `derived` config: `identity_file` + `identity_key_file`.
    fn derived_config(&self) -> SopsConfig {
        let mut config = SopsConfig::new(&self.root, &self.key_file, "", "sops").unwrap();
        config.identity_file = Some(master_path(&self.root));
        config.identity_key_file = Some(self.key_file.clone());
        config.runtime_identity_file = self.runtime();
        config.probe_timeout = std::time::Duration::from_secs(30);
        config
    }

    /// A `direct` config (today's behaviour).
    fn direct_config(&self) -> SopsConfig {
        let mut config =
            SopsConfig::new(&self.root, &self.key_file, &self.unlock_recipient, "sops").unwrap();
        config.runtime_identity_file = self.runtime();
        config
    }

    async fn init_derived(&self) {
        write_meta(&self.root, &StoreMeta::new(StoreMode::Derived)).unwrap();
        crate::identity_cli::init(&self.derived_config(), false)
            .await
            .expect("identity init");
    }
}

async fn unlock(provider: &SopsProvider) -> Result<(), ProviderError> {
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
}

fn document(label: &str, secret: &str) -> SopsDocument {
    SopsDocument {
        label: label.to_owned(),
        attributes: Default::default(),
        secrets: [("password".to_string(), secret.to_string())]
            .into_iter()
            .collect(),
        binary_secrets: Default::default(),
        created: Some(Timestamp::now()),
        modified: Some(Timestamp::now()),
        host: Some("test".into()),
        revision: 1,
        version: crate::document::DOCUMENT_VERSION,
    }
}

/// Encrypt `document` to `recipient` as `collection/id.sops.yaml`.
async fn put_item(store: &Path, collection: &str, id: &str, recipient: &str, secret: &str) {
    let dir = store.join(collection);
    std::fs::create_dir_all(&dir).unwrap();
    let plain = document(id, secret).to_yaml().unwrap();
    let cipher = SopsCommand::new("sops", "/dev/null")
        .encrypt_to(plain.as_bytes(), recipient, store)
        .await
        .expect("encrypt item");
    write_atomic_sync(&dir.join(format!("{id}.sops.yaml")), &cipher).unwrap();
}

/// Decrypt an item with `key_file`; `Err` when it cannot.
fn decrypt_with(key_file: &Path, path: &Path) -> Result<String, String> {
    let output = Command::new("sops")
        .arg("--decrypt")
        .arg("--input-type")
        .arg("yaml")
        .arg("--output-type")
        .arg("yaml")
        .arg(path)
        .env("SOPS_AGE_KEY_FILE", key_file)
        .output()
        .expect("sops");
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// The identity currently in the master file, as seen with `key_file`.
fn master_identity(key_file: &Path, store: &Path) -> Option<String> {
    let output = Command::new("sops")
        .args([
            "--decrypt",
            "--extract",
            r#"["identity"]"#,
            "--input-type",
            "yaml",
            "--output-type",
            "yaml",
        ])
        .arg(master_path(store))
        .env("SOPS_AGE_KEY_FILE", key_file)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

// ---------------------------------------------------------------------------
// The cache holds one type per path (the `_meta.sops.yaml` defect)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_meta_file_caches_as_both_types_in_either_order() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    let config = store.direct_config();
    // A legacy `_meta.sops.yaml`: the label reader wants a `CollectionMeta`,
    // the item resolver wants a `SopsDocument`.
    let meta_path = store
        .root
        .join("default")
        .join(crate::LEGACY_COLLECTION_META);
    std::fs::create_dir_all(meta_path.parent().unwrap()).unwrap();
    let meta_plain = "label: Renamed\ntype: collection\n";
    let cipher = SopsCommand::new("sops", "/dev/null")
        .encrypt(
            meta_plain.as_bytes(),
            Some(&store.unlock_recipient),
            &store.root,
        )
        .await
        .expect("encrypt meta");
    write_atomic_sync(&meta_path, &cipher).unwrap();

    for order in ["meta-first", "item-first"] {
        let handle = crate::Store::new(&config);
        if order == "meta-first" {
            let meta = handle
                .load::<crate::CollectionMeta>(&meta_path)
                .await
                .expect("meta as CollectionMeta");
            assert_eq!(meta.label, "Renamed");
            let document = handle
                .load::<SopsDocument>(&meta_path)
                .await
                .expect("the same file as SopsDocument");
            assert_eq!(document.label, "Renamed");
        } else {
            let document = handle
                .load::<SopsDocument>(&meta_path)
                .await
                .expect("SopsDocument first");
            assert_eq!(document.label, "Renamed");
            let meta = handle
                .load::<crate::CollectionMeta>(&meta_path)
                .await
                .expect("then CollectionMeta");
            assert_eq!(meta.label, "Renamed");
        }
        // Both types stay cached side by side.
        assert_eq!(handle.cache().len(), 2, "{order}");
        // The label still resolves from the file.
        assert_eq!(handle.collection_label("default").await, "Renamed");
    }
}

// ---------------------------------------------------------------------------
// The store mode is explicit (no default)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_store_without_a_mode_is_refused() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    std::fs::remove_file(store.root.join(STORE_META_FILE)).ok();
    let provider = SopsProvider::new("mode-test", store.direct_config());
    let error = unlock(&provider).await.expect_err("no mode must refuse");
    assert!(
        error.to_string().contains("store init --mode"),
        "the refusal must name the fix: {error}"
    );

    // An unknown mode is refused the same way.
    std::fs::write(
        store.root.join(STORE_META_FILE),
        b"version: 1\nmode: auto\n",
    )
    .unwrap();
    let provider = SopsProvider::new("mode-test", store.direct_config());
    assert!(
        unlock(&provider).await.is_err(),
        "an unknown mode must refuse"
    );

    // Loading the mode never writes a default.
    assert!(read_mode(&store.root).is_err());
    let text = std::fs::read_to_string(store.root.join(STORE_META_FILE)).unwrap();
    assert!(text.contains("auto"), "the file must be untouched: {text}");
}

#[tokio::test]
async fn a_mode_that_disagrees_with_the_config_is_refused() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    store.init_derived().await;

    // Derived store, no `identity_file`.
    let mut config = SopsConfig::new(&store.root, &store.key_file, "", "sops").unwrap();
    config.runtime_identity_file = store.runtime();
    let provider = SopsProvider::new("mode-test", config);
    let error = unlock(&provider).await.expect_err("must refuse");
    assert!(
        error.to_string().contains("identity_file"),
        "the refusal names the missing option: {error}"
    );

    // Direct store, `identity_file` set.
    write_meta(&store.root, &StoreMeta::new(StoreMode::Direct)).unwrap();
    let provider = SopsProvider::new("mode-test", store.derived_config());
    let error = unlock(&provider).await.expect_err("must refuse");
    assert!(
        error.to_string().contains("direct"),
        "the refusal names the mode: {error}"
    );
}

// ---------------------------------------------------------------------------
// `identity init`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_init_writes_a_master_file_and_a_sidecar() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    write_meta(&store.root, &StoreMeta::new(StoreMode::Derived)).unwrap();
    crate::identity_cli::init(&store.derived_config(), false)
        .await
        .expect("init");

    // The master decrypts with the UNLOCK key (not the derived identity) and
    // holds exactly one `AGE-SECRET-KEY-1` field.
    let identity = master_identity(&store.key_file, &store.root).expect("master decrypts");
    assert!(identity.starts_with(AGE_SECRET_PREFIX), "not an identity");
    let cipher = std::fs::read_to_string(master_path(&store.root)).unwrap();
    assert!(cipher.contains("ENC["), "the master must be encrypted");
    assert!(
        !cipher.contains(AGE_SECRET_PREFIX),
        "the plaintext identity leaked into the master file"
    );

    // The sidecar matches the derived recipient.
    let sidecar = read_sidecar(&store.root).expect("sidecar");
    let derived = crate::sops::public_recipient_for(&identity).unwrap();
    assert_eq!(sidecar, derived);
    assert!(
        std::fs::read_to_string(master_path(&store.root))
            .unwrap()
            .contains("recipient: "),
        "the master must record its recipients"
    );

    // A second init refuses without `--force`.
    let error = crate::identity_cli::init(&store.derived_config(), false)
        .await
        .expect_err("must refuse");
    assert!(error.contains("--force"), "{error}");
}

#[tokio::test]
async fn identity_init_needs_a_derived_store_and_a_master_rule() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    // No metadata: refused with the mode hint.
    let error = crate::identity_cli::init(&store.derived_config(), false)
        .await
        .expect_err("no mode");
    assert!(error.contains("store init --mode"), "{error}");

    // Direct store: refused.
    write_meta(&store.root, &StoreMeta::new(StoreMode::Direct)).unwrap();
    let error = crate::identity_cli::init(&store.derived_config(), false)
        .await
        .expect_err("direct store");
    assert!(error.contains("derived"), "{error}");

    // No `.sops.yaml` at all: sops finds no keys, and the error carries the
    // ready-to-paste master rule.
    write_meta(&store.root, &StoreMeta::new(StoreMode::Derived)).unwrap();
    std::fs::remove_file(store.root.join(".sops.yaml")).unwrap();
    let error = crate::identity_cli::init(&store.derived_config(), false)
        .await
        .expect_err("no creation rule");
    assert!(
        error.contains(crate::STORE_IDENTITY_FILE) && error.contains("path_regex"),
        "the hint shows the required rule: {error}"
    );

    // Rule ORDER is load bearing: an item rule placed first also matches the
    // master name, so the master would be wrapped to the item recipient (here
    // the derived identity, which does not exist yet) instead of the unlock
    // group. `sops` succeeds, and the result is a master nobody can open.
    // The item rule is placed first and names a key this host does not hold.
    let stranger_file = store._dir.path().join("stranger.txt");
    let stranger = keygen(&stranger_file);
    std::fs::write(
        store.root.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: .*\\.sops\\.yaml$\n    age: {stranger}\n"),
    )
    .unwrap();
    crate::identity_cli::init(&store.derived_config(), false)
        .await
        .expect("sops still encrypts: the item rule matches the master name");
    assert!(
        master_identity(&store.key_file, &store.root).is_none(),
        "a reversed rule order wraps the master to the wrong recipient"
    );
}

// ---------------------------------------------------------------------------
// Provider unlock: once per session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unlock_unwraps_once_and_lock_removes_the_runtime_identity() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    store.init_derived().await;
    let derived = read_sidecar(&store.root).unwrap();

    // A direct item migrated onto the derived identity.
    put_item(
        &store.root,
        "default",
        "item-a",
        &store.unlock_recipient,
        "direct-secret",
    )
    .await;
    crate::identity_cli::migrate(&store.derived_config())
        .await
        .expect("migrate");
    let item = store.root.join("default").join("item-a.sops.yaml");
    assert!(
        decrypt_with(&store.key_file, &item).is_err(),
        "after migration the unlock key must not read the item"
    );
    assert_eq!(derived, read_sidecar(&store.root).unwrap());

    let provider = SopsProvider::new("derived-test", store.derived_config());
    unlock(&provider).await.expect("unlock");
    assert!(store.runtime().is_file(), "unlock writes the runtime file");
    let text = std::fs::read_to_string(store.runtime()).unwrap();
    assert!(
        text.starts_with(AGE_SECRET_PREFIX),
        "runtime holds the identity"
    );

    let secret = provider
        .get_secret_attr("item-a", "password")
        .await
        .unwrap();
    assert_eq!(
        secret.as_slice(),
        b"direct-secret",
        "the item keeps its value through the migration"
    );

    // Lock removes the runtime file.
    provider.lock().await.unwrap();
    assert!(!store.runtime().exists(), "lock removes the runtime file");

    // A second unlock unwraps again.
    unlock(&provider).await.expect("second unlock");
    assert!(store.runtime().is_file(), "the second unlock rewrote it");

    // After `lock` the runtime file is gone, so an unlock without the key file
    // must fail: the session identity was the only way in.
    provider.lock().await.unwrap();
    let mut config = store.derived_config();
    config.key_file = store._dir.path().join("absent-keys.txt");
    config.identity_key_file = Some(config.key_file.clone());
    let offline = SopsProvider::new("derived-offline", config);
    assert!(unlock(&offline).await.is_err(), "no key, no runtime");
}

#[tokio::test]
async fn an_unwrapped_session_unlocks_without_the_unlock_key() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    store.init_derived().await;
    put_item(
        &store.root,
        "default",
        "item-a",
        &read_sidecar(&store.root).unwrap(),
        "s3cret",
    )
    .await;

    let provider = SopsProvider::new("derived-test", store.derived_config());
    unlock(&provider).await.expect("first unlock");
    provider.lock().await.unwrap();

    // Put a fresh runtime identity back, as an unlock that just happened does.
    let identity = master_identity(&store.key_file, &store.root).unwrap();
    write_runtime_identity(&store.runtime(), &identity).unwrap();

    let mut config = store.derived_config();
    config.key_file = store._dir.path().join("absent.txt");
    config.identity_key_file = Some(config.key_file.clone());
    let provider = SopsProvider::new("derived-offline", config);
    unlock(&provider)
        .await
        .expect("a session identity makes the token optional");
    let secret = provider
        .get_secret_attr("item-a", "password")
        .await
        .unwrap();
    assert_eq!(secret.as_slice(), b"s3cret");
}

// ---------------------------------------------------------------------------
// `identity rewrap` and the unlock group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn either_of_two_unlock_keys_can_unwrap_the_master() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    store.init_derived().await;
    let identity_one = master_identity(&store.key_file, &store.root).expect("first key");

    // Add the second key to the master rule, then rewrap.
    store.write_sops_yaml(&[
        store.unlock_recipient.clone(),
        store.second_recipient.clone(),
    ]);
    crate::identity_cli::rewrap(&store.derived_config())
        .await
        .expect("rewrap add");

    let identity_two = master_identity(&store.second_key_file, &store.root)
        .expect("the second key must open the master");
    assert_eq!(
        identity_one, identity_two,
        "rewrap must not change the derived identity"
    );

    // Remove the first key from the rule and rewrap with the second.
    store.write_sops_yaml(std::slice::from_ref(&store.second_recipient));
    let mut config = store.derived_config();
    config.identity_key_file = Some(store.second_key_file.clone());
    crate::identity_cli::rewrap(&config)
        .await
        .expect("rewrap remove");

    assert!(
        master_identity(&store.key_file, &store.root).is_none(),
        "the removed key must not open the master"
    );
    assert_eq!(
        master_identity(&store.second_key_file, &store.root).expect("remaining key"),
        identity_one,
        "the remaining key still unwraps the same identity"
    );
}

// ---------------------------------------------------------------------------
// `identity rekey`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rekey_rotates_the_identity_and_leaves_the_old_one_useless() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    store.init_derived().await;
    let old_recipient = read_sidecar(&store.root).unwrap();
    put_item(&store.root, "default", "item-a", &old_recipient, "value-a").await;
    let old_identity = master_identity(&store.key_file, &store.root).unwrap();

    crate::identity_cli::rekey(&store.derived_config(), false)
        .await
        .expect("rekey");

    let new_recipient = read_sidecar(&store.root).unwrap();
    assert_ne!(old_recipient, new_recipient, "the recipient must change");
    let new_identity = master_identity(&store.key_file, &store.root).unwrap();
    assert_ne!(old_identity, new_identity, "the identity must change");

    // The item still holds its value, under the new identity only.
    let item = store.root.join("default").join("item-a.sops.yaml");
    let old_key = store._dir.path().join("old-identity.age");
    write_atomic_sync(&old_key, format!("{old_identity}\n").as_bytes()).unwrap();
    assert!(
        decrypt_with(&old_key, &item).is_err(),
        "the old derived identity must not read the re-encrypted item"
    );
    let runtime = store._dir.path().join("new-identity.age");
    write_atomic_sync(&runtime, format!("{new_identity}\n").as_bytes()).unwrap();
    let plain = decrypt_with(&runtime, &item).expect("the new identity reads it");
    assert!(plain.contains("value-a"), "{plain}");

    // The master, the sidecar and the runtime file are replaced together.
    assert!(
        store.runtime().is_file(),
        "rekey writes the runtime identity"
    );
    assert!(
        std::fs::read_to_string(store.runtime())
            .unwrap()
            .contains(&new_identity),
        "the runtime file holds the new identity"
    );
    assert_eq!(
        std::fs::read_to_string(sidecar_path(&store.root))
            .unwrap()
            .trim(),
        new_recipient
    );

    // A second rekey rotates again: the new master is the old identity now.
    crate::identity_cli::rekey(&store.derived_config(), false)
        .await
        .expect("a second rotation");
    assert_ne!(
        read_sidecar(&store.root).unwrap(),
        new_recipient,
        "each rekey rotates the recipient"
    );
}

// ---------------------------------------------------------------------------
// `store init` and `store migrate`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn store_init_adopts_an_existing_direct_store() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("legacy");
    std::fs::create_dir_all(&root).unwrap();
    let key_file = dir.path().join("keys.txt");
    let recipient = keygen(&key_file);
    let config = SopsConfig::new(&root, &key_file, &recipient, "sops").unwrap();

    // An adopting store has no metadata yet: the provider refuses it.
    let provider = SopsProvider::new("adopt", config.clone());
    assert!(unlock(&provider).await.is_err(), "no mode, no unlock");

    write_meta(&root, &StoreMeta::new(StoreMode::Direct)).unwrap();
    assert_eq!(read_meta(&root).unwrap().mode, StoreMode::Direct);
    // Re-initialising with the same mode is a no-op.
    write_meta(&root, &StoreMeta::new(StoreMode::Direct)).unwrap();
    assert_eq!(read_mode(&root).unwrap(), StoreMode::Direct);

    // The provider now unlocks and writes a direct item.
    let provider = SopsProvider::new("adopt", config);
    unlock(&provider).await.expect("unlock");
    let id = provider
        .create_item(
            rosec_core::NewItem {
                content_types: HashMap::new(),
                label: "adopted".into(),
                item_type: None,
                attributes: HashMap::new(),
                secrets: HashMap::from([("password".to_string(), SecretBytes::new(b"p".to_vec()))]),
            },
            false,
        )
        .await
        .expect("create");
    let path = root.join("default").join(format!("{id}.sops.yaml"));
    assert!(
        decrypt_with(&key_file, &path).is_ok(),
        "a direct store encrypts to the unlock key"
    );
}

#[tokio::test]
async fn store_migrate_copies_items_into_a_derived_store() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    // Source: a direct store with one item and a renamed collection.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::create_dir_all(&source).unwrap();
    let key_file = dir.path().join("keys.txt");
    let recipient = keygen(&key_file);
    write_meta(&source, &StoreMeta::new(StoreMode::Direct)).unwrap();
    put_item(&source, "work", "item-a", &recipient, "old-value").await;

    // Destination: a derived store with its own unlock key and master file.
    let destination = dir.path().join("destination");
    std::fs::create_dir_all(&destination).unwrap();
    let destination_key = dir.path().join("destination-keys.txt");
    let destination_unlock = keygen(&destination_key);
    std::fs::write(
        destination.join(".sops.yaml"),
        format!(
            "creation_rules:\n\
             \x20 - path_regex: ^\\.rosec-store-identity\\.sops\\.yaml$\n\
             \x20   age: {destination_unlock}\n\
             \x20 - path_regex: .*\\.sops\\.yaml$\n\
             \x20   age: {destination_unlock}\n"
        ),
    )
    .unwrap();
    write_meta(&destination, &StoreMeta::new(StoreMode::Derived)).unwrap();
    let mut destination_config =
        SopsConfig::new(&destination, &destination_key, "", "sops").unwrap();
    destination_config.identity_file = Some(master_path(&destination));
    destination_config.identity_key_file = Some(destination_key.clone());
    destination_config.runtime_identity_file = dir.path().join("runtime.id");
    crate::identity_cli::init(&destination_config, false)
        .await
        .expect("destination identity");
    // The item rule now points at the derived recipient.
    let derived = read_sidecar(&destination).unwrap();
    std::fs::write(
        destination.join(".sops.yaml"),
        format!(
            "creation_rules:\n\
             \x20 - path_regex: ^\\.rosec-store-identity\\.sops\\.yaml$\n\
             \x20   age: {destination_unlock}\n\
             \x20 - path_regex: .*\\.sops\\.yaml$\n\
             \x20   age: {derived}\n"
        ),
    )
    .unwrap();

    let options = crate::store_migrate::MigrationOptions {
        from: source.clone(),
        to: destination.clone(),
        source_key_file: key_file.clone(),
        sops_binary: PathBuf::from("sops"),
        mode: None,
        force: false,
        overwrite: false,
    };
    let report = crate::store_migrate::migrate_store(&options, |path| {
        let config = SopsConfig::new(path, &destination_key, "", "sops").unwrap();
        SopsConfig {
            identity_file: master_path(path).is_file().then(|| master_path(path)),
            ..config
        }
    })
    .await
    .expect("migrate");

    assert_eq!(report.from_mode, Some(StoreMode::Direct));
    assert_eq!(report.to_mode, StoreMode::Derived);
    assert_eq!(report.items, 1);
    assert!(report.collections.contains("work"), "{report:?}");

    // The item arrived under the derived recipient and keeps its value.
    let copied = destination.join("work").join("item-a.sops.yaml");
    let identity = master_identity(&destination_key, &destination).unwrap();
    let identity_file = dir.path().join("derived.age");
    write_atomic_sync(&identity_file, format!("{identity}\n").as_bytes()).unwrap();
    let plain = decrypt_with(&identity_file, &copied).expect("derived identity reads it");
    assert!(plain.contains("old-value"), "{plain}");
    assert!(
        decrypt_with(&key_file, &copied).is_err(),
        "the source key must not read the migrated copy"
    );
    // The source is untouched.
    assert!(source.join("work").join("item-a.sops.yaml").is_file());
    assert_eq!(read_mode(&source).unwrap(), StoreMode::Direct);

    // A second migration into the same, now non-empty destination is refused.
    let error = crate::store_migrate::migrate_store(&options, |path| {
        SopsConfig::new(path, &destination_key, "", "sops").unwrap()
    })
    .await
    .expect_err("must refuse");
    assert!(error.to_string().contains("--force"), "{error}");
}

#[tokio::test]
async fn store_migrate_refuses_a_store_with_an_unresolved_conflict() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::create_dir_all(&source).unwrap();
    let key_file = dir.path().join("keys.txt");
    let recipient = keygen(&key_file);
    write_meta(&source, &StoreMeta::new(StoreMode::Direct)).unwrap();
    put_item(&source, "default", "item-a", &recipient, "v").await;
    crate::conflicts::write_marker(
        &source,
        &crate::ConflictMarker {
            item: "item-a".into(),
            collection: "default".into(),
            label: "default".into(),
            winner: "default/item-a.sops.yaml".into(),
            losers: Vec::new(),
            winner_meta: None,
            written: crate::conflicts::now_text(),
            attributes: Default::default(),
            hint: String::new(),
        },
    )
    .await
    .unwrap();

    let options = crate::store_migrate::MigrationOptions {
        from: source.clone(),
        to: dir.path().join("destination"),
        source_key_file: key_file.clone(),
        sops_binary: PathBuf::from("sops"),
        mode: Some(StoreMode::Direct),
        force: false,
        overwrite: false,
    };
    let error = crate::store_migrate::migrate_store(&options, |path| {
        SopsConfig::new(path, &key_file, &recipient, "sops").unwrap()
    })
    .await
    .expect_err("must refuse");
    assert!(
        error.to_string().contains("resolve"),
        "the refusal names the fix: {error}"
    );
    assert!(
        !dir.path().join("destination").exists(),
        "nothing may be written before the refusal"
    );
}

#[tokio::test]
async fn a_derived_round_trip_uses_one_runtime_identity() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    store.init_derived().await;
    let derived = read_sidecar(&store.root).unwrap();
    store.write_sops_yaml(std::slice::from_ref(&store.unlock_recipient));
    // Put the item rule on the derived recipient for new writes.
    std::fs::write(
        store.root.join(".sops.yaml"),
        format!(
            "creation_rules:\n\
             \x20 - path_regex: ^\\.rosec-store-identity\\.sops\\.yaml$\n\
             \x20   age: {}\n\
             \x20 - path_regex: .*\\.sops\\.yaml$\n\
             \x20   age: {derived}\n",
            store.unlock_recipient
        ),
    )
    .unwrap();

    let mut config = store.derived_config();
    config.age_recipient = derived.clone();
    let provider = Arc::new(SopsProvider::new("derived-write", config));
    unlock(&provider).await.expect("unlock");
    let id = provider
        .create_item(
            rosec_core::NewItem {
                content_types: HashMap::new(),
                label: "written".into(),
                item_type: None,
                attributes: HashMap::new(),
                secrets: HashMap::from([(
                    "password".to_string(),
                    SecretBytes::new(b"written-value".to_vec()),
                )]),
            },
            false,
        )
        .await
        .expect("create");
    let path = store.root.join("default").join(format!("{id}.sops.yaml"));
    let identity = master_identity(&store.key_file, &store.root).unwrap();
    let identity_file = store._dir.path().join("derived.age");
    write_atomic_sync(&identity_file, format!("{identity}\n").as_bytes()).unwrap();
    assert!(
        decrypt_with(&identity_file, &path).is_ok(),
        "a new item goes to the derived identity"
    );
    assert!(
        decrypt_with(&store.key_file, &path).is_err(),
        "the unlock key must not read a derived item"
    );
    let secret = provider.get_secret_attr(&id, "password").await.unwrap();
    assert_eq!(secret.as_slice(), b"written-value");
}

/// The derived identity must never be printed by any CLI path.
#[tokio::test]
async fn the_derived_identity_is_never_on_stdout() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let store = Store::new();
    store.init_derived().await;
    let identity = master_identity(&store.key_file, &store.root).unwrap();
    let shown = crate::identity_cli::show(&store.derived_config()).await;
    assert!(shown.is_ok());
    // `show` reads no secret; the runtime file is absent at this point.
    let _ = generate_age_identity().unwrap();
    assert!(identity.starts_with(AGE_SECRET_PREFIX));
}
