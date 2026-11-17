//! Tests that use the real `sops` binary and a temporary age key.
//!
//! Every test skips itself with a clear message when `sops` or `age-keygen` is
//! not on `PATH`. Both ship in the devenv shell (`devenv shell -- cargo test -p
//! rosec-sops`), so a run inside the shell always exercises the real binary.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rosec_core::{
    ATTR_TYPE, Capability, ItemType, ItemUpdate, NewItem, Provider, ProviderError, SecretBytes,
    UnlockInput,
};
use zeroize::Zeroizing;

use crate::document::{SopsDocument, Timestamp};
use crate::provider::{
    ATTR_COLLECTION, ATTR_COLLECTION_DIR, ATTR_CONFLICT, INTERNAL_ATTRIBUTES, SopsProvider, new_id,
};
use crate::store::{COLLECTION_META, SUPERSEDED_PREFIX, SYNCTHING_CONFLICT_MARKER};
use crate::store_mode::StoreMode;
use crate::{SopsConfig, SopsError};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A temporary store with its own age identity.
struct Fixture {
    /// Keeps the temporary directory alive.
    _dir: tempfile::TempDir,
    /// Store root.
    root: PathBuf,
    /// The age identity file.
    key_file: PathBuf,
    /// The matching age recipient.
    recipient: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("store");
        let key_file = dir.path().join("age-keys.txt");
        let recipient = generate_identity(&key_file);
        std::fs::create_dir_all(&root).expect("store root");
        // Every store carries an explicit mode: `direct` keeps the original
        // behaviour (items encrypted to the unlock key itself).
        crate::store_mode::write_meta(&root, &crate::store_mode::StoreMeta::new(StoreMode::Direct))
            .expect("store metadata");
        Self {
            _dir: dir,
            root,
            key_file,
            recipient,
        }
    }

    fn config(&self) -> SopsConfig {
        SopsConfig::new(&self.root, &self.key_file, &self.recipient, "sops")
            .expect("valid test config")
    }

    /// A config with no `age_recipient`: sops uses `.sops.yaml` creation rules.
    fn config_without_recipient(&self) -> SopsConfig {
        SopsConfig::new(&self.root, &self.key_file, "", "sops").expect("valid test config")
    }

    fn provider(&self) -> Arc<SopsProvider> {
        Arc::new(SopsProvider::new("sops-test", self.config()))
    }

    fn item_path(&self, collection: &str, id: &str) -> PathBuf {
        self.root.join(collection).join(format!("{id}.sops.yaml"))
    }
}

/// Run `age-keygen -o path` and return the matching recipient.
fn generate_identity(key_file: &Path) -> String {
    let output = std::process::Command::new("age-keygen")
        .arg("-o")
        .arg(key_file)
        .output()
        .expect("run age-keygen");
    assert!(output.status.success(), "age-keygen failed: {output:?}");
    let pubkey = String::from_utf8_lossy(&output.stderr);
    pubkey
        .split_whitespace()
        .find(|word| word.starts_with("age1"))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("no recipient in age-keygen output: {pubkey}"))
}

fn has_tools() -> bool {
    for tool in ["sops", "age-keygen"] {
        let ok = std::process::Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            return false;
        }
    }
    true
}

fn new_item(label: &str, secrets: &[(&str, &str)]) -> NewItem {
    NewItem {
        content_types: HashMap::new(),
        label: label.to_owned(),
        item_type: Some(ItemType::Generic),
        attributes: HashMap::new(),
        secrets: secrets
            .iter()
            .map(|(k, v)| ((*k).to_string(), SecretBytes::new(v.as_bytes().to_vec())))
            .collect(),
    }
}

async fn unlock(provider: &SopsProvider) {
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
        .expect("unlock");
}

async fn read_secret(provider: &SopsProvider, id: &str, attr: &str) -> String {
    let bytes = provider
        .get_secret_attr(id, attr)
        .await
        .expect("secret present");
    String::from_utf8(bytes.as_slice().to_vec()).expect("utf-8 secret")
}

// ---------------------------------------------------------------------------
// Create / read / update / delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_read_update_delete() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    assert!(provider.list_items().await.unwrap().is_empty());

    let id = provider
        .create_item(new_item("github.com", &[("password", "hunter2")]), false)
        .await
        .expect("create");
    assert!(id.starts_with("item-"), "id format, got {id}");
    assert_eq!(id.len(), "item-".len() + 32, "16 random bytes in hex: {id}");

    // The file exists in the default collection and is sops ciphertext.
    let file = fixture.item_path("default", &id);
    let cipher = std::fs::read_to_string(&file).expect("item file");
    assert!(cipher.contains("sops:"), "not a sops document: {cipher}");
    assert!(
        !cipher.contains("hunter2"),
        "plaintext leaked into the file"
    );
    assert!(
        cipher.contains("ENC[") || cipher.contains("encrypted"),
        "no ciphertext marker: {cipher}"
    );

    // Reading through the provider decrypts.
    let attrs = provider.get_item_attributes(&id).await.expect("attributes");
    assert_eq!(attrs.secret_names, vec!["password".to_string()]);
    assert_eq!(
        attrs.public.get(ATTR_TYPE).map(String::as_str),
        Some("generic")
    );
    assert_eq!(
        attrs.public.get(ATTR_COLLECTION_DIR).map(String::as_str),
        Some("default")
    );
    assert_eq!(
        read_secret(&provider, &id, "password").await,
        "hunter2".to_string()
    );

    // No meta file is written for a collection whose label is its name.
    let meta = fixture.root.join("default").join(COLLECTION_META);
    assert!(
        !meta.exists(),
        "a collection named like its label must not get a meta file"
    );

    // list + search
    let items = provider.list_items().await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label, "github.com");

    provider
        .update_item(
            &id,
            ItemUpdate {
                label: Some("github.com (work)".into()),
                secrets: Some(HashMap::from([(
                    "password".to_string(),
                    SecretBytes::new(b"correct-horse".to_vec()),
                )])),
                ..Default::default()
            },
        )
        .await
        .expect("update");
    let items = provider.list_items().await.unwrap();
    assert_eq!(items[0].label, "github.com (work)");
    assert_eq!(
        read_secret(&provider, &id, "password").await,
        "correct-horse".to_string()
    );

    // The revision counter went up.
    let store = provider.store().clone();
    let doc = store
        .load_document(&fixture.item_path("default", &id))
        .await
        .expect("load document");
    assert_eq!(doc.revision, 2, "revision must increment per write");
    assert!(doc.host.is_some(), "host must be stamped");

    provider.delete_item(&id).await.expect("delete");
    assert!(provider.list_items().await.unwrap().is_empty());
    assert!(!fixture.item_path("default", &id).exists());
    assert!(matches!(
        provider.get_secret_attr(&id, "password").await,
        Err(ProviderError::NotFound)
    ));
}

#[tokio::test]
async fn item_ids_are_random_and_not_secret_derived() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let first = provider
        .create_item(new_item("same", &[("password", "hunter2")]), false)
        .await
        .unwrap();

    // The id must not be an offline verifier for the secret.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"password\0hunter2\0");
    let derived = format!(
        "item-{}",
        hasher
            .finalize()
            .iter()
            .take(10)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert_ne!(first, derived, "the id must not be sha256 of the secrets");
    assert!(
        !first.contains("hunter2"),
        "the id must not name the secret"
    );
    assert_eq!(new_id().len(), "item-".len() + 32);

    // 128 random bits: two generated ids never collide.
    let ids = (0..64)
        .map(|_| new_id())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 64, "random ids must be unique");
}

#[tokio::test]
async fn create_with_replace_updates_the_existing_item() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let mut token = new_item("token", &[("secret", "abc")]);
    token.attributes.insert("service".into(), "token".into());
    let first = provider.create_item(token.clone(), false).await.unwrap();
    assert!(matches!(
        provider.create_item(token, false).await,
        Err(ProviderError::AlreadyExists)
    ));
    let mut renamed = new_item("token renamed", &[("secret", "abc")]);
    renamed.attributes.insert("service".into(), "token".into());
    let second = provider.create_item(renamed, true).await.unwrap();
    assert_eq!(first, second, "replace must hit the same file");
    assert_eq!(provider.list_items().await.unwrap().len(), 1);

    // Different secrets under the same label are a separate item, not an
    // update.
    let mut rotated = new_item("token", &[("secret", "different")]);
    rotated.attributes.insert("service".into(), "token".into());
    let other = provider.create_item(rotated, true).await.unwrap();
    assert_eq!(first, other, "a rotated secret must replace in place");
    assert_eq!(provider.list_items().await.unwrap().len(), 1);
    assert_eq!(
        provider
            .get_secret_value(&first, "secret")
            .await
            .unwrap()
            .bytes
            .as_slice(),
        b"different"
    );
}

#[tokio::test]
async fn label_matched_items_keep_the_content_check() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    // No client attributes: the label is only a heuristic identity (a CLI convenience, not the
    // Secret Service contract), so two different notes that happen to share a label must stay
    // separate even with replace set.
    let first = provider
        .create_item(new_item("note", &[("secret", "one")]), false)
        .await
        .unwrap();
    let second = provider
        .create_item(new_item("note", &[("secret", "two")]), true)
        .await
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(provider.list_items().await.unwrap().len(), 2);
}

#[tokio::test]
async fn create_with_replace_matches_by_attribute_subset() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let mut login = new_item("login", &[("password", "pw")]);
    login.attributes.insert("username".into(), "user".into());
    let first = provider.create_item(login.clone(), false).await.unwrap();

    // Same attributes and secrets: an update, so the same file.
    login.label = "login renamed".into();
    let second = provider.create_item(login, true).await.unwrap();
    assert_eq!(first, second);

    // A different username is a different item.
    let mut other = new_item("login", &[("password", "pw")]);
    other.attributes.insert("username".into(), "someone".into());
    let third = provider.create_item(other, false).await.unwrap();
    assert_ne!(first, third);
}

#[tokio::test]
async fn search_matches_attribute_subsets() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let mut login = new_item("login", &[("password", "pw")]);
    login.attributes.insert("username".into(), "user".into());
    let login_id = provider.create_item(login, false).await.unwrap();
    provider
        .create_item(new_item("note", &[("secret", "text")]), false)
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("username".to_string(), "user".to_string());
    let hits = provider.search(&query).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, login_id);

    // A no-match query returns nothing.
    let mut miss = HashMap::new();
    miss.insert("username".to_string(), "nobody".to_string());
    assert!(provider.search(&miss).await.unwrap().is_empty());

    // A client that echoes a full attribute map back (as the Secret Service
    // layer does on a read-modify-write) must still match: the provider-owned
    // entries are ignored, not used as a filter.
    let echoed = provider
        .get_item_attributes(&login_id)
        .await
        .unwrap()
        .public;
    let hits = provider.search(&echoed).await.unwrap();
    assert_eq!(
        hits.len(),
        1,
        "echoed attributes must still match: {hits:?}"
    );
}

// ---------------------------------------------------------------------------
// R2: provider-managed attributes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_attributes_cannot_forge_provider_managed_names() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let mut item = new_item("forge", &[("secret", "v")]);
    item.attributes
        .insert(ATTR_COLLECTION.into(), "not-a-collection".into());
    item.attributes
        .insert(ATTR_COLLECTION_DIR.into(), "work".into());
    item.attributes.insert(ATTR_CONFLICT.into(), "true".into());
    item.attributes.insert("username".into(), "user".into());
    let id = provider.create_item(item, false).await.unwrap();

    let attrs = provider.get_item_attributes(&id).await.unwrap().public;
    assert_eq!(
        attrs.get(ATTR_COLLECTION).map(String::as_str),
        Some("default"),
        "`collection` must be stamped by the provider"
    );
    assert_eq!(
        attrs.get(ATTR_COLLECTION_DIR).map(String::as_str),
        Some("default")
    );
    assert!(
        !attrs.contains_key(ATTR_CONFLICT),
        "a client must not be able to forge the conflict flag"
    );
    assert_eq!(attrs.get("username").map(String::as_str), Some("user"));

    // The stored document does not carry the forged values either.
    let stored = provider
        .store()
        .load_document(&fixture.item_path("default", &id))
        .await
        .unwrap();
    for key in INTERNAL_ATTRIBUTES {
        assert!(
            !stored.attributes.contains_key(*key),
            "{key} was stored from client input"
        );
    }

    // An update with the same names is stripped, not rejected, and the stored
    // `rosec:type` survives an attribute replacement.
    provider
        .update_item(
            &id,
            ItemUpdate {
                attributes: Some(HashMap::from([
                    (ATTR_COLLECTION_DIR.to_string(), "elsewhere".to_string()),
                    (ATTR_TYPE.to_string(), "note".to_string()),
                    ("username".to_string(), "someone".to_string()),
                ])),
                ..Default::default()
            },
        )
        .await
        .expect("an update echoing provider-managed attributes is accepted");
    let attrs = provider.get_item_attributes(&id).await.unwrap().public;
    assert_eq!(
        attrs.get(ATTR_COLLECTION_DIR).map(String::as_str),
        Some("default")
    );
    assert_eq!(attrs.get("username").map(String::as_str), Some("someone"));
    assert_eq!(
        attrs.get(ATTR_TYPE).map(String::as_str),
        Some("generic"),
        "the stored type must not be replaced through a stripped attribute"
    );

    // Reserved names are still rejected where rosec-core rejects them.
    let mut reserved = new_item("reserved", &[("secret", "v")]);
    reserved
        .attributes
        .insert(rosec_core::ATTR_PROVIDER.into(), "x".into());
    assert!(matches!(
        provider.create_item(reserved, false).await,
        Err(ProviderError::InvalidInput(_))
    ));
}

// ---------------------------------------------------------------------------
// R5: binary secrets
// ---------------------------------------------------------------------------

#[tokio::test]
async fn binary_secrets_survive_byte_for_byte() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let raw: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x80, 0x41, 0x0a, 0x27, 0x22];
    let item = NewItem {
        content_types: HashMap::new(),
        label: "binary".into(),
        item_type: Some(ItemType::Generic),
        attributes: HashMap::new(),
        secrets: HashMap::from([("blob".to_string(), SecretBytes::new(raw.clone()))]),
    };
    let id = provider.create_item(item, false).await.unwrap();

    let read = provider.get_secret_attr(&id, "blob").await.unwrap();
    assert_eq!(read.as_slice(), raw.as_slice(), "binary secret was mangled");

    // It is visible as a secret name and readable through the document.
    let attrs = provider.get_item_attributes(&id).await.unwrap();
    assert_eq!(attrs.secret_names, vec!["blob".to_string()]);
    let stored = provider
        .store()
        .load_document(&fixture.item_path("default", &id))
        .await
        .unwrap();
    assert!(stored.binary_secrets.contains_key("blob"));
    assert!(stored.secrets.is_empty());

    // An update replaces it in place, still byte-exact.
    let replacement = vec![0x9f, 0x00, 0x01];
    provider
        .update_item(
            &id,
            ItemUpdate {
                secrets: Some(HashMap::from([(
                    "blob".to_string(),
                    SecretBytes::new(replacement.clone()),
                )])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        provider
            .get_secret_attr(&id, "blob")
            .await
            .unwrap()
            .as_slice(),
        replacement.as_slice()
    );
}

#[tokio::test]
async fn a_text_value_and_a_base64_value_compare_equal() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let mut from_text = new_item("same", &[("secret", "same-bytes")]);
    from_text.attributes.insert("source".into(), "text".into());
    let id = provider.create_item(from_text, false).await.unwrap();

    // Same value stored in the binary map: comparison is on decoded bytes, so
    // a `create` with `replace` must find the existing item.
    let mut from_base64 = new_item("same", &[("secret", "same-bytes")]);
    from_base64
        .attributes
        .insert("source".into(), "text".into());
    let mut document = provider
        .store()
        .load_document(&fixture.item_path("default", &id))
        .await
        .unwrap();
    document.set_secret("secret", b"same-bytes");
    let plain = document.to_yaml().unwrap();
    let cipher = crate::SopsCommand::new("sops", &fixture.key_file)
        .encrypt(plain.as_bytes(), Some(&fixture.recipient), &fixture.root)
        .await
        .unwrap();
    std::fs::write(fixture.item_path("default", &id), cipher).unwrap();
    provider.store().cache().clear();
    assert_eq!(read_secret(&provider, &id, "secret").await, "same-bytes");

    let again = provider.create_item(from_base64, true).await.unwrap();
    assert_eq!(id, again, "equal bytes must match across the two maps");
    assert_eq!(provider.list_items().await.unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// R3: recipients
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_second_recipient_can_open_the_same_file() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();

    // A second host with its own age identity and store.
    let second_dir = tempfile::tempdir().unwrap();
    let second_key = second_dir.path().join("age-keys.txt");
    let second_recipient = generate_identity(&second_key);

    // The writer lists both recipients, as a shared synced store needs.
    let both = format!("{},{}", fixture.recipient, second_recipient);
    let config = SopsConfig::new(&fixture.root, &fixture.key_file, &both, "sops").unwrap();
    let writer = SopsProvider::new("writer", config);
    unlock(&writer).await;
    let id = writer
        .create_item(new_item("shared", &[("secret", "multi")]), false)
        .await
        .unwrap();

    // The file records both recipients.
    let cipher = std::fs::read_to_string(fixture.item_path("default", &id)).unwrap();
    assert!(cipher.contains(&fixture.recipient));
    assert!(cipher.contains(&second_recipient));

    // The second host reads it with its own identity.
    let reader_config = SopsConfig::new(&fixture.root, &second_key, &fixture.recipient, "sops")
        .unwrap_or_else(|_| SopsConfig::new(&fixture.root, &second_key, &both, "sops").unwrap());
    let reader = SopsProvider::new("reader", reader_config);
    unlock(&reader).await;
    assert_eq!(
        read_secret(&reader, &id, "secret").await,
        "multi".to_string(),
        "the second identity must open the file"
    );
}

#[tokio::test]
async fn an_update_never_narrows_the_recipient_list() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();

    // Two identities: the provider is configured with the first only.
    let second_dir = tempfile::tempdir().unwrap();
    let second_key = second_dir.path().join("age-keys.txt");
    let second_recipient = generate_identity(&second_key);

    // Hand-write a file for two recipients, outside the provider.
    std::fs::create_dir_all(fixture.root.join("default")).unwrap();
    let document = SopsDocument {
        label: "shared".into(),
        attributes: Default::default(),
        secrets: [("secret".to_string(), "original".to_string())]
            .into_iter()
            .collect(),
        binary_secrets: Default::default(),
        created: Some(Timestamp::now()),
        modified: Some(Timestamp::now()),
        host: Some("other".into()),
        revision: 1,
        version: crate::document::DOCUMENT_VERSION,
    };
    let hand = crate::SopsCommand::new("sops", &fixture.key_file);
    let plain = document.to_yaml().unwrap();
    let cipher = hand
        .encrypt(
            plain.as_bytes(),
            Some(&format!("{},{}", fixture.recipient, second_recipient)),
            &fixture.root,
        )
        .await
        .expect("encrypt to two recipients");
    std::fs::write(fixture.item_path("default", "shared-item"), cipher).unwrap();

    // Now update it through a provider configured with one recipient.
    let provider = fixture.provider();
    unlock(&provider).await;
    provider
        .update_item(
            "shared-item",
            ItemUpdate {
                secrets: Some(HashMap::from([(
                    "secret".to_string(),
                    SecretBytes::new(b"changed".to_vec()),
                )])),
                ..Default::default()
            },
        )
        .await
        .expect("update");

    let cipher = std::fs::read_to_string(fixture.item_path("default", "shared-item")).unwrap();
    assert!(
        cipher.contains(&fixture.recipient),
        "the configured recipient must stay"
    );
    assert!(
        cipher.contains(&second_recipient),
        "the pre-existing recipient must survive an update, not be narrowed away"
    );

    // The second identity still opens the updated file.
    let reader_config =
        SopsConfig::new(&fixture.root, &second_key, &second_recipient, "sops").unwrap();
    let reader = SopsProvider::new("reader", reader_config);
    unlock(&reader).await;
    assert_eq!(
        read_secret(&reader, "shared-item", "secret").await,
        "changed".to_string()
    );
}

#[tokio::test]
async fn without_age_recipient_the_store_creation_rule_decides() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    std::fs::create_dir_all(&fixture.root).unwrap();
    std::fs::write(
        fixture.root.join(".sops.yaml"),
        format!(
            "creation_rules:\n  - path_regex: .*\\.sops\\.yaml$\n    age: {}\n",
            fixture.recipient
        ),
    )
    .unwrap();

    let provider = Arc::new(SopsProvider::new(
        "rules",
        fixture.config_without_recipient(),
    ));
    unlock(&provider).await;
    let id = provider
        .create_item(new_item("from-rules", &[("secret", "v")]), false)
        .await
        .expect("create through the creation rule");

    let cipher = std::fs::read_to_string(fixture.item_path("default", &id)).unwrap();
    assert!(
        cipher.contains(&fixture.recipient),
        "the creation rule's recipient must be in the header: {cipher}"
    );
    assert_eq!(read_secret(&provider, &id, "secret").await, "v");

    // An update keeps the recipients the file already has.
    provider
        .update_item(
            &id,
            ItemUpdate {
                secrets: Some(HashMap::from([(
                    "secret".to_string(),
                    SecretBytes::new(b"w".to_vec()),
                )])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let cipher = std::fs::read_to_string(fixture.item_path("default", &id)).unwrap();
    assert!(cipher.contains(&fixture.recipient));
}

#[tokio::test]
async fn without_age_recipient_and_without_a_rule_the_write_fails_cleanly() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = Arc::new(SopsProvider::new(
        "no-rules",
        fixture.config_without_recipient(),
    ));
    unlock(&provider).await;
    let error = provider
        .create_item(new_item("nope", &[("secret", "v")]), false)
        .await
        .expect_err("no recipient and no creation rule must fail");
    let text = format!("{error}");
    assert!(
        text.contains("no encryption keys"),
        "the error must name the missing keys, got: {text}"
    );
}

#[test]
fn accepts_a_comma_separated_recipient_list() {
    let a = "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000";
    let b = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    let config = SopsConfig::new("/tmp/store", "/tmp/keys.txt", format!("{a}, {b}"), "sops")
        .expect("a list of recipients is valid");
    assert_eq!(config.age_recipient, format!("{a}, {b}"));
    // One bad entry rejects the whole list.
    assert!(SopsConfig::new("/tmp/store", "/tmp/keys.txt", format!("{a},nope"), "sops").is_err());
}

// ---------------------------------------------------------------------------
// R4: the unlock probe
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unlock_fails_when_the_identity_cannot_decrypt_the_store() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    {
        let provider = fixture.provider();
        unlock(&provider).await;
        provider
            .create_item(new_item("probe", &[("secret", "v")]), false)
            .await
            .unwrap();
    }

    // A different identity file — the YubiKey-in-the-wrong-slot case.
    let other_dir = tempfile::tempdir().unwrap();
    let other_key = other_dir.path().join("age-keys.txt");
    generate_identity(&other_key);
    let config = SopsConfig::new(&fixture.root, &other_key, &fixture.recipient, "sops").unwrap();
    let provider = SopsProvider::new("wrong-identity", config);
    let error = provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
        .expect_err("unlock must fail when the identity cannot decrypt");
    assert!(
        matches!(error, ProviderError::AuthFailed),
        "a wrong identity must report AuthFailed, got {error:?}"
    );
    assert!(
        provider.status().await.unwrap().locked,
        "a failed unlock must leave the provider locked"
    );
    assert!(
        matches!(provider.list_items().await, Err(ProviderError::Locked)),
        "a failed unlock leaves the provider locked"
    );
}

#[tokio::test]
async fn unlock_probes_an_existing_store_without_creating_anything() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    // An empty store: nothing to prove, so unlock succeeds.
    let provider = fixture.provider();
    unlock(&provider).await;
    assert!(!provider.status().await.unwrap().locked);
    // The probe must not leave a file behind.
    let files: Vec<_> = std::fs::read_dir(fixture.root.join("default"))
        .map(|dir| dir.filter_map(Result::ok).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        files.is_empty(),
        "the unlock probe must not create store files: {files:?}"
    );
}

#[tokio::test]
async fn an_unreadable_meta_file_does_not_hide_the_collection() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let id = provider
        .create_item(new_item("visible", &[("secret", "v")]), false)
        .await
        .unwrap();
    // A garbage meta file must fall back to the directory name.
    std::fs::write(
        fixture.root.join("default").join(COLLECTION_META),
        b"not sops",
    )
    .unwrap();
    let items = provider.list_items().await.unwrap();
    assert_eq!(items.len(), 1, "items must survive a broken meta file");
    assert_eq!(items[0].id, id);
    assert_eq!(
        items[0].attributes.get("collection").map(String::as_str),
        Some("default")
    );
}

// ---------------------------------------------------------------------------
// R1: conflict copies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn newest_modified_conflict_copy_wins_and_loser_stays_on_disk() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let id = provider
        .create_item(new_item("shared", &[("secret", "old")]), false)
        .await
        .expect("create");
    let canonical = fixture.item_path("default", &id);

    // Build a Syncthing-style conflict copy: same id, newer `modified`,
    // different secret and a different host.
    let store = provider.store().clone();
    let canonical_doc = store.load_document(&canonical).await.unwrap();
    let mut copy = canonical_doc.clone();
    copy.secrets
        .insert("secret".into(), "new-from-other-host".into());
    copy.modified = Some(Timestamp(
        std::time::SystemTime::now() + std::time::Duration::from_secs(60),
    ));
    copy.host = Some("zzz-otherhost".into());
    copy.revision = canonical_doc.revision + 1;

    // Syncthing renames the *whole* name, so the marker lands after the
    // `.sops.yaml` suffix: `<id>.sops.yaml.sync-conflict-<date>-<time>-<device>`.
    let conflict_name = format!("{id}.sops.yaml{SYNCTHING_CONFLICT_MARKER}20261114-181502-ZZZZZZZ");
    fixture_copy(&fixture, &conflict_name, &copy).await;

    let conflict_on_disk = fixture.root.join("default").join(&conflict_name);
    assert!(conflict_on_disk.is_file());

    // The provider serves the newer copy…
    assert_eq!(
        read_secret(&provider, &id, "secret").await,
        "new-from-other-host".to_string()
    );
    // …flags it…
    let attrs = provider.get_item_attributes(&id).await.unwrap();
    assert_eq!(
        attrs.public.get(ATTR_CONFLICT).map(String::as_str),
        Some("true")
    );
    // …lists the id once…
    let items = provider.list_items().await.unwrap();
    assert_eq!(items.len(), 1, "one item per id, not one per file");
    // …and a read never deletes the loser.
    assert!(
        conflict_on_disk.is_file(),
        "conflict copy must stay on disk"
    );
    assert!(canonical.is_file(), "canonical file must stay on disk");

    let _ = provider.list_items().await.unwrap();
    assert!(conflict_on_disk.is_file());
    assert!(canonical.is_file());
}

#[tokio::test]
async fn a_write_archives_the_superseded_conflict_copy_and_keeps_winning() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let id = provider
        .create_item(new_item("shared", &[("secret", "old")]), false)
        .await
        .unwrap();
    let canonical = fixture.item_path("default", &id);
    let store = provider.store().clone();

    // The freshest copy is a conflict copy from another host.
    let mut copy = store.load_document(&canonical).await.unwrap();
    copy.secrets
        .insert("secret".into(), "from-other-host".into());
    copy.modified = Some(Timestamp(
        std::time::SystemTime::now() + std::time::Duration::from_secs(60),
    ));
    copy.host = Some("otherhost".into());
    copy.revision += 1;
    let conflict_name = format!("{id}.sops.yaml{SYNCTHING_CONFLICT_MARKER}20261114-181502-ZZZZZZZ");
    fixture_copy(&fixture, &conflict_name, &copy).await;
    let conflict_on_disk = fixture.root.join("default").join(&conflict_name);
    assert!(conflict_on_disk.is_file());

    // A read-modify-write must land on the canonical file and retire the copy.
    provider
        .update_item(
            &id,
            ItemUpdate {
                secrets: Some(HashMap::from([(
                    "secret".to_string(),
                    SecretBytes::new(b"merged".to_vec()),
                )])),
                ..Default::default()
            },
        )
        .await
        .expect("update");

    // The canonical file holds the merged value...
    let canonical_doc = store.load_document(&canonical).await.unwrap();
    assert_eq!(
        canonical_doc.secrets.get("secret").map(String::as_str),
        Some("merged")
    );
    // ...the divergent copy is archived, not left live and not deleted...
    assert!(
        !conflict_on_disk.exists(),
        "the superseded copy must no longer resolve as a candidate"
    );
    let archives: Vec<PathBuf> = std::fs::read_dir(fixture.root.join("default"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with(SUPERSEDED_PREFIX))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(archives.len(), 1, "exactly one archive, got {archives:?}");
    let archive_name = archives[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(archive_name.contains(&id), "{archive_name}");
    assert!(archive_name.ends_with(".sops.yaml"), "{archive_name}");
    // The archive holds the losing value, decrypted, for review.
    let archived_doc = store.load_document(&archives[0]).await.unwrap();
    assert_eq!(
        archived_doc.secrets.get("secret").map(String::as_str),
        Some("from-other-host"),
        "the archive must keep the losing value"
    );

    // Re-resolution keeps returning the written value, even after the clock
    // moves past the copy's `modified`: the copy no longer participates.
    let later = Timestamp(std::time::SystemTime::now() + std::time::Duration::from_secs(3600));
    let mut rewritten = canonical_doc.clone();
    rewritten.modified = Some(later);
    let plain = rewritten.to_yaml().unwrap();
    let sops = crate::SopsCommand::new("sops", &fixture.key_file);
    let cipher = sops
        .encrypt(plain.as_bytes(), Some(&fixture.recipient), &fixture.root)
        .await
        .unwrap();
    std::fs::write(&canonical, cipher).unwrap();
    provider.store().cache().clear();
    assert_eq!(
        read_secret(&provider, &id, "secret").await,
        "merged",
        "the winner must be deterministic after the archive"
    );
    assert_eq!(provider.list_items().await.unwrap().len(), 1);
}

#[tokio::test]
async fn deleting_an_item_removes_its_archive_too() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let id = provider
        .create_item(new_item("gone", &[("secret", "v")]), false)
        .await
        .unwrap();
    let mut copy = provider
        .store()
        .load_document(&fixture.item_path("default", &id))
        .await
        .unwrap();
    copy.modified = Some(Timestamp(
        std::time::SystemTime::now() + std::time::Duration::from_secs(30),
    ));
    fixture_copy(
        &fixture,
        &format!("{id}.sops.yaml{SYNCTHING_CONFLICT_MARKER}20261114-181502-ZZZZZZZ"),
        &copy,
    )
    .await;
    provider
        .update_item(&id, ItemUpdate::default())
        .await
        .unwrap();
    provider.delete_item(&id).await.expect("delete");
    let leftovers: Vec<String> = std::fs::read_dir(fixture.root.join("default"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(&id))
        .collect();
    assert!(leftovers.is_empty(), "files left behind: {leftovers:?}");
}

#[tokio::test]
async fn equal_modified_prefers_canonical_then_greater_host() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    let id = provider
        .create_item(new_item("tie", &[("secret", "canonical")]), false)
        .await
        .unwrap();
    let store = provider.store().clone();
    let canonical = store
        .load_document(&fixture.item_path("default", &id))
        .await
        .unwrap();

    // Same `modified`, host sorts *before* the canonical host name, so the
    // canonical must win the tie.
    let mut older_host = canonical.clone();
    older_host
        .secrets
        .insert("secret".into(), "from-aaa-host".into());
    older_host.host = Some("aaa-host".into());
    fixture_copy(
        &fixture,
        &format!("{id}.sops.yaml{SYNCTHING_CONFLICT_MARKER}20261114-181600-AAAAAAA"),
        &older_host,
    )
    .await;

    assert_eq!(
        read_secret(&provider, &id, "secret").await,
        "canonical".to_string(),
        "canonical wins an equal-`modified` tie"
    );

    // A greater host name wins the tie instead.
    let mut newer_host = canonical.clone();
    newer_host
        .secrets
        .insert("secret".into(), "from-zzz-host".into());
    newer_host.host = Some("zzz-host".into());
    fixture_copy(
        &fixture,
        &format!("{id}.sops.yaml{SYNCTHING_CONFLICT_MARKER}20261114-181700-ZZZZZZZ"),
        &newer_host,
    )
    .await;

    assert_eq!(
        read_secret(&provider, &id, "secret").await,
        "from-zzz-host".to_string(),
        "the lexicographically greater host wins"
    );
}

/// Encrypt `document` into `default/<name>` with the fixture's recipient.
async fn fixture_copy(fixture: &Fixture, name: &str, document: &SopsDocument) {
    let dir = fixture.root.join("default");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = document.to_yaml().unwrap();
    let sops = crate::SopsCommand::new("sops", &fixture.key_file);
    let cipher = sops
        .encrypt(plain.as_bytes(), Some(&fixture.recipient), &fixture.root)
        .await
        .expect("encrypt conflict copy");
    std::fs::write(dir.join(name), cipher).unwrap();
}

// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_locked_provider_reports_locked_instead_of_an_empty_list() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let id = provider
        .create_item(new_item("locked", &[("secret", "s")]), false)
        .await
        .unwrap();
    assert_eq!(provider.list_items().await.unwrap().len(), 1);

    provider.lock().await.unwrap();
    assert!(provider.status().await.unwrap().locked);
    assert!(
        matches!(provider.list_items().await, Err(ProviderError::Locked)),
        "`Ok([])` would be a complete refresh of zero items and wipe the daemon cache"
    );
    assert!(
        matches!(
            provider.search(&HashMap::new()).await,
            Err(ProviderError::Locked)
        ),
        "search must report Locked too"
    );
    assert!(
        provider.store().cache().is_empty(),
        "lock must drop the cache"
    );
    assert!(matches!(
        provider.get_secret_attr(&id, "secret").await,
        Err(ProviderError::Locked)
    ));
    assert!(matches!(
        provider
            .create_item(new_item("new", &[("secret", "x")]), false)
            .await,
        Err(ProviderError::Locked)
    ));
    assert!(matches!(
        provider.update_item(&id, ItemUpdate::default()).await,
        Err(ProviderError::Locked)
    ));
    assert!(matches!(
        provider.delete_item(&id).await,
        Err(ProviderError::Locked)
    ));
}

#[tokio::test]
async fn unlock_requires_the_age_identity_file() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    std::fs::remove_file(&fixture.key_file).unwrap();
    let provider = fixture.provider();
    let error = provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
        .expect_err("unlock must fail without a key file");
    let text = format!("{error}");
    assert!(
        text.contains("age identity file"),
        "unexpected error: {text}"
    );
    assert!(provider.status().await.unwrap().locked);
}

#[tokio::test]
async fn unlock_requires_the_sops_binary() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let config = SopsConfig::new(
        &fixture.root,
        &fixture.key_file,
        &fixture.recipient,
        "/nonexistent/sops",
    )
    .unwrap();
    let provider = SopsProvider::new("no-sops", config);
    let error = provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
        .expect_err("unlock must fail without the binary");
    assert!(
        format!("{error}").contains("cannot run"),
        "unexpected error: {error}"
    );
}

// ---------------------------------------------------------------------------
// R5: no plaintext in error paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_decryption_failure_does_not_leak_plaintext() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let id = provider
        .create_item(new_item("leak", &[("secret", "swordfish")]), false)
        .await
        .unwrap();
    let path = fixture.item_path("default", &id);

    // Craft a file that claims to be sops ciphertext but carries a plaintext
    // value where sops expects an `ENC[...]` marker: sops then fails while
    // quoting the offending line.
    let crafted = "label: leak\n\
                   secrets:\n  \
                   secret: swordfish-LEAK-ME\n\
                   sops:\n  \
                   age:\n    - recipient: age1notarealrecipient\n  \
                   version: 3.13.3\n";
    std::fs::write(&path, crafted).unwrap();
    provider.store().cache().clear();

    let store = provider.store().clone();
    let error = store.load_document(&path).await.expect_err("must fail");
    let text = format!("{error}");
    assert!(
        !text.contains("LEAK-ME"),
        "plaintext reached the error text: {text}"
    );

    // Through the provider too: the read fails, and the rendered error names
    // no plaintext.
    let error = provider
        .get_secret_attr(&id, "secret")
        .await
        .expect_err("a malformed ciphertext must not yield a value");
    let text = format!("{error}");
    assert!(
        !text.contains("LEAK-ME"),
        "plaintext reached the provider error: {text}"
    );
}

#[test]
fn a_crafted_sops_error_cannot_leak_a_secret() {
    let secret = "s3cr3t-from-a-test";
    // Every shape a sops failure can take, all quoting plaintext.
    let shapes = [
        format!("Error decrypting data key: failed\n  secrets:\n    secret: {secret}"),
        format!("unmarshal of yaml failed: {secret}\nENC[AES256_GCM,data:AA]"),
        format!("shredding failed for value {secret}"),
        format!("no keys provided; value was {secret}"),
    ];
    for stderr in shapes {
        let class = crate::sops::classify_stderr(stderr.as_bytes());
        assert!(
            !class.contains(secret),
            "the classified reason leaked plaintext: {class}"
        );
        let error = SopsError::SopsFailed {
            args: "--encrypt".into(),
            status: "exit 1".into(),
            reason: class,
        };
        assert!(!format!("{error}").contains(secret));
    }
}

// ---------------------------------------------------------------------------
// Path and option validation
// ---------------------------------------------------------------------------

#[test]
fn rejects_bad_paths_and_recipients() {
    // A relative store path must fail.
    assert!(
        SopsConfig::new(
            "relative/store",
            "/tmp/keys.txt",
            "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000",
            "sops"
        )
        .is_err()
    );
    // A relative key file must fail.
    assert!(
        SopsConfig::new(
            "/tmp/store",
            "keys.txt",
            "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000",
            "sops"
        )
        .is_err()
    );
    // A non-age recipient must fail.
    assert!(SopsConfig::new("/tmp/store", "/tmp/keys.txt", "ssh-ed25519 AAAA", "sops").is_err());
    // `~/` expands and stays absolute.
    let config = SopsConfig::new(
        "~/store",
        "~/.config/sops/age/keys.txt",
        "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000",
        "sops",
    )
    .expect("tilde paths are accepted");
    assert!(config.path.is_absolute());
    assert!(config.key_file.is_absolute());
}

#[tokio::test]
async fn rejects_item_ids_that_escape_the_store() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    for bad in ["../escape", "a/b", "with:colon"] {
        assert!(
            matches!(
                provider.get_secret_attr(bad, "secret").await,
                Err(ProviderError::NotFound) | Err(ProviderError::InvalidInput(_))
            ),
            "`{bad}` must not resolve"
        );
    }
    assert!(
        std::fs::read_dir(fixture._dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .all(|e| e.file_name() != "escape.sops.yaml"),
        "no file may be created outside the store"
    );
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn collection_label_comes_from_the_meta_file() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;

    provider
        .store()
        .write_collection_meta("default", "My Default Collection")
        .await
        .unwrap();
    assert!(
        fixture.root.join("default").join(COLLECTION_META).is_file(),
        "a renamed collection needs a meta file"
    );
    provider
        .create_item(new_item("thing", &[("secret", "v")]), false)
        .await
        .unwrap();

    let items = provider.list_items().await.unwrap();
    assert_eq!(
        items[0].attributes.get("collection").map(String::as_str),
        Some("My Default Collection")
    );

    // Writing the directory name as the label removes a redundant meta file.
    provider
        .store()
        .write_collection_meta("default", "default")
        .await
        .unwrap();
    assert!(
        !fixture.root.join("default").join(COLLECTION_META).exists(),
        "the directory name needs no file"
    );
    let items = provider.list_items().await.unwrap();
    assert_eq!(
        items[0].attributes.get("collection").map(String::as_str),
        Some("default")
    );

    // A collection without a meta file falls back to the directory name.
    let other = fixture.root.join("work");
    std::fs::create_dir_all(&other).unwrap();
    let doc = SopsDocument {
        label: "work item".into(),
        attributes: Default::default(),
        secrets: [("secret".to_string(), "w".to_string())]
            .into_iter()
            .collect(),
        binary_secrets: Default::default(),
        created: Some(Timestamp::now()),
        modified: Some(Timestamp::now()),
        host: Some("t".into()),
        revision: 1,
        version: crate::document::DOCUMENT_VERSION,
    };
    fixture_copy_to(&fixture, "work", "manual.sops.yaml", &doc).await;
    let items = provider.list_items().await.unwrap();
    let manual = items
        .iter()
        .find(|i| i.label == "work item")
        .expect("item from the work directory");
    assert_eq!(
        manual.attributes.get("collection").map(String::as_str),
        Some("work")
    );
    assert_eq!(
        manual
            .attributes
            .get(ATTR_COLLECTION_DIR)
            .map(String::as_str),
        Some("work")
    );
    // Non-default collections get a qualified id.
    assert!(manual.id.starts_with("work/"), "got {}", manual.id);
}

async fn fixture_copy_to(fixture: &Fixture, collection: &str, name: &str, document: &SopsDocument) {
    let dir = fixture.root.join(collection);
    std::fs::create_dir_all(&dir).unwrap();
    let plain = document.to_yaml().unwrap();
    let sops = crate::SopsCommand::new("sops", &fixture.key_file);
    let cipher = sops
        .encrypt(plain.as_bytes(), Some(&fixture.recipient), &fixture.root)
        .await
        .expect("encrypt");
    std::fs::write(dir.join(name), cipher).unwrap();
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

#[test]
fn errors_map_to_provider_errors() {
    assert!(matches!(
        SopsError::Locked.into_provider_error(),
        ProviderError::Locked
    ));
    assert!(matches!(
        SopsError::NotFound("x".into()).into_provider_error(),
        ProviderError::NotFound
    ));
    assert!(matches!(
        SopsError::Config("bad".into()).into_provider_error(),
        ProviderError::InvalidInput(_)
    ));
    assert!(matches!(
        SopsError::Unreadable {
            path: "p".into(),
            reason: "r".into()
        }
        .into_provider_error(),
        ProviderError::AuthFailed
    ));
}

#[test]
fn provider_declares_write_capability() {
    let fixture_key = Path::new("/tmp/unused-keys.txt");
    let config = SopsConfig::new(
        "/tmp/store",
        fixture_key,
        "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000",
        "sops",
    )
    .unwrap();
    let provider = SopsProvider::new("x", config);
    assert!(provider.capabilities().contains(&Capability::Write));
    assert_eq!(provider.kind(), "sops");
}

// ---------------------------------------------------------------------------
// R2: conflict markers and `rosec-sops conflicts`
// ---------------------------------------------------------------------------

/// A known secret value every marker test writes and then searches for.
const MARKER_SECRET: &str = "marker-test-KNOWN-SECRET-9f3a";

/// Create an item, then a newer Syncthing conflict copy from another host, so
/// the next write archives the copy. Returns `(id, canonical, conflict)`.
async fn two_writer_conflict(
    fixture: &Fixture,
    provider: &SopsProvider,
    secret_name: &str,
) -> (String, PathBuf, PathBuf) {
    let id = provider
        .create_item(new_item("shared", &[(secret_name, MARKER_SECRET)]), false)
        .await
        .expect("create");
    let canonical = fixture.item_path("default", &id);
    let mut copy = provider.store().load_document(&canonical).await.unwrap();
    copy.secrets.insert(
        secret_name.into(),
        format!("{MARKER_SECRET}-LOSER-from-earlier-copy"),
    );
    copy.modified = Some(Timestamp(
        std::time::SystemTime::now() + std::time::Duration::from_secs(60),
    ));
    copy.host = Some("otherhost".into());
    copy.revision += 1;
    let name = format!("{id}.sops.yaml{SYNCTHING_CONFLICT_MARKER}20261114-181502-ZZZZZZZ");
    fixture_copy(fixture, &name, &copy).await;
    (id, canonical, fixture.root.join("default").join(&name))
}

#[tokio::test]
async fn a_conflict_writes_a_marker_that_resolution_removes() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let (id, canonical, _copy) = two_writer_conflict(&fixture, &provider, "secret").await;

    // Nothing is recorded before a write archives a copy.
    assert!(
        crate::conflicts::list_markers(&fixture.root)
            .await
            .unwrap()
            .is_empty()
    );

    provider
        .update_item(
            &id,
            ItemUpdate {
                secrets: Some(HashMap::from([(
                    "secret".to_string(),
                    SecretBytes::new(b"merged".to_vec()),
                )])),
                ..Default::default()
            },
        )
        .await
        .expect("update");

    // 1. a marker exists, under the collection, named after the item
    let marker_file = crate::conflicts::marker_path(&fixture.root, "default", &id);
    assert!(
        marker_file.is_file(),
        "no marker at {}",
        marker_file.display()
    );
    let markers = crate::conflicts::list_markers(&fixture.root).await.unwrap();
    assert_eq!(markers.len(), 1);
    let marker = markers[0].marker.clone();
    assert_eq!(marker.item, id);
    assert_eq!(marker.collection, "default");
    // The label lives inside the encrypted document, so a marker written
    // without decrypting may fall back to the collection label.
    assert!(
        marker.label == "shared" || marker.label == "default",
        "unexpected label {:?}",
        marker.label
    );
    assert_eq!(marker.winner, format!("default/{id}.sops.yaml"));
    assert_eq!(marker.losers.len(), 1, "one archived loser: {marker:?}");
    assert!(
        marker.losers[0].file.starts_with("default/.superseded-"),
        "{:?}",
        marker.losers[0].file
    );
    assert_eq!(marker.losers[0].host.as_deref(), Some("otherhost"));
    assert_eq!(marker.losers[0].revision, 2);
    assert!(marker.losers[0].modified.is_some());

    // 2. the provider flags the item for a client
    let attrs = provider.get_item_attributes(&id).await.unwrap().public;
    assert_eq!(
        attrs
            .get(crate::ATTR_UNRESOLVED_CONFLICT)
            .map(String::as_str),
        Some("true"),
        "an unresolved marker must be visible through the provider"
    );
    let listed = provider.list_items().await.unwrap();
    assert_eq!(
        listed[0]
            .attributes
            .get(crate::ATTR_UNRESOLVED_CONFLICT)
            .map(String::as_str),
        Some("true")
    );

    // 3. resolution keeps the winner and removes the marker
    let store = provider.store().clone();
    let resolution = store
        .resolve_conflict("default", &id, &WindowlessKeep::WINNER)
        .await
        .expect("resolve keeping the winner");
    assert_eq!(resolution.kept, canonical);
    assert!(!resolution.promoted);
    assert_eq!(resolution.deleted.len(), 1);
    assert!(!marker_file.exists(), "the marker must be gone");
    assert!(
        store
            .archived_copies_of("default", &id)
            .await
            .unwrap()
            .is_empty(),
        "no archive may survive a resolution"
    );
    assert!(canonical.is_file());
    // The kept value is the merged one.
    assert_eq!(
        read_secret(&provider, &id, "secret").await,
        "merged".to_string()
    );
    // 4. the flag disappears with the marker
    let attrs = provider.get_item_attributes(&id).await.unwrap().public;
    assert!(!attrs.contains_key(crate::ATTR_UNRESOLVED_CONFLICT));
    // 5. a resolution needs a marker
    let refused = store
        .resolve_conflict("default", &id, &WindowlessKeep::WINNER)
        .await
        .expect_err("a second resolution must refuse");
    assert!(
        matches!(refused, crate::SopsError::NotFound(_)),
        "{refused}"
    );
}

/// Shorthand for the `Keep` values, so a test reads as prose.
struct WindowlessKeep;

impl WindowlessKeep {
    const WINNER: crate::store::Keep = crate::store::Keep::Winner;
    const LOSER: crate::store::Keep = crate::store::Keep::Loser;
}

#[tokio::test]
async fn resolving_can_keep_the_loser() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let (id, canonical, _copy) = two_writer_conflict(&fixture, &provider, "secret").await;
    provider
        .update_item(
            &id,
            ItemUpdate {
                secrets: Some(HashMap::from([(
                    "secret".to_string(),
                    SecretBytes::new(b"merged".to_vec()),
                )])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let store = provider.store().clone();
    let losers = store.archived_copies_of("default", &id).await.unwrap();
    assert_eq!(losers.len(), 1);

    // A resolution decrypts the kept copy; `store` was cloned before the write
    // above, so share the provider's cache first.
    let store = fixture.provider().store().clone();
    let resolution = store
        .resolve_conflict("default", &id, &WindowlessKeep::LOSER)
        .await
        .expect("resolve keeping the loser");
    assert!(resolution.promoted, "the loser must be promoted");
    assert_eq!(resolution.kept, losers[0]);
    assert_eq!(
        resolution.unarchived.len(),
        1,
        "the previous canonical file must be archived, not deleted: {resolution:?}"
    );
    // The loser is now the canonical file, and it decrypts.
    assert!(canonical.is_file());
    assert!(!losers[0].exists(), "the archive must have been promoted");
    provider.store().cache().clear();
    let served = provider.store().load_document(&canonical).await.unwrap();
    assert_eq!(
        served.secrets.get("secret").map(String::as_str),
        Some(format!("{MARKER_SECRET}-LOSER-from-earlier-copy").as_str())
    );
    // The replaced winner still exists, archived.
    let archived = &resolution.unarchived[0];
    assert!(archived.is_file());
    // The write already removed the marker; the early one is gone too.
    assert!(
        !crate::conflicts::marker_path(&fixture.root, "default", &id).exists(),
        "the marker must be gone"
    );
}

#[tokio::test]
async fn resolving_can_keep_a_named_file() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let (id, canonical, _copy) = two_writer_conflict(&fixture, &provider, "secret").await;
    provider
        .update_item(&id, ItemUpdate::default())
        .await
        .unwrap();
    let store = provider.store().clone();
    let losers = store.archived_copies_of("default", &id).await.unwrap();
    let relative = store.relative(&losers[0]);
    let keep = crate::store::Keep::File(relative.clone());
    let resolution = store
        .resolve_conflict("default", &id, &keep)
        .await
        .expect("resolve keeping a named file");
    assert!(resolution.promoted);
    assert_eq!(resolution.kept, losers[0]);
    assert!(canonical.is_file());

    // A file that belongs to no copy is refused before anything changes.
    let bogus = crate::store::Keep::File("default/nope.sops.yaml".into());
    let fixture_b = Fixture::new();
    let provider_b = fixture_b.provider();
    unlock(&provider_b).await;
    let (id_b, _, _) = two_writer_conflict(&fixture_b, &provider_b, "secret").await;
    provider_b
        .update_item(&id_b, ItemUpdate::default())
        .await
        .unwrap();
    let store_b = provider_b.store().clone();
    let before = store_b.archived_copies_of("default", &id_b).await.unwrap();
    let refused = store_b
        .resolve_conflict("default", &id_b, &bogus)
        .await
        .expect_err("an unknown file must be refused");
    assert!(
        matches!(refused, crate::SopsError::NotFound(_)),
        "{refused}"
    );
    assert_eq!(
        store_b.archived_copies_of("default", &id_b).await.unwrap(),
        before,
        "a refusal must not touch the store"
    );
    assert!(crate::conflicts::marker_path(&fixture_b.root, "default", &id_b).exists());
}

#[tokio::test]
async fn resolving_an_unknown_id_is_refused() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let store = provider.store().clone();
    for (collection, id) in [
        ("default", "item-does-not-exist"),
        ("no-such-collection", "item-x"),
    ] {
        let refused = store
            .resolve_conflict(collection, id, &WindowlessKeep::WINNER)
            .await
            .expect_err("an unknown id must be refused");
        assert!(
            matches!(refused, crate::SopsError::NotFound(_)),
            "{refused}"
        );
    }
    assert!(
        crate::conflicts::list_markers(&fixture.root)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_marker_never_holds_a_secret_value() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let (id, _, _) = two_writer_conflict(&fixture, &provider, "secret").await;
    // A second, differently named secret that must stay out of the marker too.
    let update = ItemUpdate {
        secrets: Some(HashMap::from([
            (
                "secret".to_string(),
                SecretBytes::new(b"winner-value-KNOWN-SECRET-4b1c".to_vec()),
            ),
            (
                "password".to_string(),
                SecretBytes::new(b"another-KNOWN-SECRET-77de".to_vec()),
            ),
        ])),
        ..Default::default()
    };
    provider.update_item(&id, update).await.unwrap();

    let path = crate::conflicts::marker_path(&fixture.root, "default", &id);
    let text = std::fs::read_to_string(&path).expect("marker");
    for secret in [
        MARKER_SECRET,
        "winner-value-KNOWN-SECRET-4b1c",
        "another-KNOWN-SECRET-77de",
        "merged",
        "LOSER-from-earlier-copy",
    ] {
        assert!(
            !text.contains(secret),
            "secret `{secret}` leaked into the marker:\n{text}"
        );
    }
    // Names, not values, are the readable part.
    assert!(text.contains("secret"), "{text}");
    assert!(text.contains("password"), "{text}");
}

#[tokio::test]
async fn deleting_a_conflicted_item_removes_its_marker() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.provider();
    unlock(&provider).await;
    let (id, _, _) = two_writer_conflict(&fixture, &provider, "secret").await;
    provider
        .update_item(&id, ItemUpdate::default())
        .await
        .unwrap();
    let marker = crate::conflicts::marker_path(&fixture.root, "default", &id);
    assert!(marker.is_file());
    provider.delete_item(&id).await.expect("delete");
    assert!(!marker.is_file(), "a deleted item must leave no marker");
    assert!(
        crate::conflicts::list_markers(&fixture.root)
            .await
            .unwrap()
            .is_empty()
    );
}
