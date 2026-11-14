//! Integration test for the `rosec-sops` binary.
//!
//! Drives the real binary over a temporary store with a generated age key:
//! create a conflict through the provider (so the write archives a copy and
//! writes the marker), then `conflicts list --json`, `conflicts show`,
//! `conflicts resolve --keep loser` and a second `list`. Every command output
//! is also searched for the known secret value.
//!
//! The test skips itself when `sops` or `age-keygen` is missing, like the
//! provider unit tests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use rosec_core::{ItemUpdate, NewItem, Provider, SecretBytes, UnlockInput};
use rosec_sops::{SopsConfig, SopsProvider, Timestamp};
use zeroize::Zeroizing;

const SECRET: &str = "cli-test-KNOWN-SECRET-2f8c";

fn has_tools() -> bool {
    ["sops", "age-keygen"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn binary() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for the integration test.
    PathBuf::from(env!("CARGO_BIN_EXE_rosec-sops"))
}

fn run(store: &Path, args: &[&str]) -> (i32, String, String) {
    run_env(store, args, &[])
}

fn run_env(store: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut command = Command::new(binary());
    command.arg("--store").arg(store).args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("run rosec-sops");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

async fn conflicted_store(
    root: &Path,
    key_file: &Path,
    recipient: &str,
    provider: &SopsProvider,
) -> String {
    let item = NewItem {
        content_types: HashMap::new(),
        label: "cli demo".into(),
        item_type: None,
        attributes: HashMap::from([("username".to_string(), "user".to_string())]),
        secrets: HashMap::from([(
            "password".to_string(),
            SecretBytes::new(SECRET.as_bytes().to_vec()),
        )]),
    };
    let id = provider.create_item(item, false).await.expect("create");
    let canonical = root.join("default").join(format!("{id}.sops.yaml"));
    let mut copy = provider
        .store()
        .load_document(&canonical)
        .await
        .expect("winner");
    copy.secrets
        .insert("password".into(), format!("{SECRET}-loser"));
    copy.modified = Some(Timestamp(
        std::time::SystemTime::now() + std::time::Duration::from_secs(60),
    ));
    copy.host = Some("otherhost".into());
    copy.revision += 1;
    let plain = copy.to_yaml().expect("yaml");
    let cipher = rosec_sops::SopsCommand::new("sops", key_file)
        .encrypt(plain.as_bytes(), Some(recipient), root)
        .await
        .expect("encrypt copy");
    std::fs::write(
        root.join("default").join(format!(
            "{id}.sops.yaml.sync-conflict-20261114-181502-ZZZZZZZ"
        )),
        cipher,
    )
    .expect("write copy");
    provider.store().cache().clear();
    // A write archives the copy and writes the marker.
    provider
        .update_item(&id, ItemUpdate::default())
        .await
        .expect("update");
    id
}

#[tokio::test(flavor = "current_thread")]
async fn lists_shows_and_resolves_a_conflict_through_the_binary() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("store");
    let key_file = dir.path().join("age-keys.txt");
    let output = Command::new("age-keygen")
        .arg("-o")
        .arg(&key_file)
        .output()
        .expect("age-keygen");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let recipient = stderr
        .split_whitespace()
        .find(|word| word.starts_with("age1"))
        .expect("recipient")
        .to_owned();

    std::fs::create_dir_all(&root).expect("store root");
    rosec_sops::write_meta(
        &root,
        &rosec_sops::StoreMeta::new(rosec_sops::StoreMode::Direct),
    )
    .expect("store metadata");
    let config = SopsConfig::new(&root, &key_file, &recipient, "sops").expect("config");
    let provider = SopsProvider::new("cli-test", config);
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
        .expect("unlock");
    let id = conflicted_store(&root, &key_file, &recipient, &provider).await;

    // list --json
    let (code, stdout, stderr) = run(&root, &["conflicts", "list", "--json"]);
    assert_eq!(code, 0, "list failed: {stderr}");
    let rows: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let rows = rows.as_array().expect("array");
    assert_eq!(rows.len(), 1, "{stdout}");
    assert_eq!(rows[0]["item"], id.as_str());
    assert_eq!(rows[0]["collection"], "default");
    assert!(
        rows[0]["losers"][0]
            .as_str()
            .unwrap()
            .contains(".superseded-"),
        "{stdout}"
    );
    assert_eq!(rows[0]["loser_host"][0], "otherhost");
    assert!(
        !stdout.contains(SECRET),
        "a secret leaked into list: {stdout}"
    );

    // show
    let (code, stdout, stderr) = run(&root, &["conflicts", "show", &id]);
    assert_eq!(code, 0, "show failed: {stderr}");
    assert!(stdout.contains(&id), "{stdout}");
    assert!(stdout.contains("archived losers"), "{stdout}");
    assert!(
        !stdout.contains(SECRET),
        "a secret leaked into show: {stdout}"
    );

    // resolve, keeping the loser. The CLI starts its own `sops` for the
    // decrypt check, so it gets the identity file this test generated.
    let key = key_file.display().to_string();
    let (code, stdout, stderr) = run_env(
        &root,
        &["conflicts", "resolve", &id, "--keep", "loser"],
        &[("SOPS_AGE_KEY_FILE", key.as_str())],
    );
    assert_eq!(code, 0, "resolve failed: {stderr}");
    assert!(stdout.contains("promoted"), "{stdout}");
    assert!(
        !stdout.contains(SECRET),
        "a secret leaked into resolve: {stdout}"
    );

    // the marker is gone and the list is empty
    let (code, stdout, stderr) = run(&root, &["conflicts", "list"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("no conflicts"), "{stdout}");

    // a second resolution refuses
    let (code, _stdout, stderr) = run(&root, &["conflicts", "resolve", &id, "--keep", "winner"]);
    assert_eq!(code, 1, "a second resolve must fail");
    assert!(stderr.contains("no recorded conflict"), "{stderr}");

    // the promoted copy is the canonical file now
    let canonical = root.join("default").join(format!("{id}.sops.yaml"));
    let plain = rosec_sops::SopsCommand::new("sops", &key_file)
        .decrypt(&canonical)
        .await
        .expect("decrypt promoted file");
    let document = rosec_sops::SopsDocument::from_yaml(&plain, "<test>").expect("yaml");
    assert_eq!(
        document.secrets.get("password").map(String::as_str),
        Some(format!("{SECRET}-loser").as_str())
    );
}

#[test]
fn refuses_an_unknown_item_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    for args in [
        vec!["conflicts", "resolve", "item-unknown", "--keep", "winner"],
        vec!["conflicts", "show", "item-unknown"],
    ] {
        let (code, stdout, stderr) = run(dir.path(), &args);
        assert_eq!(code, 1, "{args:?} must fail: {stdout}{stderr}");
        assert!(stderr.contains("no recorded conflict"), "{stderr}");
    }
    // A bare id that no marker names is refused too.
    let (code, _stdout, stderr) = run(dir.path(), &["conflicts", "list"]);
    assert_eq!(code, 0, "{stderr}");
}

/// End to end through the binary: adopt a direct store, create a derived one,
/// migrate into it, inspect it. Every output is searched for the item secret.
#[tokio::test(flavor = "current_thread")]
async fn store_and_identity_commands_migrate_a_store_through_the_binary() {
    if !has_tools() {
        eprintln!("SKIP: sops or age-keygen missing");
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("source");
    let destination = dir.path().join("destination");
    let key_file = dir.path().join("age-keys.txt");
    let recipient = age_recipient(&key_file);
    std::fs::create_dir_all(&source).unwrap();

    // A direct store adopted with `store init --mode direct`, plus one item.
    let (code, stdout, stderr) = run(&source, &["store", "init", "--mode", "direct"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("direct"), "{stdout}");
    // A second, different mode is refused.
    let (code, _stdout, stderr) = run(&source, &["store", "init", "--mode", "derived", "--force"]);
    assert_eq!(code, 2, "the mode must not change in place");
    assert!(stderr.contains("Migrate into a new store"), "{stderr}");

    let config = SopsConfig::new(&source, &key_file, &recipient, "sops").expect("config");
    let provider = SopsProvider::new("cli-cli", config);
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
        .expect("unlock");
    let id = provider
        .create_item(
            NewItem {
                content_types: HashMap::new(),
                label: "migrated".into(),
                item_type: None,
                attributes: HashMap::new(),
                secrets: HashMap::from([(
                    "password".to_string(),
                    SecretBytes::new(SECRET.as_bytes().to_vec()),
                )]),
            },
            false,
        )
        .await
        .expect("create");
    // The daemon seeded a `default` collection: the store has items now.
    let _ = id;

    // Derived destination: mode, `.sops.yaml`, `identity init`.
    let (code, stdout, stderr) = run(&destination, &["store", "init", "--mode", "derived"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("identity init"), "{stdout}");
    // Master rule first; the item rule is filled in after `identity init`
    // has printed the derived recipient.
    std::fs::write(
        destination.join(".sops.yaml"),
        format!(
            "creation_rules:\n\
             \x20 - path_regex: ^\\.rosec-store-identity\\.sops\\.yaml$\n\
             \x20   age: {recipient}\n"
        ),
    )
    .unwrap();
    let key = key_file.display().to_string();
    let (code, stdout, stderr) = run_env(
        &destination,
        &["identity", "init"],
        &[("SOPS_AGE_KEY_FILE", key.as_str())],
    );
    assert_eq!(code, 0, "identity init failed: {stderr}");
    assert!(stdout.contains("derived recipient:"), "{stdout}");
    assert!(
        !stdout.contains("AGE-SECRET-KEY-1"),
        "a key leaked: {stdout}"
    );
    assert!(
        !stderr.contains("AGE-SECRET-KEY-1"),
        "a key leaked: {stderr}"
    );

    // Point the item rule at the derived recipient, as the init hint says.
    let derived = stdout
        .lines()
        .find_map(|line| line.strip_prefix("derived recipient: "))
        .expect("derived recipient")
        .trim()
        .to_owned();
    std::fs::write(
        destination.join(".sops.yaml"),
        format!(
            "creation_rules:\n\
             \x20 - path_regex: ^\\.rosec-store-identity\\.sops\\.yaml$\n\
             \x20   age: {recipient}\n\
             \x20 - path_regex: .*\\.sops\\.yaml$\n\
             \x20   age: {derived}\n"
        ),
    )
    .unwrap();

    // `identity show` needs no decryption and prints no secret.
    let (code, stdout, stderr) = run(&destination, &["identity", "show"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("mode:              derived"), "{stdout}");
    assert!(stdout.contains("runtime identity:  absent"), "{stdout}");
    assert!(!stdout.contains("AGE-SECRET-KEY-1"), "{stdout}");

    // Migrate the direct store into the derived one.
    let from = source.display().to_string();
    let to = destination.display().to_string();
    let (code, stdout, stderr) = run_env(
        &source,
        &["store", "migrate", "--from", &from, "--to", &to],
        &[("SOPS_AGE_KEY_FILE", key.as_str())],
    );
    assert_eq!(code, 0, "migrate failed: {stdout}{stderr}");
    assert!(stdout.contains("migrated 1 file(s)"), "{stdout}");
    assert!(stdout.contains("direct"), "{stdout}");
    assert!(stdout.contains("derived"), "{stdout}");
    assert!(!stdout.contains(SECRET), "a secret leaked: {stdout}");

    // The copied item is in the destination and opens with the derived key.
    let copied = destination.join("default").join(format!("{id}.sops.yaml"));
    assert!(
        copied.is_file(),
        "the item was not copied to {}",
        copied.display()
    );
    assert!(
        rosec_sops::SopsCommand::new("sops", &key_file)
            .decrypt(&copied)
            .await
            .is_err(),
        "the source key must not read the migrated item"
    );

    // A store without a mode is refused with the fix.
    let bare = dir.path().join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    let (code, _stdout, stderr) = run(&bare, &["store", "show"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("store init --mode"), "{stderr}");
}

/// The public recipient of a freshly generated identity file.
fn age_recipient(key_file: &Path) -> String {
    let output = Command::new("age-keygen")
        .arg("-o")
        .arg(key_file)
        .output()
        .expect("age-keygen");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stderr)
        .split_whitespace()
        .find(|word| word.starts_with("age1"))
        .expect("recipient")
        .to_owned()
}
