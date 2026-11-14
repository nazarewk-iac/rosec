//! Integration test: the sops provider behind the real Secret Service with the
//! real `secret-tool` client.
//!
//! Runs a private D-Bus session, registers `rosec-sops` as the only provider,
//! then drives `secret-tool store/lookup/clear` against it. Requires `sops`,
//! `age-keygen`, `dbus-daemon` and `secret-tool` on `PATH` — all present in the
//! devenv shell.
//!
//! The test is skipped (not failed) when a tool is missing, so `cargo test`
//! outside the shell stays green.

#[path = "../../tests/support/private_bus.rs"]
mod private_bus;

use std::collections::HashMap;
use std::sync::Arc;

use private_bus::PrivateBus;
use rosec_core::{Provider, UnlockInput};
use zeroize::Zeroizing;

fn have(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tools_available() -> bool {
    ["sops", "age-keygen", "dbus-daemon", "secret-tool"]
        .iter()
        .all(|tool| have(tool))
}

/// A temporary store plus the matching age identity.
struct Fixture {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    key_file: std::path::PathBuf,
    recipient: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("store");
        let key_file = dir.path().join("age-keys.txt");
        let output = std::process::Command::new("age-keygen")
            .arg("-o")
            .arg(&key_file)
            .output()
            .expect("age-keygen");
        assert!(output.status.success(), "age-keygen failed");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let recipient = stderr
            .split_whitespace()
            .find(|word| word.starts_with("age1"))
            .expect("recipient in age-keygen output")
            .to_string();
        // The store mode is explicit; this store keeps the direct behaviour.
        std::fs::create_dir_all(&root).expect("store root");
        rosec_sops::write_meta(
            &root,
            &rosec_sops::StoreMeta::new(rosec_sops::StoreMode::Direct),
        )
        .expect("store metadata");
        Self {
            _dir: dir,
            root,
            key_file,
            recipient,
        }
    }
}

async fn setup(bus: &PrivateBus, providers: Vec<Arc<dyn Provider>>) -> zbus::Connection {
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .build()
        .await
        .unwrap();
    let router = Arc::new(rosec_core::router::Router::new(
        rosec_core::router::RouterConfig {
            dedup_strategy: rosec_core::DedupStrategy::Priority,
            dedup_time_fallback: rosec_core::DedupTimeFallback::None,
        },
    ));
    rosec_secret_service::server::register_objects(
        &conn,
        providers,
        router,
        Arc::new(rosec_secret_service::session::SessionManager::new()),
    )
    .await
    .unwrap();
    conn
}

fn secret_tool(address: &str, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = std::process::Command::new("secret-tool")
        .args(args)
        .env("DBUS_SESSION_BUS_ADDRESS", address)
        // `secret-tool store` reads the secret from stdin and; without a pipe
        // it stores an empty value, which would hide a broken round trip.
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn secret-tool");
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())
            .expect("write secret to secret-tool");
    }
    child.wait_with_output().expect("run secret-tool")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_tool_roundtrip_through_the_sops_store() {
    if !tools_available() {
        eprintln!("SKIP: sops, age-keygen, dbus-daemon or secret-tool missing");
        return;
    }

    let fixture = Fixture::new();
    let config =
        rosec_sops::SopsConfig::new(&fixture.root, &fixture.key_file, &fixture.recipient, "sops")
            .expect("config");
    let provider = Arc::new(rosec_sops::SopsProvider::new("sops-it", config));
    provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await
        .expect("unlock");

    let bus = PrivateBus::new();
    let conn = setup(&bus, vec![provider.clone() as Arc<dyn Provider>]).await;
    conn.request_name("org.freedesktop.secrets").await.unwrap();

    let address = bus.address.clone();
    let run = move |args: Vec<String>, stdin: Option<String>| {
        let address = address.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
                secret_tool(&address, &borrowed, stdin.as_deref())
            })
            .await
            .unwrap()
        }
    };

    // The secret must be non-empty: an empty value would round-trip even if
    // the sops encrypt/decrypt path dropped it.
    let secret = "it-non-empty-secret-with spaces:and-punctuation";

    // store
    let out = run(
        vec![
            "store".into(),
            "--label=it-login".into(),
            "service".into(),
            "it-rosec-sops".into(),
            "username".into(),
            "user".into(),
        ],
        Some(secret.to_owned()),
    )
    .await;
    assert!(
        out.status.success(),
        "secret-tool store failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The store now has exactly one encrypted file, in `default/`.
    let entries: Vec<_> = std::fs::read_dir(fixture.root.join("default"))
        .expect("default collection")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".sops.yaml") && !n.starts_with("_meta"))
        .collect();
    assert_eq!(entries.len(), 1, "expected one item file, got {entries:?}");

    // lookup returns the exact secret bytes.
    let out = run(
        vec![
            "lookup".into(),
            "service".into(),
            "it-rosec-sops".into(),
            "username".into(),
            "user".into(),
        ],
        None,
    )
    .await;
    assert!(
        out.status.success(),
        "secret-tool lookup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'),
        secret,
        "the secret must survive the sops encrypt/decrypt round trip"
    );

    // The stored file is ciphertext that does not contain the plaintext.
    let stored =
        std::fs::read_to_string(fixture.root.join("default").join(&entries[0])).expect("item file");
    assert!(
        !stored.contains(secret),
        "plaintext leaked into the store file"
    );
    assert!(stored.contains("ENC["), "not sops ciphertext: {stored}");

    // search finds it by attribute.
    let out = run(
        vec![
            "search".into(),
            "--all".into(),
            "service".into(),
            "it-rosec-sops".into(),
        ],
        None,
    )
    .await;
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("it-login"),
        "search output missing the label: {text}"
    );

    // clear removes the item file.
    let out = run(
        vec!["clear".into(), "service".into(), "it-rosec-sops".into()],
        None,
    )
    .await;
    assert!(out.status.success(), "secret-tool clear failed");
    let items = provider.list_items().await.unwrap();
    assert!(items.is_empty(), "item survived clear: {items:?}");

    // Quotes that must not end up in the store.
    assert!(
        provider.search(&HashMap::new()).await.unwrap().is_empty(),
        "no item may remain after clear"
    );
}
