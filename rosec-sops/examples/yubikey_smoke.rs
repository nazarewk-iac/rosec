//! Real-hardware smoke test for the sops provider.
//!
//! Creates an item through the provider using the real age identity file (here
//! a YubiKey identity), reads it back, checks the file on disk is sops
//! ciphertext, and deletes the item.
//!
//! Run from the fork:
//!
//! ```sh
//! devenv shell -- cargo run -p rosec-sops --example yubikey_smoke -- \
//!     ~/Nextcloud/drag0nius@nc.nazarewk.pw/important/rosec-storage \
//!     ~/.config/sops/age/keys.txt \
//!     age1yubikey1…
//! ```
//!
//! Add `--dry-run` to use a fresh temporary store instead of the one named on
//! the command line, so the hardware path can be exercised without writing to
//! the synced tree.
//!
//! This example is deliberately not a test: it needs the hardware token, so it
//! must never run unattended.

use std::collections::HashMap;

use rosec_core::{ItemUpdate, NewItem, Provider, SecretBytes, UnlockInput};
use rosec_sops::{SopsConfig, SopsProvider};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    args.retain(|arg| arg != "--dry-run");
    if args.len() < 3 {
        return Err(
            "usage: yubikey_smoke [--dry-run] <store root> <key file> <age recipient>".into(),
        );
    }
    let (root, key_file, recipient) = if dry_run {
        let dir = std::env::temp_dir().join(format!("rosec-sops-smoke-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        (dir, args[1].clone(), args[2].clone())
    } else {
        (args[0].clone().into(), args[1].clone(), args[2].clone())
    };

    let config = SopsConfig::new(&root, &key_file, recipient, "sops")?;
    let provider = SopsProvider::new("sops-poc", config);
    println!("store root: {}", provider.config().path.display());
    println!("key file:   {}", provider.config().key_file.display());
    if dry_run {
        println!("dry run: using a temporary store, the real store is untouched");
    }

    provider
        .unlock(UnlockInput::Password(Zeroizing::new(String::new())))
        .await?;
    println!("unlocked (sops ran, identity file present, and a store file decrypted)");

    let label = format!("rosec-sops poc ({})", std::process::id());
    let mut item = NewItem {
        content_types: HashMap::new(),
        label: label.clone(),
        item_type: None,
        attributes: HashMap::new(),
        secrets: HashMap::from([(
            "secret".to_string(),
            SecretBytes::new(b"poc-secret-value".to_vec()),
        )]),
    };
    // A client attribute can never overwrite a provider-managed one.
    item.attributes
        .insert(rosec_sops::ATTR_COLLECTION_DIR.into(), "forged".into());
    item.attributes
        .insert("rosec_sops_poc".to_string(), "true".to_string());

    // `create_item` with replace=true updates the earlier POC item instead of
    // piling one up per run.
    let id = provider.create_item(item, true).await?;
    println!("created/updated item id: {id}");

    let attrs = provider.get_item_attributes(&id).await?;
    let secret = provider.get_secret_attr(&id, "secret").await?;
    println!("secret names: {:?}", attrs.secret_names);
    // Never print the value itself; prove the round trip instead.
    println!(
        "secret round-tripped exactly: {}",
        secret.as_slice() == b"poc-secret-value"
    );
    println!(
        "provider-owned attribute kept: {:?}",
        attrs.public.get(rosec_sops::ATTR_COLLECTION_DIR)
    );

    // Find the ciphertext file behind the id.
    let items = provider.list_items().await?;
    let meta = items
        .iter()
        .find(|m| m.id == id)
        .ok_or("item missing from list_items")?;
    let collection = meta
        .attributes
        .get(rosec_sops::ATTR_COLLECTION_DIR)
        .cloned()
        .unwrap_or_else(|| "default".to_string());
    let local_id = id.rsplit('/').next().unwrap_or(&id);
    let path = provider.store().item_path(&collection, local_id);
    println!("ciphertext file: {}", path.display());
    let text = std::fs::read_to_string(&path)?;
    println!(
        "file is sops ciphertext: {}",
        text.contains("sops:") && !text.contains("poc-secret-value")
    );
    println!("-- first lines of the file --");
    for line in text.lines().take(6) {
        println!("{line}");
    }

    // Update, then delete.
    provider
        .update_item(
            &id,
            ItemUpdate {
                label: Some(format!("{label} updated")),
                ..Default::default()
            },
        )
        .await?;
    println!("updated label ok");

    provider.delete_item(&id).await?;
    println!("deleted item; file exists now: {}", path.exists());

    provider.lock().await?;
    println!(
        "locked; list_items while locked reports: {:?}",
        provider.list_items().await.err()
    );

    if dry_run {
        let _ = std::fs::remove_dir_all(&root);
        println!("dry run: temporary store removed");
    }
    Ok(())
}
