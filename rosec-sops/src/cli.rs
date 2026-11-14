//! `rosec-sops` command line: the user-facing side of the conflict markers.
//!
//! The provider writes a plaintext marker when a write archives a divergent
//! copy (see [`crate::conflicts`]). This binary is how the user sees and
//! resolves one:
//!
//! ```text
//! rosec-sops conflicts list [--json]
//! rosec-sops conflicts show <item-id|collection/item-id> [--json]
//! rosec-sops conflicts resolve <item-id|collection/item-id> --keep <winner|loser|file>
//! ```
//!
//! **The marker is plaintext**, so `list` and `show` need neither the daemon
//! nor a decryption. `resolve` also promises to print nothing secret: it
//! reports file names, revisions, hosts and timestamps, never a value.
//!
//! **Offline by design.** `list`, `show` and `resolve` never contact `rosecd`.
//! They do not even read the lock state of a running daemon: the store is a
//! plain synced file tree with exactly one writer per file at a time, and a
//! marker may be resolved from a host where the daemon is stopped. Resolution
//! is the user's decision, so requiring an unlock (a YubiKey touch) to delete an
//! archive would be worse than the small race it avoids.
//!
//! Configuration comes from the same places the provider uses:
//!
//! 1. `--store <path>`, or the `ROSEC_SOPS_STORE` environment variable;
//! 2. `--config <path>`, or `$XDG_CONFIG_HOME/rosec/config.toml`;
//! 3. inside that file: the `[[provider]]` entry whose `kind` is `sops`,
//!    optionally chosen with `--provider <id>`.

use std::path::{Path, PathBuf};

use crate::config::SopsConfig;
use crate::conflicts::{ConflictMarker, StoredMarker, list_markers};
use crate::store::Keep;
use crate::{Store, StoreCache};
use clap::{Args, Parser, Subcommand};
use rosec_core::config_load;
use serde::Serialize;

/// Environment variable that names the store root directly.
pub const STORE_ENV: &str = "ROSEC_SOPS_STORE";

/// Environment variable that names the rosec config file.
pub const CONFIG_ENV: &str = "ROSEC_CONFIG";

/// Conflicts: the user-facing side of a superseded copy.
#[derive(Debug, Parser)]
#[command(
    name = "rosec-sops",
    version,
    about = "Inspect and resolve conflicts of a rosec sops store",
    long_about = None,
)]
pub struct Cli {
    /// rosec config file holding the `kind = "sops"` provider entry
    /// (default: `$XDG_CONFIG_HOME/rosec/config.toml`; see also `ROSEC_CONFIG`).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Store root, instead of reading a config file
    /// (see also `ROSEC_SOPS_STORE`).
    #[arg(long, global = true)]
    pub store: Option<PathBuf>,

    /// Provider id to use when the config holds several `kind = "sops"` entries.
    #[arg(long, global = true)]
    pub provider: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect and resolve recorded conflicts.
    Conflicts(ConflictsArgs),
    /// Create, inspect and rotate the derived sops identity.
    Identity(IdentityArgs),
    /// Initialise the store mode and migrate a store.
    Store(StoreArgs),
}

/// `rosec-sops identity …`
#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub action: IdentityCommand,
}

/// `rosec-sops identity <action>`
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Generate the derived identity, its master file and the recipient sidecar.
    Init {
        /// Overwrite an existing master file (every existing item stays
        /// encrypted to the old identity).
        #[arg(long)]
        force: bool,
    },
    /// Print the derived recipient, the master path and the runtime state.
    Show,
    /// Re-wrap the master file to the current `.sops.yaml` master rule.
    Rewrap,
    /// Generate a new derived identity and re-encrypt every item.
    Rekey {
        /// Rotate even when the old master file is gone.
        #[arg(long)]
        force: bool,
    },
    /// One-time move of a direct store's items onto the derived identity.
    Migrate,
}

/// `rosec-sops store …`
#[derive(Debug, Args)]
pub struct StoreArgs {
    #[command(subcommand)]
    pub action: StoreCommand,
}

/// `rosec-sops store <action>`
#[derive(Debug, Subcommand)]
pub enum StoreCommand {
    /// Write the plaintext store metadata (`.rosec-store.yaml`).
    Init {
        /// `direct`: item files are encrypted to the unlock keys.
        /// `derived`: item files are encrypted to a derived sops identity.
        #[arg(long, value_name = "direct|derived")]
        mode: String,
        /// Replace an existing metadata file.
        #[arg(long)]
        force: bool,
    },
    /// Copy a store into a new one, optionally with a different mode.
    Migrate {
        /// Source store root.
        #[arg(long, value_name = "PATH")]
        from: PathBuf,
        /// Destination store root (new or empty).
        #[arg(long, value_name = "PATH")]
        to: PathBuf,
        /// Mode of the destination, when it has no metadata yet.
        #[arg(long, value_name = "direct|derived")]
        mode: Option<String>,
        /// Write into an existing destination directory.
        #[arg(long)]
        force: bool,
        /// Replace files that already exist in the destination.
        #[arg(long)]
        overwrite: bool,
    },
    /// Show the recorded store mode.
    Show,
}

/// `rosec-sops conflicts …`
#[derive(Debug, Args)]
pub struct ConflictsArgs {
    #[command(subcommand)]
    pub action: ConflictsCommand,
}

/// `rosec-sops conflicts <action>`
#[derive(Debug, Subcommand)]
pub enum ConflictsCommand {
    /// List every recorded conflict (item, files, hosts, timestamps).
    List {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Show one conflict: the marker plus the winner/loser metadata.
    Show {
        /// `item-id` or `collection/item-id`.
        item: String,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Resolve one conflict and remove its marker.
    Resolve {
        /// `item-id` or `collection/item-id`.
        item: String,
        /// Copy to keep: `winner`, `loser`, or a file path/name from `show`.
        #[arg(long, value_name = "winner|loser|file")]
        keep: String,
    },
}

/// One row of `conflicts list --json`.
#[derive(Debug, Serialize)]
pub struct ConflictRow {
    /// Item id.
    pub item: String,
    /// Collection directory.
    pub collection: String,
    /// Collection label.
    pub label: String,
    /// Conflict marker path.
    pub marker: String,
    /// Canonical file served now.
    pub winner: String,
    /// Archived losers.
    pub losers: Vec<String>,
    /// `modified` of the winner.
    pub winner_modified: Option<String>,
    /// `host` of the winner.
    pub winner_host: Option<String>,
    /// `revision` of the winner.
    pub winner_revision: Option<u64>,
    /// `modified` of each loser, in the same order as `losers`.
    pub loser_modified: Vec<Option<String>>,
    /// `host` of each loser.
    pub loser_host: Vec<Option<String>>,
    /// `revision` of each loser.
    pub loser_revision: Vec<u64>,
    /// When the marker was written.
    pub written: String,
}

impl ConflictRow {
    fn from_stored(stored: &StoredMarker, root: &Path) -> Self {
        let marker = &stored.marker;
        Self {
            item: marker.item.clone(),
            collection: marker.collection.clone(),
            label: marker.label.clone(),
            marker: relative(root, &stored.path),
            winner: marker.winner.clone(),
            losers: marker.losers.iter().map(|l| l.file.clone()).collect(),
            winner_modified: marker.winner_meta.as_ref().and_then(|m| m.modified.clone()),
            winner_host: marker.winner_meta.as_ref().and_then(|m| m.host.clone()),
            winner_revision: marker.winner_meta.as_ref().map(|m| m.revision),
            loser_modified: marker.losers.iter().map(|l| l.modified.clone()).collect(),
            loser_host: marker.losers.iter().map(|l| l.host.clone()).collect(),
            loser_revision: marker.losers.iter().map(|l| l.revision).collect(),
            written: marker.written.clone(),
        }
    }
}

/// Path relative to `root` when it is below it.
fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// The store a command works on.
#[derive(Debug, Clone)]
pub struct Target {
    /// Store root.
    pub root: PathBuf,
    /// Configuration used to build a [`Store`] (needs `sops` only to promote).
    pub config: SopsConfig,
}

/// Default config file: `$XDG_CONFIG_HOME/rosec/config.toml`.
pub fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rosec").join("config.toml")
}

/// Resolve the store from the flags, the environment, or the rosec config.
///
/// This is exactly the discovery the daemon uses for a `kind = "sops"`
/// provider entry: `path` (or `options.path`) plus `options.key_file`. A
/// `--store` flag wins and builds a store with the defaults for everything
/// else, so the command works on a store whose config is not installed yet.
pub fn resolve_target(
    config: Option<&Path>,
    store: Option<&Path>,
    provider: Option<&str>,
) -> Result<Target, String> {
    if let Some(store) = store {
        // The identity comes from `SOPS_AGE_KEY_FILE` when only a store is
        // named: there is no config entry to read `key_file` from.
        let key_file = std::env::var_os("SOPS_AGE_KEY_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("~/{}", crate::DEFAULT_KEY_FILE)));
        let config = SopsConfig::new(store, key_file, "", crate::DEFAULT_SOPS_BINARY)
            .map_err(|e| e.to_string())?;
        return Ok(Target {
            root: config.path.clone(),
            config,
        });
    }

    let path = config
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_path);
    if !path.is_file() {
        return Err(format!(
            "no rosec config at `{}`; pass `--store <path>` or `--config <file>`",
            path.display()
        ));
    }
    let loaded = config_load::load(&path).map_err(|e| e.to_string())?;
    let mut candidates = loaded
        .config
        .provider
        .iter()
        .filter(|entry| entry.kind == "sops" && entry.enabled)
        .filter(|entry| provider.map(|id| entry.id == id).unwrap_or(true));
    let entry = candidates.next().ok_or_else(|| match provider {
        Some(id) => format!(
            "config `{}` has no enabled `kind = \"sops\"` provider with id `{id}`",
            path.display()
        ),
        None => format!(
            "config `{}` has no enabled `kind = \"sops\"` provider",
            path.display()
        ),
    })?;
    if provider.is_none() && candidates.next().is_some() {
        return Err(format!(
            "config `{}` has several `kind = \"sops\"` providers; choose one with `--provider <id>`",
            path.display()
        ));
    }
    let config = SopsConfig::from_options(entry.path.as_deref(), &entry.options)
        .map_err(|e| e.to_string())?;
    Ok(Target {
        root: config.path.clone(),
        config,
    })
}

/// Split `item-id` or `collection/item-id` into its parts.
pub fn split_item(raw: &str) -> Result<(Option<String>, String), String> {
    match raw.split_once('/') {
        Some((collection, id)) => {
            if collection.is_empty() || id.is_empty() {
                return Err(format!("`{raw}` is not `collection/item-id`"));
            }
            if id.contains('/') {
                return Err(format!("`{raw}` has more than one `/`"));
            }
            Ok((Some(collection.to_owned()), id.to_owned()))
        }
        None if raw.is_empty() => Err("an item id is required".into()),
        None => Ok((None, raw.to_owned())),
    }
}

/// Pick the marker for `item`, refusing an ambiguous bare id.
fn select<'a>(
    markers: &'a [StoredMarker],
    item: &str,
) -> Result<(PathBuf, &'a ConflictMarker), String> {
    let (collection, id) = split_item(item)?;
    let mut matches: Vec<&StoredMarker> = markers
        .iter()
        .filter(|stored| stored.marker.item == id)
        .filter(|stored| {
            collection
                .as_ref()
                .map(|c| &stored.marker.collection == c)
                .unwrap_or(true)
        })
        .collect();
    match matches.len() {
        0 => Err(format!("no recorded conflict for `{item}`")),
        1 => {
            let stored = matches.remove(0);
            Ok((stored.path.clone(), &stored.marker))
        }
        _ => {
            let names = matches
                .iter()
                .map(|stored| format!("{}/{}", stored.marker.collection, stored.marker.item))
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!("`{item}` is ambiguous; name one of: {names}"))
        }
    }
}

/// Wrap an async closure for [`with_target`].
macro_rules! run_action {
    ($target:ident => $body:expr) => {
        |$target: &Target| {
            Box::pin(async move { $body })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = std::result::Result<(), String>> + '_>,
                >
        }
    };
}

/// Run one command and print its result. Returns the process exit code.
pub async fn run(cli: Cli) -> i32 {
    // `clap`'s `env` feature is not in the workspace build, so the two
    // environment defaults are applied here, after the flag wins.
    let config = cli
        .config
        .or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from));
    let store = cli
        .store
        .or_else(|| std::env::var_os(STORE_ENV).map(PathBuf::from));
    let (config, store) = (config.as_deref(), store.as_deref());
    match cli.command {
        Command::Conflicts(args) => match args.action {
            ConflictsCommand::List { json } => {
                list(config, store, cli.provider.as_deref(), json).await
            }
            ConflictsCommand::Show { item, json } => {
                show(config, store, cli.provider.as_deref(), &item, json).await
            }
            ConflictsCommand::Resolve { item, keep } => {
                resolve(config, store, cli.provider.as_deref(), &item, &keep).await
            }
        },
        Command::Identity(args) => {
            match args.action {
                IdentityCommand::Init { force } => with_target(
                    config,
                    store,
                    cli.provider.as_deref(),
                    run_action!(target => crate::identity_cli::init(&target.config, force).await),
                )
                .await,
                IdentityCommand::Show => {
                    with_target(
                        config,
                        store,
                        cli.provider.as_deref(),
                        run_action!(target => crate::identity_cli::show(&target.config).await),
                    )
                    .await
                }
                IdentityCommand::Rewrap => {
                    with_target(
                        config,
                        store,
                        cli.provider.as_deref(),
                        run_action!(target => crate::identity_cli::rewrap(&target.config).await),
                    )
                    .await
                }
                IdentityCommand::Rekey { force } => with_target(
                    config,
                    store,
                    cli.provider.as_deref(),
                    run_action!(target => crate::identity_cli::rekey(&target.config, force).await),
                )
                .await,
                IdentityCommand::Migrate => {
                    with_target(
                        config,
                        store,
                        cli.provider.as_deref(),
                        run_action!(target => crate::identity_cli::migrate(&target.config).await),
                    )
                    .await
                }
            }
        }
        Command::Store(args) => match args.action {
            StoreCommand::Init { mode, force } => {
                store_init(config, store, cli.provider.as_deref(), &mode, force).await
            }
            StoreCommand::Migrate {
                from,
                to,
                mode,
                force,
                overwrite,
            } => {
                store_migrate(
                    config,
                    store,
                    cli.provider.as_deref(),
                    &from,
                    &to,
                    mode.as_deref(),
                    force,
                    overwrite,
                )
                .await
            }
            StoreCommand::Show => {
                with_target(
                    config,
                    store,
                    cli.provider.as_deref(),
                    run_action!(target => {
                        let meta = crate::store_mode::read_meta(&target.root)
                            .map_err(|e| e.to_string())?;
                        println!("store: {}", target.root.display());
                        println!("mode:  {}", meta.mode);
                        Ok(())
                    }),
                )
                .await
            }
        },
    }
}

/// Resolve the target, run `action`, and map its result to an exit code.
///
/// Exit 2 is a configuration or usage problem (no store, no mode, a mismatch),
/// exit 1 a failed operation. Both print `error: …` on stderr.
async fn with_target<F>(
    config: Option<&Path>,
    store: Option<&Path>,
    provider: Option<&str>,
    action: F,
) -> i32
where
    F: for<'a> FnOnce(
        &'a Target,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<(), String>> + 'a>,
    >,
{
    let target = match resolve_target(config, store, provider) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("error: {message}");
            return 2;
        }
    };
    match action(&target).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    }
}

/// `rosec-sops store init --mode direct|derived`
async fn store_init(
    config: Option<&Path>,
    store: Option<&Path>,
    provider: Option<&str>,
    mode: &str,
    force: bool,
) -> i32 {
    let target = match resolve_target(config, store, provider) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("error: {message}");
            return 2;
        }
    };
    let mode = match crate::store_mode::StoreMode::parse(mode) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let root = &target.root;
    if let Ok(existing) = crate::store_mode::read_meta(root) {
        if existing.mode == mode {
            println!("`{}` is already `{mode}`", root.display());
            return 0;
        }
        if !force {
            eprintln!(
                "error: `{}` is already `{}`; the mode never changes in place. Create a new store \
                 with `--mode {}` and run `rosec-sops store migrate --from` into it",
                root.display(),
                existing.mode,
                mode
            );
            return 2;
        }
        // Even `--force` cannot rewrite the mode: every item file was written
        // for the other one.
        eprintln!(
            "error: refusing to change the mode of `{}` from `{}` to `{mode}`: existing item \
             files would become unreadable. Migrate into a new store instead",
            root.display(),
            existing.mode
        );
        return 2;
    }
    if let Err(e) = std::fs::create_dir_all(root) {
        eprintln!("error: cannot create `{}`: {e}", root.display());
        return 2;
    }
    if let Err(e) = crate::store_mode::write_meta(root, &crate::store_mode::StoreMeta::new(mode)) {
        eprintln!("error: {e}");
        return 2;
    }
    println!(
        "store mode: {mode} (written to {})",
        crate::store_mode::StoreMeta::path(root).display()
    );
    match mode {
        crate::store_mode::StoreMode::Direct => {
            println!("this store keeps encrypting items to the unlock keys; nothing else to do");
        }
        crate::store_mode::StoreMode::Derived => {
            println!(
                "next: add the master rule to `{}/.sops.yaml`, then run",
                root.display()
            );
            println!("  rosec-sops --store {} identity init", root.display());
        }
    }
    0
}

/// `rosec-sops store migrate --from <src> --to <dst>`
#[allow(clippy::too_many_arguments)]
async fn store_migrate(
    config: Option<&Path>,
    store: Option<&Path>,
    provider: Option<&str>,
    from: &Path,
    to: &Path,
    mode: Option<&str>,
    force: bool,
    overwrite: bool,
) -> i32 {
    let mode = match mode.map(crate::store_mode::StoreMode::parse) {
        Some(Ok(mode)) => Some(mode),
        Some(Err(e)) => {
            eprintln!("error: {e}");
            return 2;
        }
        None => None,
    };
    // The identity that opens the source: the entry named by `--config`, else
    // `SOPS_AGE_KEY_FILE`, else the default key file.
    let source_key_file = match resolve_target(config, Some(from), provider) {
        Ok(target) => target.config.key_file.clone(),
        Err(message) => {
            eprintln!("error: {message}");
            return 2;
        }
    };
    let sops_binary = resolve_target(config, Some(from), provider)
        .map(|target| target.config.sops_binary)
        .unwrap_or_else(|_| PathBuf::from(crate::DEFAULT_SOPS_BINARY));
    let options = crate::store_migrate::MigrationOptions {
        from: from.to_path_buf(),
        to: to.to_path_buf(),
        source_key_file,
        sops_binary,
        mode,
        force,
        overwrite,
    };
    let _ = store;
    let report = match crate::store_migrate::migrate_store(&options, |destination| {
        let mut entry = std::collections::HashMap::new();
        entry.insert(
            "path".to_string(),
            serde_json::Value::String(destination.display().to_string()),
        );
        let config = SopsConfig::from_options(None, &entry)
            .unwrap_or_else(|_| SopsConfig::new(destination, "/dev/null", "", "sops").unwrap());
        if let Some(identity) = destination
            .join(crate::STORE_IDENTITY_FILE)
            .is_file()
            .then(|| crate::store_identity_path(destination))
        {
            SopsConfig {
                identity_file: Some(identity),
                ..config
            }
        } else {
            config
        }
    })
    .await
    {
        Ok(report) => report,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    println!(
        "migrated {} file(s) from `{}` ({}) to `{}` ({})",
        report.items,
        report.from.display(),
        report
            .from_mode
            .map(|m| m.to_string())
            .unwrap_or_else(|| "no mode".into()),
        report.to.display(),
        report.to_mode,
    );
    if !report.collections.is_empty() {
        println!(
            "collections: {}",
            report
                .collections
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !report.skipped.is_empty() {
        println!(
            "WARNING: {} file(s) could not be decrypted with the source key:",
            report.skipped.len()
        );
        for path in &report.skipped {
            println!("  {}", path.display());
        }
    }
    println!(
        "next: point the provider at `{}` (and its `identity_file` when the mode is derived)",
        report.to.display()
    );
    0
}

async fn list(
    config: Option<&Path>,
    store: Option<&Path>,
    provider: Option<&str>,
    json: bool,
) -> i32 {
    let target = match resolve_target(config, store, provider) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("error: {message}");
            return 2;
        }
    };
    let markers = match list_markers(&target.root).await {
        Ok(markers) => markers,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let rows: Vec<ConflictRow> = markers
        .iter()
        .map(|stored| ConflictRow::from_stored(stored, &target.root))
        .collect();
    if json {
        match serde_json::to_string_pretty(&rows) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        }
        return 0;
    }
    if rows.is_empty() {
        println!("no conflicts recorded in `{}`", target.root.display());
        return 0;
    }
    println!("{} conflict(s) in `{}`:", rows.len(), target.root.display());
    for row in &rows {
        println!();
        println!("  {}/{}  ({})", row.collection, row.item, row.label);
        println!(
            "    winner: {}{}",
            row.winner,
            describe(
                row.winner_modified.as_deref(),
                row.winner_host.as_deref(),
                row.winner_revision
            )
        );
        for (index, loser) in row.losers.iter().enumerate() {
            println!(
                "    loser:  {}{}",
                loser,
                describe(
                    row.loser_modified.get(index).and_then(|v| v.as_deref()),
                    row.loser_host.get(index).and_then(|v| v.as_deref()),
                    row.loser_revision.get(index).copied(),
                )
            );
        }
        println!("    recorded: {}", row.written);
        println!(
            "    resolve:  rosec-sops conflicts resolve {}/{} --keep winner|loser",
            row.collection, row.item
        );
    }
    0
}

async fn show(
    config: Option<&Path>,
    store: Option<&Path>,
    provider: Option<&str>,
    item: &str,
    json: bool,
) -> i32 {
    let target = match resolve_target(config, store, provider) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("error: {message}");
            return 2;
        }
    };
    let markers = match list_markers(&target.root).await {
        Ok(markers) => markers,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (path, marker) = match select(&markers, item) {
        Ok(selected) => selected,
        Err(message) => {
            eprintln!("error: {message}");
            return 1;
        }
    };
    if json {
        let stored = StoredMarker {
            path: path.clone(),
            marker: marker.clone(),
        };
        let row = ConflictRow::from_stored(&stored, &target.root);
        match serde_json::to_string_pretty(&row) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        }
        return 0;
    }
    match marker.to_text() {
        Ok(text) => print!("{text}"),
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    }
    println!();
    println!("marker file: {}", path.display());
    // Files that are on disk right now, so the user sees a stale marker.
    let canonical = target.root.join(&marker.winner);
    println!(
        "winner on disk: {}",
        if canonical.is_file() {
            "present"
        } else {
            "MISSING"
        }
    );
    for loser in &marker.losers {
        let path = target.root.join(&loser.file);
        println!(
            "loser on disk:  {} ({})",
            if path.is_file() { "present" } else { "MISSING" },
            loser.file
        );
    }
    println!(
        "next: rosec-sops conflicts resolve {}/{} --keep <winner|loser>",
        marker.collection, marker.item
    );
    0
}

async fn resolve(
    config: Option<&Path>,
    store: Option<&Path>,
    provider: Option<&str>,
    item: &str,
    keep: &str,
) -> i32 {
    let target = match resolve_target(config, store, provider) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("error: {message}");
            return 2;
        }
    };
    let markers = match list_markers(&target.root).await {
        Ok(markers) => markers,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (_, marker) = match select(&markers, item) {
        Ok(selected) => selected,
        Err(message) => {
            eprintln!("error: {message}");
            return 1;
        }
    };
    let collection = marker.collection.clone();
    let id = marker.item.clone();
    let keep = match Keep::parse(keep) {
        Ok(keep) => keep,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let store_handle =
        Store::with_cache(&target.config, std::sync::Arc::new(StoreCache::default()));
    let resolution = match store_handle.resolve_conflict(&collection, &id, &keep).await {
        Ok(resolution) => resolution,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    println!("resolved conflict {}/{}", collection, id);
    println!("  kept: {}", store_handle.relative(&resolution.kept));
    if resolution.promoted {
        println!("  the kept copy was promoted to the canonical item file");
    }
    for deleted in &resolution.deleted {
        println!(
            "  deleted archived loser: {}",
            store_handle.relative(deleted)
        );
    }
    for archived in &resolution.unarchived {
        println!(
            "  the previous canonical file was archived (not deleted): {}",
            store_handle.relative(archived)
        );
    }
    println!(
        "  marker removed: {}",
        store_handle.relative(&crate::conflicts::marker_path(
            store_handle.root(),
            &collection,
            &id
        ))
    );
    0
}

/// `(modified …, host …, revision …)` for one file.
fn describe(modified: Option<&str>, host: Option<&str>, revision: Option<u64>) -> String {
    let mut parts = Vec::new();
    if let Some(modified) = modified {
        parts.push(format!("modified {modified}"));
    }
    if let Some(host) = host {
        parts.push(format!("host {host}"));
    }
    if let Some(revision) = revision {
        parts.push(format!("revision {revision}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_qualified_and_bare_ids() {
        assert_eq!(
            split_item("item-abc").unwrap(),
            (None, "item-abc".to_string())
        );
        assert_eq!(
            split_item("work/item-abc").unwrap(),
            (Some("work".to_string()), "item-abc".to_string())
        );
        assert!(split_item("").is_err());
        assert!(split_item("/x").is_err());
        assert!(split_item("x/").is_err());
        assert!(split_item("a/b/c").is_err());
    }

    #[test]
    fn parses_the_keep_flag() {
        assert_eq!(Keep::parse("winner").unwrap(), Keep::Winner);
        assert_eq!(Keep::parse(" loser ").unwrap(), Keep::Loser);
        assert_eq!(
            Keep::parse("default/.superseded-x.sops.yaml").unwrap(),
            Keep::File("default/.superseded-x.sops.yaml".into())
        );
        assert!(Keep::parse("").is_err());
    }

    #[test]
    fn a_store_flag_needs_no_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = resolve_target(None, Some(dir.path()), None).expect("store flag is enough");
        assert_eq!(target.root, dir.path());
    }

    #[test]
    fn a_missing_config_is_reported() {
        let error = resolve_target(Some(Path::new("/nonexistent/rosec.toml")), None, None)
            .expect_err("a missing config must be reported");
        assert!(error.contains("--store"), "{error}");
    }
}
