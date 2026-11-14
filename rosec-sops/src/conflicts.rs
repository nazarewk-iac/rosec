//! Plaintext conflict markers: the user-facing record of a superseded copy.
//!
//! A write that supersedes a divergent copy archives the loser (see
//! [`Store::archive_superseded`]) and would otherwise hide it. Nothing a
//! client can see would mention the loser, so the user would never learn that
//! two files had diverged. This module writes a **plaintext, secret-free**
//! marker next to the store:
//!
//! ```text
//! <root>/.conflicts/<collection>/<item-id>.md   one marker per conflicted id
//! ```
//!
//! The marker is Markdown with a YAML front-matter block. It carries only what
//! is already public in the synced tree — the collection, the item id, the
//! label, the file names, the `modified`/`host`/`revision` triple and the
//! secret *names*. **No secret value is ever written**: the marker is built
//! from [`SopsDocument`] fields that hold no secret, and [`redact_metadata`]
//! checks the rendered text against every known secret value before the file
//! is written.
//!
//! Lifecycle:
//!
//! - `save`/`update_item` writes the marker when it archives at least one copy;
//!   the latest conflict overwrites the earlier marker, so one id has one
//!   marker;
//! - removing an item removes its markers, so no stale marker survives;
//! - the `rosec-sops conflicts` CLI removes the marker when the user resolves
//!   the conflict.
//!
//! The marker is plaintext, so a host-side watcher needs no key to notice a
//! new one: watching `<root>/.conflicts` is enough to notify the user.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::document::{SopsDocument, Timestamp};
use crate::error::SopsError;
use crate::sops::write_atomic;

/// Directory below the store root that holds the markers.
///
/// A dot directory never becomes a collection, and it holds no item files, so
/// it is invisible to every other store operation.
pub const CONFLICTS_DIR: &str = ".conflicts";

/// Suffix of a marker file.
pub const MARKER_SUFFIX: &str = ".md";

/// File name of the repository-level task that owns the real merge design.
pub const FOLLOW_UP_TASK: &str = "docs/tasks/2026-11/rosec-conflict-resolution/definition.md";

/// One line that tells the user what to do.
pub const RESOLUTION_HINT: &str = "Run `rosec-sops conflicts show <item-id>`, then `rosec-sops conflicts resolve <item-id> --keep <winner|loser|file>`.";

/// File-name-safe form of a collection or item id (the marker path component).
///
/// [`crate::store::validate_name`] already forbids `/`, `\`, `:` and control
/// characters, so an id or collection name is a single path component. This
/// function is the belt-and-braces version used when a name is rebuilt from a
/// marker file name, which may have been edited by hand.
fn safe_component(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Public metadata of one copy of an item. Never holds a secret value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyMeta {
    /// Path relative to the store root, e.g.
    /// `default/item-abc.sops.yaml` or
    /// `default/.superseded-item-abc.1763…-oams.sops.yaml`.
    pub file: String,
    /// `modified` of the copy, RFC 3339. Absent when the document has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// `host` of the copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `revision` of the copy.
    #[serde(default)]
    pub revision: u64,
    /// Secret *names* the copy holds. A name is metadata, not a value.
    #[serde(default)]
    pub secrets: Vec<String>,
}

impl CopyMeta {
    /// Build from a rendered document plus its path inside the store.
    pub fn from_document(file: impl Into<String>, document: &SopsDocument) -> Self {
        Self {
            file: file.into(),
            modified: document.modified.map(|t| rfc3339(t.0)),
            host: document.host.clone(),
            revision: document.revision,
            secrets: document.secret_names().cloned().collect(),
        }
    }
}

/// The contents of one `<root>/.conflicts/<collection>/<item-id>.md` marker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictMarker {
    /// Item id, as it appears in a file name.
    pub item: String,
    /// Collection (directory) that holds the item.
    pub collection: String,
    /// Collection label, which may differ from the directory name.
    pub label: String,
    /// The canonical file the write produced. Relative to the store root.
    pub winner: String,
    /// Every archived loser, oldest first. Relative to the store root.
    #[serde(default)]
    pub losers: Vec<CopyMeta>,
    /// Public metadata of the winner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winner_meta: Option<CopyMeta>,
    /// When the marker was written (RFC 3339).
    pub written: String,
    /// Public attributes of the item, without provider-internal ones.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, String>,
    /// One-line resolution hint.
    pub hint: String,
}

impl ConflictMarker {
    /// Read a marker file.
    pub async fn read(path: &Path) -> Result<Self, SopsError> {
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| SopsError::io(path.display(), e))?;
        Self::parse(&text, path)
    }

    /// Parse marker text (front matter plus the rendered body).
    pub fn parse(text: &str, path: &Path) -> Result<Self, SopsError> {
        let Some(rest) = text.strip_prefix("---\n") else {
            return Err(SopsError::Malformed {
                path: path.display().to_string(),
                reason: "conflict marker has no YAML front matter".into(),
            });
        };
        let Some((front, _body)) = rest.split_once("\n---") else {
            return Err(SopsError::Malformed {
                path: path.display().to_string(),
                reason: "conflict marker front matter is not terminated".into(),
            });
        };
        serde_yaml::from_str(front).map_err(|e| SopsError::Malformed {
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }

    /// Render the marker: front matter for a watcher or a script, body for a
    /// human.
    pub fn to_text(&self) -> Result<String, SopsError> {
        let front = serde_yaml::to_string(self).map_err(|e| SopsError::Malformed {
            path: "<in memory>".into(),
            reason: e.to_string(),
        })?;
        let mut out = String::new();
        out.push_str("---\n");
        out.push_str(&front);
        out.push_str("---\n\n");
        out.push_str(&self.body());
        Ok(out)
    }

    /// The human-readable half of the marker.
    fn body(&self) -> String {
        let mut out = format!(
            "# rosec conflict: {label} (`{id}`)\n\n\
             A write superseded a divergent copy of this item. The losing value is\n\
             archived, not deleted, so nothing was lost silently — but the item needs\n\
             your decision.\n\n\
             - item id: `{id}`\n\
             - collection: `{collection}` (label: {label})\n\
             - conflict recorded: {written}\n",
            label = self.label,
            id = self.item,
            collection = self.collection,
            written = self.written,
        );
        out.push_str(&format!(
            "- winner (canonical, served now): `{}`{}\n",
            self.winner,
            describe(self.winner_meta.as_ref())
        ));
        if self.losers.is_empty() {
            out.push_str("- archived losers: none recorded\n");
        } else {
            out.push_str("- archived losers (not served, still on disk):\n");
            for loser in &self.losers {
                out.push_str(&format!("  - `{}`{}\n", loser.file, describe(Some(loser))));
            }
        }
        if !self.attributes.is_empty() {
            out.push_str("- attributes:");
            for (key, value) in &self.attributes {
                out.push_str(&format!(" `{key}`=`{value}`"));
            }
            out.push('\n');
        }
        out.push_str(&format!(
            "\n**Resolve it:** {}\n\n\
             Secret values are not recorded here and are not printed by the CLI.\n\
             The merge itself is designed in `{FOLLOW_UP_TASK}`.\n",
            self.hint
        ));
        out
    }
}

/// ` (modified …, host …, revision …, secrets: a, b)` for one copy.
fn describe(meta: Option<&CopyMeta>) -> String {
    let Some(meta) = meta else {
        return String::new();
    };
    let mut parts = Vec::new();
    if let Some(modified) = &meta.modified {
        parts.push(format!("modified {modified}"));
    }
    if let Some(host) = &meta.host {
        parts.push(format!("host {host}"));
    }
    parts.push(format!("revision {}", meta.revision));
    if !meta.secrets.is_empty() {
        parts.push(format!("secrets: {}", meta.secrets.join(", ")));
    }
    format!(" ({})", parts.join(", "))
}

/// Throw the marker away when it quotes a secret value.
///
/// The marker is built from secret-free fields, so this is a guard against a
/// future change that starts interpolating one. A document with a very short
/// secret (`"1"`, `"a"`) would match the marker text by chance, so values
/// shorter than [`MIN_REDACT_LEN`] are not checked: a one-character needle
/// proves nothing and would suppress every marker.
pub fn redact_metadata(marker: &ConflictMarker, secrets: &[&str]) -> ConflictMarker {
    let rendered = serde_yaml::to_string(marker).unwrap_or_default();
    if secrets.iter().any(|secret| leaks(&rendered, secret)) {
        let mut redacted = marker.clone();
        redacted.attributes.clear();
        redacted.label = redacted.label.clone();
        redacted
    } else {
        marker.clone()
    }
}

/// Shortest secret value that is worth searching for.
const MIN_REDACT_LEN: usize = 4;

/// True when `text` contains `secret` and `secret` is long enough to matter.
fn leaks(text: &str, secret: &str) -> bool {
    secret.len() >= MIN_REDACT_LEN && text.contains(secret)
}

/// Path of the marker for `collection`/`id` below `root`.
pub fn marker_path(root: &Path, collection: &str, id: &str) -> PathBuf {
    root.join(CONFLICTS_DIR)
        .join(safe_component(collection))
        .join(format!("{}{MARKER_SUFFIX}", safe_component(id)))
}

/// One marker found on disk.
#[derive(Debug, Clone)]
pub struct StoredMarker {
    /// Absolute path of the marker file.
    pub path: PathBuf,
    /// Parsed marker.
    pub marker: ConflictMarker,
}

/// Every marker below `<root>/.conflicts`, sorted by collection then item.
///
/// An unreadable marker is reported as an error with its path, so the CLI can
/// name the bad file instead of hiding it.
pub async fn list_markers(root: &Path) -> Result<Vec<StoredMarker>, SopsError> {
    let mut out = Vec::new();
    let base = root.join(CONFLICTS_DIR);
    let mut collections = match tokio::fs::read_dir(&base).await {
        Ok(reader) => reader,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(SopsError::io(base.display(), e)),
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    while let Some(entry) = collections
        .next_entry()
        .await
        .map_err(|e| SopsError::io(base.display(), e))?
    {
        if entry.path().is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    for dir in dirs {
        let mut entries = tokio::fs::read_dir(&dir)
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?;
        let mut paths: Vec<PathBuf> = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?
        {
            let path = entry.path();
            if path
                .file_name()
                .map(|n| n.to_string_lossy().ends_with(MARKER_SUFFIX))
                .unwrap_or(false)
            {
                paths.push(path);
            }
        }
        paths.sort();
        for path in paths {
            out.push(StoredMarker {
                marker: ConflictMarker::read(&path).await?,
                path,
            });
        }
    }
    Ok(out)
}

/// Item ids that have a marker, as `(collection, item)` pairs.
pub async fn conflicted_ids(root: &Path) -> Result<BTreeSet<(String, String)>, SopsError> {
    Ok(list_markers(root)
        .await?
        .into_iter()
        .map(|stored| (stored.marker.collection, stored.marker.item))
        .collect())
}

/// Synchronous form of [`conflicted_ids`].
///
/// The marker directory is plaintext and tiny, so `list_items` reads it with
/// blocking calls instead of awaiting a second directory walk per item. The
/// file names are enough: the marker path is
/// `<root>/.conflicts/<collection>/<item>.md`.
pub fn conflicted_ids_blocking(root: &Path) -> Result<BTreeSet<(String, String)>, SopsError> {
    let mut out = BTreeSet::new();
    let base = root.join(CONFLICTS_DIR);
    let collections = match std::fs::read_dir(&base) {
        Ok(reader) => reader,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(SopsError::io(base.display(), e)),
    };
    for collection in collections {
        let collection = collection.map_err(|e| SopsError::io(base.display(), e))?;
        if !collection.path().is_dir() {
            continue;
        }
        let dir = collection.file_name().to_string_lossy().into_owned();
        let entries =
            std::fs::read_dir(collection.path()).map_err(|e| SopsError::io(dir.clone(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| SopsError::io(dir.clone(), e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(item) = name.strip_suffix(MARKER_SUFFIX) {
                out.insert((dir.clone(), item.to_owned()));
            }
        }
    }
    Ok(out)
}

/// Render a [`Timestamp`] as RFC 3339 UTC, the form the marker carries.
pub fn rfc3339(time: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The `now` argument of a marker write, kept as a function for tests.
pub fn now_text() -> String {
    rfc3339(Timestamp::now().0)
}

/// Write a marker atomically, creating `<root>/.conflicts/<collection>/`.
pub async fn write_marker(root: &Path, marker: &ConflictMarker) -> Result<PathBuf, SopsError> {
    let path = marker_path(root, &marker.collection, &marker.item);
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| SopsError::io(dir.display(), e))?;
    }
    let text = marker.to_text()?;
    write_atomic(&path, text.as_bytes()).await?;
    Ok(path)
}

/// Remove the marker of `collection`/`id`. A missing marker is not an error.
pub async fn remove_marker(root: &Path, collection: &str, id: &str) -> Result<bool, SopsError> {
    let path = marker_path(root, collection, id);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {
            // An empty collection directory is noise; drop it when we can.
            if let Some(dir) = path.parent() {
                let _ = tokio::fs::remove_dir(dir).await;
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(SopsError::io(path.display(), e)),
    }
}

/// Remove every marker whose item id no longer resolves in the store.
///
/// Called after a delete and at the end of `resolve`, so a marker can never
/// outlive the conflict it describes.
pub async fn prune(
    root: &Path,
    alive: impl Fn(&str, &str) -> bool,
) -> Result<Vec<PathBuf>, SopsError> {
    let mut removed = Vec::new();
    for stored in list_markers(root).await? {
        if !alive(&stored.marker.collection, &stored.marker.item) {
            match tokio::fs::remove_file(&stored.path).await {
                Ok(()) => removed.push(stored.path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(SopsError::io(stored.path.display(), e)),
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConflictMarker {
        ConflictMarker {
            item: "item-abc".into(),
            collection: "default".into(),
            label: "github.com".into(),
            winner: "default/item-abc.sops.yaml".into(),
            losers: vec![CopyMeta {
                file: "default/.superseded-item-abc.1763150000000000000-oams.sops.yaml".into(),
                modified: Some("2026-11-14T18:41:09Z".into()),
                host: Some("oams".into()),
                revision: 8,
                secrets: vec!["password".into()],
            }],
            winner_meta: Some(CopyMeta {
                file: "default/item-abc.sops.yaml".into(),
                modified: Some("2026-11-14T18:42:00Z".into()),
                host: Some("oams".into()),
                revision: 9,
                secrets: vec!["password".into()],
            }),
            written: now_text(),
            attributes: std::collections::BTreeMap::from([(
                "username".to_string(),
                "kdn".to_string(),
            )]),
            hint: RESOLUTION_HINT.into(),
        }
    }

    #[test]
    fn round_trips_through_text() {
        let marker = sample();
        let text = marker.to_text().unwrap();
        assert!(text.starts_with("---\n"), "{text}");
        assert!(text.contains("# rosec conflict: github.com"), "{text}");
        assert!(text.contains("archived losers"), "{text}");
        let back = ConflictMarker::parse(&text, Path::new("<test>")).unwrap();
        assert_eq!(back, marker);
    }

    #[test]
    fn rejects_text_without_front_matter() {
        let error = ConflictMarker::parse("# nothing\n", Path::new("<t>")).unwrap_err();
        assert!(format!("{error}").contains("front matter"), "{error}");
        let unterminated = ConflictMarker::parse("---\nitem: x\n", Path::new("<t>")).unwrap_err();
        assert!(format!("{unterminated}").contains("not terminated"));
    }

    #[test]
    fn marker_paths_stay_below_the_conflicts_directory() {
        let root = Path::new("/store");
        assert_eq!(
            marker_path(root, "default", "item-abc"),
            PathBuf::from("/store/.conflicts/default/item-abc.md")
        );
        // A hostile id cannot escape the collections directory.
        let escaped = marker_path(root, "../../etc", "..");
        assert!(
            escaped.starts_with("/store/.conflicts"),
            "{}",
            escaped.display()
        );
    }

    #[test]
    fn no_secret_value_reaches_the_marker() {
        let marker = sample();
        let text = marker.to_text().unwrap();
        for known in ["hunter2", "correct horse", "from-other-host"] {
            assert!(!text.contains(known), "secret `{known}` leaked: {text}");
        }
        // Only the *name* of a secret appears.
        assert!(text.contains("password"), "{text}");
    }

    #[test]
    fn redaction_drops_attributes_that_quote_a_secret() {
        let mut marker = sample();
        marker
            .attributes
            .insert("notes".into(), "hunter2-in-an-attribute".into());
        let redacted = redact_metadata(&marker, &["hunter2-in-an-attribute"]);
        assert!(
            redacted.attributes.is_empty(),
            "attributes carrying a secret must be dropped"
        );
        // A short secret proves nothing and must not trip the guard.
        let kept = redact_metadata(&marker, &["a"]);
        assert_eq!(kept.attributes.len(), marker.attributes.len());
    }
}
