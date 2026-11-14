//! The plaintext document stored inside each `.sops.yaml` file.
//!
//! The wire shape is deliberately small and stable so that a human (or a
//! future provider) can reason about it:
//!
//! ```yaml
//! label: github.com
//! attributes:
//!   rosec:type: login
//!   username: user
//! secrets:
//!   password: hunter2
//! binary_secrets:
//!   blob: aGVsbG8=
//! created: 2026-11-14T18:02:11Z
//! modified: 2026-11-14T18:41:09.417Z
//! host: host-a
//! revision: 7
//! version: 1
//! ```
//!
//! `secrets` holds UTF-8 text and keeps the file readable and greppable after
//! `sops --decrypt`. `binary_secrets` holds standard-base64 values, so a secret
//! that is not UTF-8 survives a round trip byte for byte instead of being
//! mangled to U+FFFD. Both maps are inside the sops payload, so both are
//! encrypted.
//!
//! Timestamps are RFC 3339 (UTC, nanosecond precision) on write. On read both
//! RFC 3339 text and a bare Unix epoch (seconds, fractional seconds allowed)
//! are accepted, so a hand-edited file keeps working.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::error::SopsError;

/// Schema version of an item document.
///
/// A missing `version` field means version 1, so every file written before the
/// field existed still reads. A document from a newer writer is refused on read
/// instead of being silently rewritten without its newer fields.
pub const DOCUMENT_VERSION: u32 = 1;

/// One item, as stored in a single sops file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SopsDocument {
    /// Display label.
    pub label: String,
    /// Public, searchable attributes (including `rosec:type`).
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Named UTF-8 secret values, e.g. `password` or `private_key`.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    /// Named non-UTF-8 secret values, standard base64 encoded.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub binary_secrets: BTreeMap<String, String>,
    /// Creation time.
    #[serde(default)]
    pub created: Option<Timestamp>,
    /// Last-modification time. The conflict rule reads this field.
    #[serde(default)]
    pub modified: Option<Timestamp>,
    /// Hostname that produced the newest revision.
    #[serde(default)]
    pub host: Option<String>,
    /// Monotonic revision counter, incremented on every write.
    #[serde(default)]
    pub revision: u64,
    /// Schema version. Missing means version 1; a zero or newer version is refused on read.
    #[serde(default = "document_version")]
    pub version: u32,
}

/// Serde default for a document written before the `version` field existed.
fn document_version() -> u32 {
    DOCUMENT_VERSION
}

/// Decode error for a stored secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretDecodeError {
    /// The name is stored in `binary_secrets`, but the value is not base64.
    NotBase64,
}

impl SopsDocument {
    /// Every secret name, text and binary alike.
    pub fn secret_names(&self) -> impl Iterator<Item = &String> {
        self.secrets.keys().chain(self.binary_secrets.keys())
    }

    /// True when the document holds a secret with this name.
    pub fn has_secret(&self, name: &str) -> bool {
        self.secrets.contains_key(name) || self.binary_secrets.contains_key(name)
    }

    /// The secret as bytes, decoding a base64 entry when needed.
    ///
    /// Returns `None` when the name is absent and
    /// `Some(Err(SecretDecodeError))` when a base64 entry is corrupt.
    pub fn secret_bytes(&self, name: &str) -> Option<Result<Vec<u8>, SecretDecodeError>> {
        if let Some(text) = self.secrets.get(name) {
            return Some(Ok(text.as_bytes().to_vec()));
        }
        self.binary_secrets.get(name).map(|encoded| {
            BASE64
                .decode(encoded)
                .map_err(|_| SecretDecodeError::NotBase64)
        })
    }

    /// Store a secret value, choosing the text or the base64 map.
    ///
    /// A UTF-8 value goes to `secrets`; anything else goes to `binary_secrets`.
    /// Setting a name replaces its value in either map.
    pub fn set_secret(&mut self, name: &str, value: &[u8]) {
        match std::str::from_utf8(value) {
            Ok(text) => {
                self.binary_secrets.remove(name);
                self.secrets.insert(name.to_owned(), text.to_owned());
            }
            Err(_) => {
                self.secrets.remove(name);
                self.binary_secrets
                    .insert(name.to_owned(), BASE64.encode(value));
            }
        }
    }

    /// True when both documents hold the same secret values.
    ///
    /// Compares decoded bytes, so a text entry and a base64 entry that decode
    /// to the same value count as equal.
    pub fn secrets_equal(&self, other: &SopsDocument) -> bool {
        let mine = self
            .secret_names()
            .collect::<std::collections::BTreeSet<_>>();
        let theirs = other
            .secret_names()
            .collect::<std::collections::BTreeSet<_>>();
        if mine != theirs {
            return false;
        }
        mine.into_iter()
            .all(|name| self.secret_bytes(name) == other.secret_bytes(name))
    }

    /// Plaintext bytes to hand to `sops --encrypt`.
    ///
    /// YAML with two-space indentation, block style, keys sorted. The output
    /// is itself a valid sops input document; sops replaces the values with
    /// `ENC[...]` markers.
    pub fn to_yaml(&self) -> Result<String, SopsError> {
        serde_yaml::to_string(self).map_err(|e| SopsError::Malformed {
            path: "<in memory>".into(),
            reason: e.to_string(),
        })
    }

    /// Parse decrypted plaintext.
    pub fn from_yaml(bytes: &[u8], path: &str) -> Result<Self, SopsError> {
        let document: Self = serde_yaml::from_slice(bytes).map_err(|e| SopsError::Malformed {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;
        if document.version == 0 || document.version > DOCUMENT_VERSION {
            return Err(SopsError::Malformed {
                path: path.to_owned(),
                reason: format!(
                    "document version {} is not supported (this build supports 1..={DOCUMENT_VERSION})",
                    document.version
                ),
            });
        }
        Ok(document)
    }

    /// Sort key for the conflict rule: `modified` (missing = epoch), then the
    /// hostname, then the revision.
    ///
    /// See the crate docs for the full rule.
    pub fn freshness(&self) -> (u128, &str, u64) {
        (
            self.modified.map(Timestamp::nanos).unwrap_or(0),
            self.host.as_deref().unwrap_or(""),
            self.revision,
        )
    }
}

/// A timestamp that round-trips as RFC 3339 but also reads an epoch number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(pub SystemTime);

impl Timestamp {
    /// Current wall-clock time.
    pub fn now() -> Self {
        Self(SystemTime::now())
    }

    /// Nanoseconds since the Unix epoch (0 before it).
    pub fn nanos(self) -> u128 {
        self.0
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }

    /// File-name-safe UTC form, `1763150000000000000` (nanoseconds).
    pub fn file_stamp(self) -> String {
        format!("{:020}", self.nanos())
    }
}

impl From<SystemTime> for Timestamp {
    fn from(value: SystemTime) -> Self {
        Self(value)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let dt = chrono::DateTime::<chrono::Utc>::from(self.0);
        serializer.serialize_str(&dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Epoch(f64),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Text(text) => parse_timestamp(&text)
                .map(Timestamp)
                .map_err(serde::de::Error::custom),
            Raw::Epoch(seconds) => Ok(Timestamp(epoch_to_system_time(seconds))),
        }
    }
}

fn epoch_to_system_time(seconds: f64) -> SystemTime {
    if !seconds.is_finite() || seconds <= 0.0 {
        return UNIX_EPOCH;
    }
    let whole = seconds.trunc() as u64;
    let nanos = ((seconds.fract()) * 1_000_000_000.0).round() as u32;
    UNIX_EPOCH + Duration::new(whole, nanos.min(999_999_999))
}

/// Parse an RFC 3339 timestamp, falling back to a Unix epoch number.
pub fn parse_timestamp(text: &str) -> Result<SystemTime, String> {
    let trimmed = text.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Ok(SystemTime::from(dt.with_timezone(&chrono::Utc)));
    }
    if let Ok(seconds) = trimmed.parse::<f64>() {
        return Ok(epoch_to_system_time(seconds));
    }
    Err(format!("`{trimmed}` is neither RFC 3339 nor a Unix epoch"))
}

/// Collection label, stored in `<collection>/_meta.meta.yaml` when a
/// collection's label is not its directory name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionMeta {
    /// Human-readable collection label.
    pub label: String,
    /// Creation time.
    #[serde(default)]
    pub created: Option<Timestamp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SopsDocument {
        SopsDocument {
            label: "github.com".into(),
            attributes: BTreeMap::from([("username".to_string(), "user".to_string())]),
            secrets: BTreeMap::from([("password".to_string(), "hunter2".to_string())]),
            binary_secrets: BTreeMap::new(),
            created: Some(Timestamp(UNIX_EPOCH + Duration::from_secs(1_700_000_000))),
            modified: Some(Timestamp(UNIX_EPOCH + Duration::from_secs(1_700_000_100))),
            host: Some("host-a".into()),
            revision: 3,
            version: DOCUMENT_VERSION,
        }
    }

    #[test]
    fn round_trips_yaml() {
        let doc = sample();
        let yaml = doc.to_yaml().unwrap();
        assert!(yaml.contains("password: hunter2"), "{yaml}");
        assert!(yaml.contains("modified: 2023-11-14T"), "{yaml}");
        assert!(yaml.contains("version: 1"), "{yaml}");
        assert!(
            !yaml.contains("binary_secrets"),
            "empty binary map must not be written: {yaml}"
        );
        let back = SopsDocument::from_yaml(yaml.as_bytes(), "<test>").unwrap();
        assert_eq!(back, doc);
    }

    #[test]
    fn missing_version_defaults_to_one() {
        let doc = SopsDocument::from_yaml(b"label: x\n", "<t>").unwrap();
        assert_eq!(doc.version, DOCUMENT_VERSION);
    }

    #[test]
    fn refuses_a_newer_document_version() {
        let error = SopsDocument::from_yaml(b"label: x\nversion: 2\n", "<t>").unwrap_err();
        let text = error.to_string();
        assert!(text.contains("version 2"), "{text}");
        assert!(text.contains("not supported"), "{text}");
    }

    #[test]
    fn refuses_version_zero() {
        let error = SopsDocument::from_yaml(b"label: x\nversion: 0\n", "<t>").unwrap_err();
        let text = error.to_string();
        assert!(text.contains("version 0"), "{text}");
        assert!(text.contains("not supported"), "{text}");
    }

    #[test]
    fn keeps_binary_secrets_byte_for_byte() {
        let mut doc = sample();
        let raw = [0xffu8, 0x00, 0xfe, 0x80, 0x41];
        doc.set_secret("blob", &raw);
        doc.set_secret("password", "plain".as_bytes());
        let yaml = doc.to_yaml().unwrap();
        assert!(yaml.contains("binary_secrets:"), "{yaml}");
        let back = SopsDocument::from_yaml(yaml.as_bytes(), "<test>").unwrap();
        assert_eq!(
            back.secret_bytes("blob").unwrap().unwrap(),
            raw.to_vec(),
            "binary value must survive the YAML round trip"
        );
        assert_eq!(
            back.secret_bytes("password").unwrap().unwrap(),
            b"plain".to_vec()
        );
        assert!(back.secrets_equal(&doc), "decoded bytes compare equal");
        // No U+FFFD mangling anywhere.
        assert!(!yaml.contains('\u{FFFD}'), "{yaml}");
    }

    #[test]
    fn setting_a_name_moves_it_between_the_maps() {
        let mut doc = sample();
        doc.set_secret("password", &[0u8, 159]);
        assert!(!doc.secrets.contains_key("password"));
        assert!(doc.binary_secrets.contains_key("password"));
        doc.set_secret("password", b"text again");
        assert!(!doc.binary_secrets.contains_key("password"));
        assert_eq!(
            doc.secret_bytes("password").unwrap().unwrap(),
            b"text again".to_vec()
        );
    }

    #[test]
    fn rejects_corrupt_base64() {
        let doc = SopsDocument::from_yaml(b"label: x\nbinary_secrets:\n  blob: \"***\"\n", "<t>")
            .unwrap();
        assert_eq!(
            doc.secret_bytes("blob"),
            Some(Err(SecretDecodeError::NotBase64))
        );
    }

    #[test]
    fn accepts_epoch_timestamps() {
        let yaml = "label: plain\nmodified: 1700000100\ncreated: 1700000000.5\n";
        let doc = SopsDocument::from_yaml(yaml.as_bytes(), "<test>").unwrap();
        assert_eq!(doc.modified.unwrap().nanos(), 1_700_000_100_000_000_000);
        assert_eq!(doc.created.unwrap().nanos(), 1_700_000_000_500_000_000);
    }

    #[test]
    fn missing_fields_use_defaults() {
        let doc = SopsDocument::from_yaml(b"label: sparse\n", "<test>").unwrap();
        assert!(doc.attributes.is_empty());
        assert!(doc.secrets.is_empty());
        assert!(doc.binary_secrets.is_empty());
        assert_eq!(doc.revision, 0);
        assert_eq!(doc.freshness(), (0, "", 0));
    }

    #[test]
    fn rejects_unknown_shapes() {
        assert!(SopsDocument::from_yaml(b"- just\n- a list\n", "<test>").is_err());
    }
}
