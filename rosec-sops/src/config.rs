//! Provider configuration: the `path`, `key_file`, `age_recipient` and
//! `sops_binary` options of a `kind = "sops"` provider entry, plus the
//! unlock-once options `identity_file`, `identity_key_file` and
//! `runtime_identity_file`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rosec_core::ProviderError;

use crate::error::SopsError;
use crate::store_mode::StoreMode;

/// Default path of the sops age identity file, relative to `$HOME`.
///
/// This is the file that `sops` itself reads when `SOPS_AGE_KEY_FILE` is not
/// set, and the file this host keeps its YubiKey age identities in.
pub const DEFAULT_KEY_FILE: &str = ".config/sops/age/keys.txt";

/// Default `sops` executable name, resolved through `$PATH`.
pub const DEFAULT_SOPS_BINARY: &str = "sops";

/// The full set of options a `kind = "sops"` provider entry accepts.
///
/// In the daemon config file:
///
/// ```toml
/// [[provider]]
/// id   = "sops"
/// kind = "sops"
/// path = "~/Nextcloud/rosec-store"
///
/// [provider.options]
/// key_file      = "~/.config/sops/age/keys.txt"
/// age_recipient = "age1yubikey1..."   # optional, see below
/// sops_binary   = "sops"
/// probe_timeout_seconds = 30          # optional, default 30
/// ```
///
/// `path` normally comes from the shared `ProviderEntry::path` field; it may
/// also be written as `options.path`, which wins when both are set.
///
/// `age_recipient` has two modes:
///
/// - **unset** — `sops --encrypt` runs without `--age`, so the creation rules
///   of a `.sops.yaml` in the store root decide the recipients. A missing or
///   non-matching rule makes sops fail with "no keys provided", which surfaces
///   as `SopsError::SopsFailed`.
/// - **set** — every new file is encrypted to these recipients. An update of
///   an existing file encrypts to the **union** of the list and the recipients
///   already in the file's header, so a configured list never narrows access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SopsConfig {
    /// Store root. One directory per collection below it.
    pub path: PathBuf,
    /// sops age identity file, passed as `SOPS_AGE_KEY_FILE`.
    pub key_file: PathBuf,
    /// age recipient(s) for new and updated files (the YubiKey recipient).
    ///
    /// One recipient or several, comma-separated. Several recipients let one
    /// synced store be readable on each host with that host's own YubiKey.
    ///
    /// Empty when the option is unset: sops then takes the recipients from the
    /// creation rules of the store's `.sops.yaml`.
    pub age_recipient: String,
    /// The `sops` executable.
    pub sops_binary: PathBuf,
    /// Upper bound for the decrypt probe that `unlock` runs.
    ///
    /// `unlock` proves the identity works by decrypting one store file, so a
    /// YubiKey in the wrong slot fails at unlock instead of on the first read.
    /// The probe is bounded so an unplugged token cannot hang `rosec unlock`.
    pub probe_timeout: Duration,
    /// The sops-encrypted master file that holds the derived sops identity
    /// (`<store>/.rosec-store-identity.sops.yaml`).
    ///
    /// `None` means the `direct` store mode: `key_file` is the identity of
    /// every item operation, exactly as before. `Some` means the `derived`
    /// store mode: the master is unwrapped once per session and the derived
    /// identity does the item work.
    pub identity_file: Option<PathBuf>,
    /// The identity used **only** to decrypt the master file.
    ///
    /// `None` falls back to `key_file`. The recipients of the master file are
    /// chosen by the store's own `.sops.yaml` rule, so that rule — not this
    /// option — decides whether an age, PGP or KMS key is needed.
    pub identity_key_file: Option<PathBuf>,
    /// Where `unlock` caches the unwrapped derived identity for this session,
    /// with mode 0600 below a 0700 directory.
    pub runtime_identity_file: PathBuf,
}

impl SopsConfig {
    /// Build the configuration from the raw provider entry fields.
    ///
    /// `provider_path` is `ProviderEntry::path`; `options` is
    /// `ProviderEntry::options`. All `~` prefixes are expanded against
    /// `$HOME`. Relative paths are rejected: a store must have one absolute
    /// location, otherwise the daemon and the user can disagree about which
    /// files they mean.
    pub fn from_options(
        provider_path: Option<&str>,
        options: &HashMap<String, serde_json::Value>,
    ) -> Result<Self, ProviderError> {
        let path = string_option(options, "path")
            .or_else(|| provider_path.map(str::to_owned))
            .ok_or_else(|| {
                SopsError::Config(
                    "missing `path`: set the provider entry's `path` (the store root)".into(),
                )
                .into_provider_error()
            })?;

        let key_file = string_option(options, "key_file")
            .or_else(|| Some(default_key_file()))
            .expect("default key file is always present");
        // Absent or empty: let the store's `.sops.yaml` creation rules decide
        // (see the type docs). Only an obviously malformed value is rejected,
        // so a typo cannot silently fall back to the sops config.
        let age_recipient = string_option(options, "age_recipient").unwrap_or_default();
        let sops_binary =
            string_option(options, "sops_binary").unwrap_or_else(|| DEFAULT_SOPS_BINARY.into());
        let mut config = Self::new(path, key_file, age_recipient, sops_binary)?;
        if let Some(seconds) = number_option(options, "probe_timeout_seconds") {
            if !(1..=600).contains(&seconds) {
                return Err(SopsError::Config(format!(
                    "`probe_timeout_seconds` must be between 1 and 600, got {seconds}"
                ))
                .into_provider_error());
            }
            config.probe_timeout = Duration::from_secs(seconds);
        }
        config.identity_file = match string_option(options, "identity_file") {
            Some(raw) => Some(expand_home(&raw)?),
            None => None,
        };
        config.identity_key_file = match string_option(options, "identity_key_file") {
            Some(raw) => Some(expand_home(&raw)?),
            None => None,
        };
        if let Some(raw) = string_option(options, "runtime_identity_file") {
            config.runtime_identity_file = expand_home(&raw)?;
        }
        Ok(config)
    }

    /// Validate and normalise the four options.
    pub fn new(
        path: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        age_recipient: impl Into<String>,
        sops_binary: impl AsRef<Path>,
    ) -> Result<Self, ProviderError> {
        let path = expand_home(path.as_ref().to_string_lossy().as_ref())?;
        let key_file = expand_home(key_file.as_ref().to_string_lossy().as_ref())?;
        let sops_binary = sops_binary.as_ref().to_path_buf();
        let age_recipient = age_recipient.into().trim().to_owned();

        if sops_binary.as_os_str().is_empty() {
            return Err(SopsError::Config("`sops_binary` is empty".into()).into_provider_error());
        }
        if !age_recipient.is_empty() {
            for recipient in split_recipients(&age_recipient) {
                validate_recipient(recipient)?;
            }
        }
        if path == Path::new("/") {
            return Err(
                SopsError::Config("`path` must not be the filesystem root".into())
                    .into_provider_error(),
            );
        }

        Ok(Self {
            path,
            key_file,
            age_recipient,
            sops_binary,
            probe_timeout: crate::sops::DEFAULT_PROBE_TIMEOUT,
            identity_file: None,
            identity_key_file: None,
            runtime_identity_file: default_runtime_identity_file(),
        })
    }

    /// The store mode these options describe.
    ///
    /// `identity_file` is the only switch: `Some` means `derived`, `None` means
    /// `direct`. The store's own metadata must agree — see
    /// [`SopsConfig::check_mode`].
    pub fn mode(&self) -> StoreMode {
        match self.identity_file {
            Some(_) => StoreMode::Derived,
            None => StoreMode::Direct,
        }
    }

    /// The identity file that decrypts the master file.
    ///
    /// `identity_key_file` when set, else `key_file` (the local unlock
    /// identity).
    pub fn master_key_file(&self) -> &Path {
        self.identity_key_file.as_deref().unwrap_or(&self.key_file)
    }

    /// Refuse a configuration that disagrees with the store metadata.
    ///
    /// The mode is recorded in `<store>/.rosec-store.yaml` and never changes
    /// in place, so a mismatch is a configuration error, not something to
    /// guess around: a `derived` store read through a `direct` entry would
    /// write item files that the derived identity cannot open.
    pub fn check_mode(&self, mode: StoreMode) -> Result<(), ProviderError> {
        match (mode, self.identity_file.is_some()) {
            (StoreMode::Direct, false) | (StoreMode::Derived, true) => Ok(()),
            (StoreMode::Direct, true) => Err(SopsError::Config(format!(
                "`{}` is a `direct` store but this provider sets `identity_file`; remove \
                 `identity_file` (or migrate the store: `rosec-sops store migrate`)",
                self.path.display()
            ))
            .into_provider_error()),
            (StoreMode::Derived, false) => Err(SopsError::Config(format!(
                "`{}` is a `derived` store but this provider has no `identity_file`; set it to \
                 `{}/{}`",
                self.path.display(),
                self.path.display(),
                crate::store_mode::STORE_IDENTITY_FILE
            ))
            .into_provider_error()),
        }
    }
}

/// The master file inside a store root.
pub fn store_identity_path(store: &Path) -> PathBuf {
    store.join(crate::store_mode::STORE_IDENTITY_FILE)
}

/// The plaintext sidecar holding the derived **public** recipient.
pub fn store_identity_recipient_path(store: &Path) -> PathBuf {
    store.join(crate::store_mode::STORE_IDENTITY_RECIPIENT_FILE)
}

/// The runtime file a session keeps the unwrapped derived identity in.
///
/// `$XDG_RUNTIME_DIR/rosec/store-identity.age`, else
/// `/tmp/rosec-<uid>/store-identity.age` when `XDG_RUNTIME_DIR` is unset.
pub fn default_runtime_identity_file() -> PathBuf {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("rosec"),
        _ => PathBuf::from(format!(
            "/tmp/rosec-{}",
            // `id -u` without a dependency: the effective uid via `std`.
            effective_uid()
        )),
    };
    dir.join("store-identity.age")
}

/// Effective user id, used only for the `/tmp` fallback path.
fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // `/proc/self` is owned by the effective uid on Linux.
        if let Ok(meta) = std::fs::metadata("/proc/self") {
            return meta.uid();
        }
        0
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Expand a leading `~` against `$HOME` and require the result to be absolute.
pub fn expand_home(raw: &str) -> Result<PathBuf, ProviderError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SopsError::Config("a path option is empty".into()).into_provider_error());
    }
    let expanded = if trimmed == "~" || trimmed.starts_with("~/") {
        let home = home_dir()?;
        if trimmed == "~" {
            home
        } else {
            home.join(&trimmed[2..])
        }
    } else {
        PathBuf::from(trimmed)
    };
    if !expanded.is_absolute() {
        return Err(SopsError::Config(format!(
            "path `{trimmed}` is relative; `rosec-sops` needs an absolute path or a `~/` prefix"
        ))
        .into_provider_error());
    }
    Ok(expanded)
}

/// `$HOME`, with the same fallbacks sops and most Unix tools use.
fn home_dir() -> Result<PathBuf, ProviderError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .ok_or_else(|| {
            SopsError::Config("cannot expand `~`: $HOME is not set".into()).into_provider_error()
        })
}

fn default_key_file() -> String {
    format!("~/{DEFAULT_KEY_FILE}")
}

fn number_option(options: &HashMap<String, serde_json::Value>, key: &str) -> Option<u64> {
    options.get(key).and_then(|v| v.as_u64())
}

fn string_option(options: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    options
        .get(key)
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// Split a comma-separated recipient list into its parts.
pub fn split_recipients(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',').map(str::trim).filter(|r| !r.is_empty())
}

/// Check the shape of an age recipient.
///
/// Accepted: `age1...` (a plain age X25519 recipient, or a plugin recipient
/// such as `age1yubikey1...`) and `age1<plugin>1...` in general. The check is
/// lexical only — the recipient is not contacted here. A malformed recipient
/// would only surface when `sops` rejects it while writing the first file, so
/// it is worth catching at startup.
fn validate_recipient(recipient: &str) -> Result<(), ProviderError> {
    let fail = |reason: String| {
        SopsError::Config(format!("invalid `age_recipient` `{recipient}`: {reason}"))
            .into_provider_error()
    };
    if recipient.is_empty() {
        return Err(fail("value is empty".into()));
    }
    if !recipient.starts_with("age1") {
        return Err(fail("must start with `age1`".into()));
    }
    if !recipient
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(fail("must be lowercase base32".into()));
    }
    if recipient.len() < 20 {
        return Err(fail("value is too short to be a recipient".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tilde_and_accepts_absolute_paths() {
        // SAFETY: single-threaded test; no other thread reads HOME here.
        unsafe { std::env::set_var("HOME", "/home/tester") };
        assert_eq!(
            expand_home("~/store").unwrap(),
            PathBuf::from("/home/tester/store")
        );
        assert_eq!(expand_home("~").unwrap(), PathBuf::from("/home/tester"));
        assert_eq!(
            expand_home("/abs/store").unwrap(),
            PathBuf::from("/abs/store")
        );
    }

    #[test]
    fn rejects_relative_and_empty_paths() {
        assert!(expand_home("store").is_err(), "relative path must fail");
        assert!(expand_home("").is_err(), "empty path must fail");
    }

    #[test]
    fn rejects_bad_recipients() {
        assert!(validate_recipient("").is_err());
        assert!(validate_recipient("age1SHORT").is_err());
        assert!(validate_recipient("ssh-ed25519 AAAAC3Nza").is_err());
        assert!(
            validate_recipient(
                "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000"
            )
            .is_ok()
        );
        assert!(
            validate_recipient("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
                .is_ok()
        );
    }

    #[test]
    fn requires_path_but_not_a_recipient() {
        let mut options = HashMap::new();
        assert!(
            SopsConfig::from_options(None, &options).is_err(),
            "path is required"
        );

        options.insert("path".into(), serde_json::json!("~/store"));
        let cfg = SopsConfig::from_options(None, &options)
            .expect("age_recipient is optional: the store's sops config decides");
        assert_eq!(cfg.age_recipient, "", "unset recipient stays empty");
        assert_eq!(cfg.sops_binary, PathBuf::from(DEFAULT_SOPS_BINARY));
        assert!(cfg.key_file.ends_with(DEFAULT_KEY_FILE));

        options.insert(
            "age_recipient".into(),
            serde_json::json!(
                "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000"
            ),
        );
        let cfg = SopsConfig::from_options(None, &options).unwrap();
        assert!(cfg.age_recipient.starts_with("age1yubikey1"));
    }

    #[test]
    fn rejects_a_malformed_recipient_instead_of_falling_back() {
        let mut options = HashMap::new();
        options.insert("path".into(), serde_json::json!("~/store"));
        options.insert("age_recipient".into(), serde_json::json!("age1SHORT"));
        assert!(
            SopsConfig::from_options(None, &options).is_err(),
            "a typo must not silently fall back to the creation rules"
        );
    }

    #[test]
    fn provider_path_is_the_fallback_for_options_path() {
        let mut options = HashMap::new();
        options.insert(
            "age_recipient".into(),
            serde_json::json!(
                "age1yubikey1qtestrecipient0000000000000000000000000000000000000000000"
            ),
        );
        let cfg = SopsConfig::from_options(Some("/srv/store"), &options).unwrap();
        assert_eq!(cfg.path, PathBuf::from("/srv/store"));

        // An empty recipient list is valid: sops reads `.sops.yaml` instead.
        let cfg = SopsConfig::new("/srv/store", "/tmp/keys.txt", "", "sops").unwrap();
        assert!(cfg.age_recipient.is_empty());
        // A partially bad list still fails.
        assert!(
            SopsConfig::new(
                "/srv/store",
                "/tmp/keys.txt",
                "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p,nope",
                "sops"
            )
            .is_err()
        );
    }
}
