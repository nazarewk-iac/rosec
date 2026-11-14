//! Error type for the sops store.
//!
//! Every variant is safe to log: `SopsFailed` carries a *classified* reason
//! (see [`crate::sops::classify_stderr`]), never the raw stderr of `sops`.

use rosec_core::ProviderError;

/// A failed sops store operation.
#[derive(Debug, thiserror::Error)]
pub enum SopsError {
    /// A configuration option is missing or malformed.
    #[error("sops store config: {0}")]
    Config(String),

    /// The `sops` executable, the age identity file, or the store root is
    /// missing or unusable.
    #[error("sops store unavailable: {0}")]
    Unavailable(String),

    /// The requested item has no file in the store.
    #[error("item `{0}` not found")]
    NotFound(String),

    /// A file exists but its content is not the expected document.
    #[error("malformed sops store file `{path}`: {reason}")]
    Malformed {
        /// File that could not be parsed.
        path: String,
        /// Why parsing failed.
        reason: String,
    },

    /// A stored secret value cannot be decoded.
    #[error("malformed secret in `{path}`: {name} is not valid base64")]
    MalformedSecret {
        /// File that holds the value.
        path: String,
        /// Secret name.
        name: String,
    },

    /// The `sops` command exited with a non-zero status.
    #[error("`sops {args}` failed ({status}): {reason}")]
    SopsFailed {
        /// The arguments, minus the binary name. Recipients are public; the
        /// key file is only ever passed through the environment.
        args: String,
        /// Termination status as text (`exit 1`, `timeout`, ...).
        status: String,
        /// Classified stderr. Never the raw text.
        reason: String,
    },

    /// A store file exists but this identity cannot decrypt it.
    ///
    /// Maps to [`ProviderError::AuthFailed`], so the daemon prompts instead of
    /// showing a generic fault.
    #[error("cannot decrypt `{path}` with the configured age identity: {reason}")]
    Unreadable {
        /// File that could not be decrypted.
        path: String,
        /// Classified reason.
        reason: String,
    },

    /// An I/O operation failed.
    #[error("sops store I/O error at `{path}`: {source}")]
    Io {
        /// The path involved.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },

    /// The provider is locked, so no store access is possible.
    #[error("sops store is locked")]
    Locked,
}

impl SopsError {
    /// Map to the daemon-facing error type.
    pub fn into_provider_error(self) -> ProviderError {
        match self {
            SopsError::Config(msg) => ProviderError::InvalidInput(msg.into()),
            SopsError::Locked => ProviderError::Locked,
            SopsError::NotFound(id) => {
                tracing::debug!(item_id = %id, "sops store item not found");
                ProviderError::NotFound
            }
            SopsError::Unreadable { path, reason } => {
                tracing::warn!(path = %path, reason = %reason, "sops store file is unreadable");
                ProviderError::AuthFailed
            }
            other => ProviderError::Other(anyhow::Error::new(other)),
        }
    }

    /// Build an I/O error with the path attached.
    pub fn io(path: impl std::fmt::Display, source: std::io::Error) -> Self {
        SopsError::Io {
            path: path.to_string(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "hunter2-chosen-by-the-test";

    #[test]
    fn a_sops_failure_never_carries_plaintext() {
        // A crafted stderr that quotes plaintext, as sops can do for a
        // malformed document.
        let stderr =
            format!("failed to parse: secrets:\\n  password: {SECRET}\\nENC[AES256_GCM,data:x]");
        let error = SopsError::SopsFailed {
            args: "--encrypt --age age1x".into(),
            status: "exit 1".into(),
            reason: crate::sops::classify_stderr(stderr.as_bytes()),
        };
        let rendered = format!("{error}");
        assert!(
            !rendered.contains(SECRET),
            "plaintext reached the error: {rendered}"
        );
        let mapped = ProviderError::Other(anyhow::Error::new(error));
        let rendered = format!("{mapped}");
        assert!(
            !rendered.contains(SECRET),
            "plaintext reached the provider error: {rendered}"
        );
    }

    #[test]
    fn unreadable_files_map_to_auth_failed() {
        let mapped = SopsError::Unreadable {
            path: "/store/default/item-x.sops.yaml".into(),
            reason: "decryption failed".into(),
        }
        .into_provider_error();
        assert!(
            matches!(mapped, ProviderError::AuthFailed),
            "wrong identity must ask for authentication, got {mapped:?}"
        );
    }
}
