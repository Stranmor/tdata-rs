//! TDesktop client implementation
//!
//! Main entry point for parsing tdata folders.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::account::Account;
use crate::crypto::AuthKey;
use crate::storage::{
    decrypt_key_data, get_absolute_path, get_default_tdata_path, read_key_data, read_mtp_data,
    KeyInfo,
};
use crate::{Error, Result, DEFAULT_KEY_FILE};

/// Telegram Desktop client representation
///
/// Represents a parsed tdata folder with all its accounts.
pub struct TDesktop {
    /// Base path to the tdata folder
    base_path: PathBuf,
    /// Key file name (usually "data")
    key_file: String,
    /// Whether a non-empty passcode was supplied for decryption.
    ///
    /// The passcode itself is deliberately not retained after loading.
    has_passcode: bool,
    /// Local encryption key
    local_key: AuthKey,
    /// List of accounts
    accounts: Vec<Account>,
    /// App version from tdata
    app_version: u32,
}

impl fmt::Debug for TDesktop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TDesktop")
            .field("base_path", &"<redacted>")
            .field("key_file", &self.key_file)
            .field("has_passcode", &self.has_passcode)
            .field("accounts_count", &self.accounts.len())
            .field("app_version", &self.app_version)
            .finish()
    }
}

impl TDesktop {
    /// Load TDesktop from the default tdata location
    ///
    /// # Returns
    /// - `Ok(TDesktop)` if loading succeeded
    /// - `Err(Error::FolderNotFound)` if the default location doesn't exist
    pub fn from_default() -> Result<Self> {
        let path = get_default_tdata_path().ok_or_else(|| Error::FolderNotFound {
            path: PathBuf::from("(default tdata path)"),
        })?;

        Self::from_path(path)
    }

    /// Load TDesktop from a specific path
    ///
    /// # Arguments
    /// - `path`: Path to the tdata folder
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::with_options(path, None, None)
    }

    /// Load TDesktop with a passcode
    ///
    /// Use this when the tdata is protected with a Local Passcode.
    ///
    /// # Arguments
    /// - `path`: Path to the tdata folder
    /// - `passcode`: The Local Passcode
    pub fn from_path_with_passcode<P: AsRef<Path>>(path: P, passcode: &str) -> Result<Self> {
        Self::with_options(path, Some(passcode), None)
    }

    /// Load TDesktop with all options
    ///
    /// # Arguments
    /// - `path`: Path to the tdata folder
    /// - `passcode`: Optional Local Passcode
    /// - `key_file`: Optional key file name (default: "data")
    pub fn with_options<P: AsRef<Path>>(
        path: P,
        passcode: Option<&str>,
        key_file: Option<&str>,
    ) -> Result<Self> {
        let base_path = get_absolute_path(path.as_ref());

        if !base_path.exists() {
            return Err(Error::FolderNotFound {
                path: base_path.clone(),
            });
        }

        let key_file = key_file.unwrap_or(DEFAULT_KEY_FILE).to_string();
        let passcode = passcode.unwrap_or("");
        let has_passcode = !passcode.is_empty();

        // Read and decrypt key data
        let key_data = read_key_data(&base_path, &key_file)?;

        let KeyInfo {
            local_key,
            account_indices,
        } = decrypt_key_data(&key_data, passcode.as_bytes())?;

        tracing::info!("Loaded key data: {} accounts found", account_indices.len());

        // Load accounts
        let mut accounts = Vec::new();
        for index in account_indices {
            match Self::load_account(&base_path, index, &local_key, &key_file) {
                Ok(account) => {
                    tracing::info!("Loaded account {} for DC {}", index, account.dc_id());
                    accounts.push(account);
                }
                Err(e) => {
                    tracing::warn!("Failed to load account {}: {}", index, e);
                }
            }
        }

        if accounts.is_empty() {
            return Err(Error::NoAccounts);
        }

        Ok(Self {
            base_path,
            key_file,
            has_passcode,
            local_key,
            accounts,
            app_version: key_data.version,
        })
    }

    /// Load a single account
    fn load_account(
        base_path: &Path,
        index: i32,
        local_key: &AuthKey,
        key_file: &str,
    ) -> Result<Account> {
        let mtp_data = read_mtp_data(base_path, index, local_key, key_file)?;

        Ok(Account::new(
            index,
            mtp_data.dc_id,
            mtp_data.user_id,
            mtp_data.auth_key,
        ))
    }

    /// Get the base path to the tdata folder.
    ///
    /// Local paths can reveal account names and workstation layout. Avoid logging them.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Get the number of accounts
    pub fn accounts_count(&self) -> usize {
        self.accounts.len()
    }

    /// Get all accounts
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Get the main (first) account
    pub fn main_account(&self) -> Option<&Account> {
        self.accounts.first()
    }

    /// Get an account by index
    pub fn account(&self, index: usize) -> Option<&Account> {
        self.accounts.get(index)
    }

    /// Get the app version
    pub fn app_version(&self) -> u32 {
        self.app_version
    }

    /// Check if the tdata has a passcode
    pub fn has_passcode(&self) -> bool {
        self.has_passcode
    }

    /// Get the key file name
    pub fn key_file(&self) -> &str {
        &self.key_file
    }

    /// Get the local encryption key.
    ///
    /// This is credential material. Never log, serialize, or expose it.
    pub fn local_key(&self) -> &AuthKey {
        &self.local_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Builder for TDesktop with more control over loading
    struct TDesktopBuilder {
        path: PathBuf,
        passcode: Option<String>,
        key_file: Option<String>,
    }

    impl TDesktopBuilder {
        /// Create a new builder with the given path
        fn new<P: AsRef<Path>>(path: P) -> Self {
            Self {
                path: path.as_ref().to_path_buf(),
                passcode: None,
                key_file: None,
            }
        }

        /// Set the passcode
        fn passcode(mut self, passcode: impl Into<String>) -> Self {
            self.passcode = Some(passcode.into());
            self
        }

        /// Set the key file name
        fn key_file(mut self, key_file: impl Into<String>) -> Self {
            self.key_file = Some(key_file.into());
            self
        }
    }

    #[test]
    fn test_builder() {
        let builder = TDesktopBuilder::new("/path/to/tdata")
            .passcode("secret")
            .key_file("custom");

        assert_eq!(builder.path, PathBuf::from("/path/to/tdata"));
        assert_eq!(builder.passcode, Some("secret".to_string()));
        assert_eq!(builder.key_file, Some("custom".to_string()));
    }

    #[test]
    fn debug_redacts_storage_path_and_account_identity() -> Result<()> {
        let tdesktop = TDesktop {
            base_path: PathBuf::from("/private/user/TelegramDesktop/tdata"),
            key_file: "data".to_string(),
            has_passcode: true,
            local_key: AuthKey::from_bytes(&[0xCD; crate::AUTH_KEY_SIZE])?,
            accounts: vec![Account::new(0, 2, 12_345_678, [0xAB; crate::AUTH_KEY_SIZE])],
            app_version: 6_004_001,
        };
        let debug = format!("{tdesktop:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("/private/user"));
        assert!(!debug.contains("12345678"));
        assert!(!debug.contains("171, 171"));
        assert!(!debug.contains("205, 205"));
        Ok(())
    }
}
