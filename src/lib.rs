//! # tdata-rs
//!
//! A pure Rust library for parsing Telegram Desktop `tdata` folders and converting
//! them to grammers sessions.
//!
//! ## Features
//!
//! - Parse `tdata` folders from Telegram Desktop
//! - Extract authorization keys (auth_key) and datacenter IDs
//! - Convert to grammers session format
//! - Support for password-protected tdata (Local Passcode)
//! - Zero Python dependencies
//!
//! ## Example
//!
//! ```rust,no_run
//! use tdata_rs::TDesktop;
//!
//! fn main() -> Result<(), tdata_rs::Error> {
//!     // Load tdata from default location
//!     let tdesktop = TDesktop::from_path("/path/to/tdata")?;
//!     
//!     // Get the main account's session
//!     if let Some(account) = tdesktop.main_account() {
//!         let session_data = account.to_grammers_session_data();
//!         println!("DC ID: {}", account.dc_id());
//!         println!("User ID: {}", account.user_id());
//!     }
//!     
//!     Ok(())
//! }
//! ```

mod error;
mod qdatastream;
mod crypto;
mod storage;
mod account;
mod tdesktop;

pub use error::{Error, Result};
pub use account::Account;
pub use tdesktop::TDesktop;

/// Auth key size in bytes (256 bytes = 2048 bits)
pub const AUTH_KEY_SIZE: usize = 256;

/// Default key file name
pub const DEFAULT_KEY_FILE: &str = "data";

/// Maximum number of accounts supported by Telegram Desktop
pub const MAX_ACCOUNTS: usize = 3;
