# tdata-rs 🚀

**Pure Rust parser for Telegram Desktop's `tdata` storage.**

[![Crates.io](https://img.shields.io/crates/v/tdata-rs.svg)](https://crates.io/crates/tdata-rs)
[![Documentation](https://docs.rs/tdata-rs/badge.svg)](https://docs.rs/tdata-rs)
[![CI](https://github.com/stranmor/tdata-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/stranmor/tdata-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Extract sessions and authentication keys from Telegram Desktop's local storage (`tdata`) **without** launching the official client, using `Qt`, or relying on `Python`.

## ⚡️ Features

- **Pure Rust**: No dependencies on Qt, C++, or Python. Statically linked and blazing fast.
- **Cross-Platform**: Works on Linux, Windows, and macOS tdata folders.
- **Cryptography**: Full implementation of TDesktop's custom encryption scheme:
  - PBKDF2-SHA512 key derivation with custom parameters.
  - AES-256-IGE encryption implementation.
  - Custom MD5/SHA1 file integrity verification.
- **MTP Parsing**:
  - Parses `key_data` (local keys).
  - Parses `map` files (account data).
  - Extracts `AuthKey`, `UserId`, and `DcId`.
  - Supports new (64-bit ID) and legacy tdata formats.
- **Interoperability**:
  - Generates session strings compatible with [`grammers`](https://github.com/Lonami/grammers) (Rust).
  - Easily adaptable for `telethon` or `pyrogram`.
- **Multi-Account**: Automatically detects and extracts all active accounts.

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tdata-rs = "0.1"
```

## 🚀 Quick Start

### Convert tdata to Session String

```rust
use tdata_rs::TDesktop;
use std::path::PathBuf;

fn main() -> Result<(), tdata_rs::Error> {
    // 1. Path to tdata (Linux example)
    let tdata_path = PathBuf::from(std::env::var("HOME").unwrap())
        .join(".local/share/TelegramDesktop/tdata");

    // 2. Load TDesktop storage
    let tdata = TDesktop::from_path(&tdata_path)?;

    println!("Found {} accounts!", tdata.accounts().len());

    // 3. Iterate accounts
    for account in tdata.accounts() {
        println!("User ID: {}", account.user_id());
        
        // 4. Generate session string for Grammers
        let session = account.to_session_string()?;
        println!("Session: {}", session);
        
        // 5. Or get raw auth key
        let auth_key = account.auth_key_bytes();
        println!("Auth Key: {}", hex::encode(auth_key));
    }

    Ok(())
}
```

## 🛠 CLI Utility

This crate includes a ready-to-use CLI tool to inspect tdata and extract sessions.

```bash
# Clone and run
git clone https://github.com/stranmor/tdata-rs
cd tdata-rs

# Run with default tdata path
cargo run --example cli

# Or specify a custom path
cargo run --example cli -- /path/to/tdata

# With passcode
cargo run --example cli -- --passcode "secret123"
```

**Output example:**
```text
📂 Reading tdata from: "/home/user/.local/share/TelegramDesktop/tdata"
✅ Successfully loaded TDesktop storage!
   App Version: 6004001
   Passcode:    NO
   Accounts:    2

👤 Account #1 (Index 0)
   User ID:   123456789
   DC ID:     2
   Session:   1BQAz... (ready for grammers)

👤 Account #2 (Index 1)
   User ID:   987654321
   DC ID:     2
   Session:   1BQBm...
```

## 🔒 Security Note

This library deals with **sensitive authentication keys**.

- ⚠️ Never share your `tdata` folder or the output of this tool.
- ⚠️ Anyone with the `AuthKey` can access your Telegram account without 2FA.
- ✅ This tool runs locally on your machine and does not transmit keys anywhere.

## 🤝 Acknowledgements

- **[opentele](https://github.com/thedemons/opentele)** (Python) - Protocol reference.
- **[tdesktop](https://github.com/telegramdesktop/tdesktop)** (C++) - The source of truth.
- **[grammers](https://github.com/Lonami/grammers)** (Rust) - Session format compatibility.

## 📜 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
