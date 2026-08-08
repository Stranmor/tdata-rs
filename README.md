# tdata-rs

**Pure Rust parser for Telegram Desktop's `tdata` storage.**

[![Crates.io](https://img.shields.io/crates/v/tdata-rs.svg)](https://crates.io/crates/tdata-rs)
[![Documentation](https://docs.rs/tdata-rs/badge.svg)](https://docs.rs/tdata-rs)
[![CI](https://github.com/stranmor/tdata-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/stranmor/tdata-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Parse Telegram Desktop's local `tdata` storage and convert authorized account
data into [`grammers`](https://github.com/Lonami/grammers) session formats.
The crate reads local files only and does not include a network client.

> [!CAUTION]
> Session strings and authentication keys grant account access. Use this crate
> only with storage you own or are explicitly authorized to inspect, and treat
> every generated session as a credential.

## Features

- **Pure Rust parser**: No Qt, C++, or Python runtime dependency.
- **Local storage cryptography**:
  - PBKDF2-SHA512 key derivation with custom parameters.
  - AES-256-IGE decryption through `grammers-crypto`.
  - MD5/SHA1 file integrity verification.
- **MTP parsing**:
  - Parses `key_data` (local keys).
  - Parses `map` files (account data).
  - Reads `AuthKey`, `UserId`, and `DcId` values.
  - Supports new (64-bit ID) and legacy tdata formats.
- **Interoperability**:
  - Produces `grammers_session::SessionData` values and session strings.
- **Multi-account storage**: Reads every account index present in the local key data.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tdata-rs = "0.1"
```

## Quick start

### Convert tdata to Session String

```rust
use tdata_rs::TDesktop;

fn main() -> Result<(), tdata_rs::Error> {
    let tdata = TDesktop::from_default()?;

    println!("Found {} account(s)", tdata.accounts().len());

    // Session strings are authentication credentials: never log them.
    for account in tdata.accounts() {
        let session = account.to_session_string()?;
        println!("Session generated ({} bytes)", session.len());
    }

    Ok(())
}
```

## CLI utility

The repository includes a local inspection example. Credential output remains
redacted unless an explicit `--show-*` flag is supplied.

```bash
# Clone and run
git clone https://github.com/stranmor/tdata-rs
cd tdata-rs

# Run with default tdata path
cargo run --example cli

# Or specify a custom path
cargo run --example cli -- /path/to/tdata

# Prompt for a passcode without echoing it or storing it in shell history
cargo run --example cli -- --prompt-passcode

# For automation, pass it through stdin rather than a command-line argument
printf '%s\n' "$TDATA_PASSCODE" | cargo run --example cli -- --passcode-stdin

# Full session strings and auth keys are opt-in because both grant account access
cargo run --example cli -- --show-session
cargo run --example cli -- --show-keys
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
   Session:   [redacted; use --show-session to reveal]
   Auth Key:  [redacted; use --show-keys to reveal]

👤 Account #2 (Index 1)
   User ID:   987654321
   DC ID:     2
   Session:   [redacted; use --show-session to reveal]
   Auth Key:  [redacted; use --show-keys to reveal]
```

## Security

This library handles live authentication credentials.

- Never share your `tdata` folder, session strings, auth keys, or output produced with a `--show-*` option.
- Anyone with a session string or `AuthKey` can access the corresponding Telegram account without 2FA.
- The CLI redacts session strings and auth keys by default.
- Passcodes can be entered through a hidden prompt or stdin and are not retained by the parsed `TDesktop` object.
- The crate performs no network requests.

## Acknowledgements

- **[opentele](https://github.com/thedemons/opentele)** (Python) - Protocol reference.
- **[tdesktop](https://github.com/telegramdesktop/tdesktop)** (C++) - The source of truth.
- **[grammers](https://github.com/Lonami/grammers)** (Rust) - Session format compatibility.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome through issues and pull requests.
