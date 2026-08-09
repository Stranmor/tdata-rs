# hermes-tdata

**Pure Rust parser for Telegram Desktop's `tdata` storage.**

[![Crates.io](https://img.shields.io/crates/v/hermes-tdata.svg)](https://crates.io/crates/hermes-tdata)
[![Documentation](https://docs.rs/hermes-tdata/badge.svg)](https://docs.rs/hermes-tdata)
[![CI](https://github.com/Stranmor/hermes-tdata/actions/workflows/ci.yml/badge.svg)](https://github.com/Stranmor/hermes-tdata/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Parse Telegram Desktop's local `tdata` storage and convert authorized account
data into [`grammers_session::SessionData`](https://docs.rs/grammers-session/latest/grammers_session/struct.SessionData.html).
The crate reads local files only and does not include a network client.

> [!CAUTION]
> Session data and authentication keys grant account access. Use this crate
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
  - Produces `grammers_session::SessionData` values for import into a `grammers` session storage.
- **Multi-account storage**: Reads every account index present in the local key data.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hermes-tdata = "0.2"
```

## Quick start

### Convert tdata to grammers SessionData

```rust
use hermes_tdata::TDesktop;

fn main() -> Result<(), hermes_tdata::Error> {
    let tdata = TDesktop::from_default()?;

    println!("Found {} account(s)", tdata.accounts().len());

    // SessionData contains authentication credentials: never log or serialize it.
    for account in tdata.accounts() {
        let session_data = account.to_grammers_session_data();
        println!("SessionData prepared for DC {}", session_data.home_dc);
    }

    Ok(())
}
```

## CLI utility

The repository includes a local inspection example. Credential output remains
redacted unless an explicit `--show-*` flag is supplied.

```bash
# Clone and run
git clone https://github.com/Stranmor/hermes-tdata
cd hermes-tdata

# Run with default tdata path
cargo run --example cli

# Or specify a custom path
cargo run --example cli -- /path/to/tdata

# Prompt for a passcode without echoing it or storing it in shell history
cargo run --example cli -- --prompt-passcode

# For automation, pass it through stdin rather than a command-line argument
printf '%s\n' "$TDATA_PASSCODE" | cargo run --example cli -- --passcode-stdin

# Private paths, account identifiers, and auth keys are opt-in
cargo run --example cli -- --show-identifiers
cargo run --example cli -- --show-keys
```

**Output example:**
```text
📂 Reading tdata from: [redacted; use --show-identifiers to reveal]
✅ Successfully loaded TDesktop storage!
   App Version: 6004001
   Passcode:    NO
   Accounts:    2

👤 Account #1 (Index 0)
   User ID:   [redacted; use --show-identifiers to reveal]
   DC ID:     2
   Grammers:  SessionData conversion available
   Auth Key:  [redacted; use --show-keys to reveal]

👤 Account #2 (Index 1)
   User ID:   [redacted; use --show-identifiers to reveal]
   DC ID:     2
   Grammers:  SessionData conversion available
   Auth Key:  [redacted; use --show-keys to reveal]
```

## Security

This library handles live authentication credentials.

- Never share your `tdata` folder, session data, auth keys, or output produced with a `--show-*` option.
- Anyone with session data or an `AuthKey` can access the corresponding Telegram account without 2FA.
- The CLI does not print session data and redacts paths, account identifiers, and auth keys by default.
- `Debug` output for `Account`, `TDesktop`, and `AuthKey` redacts paths, account identifiers, and key material.
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
