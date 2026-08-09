# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-09

### Security

- Redact session strings and auth keys in the CLI by default; revealing either now requires an explicit flag.
- Replace the command-line passcode argument with hidden-prompt and stdin input modes.
- Stop retaining the supplied passcode inside the parsed `TDesktop` object.
- Redact credential prefixes, storage paths, and account identifiers from diagnostic output by default.
- Redact storage paths, account identifiers, and auth keys from public `Debug` output.
- Upgrade `grammers` dependencies to maintained releases, removing the yanked `core2` dependency that blocked fresh installs.

### Changed

- Publish the first crates.io release from the current security-hardened source.
- Align the crate manifest with the already-supported Rust 2024 edition and Rust 1.85 MSRV.
- Make `grammers_session::SessionData` the documented interoperability path and deprecate the misleading crate-specific `to_session_string()` name.
- Make legacy credential export fallible instead of truncating invalid datacenter identifiers.
- Reject out-of-bounds binary lengths and offsets without panic-prone indexing or lossy integer casts.
- Add contributor, vulnerability-reporting, dependency-update, and release surfaces.

## [0.1.0] - 2026-01-12

This version existed in the repository but was not published to crates.io.

### Added

- Initial release
- Pure Rust implementation of Telegram Desktop `tdata` parser
- PBKDF2-SHA512 key derivation with custom Telegram parameters
- AES-256-IGE encryption/decryption
- MD5 and SHA1 checksum verification
- QDataStream (Qt 5.1 binary format) parser
- MTP authorization data extraction
- Support for 64-bit user IDs (kWideIdsTag)
- Multi-account support (up to 3 accounts)
- Legacy crate-specific credential string generation
- CLI utility for quick session export

### Security

- All cryptographic operations performed locally
- No network requests, no telemetry
- Auth keys never leave your machine

[Unreleased]: https://github.com/Stranmor/tdata-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Stranmor/tdata-rs/compare/ad6eb902bda7d31c052951e1128dbb8e015a0f3f...v0.2.0
[0.1.0]: https://github.com/Stranmor/tdata-rs/tree/ad6eb902bda7d31c052951e1128dbb8e015a0f3f
