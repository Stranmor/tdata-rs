# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-12

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
- Session string generation compatible with `grammers`
- CLI utility for quick session export

### Security

- All cryptographic operations performed locally
- No network requests, no telemetry
- Auth keys never leave your machine

[Unreleased]: https://github.com/stranmor/tdata-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/stranmor/tdata-rs/releases/tag/v0.1.0
