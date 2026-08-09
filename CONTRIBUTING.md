# Contributing

Contributions are welcome when they preserve the crate's local-only and credential-safe boundary.

## Development

Use Rust 1.85 or newer, then run:

```bash
cargo fmt --all -- --check
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

## Pull requests

- Keep changes focused and explain the user-visible behavior.
- Add tests for parser, compatibility, or credential-handling changes.
- Use only synthetic fixtures. Never commit real Telegram storage, session strings, authentication keys, passcodes, or account identifiers.
- Update `CHANGELOG.md` for behavior that users need to know about.

Security reports belong in a private GitHub security advisory, not a public issue.
