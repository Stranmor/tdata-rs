## What changed

Describe the user-visible behavior and why this is the smallest correct change.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --all-targets --all-features`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Documentation builds with warnings denied

## Safety

- [ ] The change includes no real `tdata`, session string, auth key, passcode, account identifier, or private path.
- [ ] Parser and credential-handling changes use synthetic fixtures and preserve local-only behavior.
