# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-08-09

### Security

- Redact auth keys, account identifiers, storage paths, and credential-bearing
  structures from default CLI, tracing, and `Debug` output.
- Replace command-line passcodes with hidden-prompt and stdin input modes, and
  stop retaining the supplied passcode in the parsed object.
- Remove the ambiguous `to_session_string()` compatibility surface rather than
  silently returning a different serialization than `hermes-tdata` 0.1.
- Reject malformed binary lengths and offsets without panic-prone indexing or
  lossy integer casts.
- Upgrade `grammers` dependencies to maintained releases so fresh installs do
  not depend on yanked transitive packages.

### Changed

- Restore the established `hermes-tdata` package identity so existing users,
  download history, and future releases stay on one crates.io page.
- Restore the canonical Rust import path to `hermes_tdata` and align repository,
  documentation, badges, and release metadata with that identity.
- Replace the 0.1 session-string API with
  `Account::to_grammers_session_data()`; version 0.2 is intentionally a breaking
  release and migration is documented in the README.
- Add contributor, vulnerability-reporting, dependency-update, CI, CodeQL, and
  signed release surfaces.

Version `0.2.0` was not published as `hermes-tdata`; `0.2.1` is used so the
package release is never associated with the earlier short-lived repository
tag's different bytes.

## [0.1.1] - 2026-03-12

- Last patch release from the original Hermes monorepo implementation.
- Published on crates.io under the established `hermes-tdata` identity.

## [0.1.0] - 2026-03-12

- Initial public crates.io release from the Hermes monorepo.

[Unreleased]: https://github.com/Stranmor/hermes-tdata/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/Stranmor/hermes-tdata/compare/v0.2.0...v0.2.1
[0.1.1]: https://crates.io/crates/hermes-tdata/0.1.1
[0.1.0]: https://crates.io/crates/hermes-tdata/0.1.0
