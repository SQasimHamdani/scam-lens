# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]
### Fixed
- No more crash on Windows when look-alike or non-Latin characters are printed to redirected or
  piped output (#5).
- The same clue is no longer scored twice when packs overlap (#3). Some messages that were
  *likely a scam* only because of the double count are now *suspicious*.

### Added
- Optional `group` field for rules in a pack.

## [0.1.0] - 2026-11-24
### Added
- Rule-based analyzer with plain-language explanations for each red flag.
- Link checks: shorteners, raw IP addresses, punycode, `user@host` trick, abused domain endings,
  and brand look-alike or mismatch.
- Rule packs: `global` and a starter `pk` pack; support for custom packs via `--pack-file`.
- Command-line interface with JSON output and script-friendly exit codes; Python API.
- Test suite and continuous integration.
