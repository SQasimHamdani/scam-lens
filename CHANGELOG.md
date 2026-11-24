# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-24
### Added
- Rule-based analyzer with plain-language explanations for each red flag.
- Link checks: shorteners, raw IP addresses, punycode, `user@host` trick, abused domain endings,
  and brand look-alike or mismatch.
- Rule packs: `global` and a starter `pk` pack; support for custom packs via `--pack-file`.
- Command-line interface with JSON output and script-friendly exit codes; Python API.
- Test suite and continuous integration.
