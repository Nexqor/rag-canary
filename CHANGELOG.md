# Changelog

All notable changes to this project are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-21

### Added
- `new`, `embed`, `scan` and `list` commands.
- Four token styles: `id`, `key`, `email` (reserved `.invalid` TLD), `phrase`.
- HMAC-tagged tokens to prevent false positives from look-alike strings.
- Exact, case-insensitive and fragment matching in scans; stdin support.
- Format-aware embedding for Markdown, text, HTML and CSV.
- JSON output and non-zero exit code on hits for cron / CI / SIEM use.
