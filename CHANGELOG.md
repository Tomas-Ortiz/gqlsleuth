# Changelog

User-visible changes are recorded here. The current development package is not a v1.0 release.

## [Unreleased]

### Added

- GraphQL endpoint discovery, introspection, schema analysis, deterministic review priorities,
  minimal bounded Query generation and conservative SAFE execution.
- Explicitly confirmed ACTIVE validation, including selected Mutations, authorization policies,
  bounded object/IDOR review, authentication and token checks, and GraphQL runtime controls.
- Controlled upload, federation and Subscription/WebSocket security validation.
- Generic named HTTP authentication contexts and deterministic differential authorization review.
- JSON evidence reports and standalone Markdown/HTML assessments, with Findings distinguished
  from review candidates, scoped controls and unresolved checks.
- Optional local Ollama interpretation of completed scans, with allowlisted context and
  deterministic facts remaining authoritative.
- Installed wheel/source-distribution release checks on Python 3.13 in Ubuntu and Windows CI.

### Changed

- Assessment-oriented compact console output with complete technical detail available through
  verbose output and reports.
- Package metadata is the authoritative installed version; release metadata identifies this
  development package as Beta, not a stable v1.0 release.
- Transport failures provide actionable, secret-safe guidance. Completed scans retain their
  existing exit status, including when target requests fail.

### Fixed

- Excessively nested response JSON and recursive schema reconstruction fail through controlled
  results instead of aborting the scan. Human output uses concise nesting notices.

### Security

- Target URLs containing embedded credentials are rejected before scanning, reporting or AI
  processing, without echoing their credentials. Authentication remains explicit through headers
  and supported named contexts.
