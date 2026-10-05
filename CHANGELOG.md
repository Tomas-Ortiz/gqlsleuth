# Changelog

User-visible changes are recorded here. A prepared release entry does not imply publication.

## [Unreleased]

### Changed

- All CLI commands and help paths start with the installed version and author header exactly once.
  Scans show terminal activity indicators during deterministic scanning and optional local AI
  interpretation. Interactive prompts remain
  free of spinner rendering.

### Fixed

- Compact assessments show confirmed/probable GraphQL endpoint URLs separately from the supplied
  target, with consistent endpoint labels in pre-ACTIVE context.
- Ctrl+C at any ACTIVE selection or confirmation now stops the entire scan interaction with
  exit code 130, instead of continuing into later capabilities.
- ACTIVE scans show compact endpoint/schema context before candidate selection, while keeping
  final Findings and control conclusions in the completed assessment.
- Introspection presentation distinguishes an enabled minimal probe from blocked or failed full
  schema retrieval, retaining the server reason and existing evidence without extra requests.
- Local Ollama failures now distinguish initial connection failures from interrupted requests,
  without guessing why the service became unavailable or failing the deterministic scan.
- Local AI inference now defaults to a ten-minute wait and supports finite positive
  `--ai-timeout SECONDS` overrides for slower CPU-only systems, independently of target timeouts.
- Local qwen3 structured output now constrains references to supplied operation/fact values,
  preventing bare operation names from failing strict reference validation. Internal diagnostics
  distinguish parsing, schema, reference and execution-fact failures without exposing model text.
- ACTIVE preparation supports graphql-core 3.3's immutable AST nodes while retaining 3.2
  compatibility, including alias multiplicity and shared authorization/depth transformations.

## [1.0.0] - 2026-09-28

### Added

- GraphQL endpoint discovery, introspection, schema analysis, deterministic review priorities,
  minimal bounded Query generation and conservative SAFE execution.
- Controlled, explicitly confirmed Mutation execution and sensitive-input validation.
- Authorization review and explicit policy validation, including bounded object authorization
  and IDOR/BOLA validation against operator-supplied expectations.
- Authentication and token security checks, bounded rate-limit/abuse validation, and controlled
  GraphQL multiplicity and Query-depth checks.
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
- Package metadata is the authoritative installed version. The initial release candidate
  retains the Beta classifier pending public-release experience.
- Transport failures provide actionable, secret-safe guidance. Completed scans retain their
  existing exit status, including when target requests fail.

### Fixed

- Excessively nested response JSON and recursive schema reconstruction fail through controlled
  results instead of aborting the scan. An explicit iterative nesting bound removes platform
  dependence; human output uses concise nesting notices.
- CI help assertions tolerate terminal styling while retaining narrow-terminal rendering checks.

### Security

- Target URLs containing embedded credentials are rejected before scanning, reporting or AI
  processing, without echoing their credentials. Authentication remains explicit through headers
  and supported named contexts.
