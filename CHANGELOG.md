# Changelog

User-visible changes are recorded here. A prepared release entry does not imply publication.

## [Unreleased]

### Changed

- Schema retrieval now makes one reduced introspection fallback when introspection is enabled
  but the standard full query is explicitly rejected by a query depth/complexity/cost limit.
  Successful fallbacks are labeled PARTIAL and continue through deterministic analysis without
  implying complete schema coverage. Other failures do not trigger the fallback.
- AI output now separates application-owned facts from referenced interpretation: one entry per
  supplied operation, up to three global review themes, and up to two limitations. JSON report
  schema and AI contract advance to version 2; input privacy and the 12-operation cap are unchanged.
  Safe per-attempt token telemetry distinguishes output-budget exhaustion from malformed content
  without retaining rejected prose or changing the fixed generation budget.
  Summary, theme and limitation references now share one typed array so generation-schema and
  validation limits agree on three references total, rather than separate per-kind limits.
- Optional local AI now regenerates a complete interpretation after hard structural model-output
  validation failures, with cumulative distinct-category corrections and a hard ten-attempt limit.
  It stops
  at the first valid result, shows progress and retains only safe attempt metadata. Provider errors
  are not retried; `--ai-timeout` applies per request. Scanning and reporting add no target traffic.
- Compact execution and capability statuses share semantic console colors; GraphQL errors remain
  yellow observed outcomes, while hard failures are red and safety blocks/skips are magenta.
- All CLI commands and help paths start with the installed version and author header exactly once.
  Scans show terminal activity indicators during deterministic scanning and optional local AI
  interpretation. Interactive prompts remain
  free of spinner rendering.

### Fixed

- AI prose checks for unsupported assurance, absence, causal/control/review conclusions,
  execution claims and clipped endings now produce advisory quality warnings instead of
  discarding usable structured interpretations. Structural schema/reference/coverage and
  provider-truncation failures still regenerate; semantic concerns never do.
- All human AI output starts with the same explicit warning that interpretation may be incomplete
  or inaccurate and requires manual validation. Deterministic facts remain authoritative;
  quality flags are heuristic diagnostics, not Findings or proof that prose is false.
- Canonical AI results retain safe, deduplicated quality-warning codes separately from hard
  validation failures, as an additive field within contract version 2.
- Documented UTF-8 native-command redirection for Windows PowerShell 5.1 encoding mismatches.
- Compact assessments show confirmed/probable GraphQL endpoint URLs separately from the supplied
  target, with consistent endpoint labels in pre-ACTIVE context.
- Ctrl+C at any ACTIVE selection or confirmation now stops the entire scan interaction with
  exit code 130, instead of continuing into later capabilities.
- ACTIVE scans show compact endpoint/schema context before candidate selection, while keeping
  final Findings and control conclusions in the completed assessment.
- Introspection presentation distinguishes an enabled minimal probe from the schema retrieval
  outcome, retaining the server reason and existing evidence.
- Local Ollama failures now distinguish initial connection failures from interrupted requests,
  without guessing why the service became unavailable or failing the deterministic scan.
- Local AI inference now defaults to a ten-minute wait and supports finite positive
  `--ai-timeout SECONDS` overrides for slower CPU-only systems, independently of target timeouts.
- Local qwen3 structured output now constrains references to supplied operation/fact values,
  preventing bare operation names from failing strict reference validation. Internal diagnostics
  distinguish hard parsing/schema/reference failures from advisory execution-prose flags without
  exposing rejected model text.
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
