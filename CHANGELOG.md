# Changelog

User-visible changes are recorded here. A prepared release entry does not imply publication.

## [Unreleased]

### Changed

- Interactive ACTIVE scans now present generic Mutation selection first, followed by Query-Shape
  and Query-Depth selection. Each capability retains its independent default-NO confirmation,
  request budget and existing safety controls.

- Clarified AI priority for attributed review facts, separate interpretation/follow-up roles and
  material coverage limitations. Closed narrow grounding gaps for unauthorized-access verb forms
  and runtime result-size control-absence claims, preserving calibrated prose and valid siblings.

- Refined AI grounding for standalone manual-review recommendations and generic GraphQL
  descriptions while preserving checks on independent assertions, exact names and operation scope.
  Unsupported ownership-effectiveness, IDOR/BOLA and runtime-sensitivity claims are withheld.
  Guidance distinguishes authorization from input validation. Verbose output now includes bounded,
  content-free field withholding diagnostics; compact output, canonical contracts, inference limits
  and deterministic scanning remain unchanged.

- Final human assessments place Operation Review before Query Execution, omit internal missing-detail
  placeholders and inherit single-endpoint review context from the header. Equivalent Object Lookup
  reviews share guidance while retaining operation-specific details and traceability. Compact AI
  metadata distinguishes warning categories from withheld fields without repeated breakdowns;
  small Mutation previews use a single status line. Display caps, preview eligibility, canonical
  data and all scanning/consent/AI behavior are unchanged.

- Simplified human summary/schema inventories while preserving exhaustive canonical JSON.
  Operation Review combines separately attributed deterministic reasons and optional AI prose,
  with exact endpoint/kind/name association, explicit display caps and concise withholding labels.
  Default Mutation results now show bounded identifier-only responses or explicit value-omission
  notices and GraphQL error counts; exact Evidence is unchanged. Offline withholding investigation
  preserved factual guards, inference limits and scanner behavior.

- Human assessments prioritize Findings before capability details, separate review kind/operation/
  focus, and avoid zero-only technical counts in compact console output. Full counts remain in
  verbose output and reports; zero Findings explicitly provides no overall security assurance.
- AI human output uses operation-oriented prose blocks with compact execution/review-interest
  metadata, concise withholding labels and subordinate exact references. Markdown/HTML share
  the layout; generation metadata follows the interpretation and HTML collapses references.
  Retained prose, canonical JSON schema 2, AI contract 2 and scanner behavior are unchanged.

- AI grounding now handles equivalent conditional word orders and generic schema descriptions
  more consistently while checking independent contradictions after review/conditional clauses.
  Consolidated guidance preserves exact coverage and safety boundaries. Internal content-free
  field diagnostics associate withholding with existing rule categories without changing reports.

- AI factual checks now cover explicit root-type contradictions, operation-specific review
  attribution and "did not execute" claims across all interpretation sections. Normal Query
  execution remains distinct from dedicated control testing. Guidance clarifies exact reference
  sets and relevant manual follow-ups while preserving grounded conditional security hypotheses.

- AI guidance now favors supplied facts and specific manual checks, withholds unsupported
  factual security claims, and preserves grounded conditional hypotheses. Bounded input paths,
  root-list shape and direct nested-list fields improve operation-specific recommendations.
  Incomplete model fragments receive a distinct notice without rewriting or another inference.
  Human quality summaries count
  withheld fields and affected operations separately from warning categories, using content-free
  decisions without adding canonical JSON fields or extra model calls.
- AI interpretation now withholds unsupported security/control assertions and execution/coverage
  contradictions before console or report rendering, retaining valid sibling guidance and safe
  quality diagnostics. Schema visibility, bounded probe acceptance and successful execution do
  not establish absent controls, unlimited support or business success. Existing context bounds,
  inference budgets, deterministic Findings/Evidence and report/AI version-2 contracts are unchanged.
- Progressive introspection uses a dedicated root-name inventory and evidence-driven alternatives
  for older servers rejecting `includeDeprecated` on recognized introspection selections. Exact
  rejected and compatible requests remain evidence, share the existing budget and do not repeat
  known incompatibilities within one endpoint recovery. Potentially omitted deprecated elements
  keep reconstruction partial and non-executable, even if its structure validates.
- Progressive recovery now captures shallow root-operation inventories before deeper type
  requests. Eligible type-specific restrictions preserve prior facts and can continue to other
  known types within the existing budget; denials and unrelated failures still stop globally.
  Human Introspection output uses structured recovery/coverage/stop rows, with exact attempted
  shapes and response classifications retained in existing canonical evidence notes.
- Recognized GraphQL depth/complexity/cost errors on HTTP 413 now permit the existing single
  reduced introspection fallback. Generic 413 responses and access denials do not. Human schema
  operation totals distinguish unavailable data from zero operations and qualify partial coverage;
  canonical numeric counts are unchanged.
- When both full and reduced introspection receive recognized query-shape restrictions, schema
  recovery uses a shallow catalogue and fixed known-name type selections, with at most 32 additional
  sequential requests. Verified partial operation inventories remain visible without enabling
  execution; only complete, strictly validated local assemblies enter normal schema analysis.
  Original request/response evidence is retained separately from assembly provenance. Access
  denials and unrelated failures stop recovery, and existing successful retrieval paths are unchanged.
- Expanded the curated GraphQL endpoint inventory from 10 to 27 paths. Core discovery runs
  first; extended discovery starts only when no core endpoint is confirmed or probable.
  Preferred endpoints retain early stopping, with four-worker bounds and unchanged confirmation
  and redirect-consent safeguards. No-endpoint scans may make more discovery requests.
- Cross-origin HTTP redirects now require per-scan, default-NO consent before transmission.
  Approval also authorizes the current request context's configured credentials and eligible
  cookies; non-interactive runs block new origins. Same-origin redirects remain automatic,
  discovery prompts run on the main thread, and Ctrl+C cancels the scan and releases waiters.
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

- AI quality warnings use correct singular/plural console wording and human-readable descriptions
  in verbose console and Markdown/HTML reports; canonical warning identifiers are unchanged.
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
