# GQLSleuth

GQLSleuth is an open-source Python CLI for authorized GraphQL security discovery and
analysis. The project is designed to automate the evidence-driven investigation workflow
used by application security professionals while remaining deterministic and safe by
default.

> [!WARNING]
> Use GQLSleuth only against systems for which you have explicit authorization. The project
> is not intended for unauthorized access, destructive testing, brute force, exploitation,
> or service disruption.

## Current status

The repository is currently at **Phase 15 — Named Authentication Contexts & Differential Authorization Review**. It provides the Phase 0
and Phase 1 foundation, the centralized Phase 2 HTTP layer, Phase 3 endpoint discovery, Phase 4
GraphQL behavior detection, Phase 5 introspection retrieval, Phase 6 deterministic schema
parsing, Phase 7 operation analysis, Phase 8 local read-only query generation, and Phase 9
controlled Query execution, followed in ACTIVE mode by Mutation previews and separately
selected and confirmed Mutation execution. Phase 11 adds opt-in JSON, Markdown, and HTML reports
from those structured results. Phase 12 adds optional local interpretation after the completed
SAFE or ACTIVE workflow, using Ollama and `qwen3:8b`.
Phase 13 adds concise default console output, optional detailed output, help/option aliases,
and comma-separated report formats. Scanning, ACTIVE controls, AI, and report semantics are unchanged.
Phase 13.1 adds bounded execution responses to human reports and console details, consistent
priority colors, grouped Mutation previews, and structured AI console tables. Canonical JSON
evidence, scanner behavior, and AI inputs/validation remain unchanged.
Phase 14 exposes repeated target headers, user-supplied authentication, explicit timeout/proxy,
and target TLS verification settings, isolated from local Ollama.
Phase 15 runs the existing SAFE workflow independently for 2–3 named HTTP contexts, then compares
their retained observations locally. Differences are manual-review candidates, not vulnerabilities.

The `scan` command first makes conservative HTTP GET requests to endpoint candidates and reuses
those responses for signal analysis. An inconclusive candidate receives at most one static POST
probe containing `query { __typename }`. Confirmed and probable GraphQL endpoints then receive a
minimal introspection probe. When introspection is enabled, one complete static introspection
query retrieves and preserves the raw HTTP response. Phase 6 validates that response with
`graphql-core` and maps it into GQLSleuth-owned immutable schema models. Phase 7 then classifies
Query and Mutation root fields with bundled, validated YAML rules and gives matching operations
a deterministic interest score and review priority. It considers operation metadata plus one
direct level of related input and output fields; it does not recursively inspect the schema.
Rules explicitly declare whether they apply to primary, input, or output context, preventing an
arbitrary returned field from being treated as evidence of the operation's purpose.

Phase 8 generates one anonymous minimal GraphQL query for each Query-root field when possible.
It includes only required arguments, creates deterministic placeholder variables, and selects a
small response field path with a maximum internal depth of three and cycle protection. Custom
scalar placeholders use the string `"test"` and are marked as potentially requiring manual
adjustment. SAFE generates Query documents only. ACTIVE reuses this same generation algorithm
for Mutation-root fields after completing the safe workflow. Subscriptions are never generated.

By default, discovery gives the preferred candidate an eight-second GET timeout and immediately applies the
existing GraphQL detection logic. A confirmed or probable preferred candidate stops discovery;
otherwise, the remaining candidates use at most four synchronous workers while retaining their
stable candidate order. GraphQL POST probes and introspection continue using the normal ten-second
HTTP timeout. A fallback POST is sent only when discovery received an inconclusive HTTP response;
transport failures without a response proceed directly to the next candidate.
An explicit `--timeout` overrides both discovery and subsequent target request timeouts.

Phase 9 defensively validates each successful generated artifact against the parsed Query root
before sending it sequentially. It executes at most 20 Query operations per scan and skips Query
names containing explicit state-changing action tokens such as `delete`, `burn`, or `reset`.
The safe workflow never executes Mutations or Subscriptions. Placeholder-related GraphQL errors are retained as
normal execution evidence rather than treated as scanner failures.

Priorities and execution results are evidence for manual review, not vulnerability severities or
proof of a vulnerability.

## Requirements

- Python 3.13
- [uv](https://docs.astral.sh/uv/)

## Installation

Clone the repository, enter its directory, and synchronize the locked environment:

```bash
uv sync --locked
```

Show the available commands:

```bash
uv run gqlsleuth --help
uv run gqlsleuth -h
uv run gqlsleuth scan -h
```

## Current commands

Display the installed version:

```bash
uv run gqlsleuth version
```

Run safe endpoint discovery, GraphQL detection, introspection, schema parsing, operation
prioritization, query generation, and safe Query execution with the default mode:

```bash
uv run gqlsleuth scan https://example.com
```

Choose a mode explicitly:

```bash
uv run gqlsleuth scan https://example.com --mode safe
uv run gqlsleuth scan https://example.com --mode active
```

ACTIVE first completes exactly the same Phase 3–9 workflow as SAFE. Selecting `--mode active`
acknowledges entry into active capabilities for an authorized target; it does **not** authorize
any Mutation request. There is no `--authorized`, `--yes`, or `--force` option.

The active stage previews all Mutation candidates in retained Phase 7 order. Executable candidates
show their endpoint once per group, field name, review priority, categories, exact anonymous Mutation document,
exact variables, and placeholder/manual-adjustment warnings. Failed generation and blocked
candidates remain visible with their reasons. Destructive primary-name tokens `delete`, `remove`,
`destroy`, `purge`, `drop`, `wipe`, `erase`, `burn`, and `truncate` block execution without an
override. Matching uses exact camelCase/PascalCase/snake_case/kebab-case tokens, not substrings,
argument names, output fields, or interest scores. Other Mutations may still be impactful.

Select individual executable indices, separated by commas:

```text
Select Mutations to execute (max 5, Enter for none): 1,3
```

There is no default selection, `all`, wildcard, or range syntax. Invalid, blocked, and
failed-generation indices are rejected with another selection attempt. Enter selects none.
The exact selected batch is displayed again, followed by **one** confirmation:

```text
WARNING: These operations may modify application state.
Execute these 2 selected Mutations? [y/N]
```

Declining or accepting the default NO executes zero Mutations. Non-interactive stdin displays
previews and a clear message, then finishes without reading input or executing Mutations; piped
selections/confirmation cannot enable execution. A schema with no Mutations ends the stage directly.

Only confirmed, selected, defensively validated and safety-approved Mutations execute. The
application independently enforces ACTIVE mode and a hard maximum of five attempted Mutation
requests, in retained Phase 7 order, sequentially. Each sends one POST containing only `query`
and `variables` through the existing HTTP client, with its TLS, timeout, redirect, response-size,
and normalized transport-error behavior. There are no retries, concurrency, or `operationName`.
One failure does not stop later selected operations.

Mutation responses reuse Phase 9 classifications: `SUCCESS` (including `data: null` without
interpretable errors), `GRAPHQL_ERROR` (including partial data), `HTTP_ERROR`, `INVALID_RESPONSE`,
and `NETWORK_FAILURE`. Only attempted requests create `MUTATION_EXECUTION` evidence containing
ACTIVE mode, the exact request, timestamp, response facts or normalized failure, duration,
classification, and Phase 7 analysis. Generation failures, invalid artifacts, safety blocks,
unselected/declined operations, and limit skips remain structured decisions with no fabricated
execution evidence. Success is not a vulnerability finding or proof of authorization bypass.

Default console output is compact: target/mode, endpoint confidence and introspection status,
schema counts, the first ten review candidates in existing Phase 7 order, Query-generation totals,
and execution counts with up to five noteworthy error/skip outcomes. Review candidates show
interest priority, kind, name, and score. The console does not dump generated Queries or rule
explanations by default. Structured results retain all operations and evidence.

Use `--verbose` / `-v` for all retained review candidates and rule matches, schema roots,
generated Query documents/variables/adjustment notes, generation failures, and detailed execution
outcomes. This is one Boolean display option; it changes neither requests nor report content.
Full Mutation previews, selected documents, variables, safety reasons, warnings, and the final
confirmation remain visible without verbose mode.

Verbose Query execution shows the observed response body, classification, HTTP status, and
duration when available. Default SAFE output continues to omit Query bodies. Attempted ACTIVE
Mutation responses are shown even without verbose mode; the final **Mutation Execution** summary
focuses on executed/success/error counts. Empty or declined batches report zero executions.
Skipped, blocked, unselected, and declined operations have no fabricated response.

Console priorities use one palette everywhere: **CRITICAL** magenta, **HIGH** red, **MEDIUM** yellow,
**LOW** green, and **INFORMATIONAL** bright blue. Priority remains review interest, not severity.

```bash
uv run gqlsleuth scan https://example.com
uv run gqlsleuth scan https://example.com -v
uv run gqlsleuth scan https://example.com -f html
uv run gqlsleuth scan https://example.com -f json,html -o ./reports
uv run gqlsleuth scan https://example.com --ai -f html
uv run gqlsleuth scan https://example.com --mode active
```

Root help (`--help` / `-h`) includes quick starts and common scan options; `scan --help` / `scan -h`
documents the full scan command. Reports remain the detailed persisted analysis/evidence output.

The execution summary distinguishes successful responses, GraphQL/application errors, transport
failures, and operations skipped for safety or because of the 20-request limit. Generated
placeholder values may be rejected by application-level validation; such responses are expected
possible outcomes.

## Reports

Request one or more formats on the existing `scan` command:

```bash
uv run gqlsleuth scan https://example.com --format json --format markdown --format html --output ./reports
uv run gqlsleuth scan https://example.com --mode active --format json --format html
```

Use `--format` / `-f` to select `json`, `markdown`, or `html`. Both comma-separated and repeated
values work, including mixed syntax such as `-f json,html -f markdown -f json`. Surrounding
whitespace is trimmed; empty or unknown values are rejected before scanning. Formats retain
first-occurrence order and each is written once. `--output` / `-o` names a directory, which is created when needed; the default is
`./gqlsleuth-reports`. Without `--format`, no report files or directories are created and the
existing scan output is unchanged. Supplying `--output` alone or an unknown format is an input
error. Output-directory options never change console verbosity. There is no separate `report` command.

Reporting runs after the existing scan and ACTIVE interaction finish. It performs **zero
additional network requests or GraphQL operations** and makes no new security decisions.

- **JSON** is the canonical machine-readable format, with `report_schema_version: 1`, stable
  field names, exact generated documents and variables, execution statuses/errors, and all
  retained evidence. Byte-valued response bodies use lossless `{ "encoding": "base64", "data":
  "..." }` objects. Evidence is preserved without introducing redaction.
- **Markdown** and **HTML** provide deterministic counts, discovery/confidence, introspection
  status, schema summaries, review candidates and reasons, generated Queries, execution
  outcomes, evidence counts, observed errors/limitations, and manual-review recommendations.
  Attempted Query and Mutation execution entries show the exact request/variables and an observed
  Response section, including status, classification, duration, and bounded response content.
  HTML uses native collapsible server-response sections, without JavaScript.
  HTML is a standalone document with embedded CSS, escaped
  target text, and no external scripts, stylesheets, or CDN dependencies.

ACTIVE reports separately record Mutation generation, safety blocks and reasons, explicit
selection, final batch confirmation, and execution outcomes. Unselected, declined, blocked,
failed, and limit-skipped candidates are not counted as executed. Only existing
`MUTATION_EXECUTION` evidence establishes an attempted Mutation request; the same rule applies
to `QUERY_EXECUTION` evidence. Human reports show exact documents and variables for attempted
Queries and Mutations. SAFE reports never imply Mutation execution.

Human response content has a **64 KiB UTF-8 presentation limit** shared by console, Markdown,
and HTML. Complete valid JSON within the limit is pretty-printed deterministically; non-JSON
text is displayed as text. Both the input prefix and expanded formatted output are bounded.
Truncation is explicitly labeled; canonical JSON/evidence retains the complete raw bytes.
Binary/unrenderable bodies receive a notice, and network failures state that no HTTP response
was received. Pretty-printing never changes execution classifications or underlying evidence.

**Markdown/HTML execution sections may contain application response data. Treat these reports
as potentially sensitive pentest artifacts.** No response fields are automatically removed or
redacted. Raw response bodies remain excluded from AI context.

Filenames use a normalized target host and UTC report timestamp, for example
`gqlsleuth-example.com-20260908-231500.json` (or `.md` / `.html`). Existing files are never
silently overwritten: conflicts receive `-2`, `-3`, and so on. Reporting failures produce a
concise error after scanning and leave the scan result unchanged. Generated reports are local
artifacts and the default report directories are ignored by Git.

Reports are intended only for authorized testing. **CRITICAL/HIGH INTEREST indicates review
priority, not vulnerability severity.** Enabled introspection and successful execution are not
proof of exploitability. Reports create no Findings; all automated results require professional
validation. Recommendations are fixed responses to observed scan state, without AI.

## Optional local AI assistance

AI is disabled by default. Without `--ai`, scans make zero Ollama requests and do not require
Ollama or a model. Enable interpretation of a completed scan with:

```bash
uv run gqlsleuth scan https://example.com --ai
uv run gqlsleuth scan https://example.com --mode active --ai
uv run gqlsleuth scan https://example.com --ai --format json --format markdown --format html --output ./reports
```

Install and start [Ollama](https://ollama.com/) separately, then obtain the model yourself:

```bash
ollama pull qwen3:8b
```

GQLSleuth never installs Ollama, downloads models, runs shell commands for AI, or manages the
installation. It uses the existing local API at `http://127.0.0.1:11434` with `qwen3:8b`.
No cloud providers, remote endpoints, API keys, or provider-selection flags are supported.

One non-streaming structured inference runs **after** deterministic scanning and the complete
ACTIVE selection/confirmation/execution stage, and **before** requested reports. AI cannot select,
confirm, generate, or execute GraphQL operations, change priorities/statuses/evidence, or feed
instructions back into the scanner. It adds zero requests to the GraphQL target.

The AI context is constructed with an explicit allowlist: effective mode, aggregate schema
counts/root names, operation kind/name/return-type name, existing interest priorities/scores and
categories, generation/manual-adjustment flags, HTTP status codes, and deterministic execution
and Mutation decision states. Endpoint labels are anonymous (`endpoint_1`, etc.). No target URLs,
headers, credentials, variable values, raw request/response bodies, raw errors/stack traces,
Evidence objects, descriptions, or complete schema graphs are sent. Generated documents are also
excluded to keep the input purely structural. This is a dedicated projection, not a generic
redaction subsystem; existing scanner evidence is untouched.

Input is limited to **20 operations** and **12,000 serialized UTF-8 bytes**, prioritizing existing
Phase 7 interest rankings. Operation names longer than 128 characters are omitted; at most ten
schema summaries are included. Size reduction removes lower-priority schema summaries before
operations. Metadata explicitly records included/omitted operations and context truncation.

The validated response contains an execution summary, up to ten operation
reviews, and ten limitations, with text bounded to 600
characters per entry. Operation references use exact endpoint/kind/name identifiers in dedicated
fields, including summary/review/limitations. Unknown references reject the whole response;
malformed JSON, extra fields, and invalid structures are rejected without retries. Model-generated
prose still requires professional validation. Thinking/reasoning metadata is ignored and never
displayed or persisted.

The execution summary uses canonical text calculated from complete scan classifications before
context truncation. The response schema requires that exact text, and validation rejects any
paraphrase or changed count. Attempts, SUCCESS, GraphQL/HTTP/transport errors, and safety/limit
skips remain distinct; HTTP 200 never overrides a GraphQL error. This summary is labeled as
validated facts; Qwen generates Operation Review and Limitations. Each Operation Review paragraph
combines the supplied review interest, apparent role, relevant recorded outcome, reason for
attention, and a concrete, non-destructive manual review direction. Priority wording explicitly
indicates review interest (for example, HIGH-interest), never vulnerability severity.

Inference uses a finite 180-second timeout (five-second connection timeout), a 128 KiB response
limit, and no redirects, environment proxies, or retries. Connection failures, timeouts, missing
models, HTTP errors, and invalid responses produce concise AI statuses. The completed scan and
requested reports remain available.

CLI, Markdown, and HTML label the optional section **AI-Assisted Interpretation**. JSON adds
`ai_interpretation` separately from deterministic counts, recommendations, execution facts, and
evidence. This additive optional field keeps report schema version 1; it is absent when AI was
not requested. HTML escapes model text. AI produces interpretation only: it is not Evidence,
does not create Findings, and does not establish vulnerability severity or confirmation.

The AI console uses neutral bold white subsection headings and cyan operation references, with separate tables for
validated execution facts and interpretation entries. Standalone priority terms in model prose
are uppercased and colored only for console display (for example, `high interest` becomes
`HIGH INTEREST`; `highly` is unchanged). Stored AI results and JSON/Markdown/HTML AI prose are
not rewritten. Model text is rendered as untrusted text, never interpreted as Rich markup.

## Configuration

Configuration uses CLI options and built-in defaults only. `--mode safe` remains the default.
Phase 14 supports **one authentication/request context per scan**, through user-supplied headers:

```bash
uv run gqlsleuth scan https://example.com -H "Authorization: Bearer TOKEN" -H "X-Tenant-ID: 123"
uv run gqlsleuth scan https://example.com --header "Cookie: session=test-session"
uv run gqlsleuth scan https://example.com -H "X-API-Key: test-api-key"
uv run gqlsleuth scan https://example.com --timeout 20 --proxy http://127.0.0.1:8080
uv run gqlsleuth scan https://example.com --no-verify-tls
```

- `-H` / `--header` is repeatable. Each value splits at the **first colon**, so additional
  colons in values are preserved. Surrounding spaces/tabs are trimmed; names must be HTTP
  tokens and values ASCII text without control characters (internal horizontal tabs are allowed).
  Invalid arguments fail before scanning, identifying the argument number without echoing values.
- Duplicate names are retained as separate fields in supplied order, not comma-joined by
  GQLSleuth. Use only duplicates understood by the target. Explicit `User-Agent` overrides
  `GQLSleuth/<version>`. Scanner-provided fields take precedence case-insensitively, and JSON
  POSTs always use HTTPX's `application/json` Content-Type, regardless of supplied Content-Type.
  Host, Content-Length, Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection,
  Proxy-Authorization, TE, Trailer, and Upgrade are transport-controlled and rejected via `-H`.
- `--timeout SECONDS` accepts finite positive integers/fractions and governs **every target
  request**, including discovery. Omitted: discovery GETs retain 8 seconds; other requests 10.
- `--verify-tls` / `--no-verify-tls` controls target certificate verification, enabled by default.
  Disabling it is insecure and prints one warning. There is no automatic insecure retry.
- `--proxy URL` accepts an explicit HTTP(S) proxy origin, optionally with credentials and a
  port. SOCKS and proxy URL paths/queries/fragments are unsupported. Proxy credentials are
  never displayed. Environment proxy variables remain ignored (`trust_env=False`).

The same settings apply to discovery GETs, fallback confirmation POSTs, minimal/full
introspection, safe Queries, and explicitly selected/confirmed ACTIVE Mutations, including
direct endpoint targets. Settings are passed through existing client lifetimes; no credential
validation request is added. Same-origin redirects retain supplied authentication, including
Cookies. On crossing scheme, host, or port, supplied headers are removed and never restored
within that redirect chain, including a redirect back. HTTPX still handles redirect methods,
limits, and body framing. Scanner-owned JSON headers remain valid.

There is no automatic login, credential acquisition, token refresh, or browser-cookie access.
Named SAFE contexts are available as described below; no role hierarchy is inferred.
Target headers, proxy, timeout,
and TLS settings **do not affect Ollama**. The unchanged AI allowlist excludes these values.
Normal/verbose console and configuration errors never display supplied header values; human
reports add no request-header-values section. Existing server response presentation is unchanged.

Treat reports as potentially sensitive pentest artifacts. Canonical JSON preserves existing
evidence, including exact variables and response headers/bodies, which may contain credentials
or echoed request information. Current evidence does **not** retain request headers or target
HTTP configuration; Phase 14 neither adds those fields nor removes existing facts. There is no
generic automatic redaction. Store reports securely and never commit real credentials/evidence.

Environment variables and configuration files are not supported yet. They remain deferred
until the project has enough settings to justify multiple configuration sources.

## Named HTTP contexts and differential review

GraphQL does not imply Bearer authentication, JWT, or any particular role. A context is simply
a tester-defined label and zero or more HTTP headers. Bearer, Cookie, API key, tenant, and
proprietary headers use the same Phase 14 header parser and transport protections:

```bash
uv run gqlsleuth scan https://example.com/graphql --auth-context public --auth-context "cliente=Authorization: Bearer TOKEN"
uv run gqlsleuth scan https://example.com/graphql --auth-context public --auth-context "empleado=Cookie: session=AAA" --auth-context "soporte=Cookie: session=BBB"
uv run gqlsleuth scan https://example.com/graphql --auth-context public --auth-context "tenant-a=X-API-Key: KEY_A" --auth-context "tenant-b=X-API-Key: KEY_B" -f json,markdown,html
```

Repeat a label to accumulate multiple headers:

```bash
uv run gqlsleuth scan https://example.com/graphql --auth-context public --auth-context "cliente=Authorization: Bearer TOKEN" --auth-context "cliente=X-Tenant-ID: 123"
```

- Supply **2–3 unique labels**, in first-seen order. Names are case-sensitive opaque labels,
  1–64 ASCII letters/digits/dots/underscores/hyphens, beginning with a letter or digit.
  Labels never establish identity, authentication success, or a privilege hierarchy.
- A bare label supplies no headers. Repeating it does not erase headers already accumulated.
  The first `=` separates label from header; the header still splits at its first colon.
- `--auth-context` cannot be combined with `-H`/`--header`, `--mode active`, or `--ai`.
  Invalid combinations fail before scanning. Existing single-context SAFE, ACTIVE, and AI
  behavior is unchanged. Differential scans make no Ollama calls.
- `--timeout`, `--proxy`, and TLS options apply equally to each independent settings/client
  instance. Headers and cookie jars are never shared between context scans. Normal redirect
  protection, response limits, discovery defaults, and SAFE Query limits remain intact.
- Each context runs the complete existing SAFE pipeline independently, including up to 20
  attempted safe Queries **per context**. No Mutation document is generated or executed in
  differential mode; Mutation-root visibility is schema information only.
- All unique pairs are compared in order: A ↔ B, A ↔ C, B ↔ C. Exact candidate URLs and
  root field names identify comparable observations. Discovery confidence/HTTP status,
  introspection status, Query/Mutation visibility, and Query classifications/HTTP status are
  compared. Raw response bodies and business data are never compared.
- Missing observations are explicit limitations, not proof of absence. Generation failures,
  failed contexts, and unavailable schemas do not cancel other contexts. Differing generated
  documents/placeholders are flagged as non-equivalent requests; no values are guessed or retried.

The console shows **Authorization Differential Review**, context summaries, and up to ten
differences; `-v` shows all candidates and comparison limitations. JSON retains each named
context's normal structured scan report/evidence plus local pair results with source evidence IDs.
Markdown/HTML show structural context facts, Query outcomes, pairwise observations, and limitations;
their compact candidate table matches the console summary. A single candidate endpoint appears
above the table; multiple endpoints use a dedicated column. HTML source-evidence IDs are collapsed
under **Evidence references**; Markdown leaves those IDs to canonical JSON. Detailed context and
pair sections remain below the summary. Both formats preserve the recorded observations;
these differential human views omit raw response bodies/errors and HTTP configuration. Safety
Notice remains their final section. All formats use the existing `-f`/`-o` output behavior.
Comparison and report generation add **zero HTTP requests** and create no new HTTP evidence.
Retained evidence is unchanged; JSON may still contain sensitive data returned by the target.

Differences can be legitimate authorization behavior. `GRAPHQL_ERROR` versus `SUCCESS` is only
an observed difference: placeholder values, business input, validation, or other server logic
may explain it. Manual validation is required. There are no authorization Findings, role/JWT
analysis, automatic login/token acquisition, BOLA/IDOR tests, ID enumeration, ownership inference,
or cross-context variable substitution. Use only against systems you are authorized to test.

### Controlled local Phase 15 validation

A test-only GraphQL-like fixture uses no real credentials or public service. Run the complete
local smoke (starts a loopback server, runs three SAFE contexts, writes all formats, then stops):

```bash
uv run python tests/fixtures/phase15_target.py --smoke --output ./reports/phase15-smoke
```

For an interactive development session, start the fixture in one terminal:

```bash
uv run python tests/fixtures/phase15_target.py --port 8765
```

Then scan from another terminal:

```bash
uv run gqlsleuth scan http://127.0.0.1:8765/graphql --auth-context public --auth-context "empleado=X-Test-Context: empleado" --auth-context "soporte=X-Test-Context: soporte" -v -f json,markdown,html -o ./reports/phase15-smoke
```

The fixture denies public introspection, varies Query/Mutation visibility, and returns different
safe Query outcomes for the other two test header values. These are fixture cases, not roles
recognized by production code. Automated tests use the same fixture logic via MockTransport.

The module entry point exposes the same CLI:

```bash
uv run python -m gqlsleuth --help
```

## Development

Install the locked runtime and development dependencies:

```bash
uv sync --locked
```

Run the project checks:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
```

The complete project scope, architecture, safety constraints, and roadmap are documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## License

GQLSleuth is licensed under the [MIT License](LICENSE).
