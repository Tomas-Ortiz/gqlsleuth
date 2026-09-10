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

The repository is currently at **Phase 11 — Reports**. It provides the Phase 0
and Phase 1 foundation, the centralized Phase 2 HTTP layer, Phase 3 endpoint discovery, Phase 4
GraphQL behavior detection, Phase 5 introspection retrieval, Phase 6 deterministic schema
parsing, Phase 7 operation analysis, Phase 8 local read-only query generation, and Phase 9
controlled Query execution, followed in ACTIVE mode by Mutation previews and separately
selected and confirmed Mutation execution. Phase 11 adds opt-in JSON, Markdown, and HTML reports
from those structured results. Phase 12 AI is not implemented.

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

Discovery gives the preferred candidate an eight-second GET timeout and immediately applies the
existing GraphQL detection logic. A confirmed or probable preferred candidate stops discovery;
otherwise, the remaining candidates use at most four synchronous workers while retaining their
stable candidate order. GraphQL POST probes and introspection continue using the normal ten-second
HTTP timeout. A fallback POST is sent only when discovery received an inconclusive HTTP response;
transport failures without a response proceed directly to the next candidate.

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
show their endpoint, field name, review priority, categories, exact anonymous Mutation document,
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

The CLI displays at most the ten highest-priority review candidates while the structured
application result retains every analyzed Query and Mutation root field. Each displayed
candidate includes its interest score, categories, matched rules, and deterministic reason.
The CLI also shows at most five generated Query examples. Structured results retain every
successful or failed Query-generation result. Generated variables are placeholders and may need
manual adjustment for the target application's semantics.

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

Repeat `--format` to select `json`, `markdown`, or `html`. Repeating the same format writes it
once. `--output` names a directory, which is created when needed; the default is
`./gqlsleuth-reports`. Without `--format`, no report files or directories are created and the
existing scan output is unchanged. Supplying `--output` alone or an unknown format is an input
error. There is no separate `report` command.

Reporting runs after the existing scan and ACTIVE interaction finish. It performs **zero
additional network requests or GraphQL operations** and makes no new security decisions.

- **JSON** is the canonical machine-readable format, with `report_schema_version: 1`, stable
  field names, exact generated documents and variables, execution statuses/errors, and all
  retained evidence. Byte-valued response bodies use lossless `{ "encoding": "base64", "data":
  "..." }` objects. Evidence is preserved without introducing redaction.
- **Markdown** and **HTML** provide deterministic counts, discovery/confidence, introspection
  status, schema summaries, review candidates and reasons, generated Queries, execution
  outcomes, evidence counts, observed errors/limitations, and manual-review recommendations.
  They omit large raw response bodies. HTML is a standalone document with embedded CSS, escaped
  target text, and no external scripts, stylesheets, or CDN dependencies.

ACTIVE reports separately record Mutation generation, safety blocks and reasons, explicit
selection, final batch confirmation, and execution outcomes. Unselected, declined, blocked,
failed, and limit-skipped candidates are not counted as executed. Only existing
`MUTATION_EXECUTION` evidence establishes an attempted Mutation request; the same rule applies
to `QUERY_EXECUTION` evidence. Human reports show exact documents and variables for attempted
Mutations. SAFE reports never imply Mutation execution.

Filenames use a normalized target host and UTC report timestamp, for example
`gqlsleuth-example.com-20260908-231500.json` (or `.md` / `.html`). Existing files are never
silently overwritten: conflicts receive `-2`, `-3`, and so on. Reporting failures produce a
concise error after scanning and leave the scan result unchanged. Generated reports are local
artifacts and the default report directories are ignored by Git.

Reports are intended only for authorized testing. **CRITICAL/HIGH INTEREST indicates review
priority, not vulnerability severity.** Enabled introspection and successful execution are not
proof of exploitability. Reports create no Findings; all automated results require professional
validation. Recommendations are fixed responses to observed scan state, without AI.

## Configuration

Phase 1 has one application setting, `mode`, with supported values `safe` and `active`. SAFE
is the built-in default. The initial implementation accepts configuration only through the
explicit `--mode` CLI option and this safe default.

Environment variables and configuration files are not supported yet. They remain deferred
until the project has enough settings to justify multiple configuration sources.

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
