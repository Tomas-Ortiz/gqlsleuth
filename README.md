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

The repository is currently at **Phase 20 — Controlled Object Authorization Validation**. It provides the Phase 0
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
Phase 16 adds local structural security review of retained schema metadata, without additional
requests, operations, or changes to generation/execution decisions.
Phase 17 adds separately selected ACTIVE Query-Shape checks. Phase 18 follows with a separately
selected bounded Query-depth check, before the existing Mutation stage. SAFE scanning and
Phase 16 remain unchanged.

## Phase 20 — Controlled Object Authorization Validation

Use this opt-in **SAFE** stage only for authorized testing of exact, known identifiers you supply.
It runs after normal SAFE scanning and local Phase 16 analysis; in named-context scans it follows
Phase 15 comparison and any optional Phase 19 nested review. It is unrelated to ACTIVE stages.

Anonymous-only testing needs no token, named context or common `--header`:

```bash
gqlsleuth scan https://example.com/graphql --object-auth-review --object-auth-case "order:id=123"
```

Each case sends exactly one additional Query if structurally eligible, with no extra baseline or
retry. At most three cases are accepted. A matching returned object creates an
`UNAUTHENTICATED_OBJECT_ACCESS` **review candidate**: validate whether public access is intended.
It does not establish that the object should be private or that a vulnerability exists.

You may retain a tester-defined label with one **bare** context:

```bash
gqlsleuth scan https://example.com/graphql --auth-context public --object-auth-review --object-auth-case "order:id=123"
```

This single-context convenience applies only with Phase 20 enabled. A single context containing
headers remains invalid; normal Phase 15 still requires 2–3 contexts. Labels such as `public`,
`anonymous` or `foo` have identical semantics when bare: no user-supplied request/authentication
headers. This does not rule out other server authentication mechanisms.

For differential validation, explicitly declare the expected authorized context in each case:

```bash
gqlsleuth scan https://example.com/graphql --auth-context "clienteA=Authorization: Bearer TOKEN_A" --auth-context "clienteB=Cookie: session=TOKEN_B" --auth-context public --object-auth-review --object-auth-case "clienteA:order:id=123"
```

The operator-declared authorized context runs first. Only if its response returns that exact
object does the same Query and variables run in the other supplied contexts, in input order.
Matching access through another header-bearing context creates `CROSS_CONTEXT_OBJECT_ACCESS`;
through an explicitly supplied bare context it creates `UNAUTHENTICATED_OBJECT_ACCESS`.
These observations require manual policy validation. Supplied headers do not prove authentication;
labels imply no ownership, role hierarchy or tenant membership. No anonymous context is added
automatically. If the declared context fails to return the object, remaining contexts are skipped.

Repeat `--object-auth-case` for up to **3 unique cases**, across at most **3 contexts**, with a hard
maximum of **9 additional requests** (anonymous-only: **3**). Exact duplicate cases are deduplicated
in first-seen order. Values preserve everything after the first `=`, including `:` and additional
`=` characters; they must be non-empty, at most 256 UTF-8 bytes and contain no control characters.
Cases without the flag, the flag without cases, ACTIVE, and common `--header` combinations fail
before scanning. Named-context AI remains unsupported; ordinary single-context AI remains optional
and receives no Phase 20 data.

Eligibility is local: a retained Phase 16 object-lookup surface, direct `ID`/`ID!` root argument,
concrete non-list object return, and direct `id: ID`/`ID!` output are required. No nested ID inputs,
ID lists, abstract runtime guessing or alternate identity-field names are supported. Phase 9
placeholder SUCCESS is **not required**. AST construction changes only the selected ID input,
preserves other inputs/selections, and may add an omitted optional ID argument or direct `id`
selection. One document is validated against all participating schemas. An exact target-URL
artifact is preferred; otherwise multiple possible endpoints are skipped as ambiguous.

`TARGET_RETURNED` requires exact returned ID equality: JSON strings are unchanged, integers use
decimal text, and Booleans/floats are rejected. Leading zeroes, whitespace, Unicode and casing are
not normalized. Explicit HTTP/GraphQL authorization signals produce `EXPLICIT_DENIAL`; null,
mismatched IDs, generic errors and ambiguous partial data are `INDETERMINATE`. Transport failures
are `NETWORK_FAILURE`. Neither denial nor return proves a general security policy.

Every attempt uses a fresh isolated client/cookie jar and existing Phase 14 HTTP protections.
There is no ID enumeration, increment/decrement, randomization, response harvesting, ownership
inference, automatic BOLA/IDOR conclusion, Mutation, Subscription, alias, batch, concurrency or retry.
Only direct returned ID equality is compared; unrelated business values never decide outcomes.
Phase 19 never supplies cases to Phase 20 and retains its independent budget.

Console, Markdown and HTML show cases, declarations, outcomes and manual-review guidance without
dumping unrelated business responses. JSON adds optional `object_authorization_review`, including
exact requests, outcomes, source references and lossless `OBJECT_AUTHORIZATION_PROBE` evidence
only for actual attempts. No outgoing authentication configuration is recorded. Treat raw evidence
as potentially sensitive. Safety Notice remains the final human-report section. With Phase 20
disabled, existing request sequences and report fields remain unchanged.

Run the dedicated test-only loopback fixture and combined Phase 19/20 smoke:

```bash
uv run python tests/fixtures/phase20_target.py --smoke
```

Without `--smoke`, it prints a local URL. Fake `X-Test-Context: clienteA` and `clienteB` headers
exercise shared object `123`, enforced object `456`, null `999`, and identity `mismatch`;
object `100` is returned without supplied credentials. No real credentials or public targets are
needed. Phase 21+ is not implemented.

## Phase 19 — Nested Authorization Review

This optional capability belongs to **SAFE named-context scanning**, independently of the ACTIVE
Phase 17/18 workflow. Run the usual independent SAFE scans and Phase 15 comparison, then opt in
to bounded nested-path requests with `--nested-auth-review`:

```bash
gqlsleuth scan https://example.com/graphql --auth-context "client=Authorization: Bearer TOKEN_A" --auth-context "support=Cookie: session=TOKEN_B" --nested-auth-review
```

The same one-line syntax works in PowerShell. The flag requires 2–3 named contexts, cannot be
combined with ACTIVE, `--header`, or `--ai`, and works non-interactively without confirmation.
Without the flag, existing Phase 15 requests, results and report fields are unchanged.

Runtime eligibility requires an actually attempted SUCCESS baseline Query in every context,
structurally equivalent baseline documents and exactly identical variables. No new baseline is
sent. Existing Phase 7 OUTPUT rules identify scalar/enum terminal fields after at least one
composite relationship, for example `project.owner.email`. Input-only rules remain input-only.
Traversal is local, deterministic, breadth-first and cycle-safe; unsupported abstract resolution,
required nested business inputs, incompatible schemas and unsafe paths produce limitations.

At most **three candidate paths globally**, **selection depth five** (root through terminal field),
and **one composite list edge in the entire Query** are allowed. Existing root selections,
arguments, placeholders and variables are preserved. The shared bound helper may supply only a
minimal optional quantity control of **1**. Unbounded new lists are skipped. One AST-built Query
is validated against all retained schemas and sent unchanged to every context, sequentially,
using fresh isolated clients/cookie jars and the existing Phase 14 transport policy. The hard
maximum is **nine additional read-only requests** (three paths × three contexts), including
transport failures, with no retries or fallback requests.

Outcomes are RETURNED (a non-null terminal occurrence, including false/zero/empty string),
EXPLICIT_DENIAL (HTTP 401/403 or an explicit GraphQL authorization error applicable to the path),
INDETERMINATE (null, empty parent collection, generic errors or ambiguous partial data), and
NETWORK_FAILURE. Only RETURNED ↔ EXPLICIT_DENIAL creates a runtime NESTED_ACCESS_DIFFERENCE.
Compatible nested schema visibility differences are local-only review candidates. Missing schemas
are limitations, never evidence of absent fields.

Context names imply no privilege order. No IDs are substituted or enumerated, no ownership is
inferred, and no business values or list sizes are compared. Differences may reflect intended
policy and require manual validation; they do not establish BOLA, IDOR, or a vulnerability.
No Mutations, Subscriptions, aliases, batching, ACTIVE probes or Ollama calls are added.

Console and human reports show structural outcomes, categories and policy-review guidance;
verbose output includes exact Queries/variables, never returned business bodies. Canonical JSON
adds `nested_authorization_review` with per-context outcomes, source references and exact
`NESTED_AUTHORIZATION_PROBE` evidence only for attempted requests. Authentication configuration
is never stored in these result models. Reports remain potentially sensitive pentest artifacts,
and Safety Notice remains the final Markdown/HTML section.

Run the test-only loopback fixture with fake contexts:

```bash
uv run python tests/fixtures/phase19_target.py --smoke
```

Without `--smoke`, it prints a local URL; use `X-Test-Context: alpha`, `beta`, or `gamma` to exercise
returned, denied and ambiguous observations. A `hidden` context provides reduced nested schema
visibility. No public target or real credentials are needed. Object substitution and automated
BOLA/IDOR validation remain outside this phase.

## Phase 18 — Controlled Query Depth Validation

The ACTIVE workflow is: ordinary Phase 9 Queries → Phase 17 multiplicity checks → Phase 18
bounded Query-depth check → Mutation interaction. Each active stage has its own explicit
selection and default-NO confirmation. Enter selects none. SAFE, ACTIVE alone and
non-interactive scans send zero depth probes. Named authentication contexts remain SAFE-only.

At most one candidate per endpoint is constructed locally from a retained Phase 16 recursive
witness and an already-attempted safe Query, preferring SUCCESS. A GRAPHQL_ERROR baseline may
be used when structurally suitable; no new baseline request is sent. The AST transformation
preserves the root arguments, exact variables, placeholders, anonymity and existing bounds. It
traverses one retained cycle once, ending with `__typename`, and may reuse the Phase 8 optional
quantity-bound helper to introduce only a minimal nested `limit=1` (or equivalent) path.
Required nested business inputs, unsupported abstract paths, unsafe field names and new
unbounded list expansion produce limitations instead of executable candidates.

Hard limits: **one Phase 18 request per scan**, **constructed selection depth at most 6**, and
**one composite list expansion in the complete document, including the root**. GQLSleuth counts
field nodes from root through terminal leaf/`__typename`; this metric need not match a server's
own depth calculation. No cycle repetition, progressive depth search, retries, concurrency,
aliases, batching, cost-threshold discovery or DoS testing is performed.

Select one displayed index, inspect the exact deeper Query and variables, and confirm separately.
ACCEPTED means only that this concrete Query shape was processed. REJECTED requires an explicit
depth/complexity/query-cost rule response. Generic errors are INDETERMINATE; transport failures
remain NETWORK_FAILURE. Neither acceptance nor rejection establishes a vulnerability, missing
controls, global protection or an exhaustion risk. No business values or timings are compared.

Only attempted depth requests create `GRAPHQL_BEHAVIOR_PROBE` evidence, retaining source IDs,
baseline/probe depths, path, exact Query/variables, response bytes and transport facts. Reports
add **Controlled Query Depth Validation**, with bounded human response display and lossless JSON.
Safety Notice remains last. Phase 18 adds nothing to AIContext and makes no Ollama call.

Run the test-only loopback smoke (accepted, rejected, indeterminate and unselected scenarios):

```bash
uv run python tests/fixtures/phase18_target.py --smoke
```

Without `--smoke`, it prints a loopback URL for manual testing. Select no Phase 17 checks, select
and confirm the depth candidate, then press Enter for no Mutations. No public target or real
credentials are needed. General query-cost analysis and other future runtime checks remain out
of scope.

## Phase 17 — Controlled GraphQL Multiplicity Validation

Use `gqlsleuth scan https://example.com/graphql --mode active` only against an authorized target.
After ordinary safe Query execution, ACTIVE previews two probe types per eligible endpoint:

- **Alias Multiplicity:** exactly three deterministic aliases of one existing safe Query field.
- **HTTP Batching:** exactly two identical Query/variables request objects in a JSON array.

The representative Query is chosen from attempted Phase 9 results, preferring SUCCESS and then
the existing retained Query order. Its exact arguments, variables, `limit=1` bounds and minimal
selection are preserved. If none qualifies, the stage records a limitation without probing.

Explicitly select individual comma-separated indices (maximum two), inspect the selected requests,
and provide one final confirmation, default NO. Enter selects none; non-interactive runs execute
none. ACTIVE alone authorizes no probes. The existing Mutation selection and confirmation remain
independent and follow the separate Phase 18 depth stage. At most one Alias request and one Batch request may be attempted
per scan; there are no retries, concurrency, threshold searches or configurable multiplicities.

ACCEPTED, REJECTED and INDETERMINATE describe only this request shape and representative Query.
Alias acceptance requires all three expected response keys without an execution error. Batch
acceptance requires two GraphQL-shaped response entries; individual entries may contain GraphQL
errors. Explicit shape rejections are distinguished from ambiguous failures. Neither acceptance
nor rejection establishes vulnerabilities, global resolver policy, higher thresholds or missing
cost/rate controls.

JSON, Markdown and HTML add **Controlled GraphQL Multiplicity Validation**, preserving selection,
confirmation, decisions and observations. Attempted requests alone create `GRAPHQL_BEHAVIOR_PROBE`
evidence with exact requests, response bytes and normalized transport errors. Human responses use
the existing bounded renderer; canonical JSON preserves complete evidence. Safety Notice remains
last. Phase 17 is excluded from AIContext and adds no Ollama call. Named authentication-context
scans remain SAFE-only and do not perform these probes.

Run the controlled loopback acceptance/rejection/ambiguous smoke without public targets:

```bash
uv run python tests/fixtures/phase17_target.py --smoke
```

Without `--smoke`, the test-only server prints a loopback URL for manual CLI testing. No real
credentials or public services are needed. General complexity, rate-limit, upload, subscription,
federation and Mutation multiplicity runtime checks are not implemented.

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
It normally omits optional/defaulted arguments, creates deterministic placeholder variables, and selects a
small response field path with a maximum internal depth of three and cycle protection. Custom
scalar placeholders use the string `"test"` and are marked as potentially requiring manual
adjustment. SAFE generates Query documents only. ACTIVE reuses this same generation algorithm
for Mutation-root fields after completing the safe workflow. Subscriptions are never generated.

For collection Queries, Phase 8 may also populate one recognized optional `Int` quantity bound
with **1**. It shares Phase 16's schema inspection of direct composite lists, one-level
page/connection wrappers, and up to three input-object levels (for example,
`options.paginate.limit`). Only that path and required inputs are populated; unrelated optional
fields stay omitted. Recognized names are `first`, `last`, `limit`, `take`, `size`, `pageSize`,
`perPage`, and `maxResults`, including snake_case equivalents. Unsafe paths are left unchanged.
This does not auto-paginate or validate server-side enforcement, and never adds bounds to Mutations.

String placeholders use exact normalized field/argument names: email/mail names use
`"test@example.com"`, password/passwd/passcode use `"TestPass123!"`, username/loginName use
`"testuser"`, name/fullName/displayName use `"Test User"`, firstName uses `"Test"`, lastName uses
`"User"`, URL names use `"https://example.com"`, and phone names use `"+15555550100"`.
Other Strings use `"test"`. Matching supports camelCase, PascalCase and snake_case without
substring matches (for example, `passwordHint` remains `"test"`). Nested inputs use each leaf's
name. ID, numeric, Boolean, enum and custom-scalar behavior remains unchanged. These are
deterministic placeholders for both Queries and Mutation previews and may require manual adjustment.

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

## GraphQL structural security review

**GraphQL Security Review** complements Phase 7 semantic interest ranking with deterministic
schema analysis. It runs after schema/operation analysis and before existing Query generation,
in SAFE and ACTIVE scans and independently within each Phase 15 named context. It needs no AI,
adds **zero HTTP requests or GraphQL operations**, and preserves all existing Query/Mutation
generation, safety, selection, limits, ordering, and execution classifications.

The implemented review candidates are:

| Candidate | Structural observation |
| --- | --- |
| `FILE_UPLOAD_SURFACE` | Exact `Upload` scalar declaration or reachable Mutation input. |
| `FEDERATION_SURFACE` | Coherent `_service`/`_Service.sdl` or `_entities`/`_Any`/`_Entity` structures. |
| `SUBSCRIPTION_SURFACE` | A Subscription root exposes fields. |
| `OBJECT_LOOKUP_REVIEW` | Query returns composite objects and accepts an `ID` argument with an exact `id`/`ids` identifier token suffix. |
| `LIST_BOUNDING_REVIEW` | Query exposes a composite list directly or through a one-level collection wrapper, without an obvious quantity control in schema inputs. |
| `RECURSIVE_GRAPH_REVIEW` | Query-reachable output cycle includes a list-valued composite relationship. |
| `FLEXIBLE_SCALAR_INPUT_REVIEW` | Root Query/Mutation input directly or indirectly reaches `JSON`, `JSONObject`, `Any`, or `Map`. |
| `COMPLEX_INPUT_REVIEW` | Root input reaches a recursive input-object relationship or more than four consecutively required input objects. |
| `DEPRECATED_SECURITY_RELEVANT_OPERATION` | Deprecated Query/Mutation already has non-zero Phase 7 interest. |

These are **manual-review candidates, not vulnerability findings**. Absence of an obvious schema
control does not prove absence of runtime enforcement. Pagination arguments do not prove correct
limits either. No new priority or severity score is introduced; related Phase 7 interest remains
unchanged. No IDs are varied, no upload/subscription/federation probes or depth/cost attacks are
introduced, and no server vendor is inferred. Existing SAFE Query behavior remains unchanged.

Bounding names use exact normalized identifiers: `first`, `last`, `limit`, `take`, `size`, `pageSize`,
`perPage`, `maxResults` (including snake-case equivalents). Position-only names such as `page`,
`offset`, `after`, `before`, and `cursor` do not qualify. Root arguments and nested input objects
are inspected breadth-first, up to **three input-object levels** (the root argument's input object
is level one), with cycle protection and the existing type/relationship budgets. For example,
`options.paginate.limit` is a schema signal even when both inputs are optional.

Generated Queries normally omit optional arguments, except recognized quantity bounds. Phase 16 inspects schema arguments rather than
generated documents when determining whether an obvious bounding mechanism exists.
Pagination/bounding arguments are schema signals only; their presence does not prove runtime
enforcement. Returned item counts never influence this static rule.

The list rule covers direct composite lists and one-level wrappers with a direct composite list
field. Exact field hints are `data`, `items`, `nodes`, `edges`, `results`, `records`, and `entries`;
alternatively, normalized type suffixes `Page`, `Connection`, `Collection`, `Results`, or `ResultSet`
qualify. One strong hint suffices; arbitrary substrings and incidental lists such as `User.roles`
do not. It never follows deeper output wrappers or flags scalar lists. Each root Query has at most
one candidate, retaining up to three collection paths in stable field-name order, plus an omitted
field count when necessary. Object Lookup candidates remain structural, with guidance contextualized
to objects that are access-controlled; public reference-data names do not suppress detection.

Arbitrary scalar inputs such as `DateTime`, `UUID`, `Email`, and `URL`
are not flexible-input candidates. Ordinary finite object chains and singular-only cycles are
not recursive-list candidates.

Input and output graph traversal each has hard limits of **512 types and 4,096 inspected
relationships**. Iterative cycle analysis emits one representative per strongly connected
component; paths are cycle-safe and deterministic. Required input depth counts a required root
argument plus required nested input objects; defaults break the required chain. Truncation or
missing schema is retained as a limitation, never an absence-of-risk conclusion. Candidates are
deduplicated by type, endpoint, and subject, ordered by the candidate types above, then endpoint
and subject. Multiple paths to the same scalar/input cycle do not duplicate candidates.

Console output is compact (up to ten candidates); verbose output includes supporting facts and
manual guidance. JSON adds `graphql_security_review` with complete facts, related Phase 7
metadata, limitations, and existing schema-evidence IDs. Markdown/HTML add the same review with
bounded supporting paths, and keep Safety Notice last. Named-context reports present each
context's review separately; Phase 15 pairwise comparisons do not compare Phase 16 candidate sets.
AI input and the one-inference behavior are unchanged; no Phase 16 data is sent to Ollama.

Run the test-only metadata fixture and generate all report formats locally:

```bash
uv run python tests/fixtures/phase16_smoke.py --output ./reports/phase16-smoke
```

This loads `tests/fixtures/phase16_schema.graphql` locally and verifies all nine candidate types.
It includes page collections with no bound, a direct `limit`, and nested `options.paginate.limit`.
Network/operation guards prevent target requests or execution; no credentials or public target
are needed. Full SAFE/ACTIVE request equivalence is separately checked with offline transports.

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
