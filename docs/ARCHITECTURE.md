# GQLSleuth — Project Specification

## 1. Project overview

GQLSleuth is an open-source Python CLI for authorized GraphQL security discovery and analysis.

The project is designed to help security professionals understand GraphQL applications by automating the initial investigation workflow:

- Discovering possible GraphQL endpoints.
- Confirming whether an endpoint behaves like GraphQL.
- Retrieving and parsing the schema when introspection is available.
- Identifying security-relevant types, fields and operations.
- Generating minimal GraphQL queries.
- Executing read-only queries in safe mode.
- Producing structured evidence and reports.
- Optionally using a local AI model to assist with interpretation and prioritization.

GQLSleuth is not intended to be a generic vulnerability scanner that blindly launches payloads or exploits.

Its primary purpose is to automate the investigative process normally performed manually by an application security professional when reviewing an unknown GraphQL implementation.

## 2. Motivation

GraphQL security assessments often require several manual steps:

- Finding the GraphQL endpoint.
- Confirming that the endpoint actually processes GraphQL.
- Testing whether introspection is enabled.
- Reading and understanding the schema.
- Identifying interesting queries, mutations, types and fields.
- Constructing syntactically valid requests.
- Prioritizing operations related to authentication, authorization, tokens, users, administrative functionality or sensitive information.
- Preserving evidence for later analysis and reporting.

Existing tools often focus on a single part of this process or provide large amounts of raw schema information without helping the tester understand what should be reviewed first.

GQLSleuth aims to combine endpoint discovery, schema analysis, query generation, controlled execution and reporting in a single workflow.

## 3. Project goals

The main goals of GQLSleuth are:

- Provide a professional CLI for GraphQL security discovery.
- Automate repetitive GraphQL reconnaissance tasks.
- Preserve a deterministic and auditable analysis process.
- Prioritize security-relevant schema elements.
- Generate valid minimal GraphQL queries automatically.
- Operate safely by default.
- Require explicit authorization before active testing.
- Produce reusable evidence and reports.
- Maintain a modular architecture that can be extended over time.
- Serve as a serious cybersecurity and software engineering portfolio project.

## 4. Non-goals

The initial versions of GQLSleuth will not attempt to:

- Become a general-purpose web vulnerability scanner.
- Automatically exploit every possible GraphQL vulnerability.
- Perform denial-of-service testing.
- Perform brute-force attacks.
- Automatically bypass authentication or authorization.
- Execute destructive mutations by default.
- Compare multiple authorization contexts in the MVP.
- Provide a SaaS platform.
- Provide a graphical web interface.
- Replace manual security analysis.
- Guarantee that a detected behavior is exploitable.
- Automatically publish findings to external platforms.

The tool should assist the tester, not replace professional judgment.

## 5. Legal and ethical use

GQLSleuth must only be used against systems for which the operator has explicit authorization.

The tool must clearly communicate this requirement in:

- The README.
- CLI help text.
- Active-mode confirmation messages.
- Generated reports.

The project must not encourage unauthorized access, destructive testing or disruption.

Active functionality must require explicit acknowledgement from the user.

Example:

```bash
gqlsleuth scan https://example.com/graphql --mode active --authorized
```

Without the `--authorized` flag, active mode must not execute.

## 6. Operating modes

GQLSleuth has two operating modes.

### 6.1 Safe mode

Safe mode is the default.

It is intended for non-destructive discovery and read-only analysis.

Safe mode may perform:

- GraphQL endpoint discovery.
- GraphQL behavior confirmation.
- Introspection requests.
- Schema retrieval.
- Schema parsing.
- Query and mutation classification.
- Security-relevant keyword analysis.
- Minimal read-only query generation.
- Read-only GraphQL query execution.
- Evidence collection.
- Report generation.

Safe mode must not:

- Execute mutations.
- Modify application state.
- Perform brute-force attacks.
- Perform denial-of-service testing.
- Flood the target with requests.
- Execute destructive or high-risk operations.

Example:

```bash
gqlsleuth scan https://example.com
```

Equivalent explicit form:

```bash
gqlsleuth scan https://example.com --mode safe
```

### 6.2 Active mode

Active mode enables functionality that may modify application state or produce a higher level of interaction with the target.

It must require both `--mode active` and `--authorized`:

```bash
gqlsleuth scan https://example.com/graphql --mode active --authorized
```

Active mode may eventually support controlled mutation execution.

Even in active mode, the tool must:

- Avoid destructive behavior by default.
- Show the operation before executing it.
- Require explicit confirmation for risky operations.
- Preserve the exact request and response as evidence.
- Apply request limits and timeouts.
- Clearly label active results in reports.

Active mode is not part of the first minimal implementation and must be introduced only after safe-mode functionality is stable.

## 7. Accepted input

GQLSleuth accepts either:

**Application base URL** — e.g. `https://example.com`. When a base URL is provided, the tool attempts to discover the GraphQL endpoint.

**Direct GraphQL endpoint** — e.g. `https://example.com/graphql`. When a direct endpoint is provided, the tool tests it directly before attempting additional discovery.

Phase 1 parses and validates input URLs while preserving:

- Original URL.
- Scheme.
- Host.
- Port.
- Path.
- Query.

Only HTTP and HTTPS URLs are initially supported.

URL normalization is a separate Phase 3 responsibility. Phase 1 does not normalize trailing
slashes, remove default ports, canonicalize hosts, resolve DNS, check reachability, generate
endpoint candidates or deduplicate URLs.

## 8. High-level workflow

The expected workflow is:

```text
Input URL
    ↓
URL normalization
    ↓
GraphQL endpoint discovery
    ↓
GraphQL behavior confirmation
    ↓
Introspection test
    ↓
Schema retrieval
    ↓
Schema parsing
    ↓
Operation and field classification
    ↓
Security prioritization
    ↓
Minimal query generation
    ↓
Safe execution
    ↓
Evidence collection
    ↓
Report generation
    ↓
Optional AI-assisted interpretation
```

Each stage must be independently testable and should not depend directly on CLI presentation code.

## 9. GraphQL endpoint discovery

When the user supplies only an application base URL, GQLSleuth attempts to identify possible GraphQL endpoints.

Phase 3 identifies endpoint candidates only. It does not submit GraphQL payloads or determine
whether a response is GraphQL; that distinction belongs to Phase 4.

The first version uses a bundled wordlist. Initial candidate paths include:

```text
/graphql
/api/graphql
/gql
/api/gql
/v1/graphql
/v2/graphql
/graphql/v1
/graphql/v2
/query
/api/query
```

Discovery normalizes scheme and host casing, removes default HTTP and HTTPS ports, preserves
non-default ports, and removes trailing path slashes for stable deduplication. It does not
resolve DNS or otherwise check reachability during normalization. If the supplied target has a
meaningful path, that normalized URL is probed first. The bundled paths are then generated from
the same origin without recursively combining them with the supplied path.

Candidates are deduplicated in their stable generation order and probed with safe HTTP GET
requests through the centralized HTTP client. All HTTP status responses are retained. A
normalized transport failure is recorded for its candidate without preventing later candidates
from being probed. Each outcome creates `ENDPOINT_CANDIDATE` evidence; no GraphQL confirmation,
observation, finding, or confidence score is produced in this phase.

Future versions may support:

- Custom wordlists.
- JavaScript endpoint extraction.

## 10. GraphQL confirmation

An HTTP 200 response is not sufficient to confirm GraphQL. The tool must use multiple signals.

Possible confirmation signals include:

- A valid response to a minimal GraphQL query, such as:

  ```graphql
  query {
    __typename
  }
  ```
- GraphQL-style JSON containing `data`.
- GraphQL-style JSON containing `errors`.
- GraphQL parser error messages.
- Validation errors referencing fields or operations.
- GraphQL-specific content types.
- Different behavior when a GraphQL payload is submitted.
- Introspection-related responses.
- Known GraphQL server headers or error formats.

The detector should assign a confidence level rather than relying on a single Boolean condition. Possible confidence levels:

- Confirmed.
- Probable.
- Possible.
- Not detected.

The evidence used to reach the conclusion must be preserved.

Phase 4 first analyzes each response already collected by Phase 3. HTTP status is never a
GraphQL signal. Generic JSON, generic HTML, malformed bodies, and arbitrary uses of words such
as `query`, `schema`, or `graphql` do not produce confidence by themselves.

The initial deterministic signals are:

- The exact GraphQL response media types `application/graphql-response+json`,
  `application/graphql+json`, and `application/graphql`.
- A JSON `data` object.
- A valid GraphQL name string in `data.__typename`.
- A non-empty `errors` array containing objects with string `message` values.
- Clear parser or validation phrases inside that errors structure: `Must provide query string`,
  `Syntax error`, `Cannot query field`, `Unknown operation named`, `Operation name is required`,
  or the anonymous-operation exclusivity error.
- The exact error extension codes `GRAPHQL_PARSE_FAILED` and `GRAPHQL_VALIDATION_FAILED`.

The exact confidence rules are:

- `CONFIRMED`: `data.__typename` contains a valid GraphQL name string.
- `PROBABLE`: a GraphQL-shaped errors array contains one of the clear parser or validation
  phrases or exact error codes above, or a GraphQL-specific media type accompanies a JSON
  `data` object or GraphQL-shaped errors array.
- `POSSIBLE`: only a GraphQL-specific media type, JSON `data` object, or GraphQL-shaped errors
  array is present.
- `NOT_DETECTED`: none of the signals above are present.

`CONFIRMED` and `PROBABLE` GET results require no duplicate request. `POSSIBLE` and
`NOT_DETECTED` GET results receive one fallback POST to the same candidate with the static JSON
body `{"query": "query { __typename }"}`. The final confidence is the stronger explicit
classification from the GET and POST analyses. A normalized POST failure is retained for that
candidate and does not stop later candidates. No introspection fields or arbitrary operations
are sent during Phase 4.

## 11. HTTP behavior

The HTTP layer must be centralized. It is responsible for:

- Request execution.
- Timeouts.
- Redirect handling.
- TLS verification options.
- Proxy configuration.
- Custom headers.
- Authentication headers.
- User-Agent configuration.
- Request limits.
- Response size limits.
- Error normalization.
- Evidence capture.

The initial HTTP client will use HTTPX. No networking logic should be duplicated across discovery, introspection or execution modules.

Phase 2 provides one reusable synchronous `httpx.Client` adapter with GQLSleuth-owned request
and response models. It streams response bodies while enforcing the configured size limit,
returns HTTP 4xx and 5xx responses normally, and normalizes HTTPX request failures into
project-specific exceptions. It does not parse JSON or GraphQL response content.

Phase 2 does not expose HTTP options through the CLI. Beginning in Phase 3, the `scan` command
uses this client for safe GET-only endpoint candidate probes. Retries, concurrency, rate
limiting and caching remain unimplemented.

The Phase 2 defaults are:

- TLS verification enabled.
- Redirects enabled.
- Maximum redirects set to 5.
- Timeout set to 10 seconds.
- Maximum response body set to 5 MiB.
- No proxy.
- Environment-derived HTTP configuration disabled with `trust_env=False`.
- User-Agent set to `GQLSleuth/<current version>`.

## 12. Introspection

After confirming a probable GraphQL endpoint, GQLSleuth tests whether introspection is available.

The tool should first attempt a minimal introspection request. If supported, it may retrieve the complete schema using the standard introspection query.

The tool must distinguish between:

- Introspection enabled.
- Introspection disabled.
- Authentication required.
- Authorization denied.
- Endpoint error.
- Invalid or incomplete response.
- Network failure.

The raw introspection response should be optionally preserved as evidence.

Failure to retrieve the schema must not terminate the entire scan abruptly. The tool should still report the endpoint and available evidence.

Phase 5 attempts introspection only for Phase 4 `CONFIRMED` and `PROBABLE` candidates. Requests
remain sequential, and a failure for one endpoint does not stop other eligible endpoints. The
minimal availability query is:

```graphql
{
  __schema {
    queryType {
      name
    }
  }
}
```

Both the minimal request and the full static introspection query use anonymous operations for
compatibility with endpoints that reject named operations.

The initial deterministic status rules, applied in this order, are:

- `AUTHENTICATION_REQUIRED`: HTTP 401.
- `AUTHORIZATION_DENIED`: HTTP 403.
- `ENABLED`: a JSON response contains a `data.__schema` object.
- `DISABLED`: a GraphQL `errors` message clearly states that introspection or `__schema` access
  is disabled, forbidden, or not allowed, including the common `Cannot query field "__schema"`
  response.
- `ENDPOINT_ERROR`: another GraphQL error prevents the operation, or another HTTP status of 400
  or greater prevents introspection.
- `INVALID_RESPONSE`: a non-error HTTP response is malformed or lacks both a `data.__schema`
  object and an interpretable GraphQL error.
- `NETWORK_FAILURE`: the centralized HTTP client raises a normalized transport failure.

Only an `ENABLED` minimal result triggers one full static introspection query. That query asks
for schema roots, types, fields, field arguments, interfaces, enum values, possible types, input
fields, nested list/non-null type references, directives, descriptions, and deprecation metadata.
The full response is classified using the same rules. A full-retrieval transport or response
failure becomes the endpoint's final status while the successful minimal response remains
preserved.

Phase 5 retains the existing `HttpResponse` objects for both requests, including the raw full
introspection JSON body. It does not convert that JSON into schema models, extract operations,
or add `graphql-core`; those responsibilities begin in Phase 6. Each processed endpoint creates
`INTROSPECTION_RESULT` evidence, and enabled introspection is not labeled as a vulnerability.

## 13. Schema parsing

Schema parsing must be deterministic. The project will use `graphql-core` when the schema functionality is introduced.

The parser should model:

- Query root.
- Mutation root.
- Subscription root.
- Object types.
- Input types.
- Scalar types.
- Enumeration types.
- Interfaces.
- Unions.
- Fields.
- Arguments.
- Return types.
- Nullability.
- Lists.
- Nested relationships.
- Deprecation metadata.
- Descriptions when available.

The internal representation must be independent from the raw introspection JSON so it can later support additional schema sources.

The initial Phase 6 implementation consumes only `ENABLED` Phase 5 results that retain a full
introspection response. It sends no HTTP requests. The response JSON `data` object is passed to
`graphql-core` for client-schema construction and schema validation, then mapped into immutable
GQLSleuth-owned models. Neither raw introspection dictionaries nor `graphql-core` objects are
exposed as the project representation.

The Phase 6 representation includes named object, input-object, scalar, enum, interface, and
union types; fields; arguments; input fields; enum values; directives; descriptions;
deprecation metadata; implemented interfaces; possible types; and references between types by
name. Recursive type references preserve named, list, and non-null nodes independently, allowing
structures such as `[User!]!` to retain outer nullability and list-item nullability while still
exposing the base named type.

Application-facing types are ordered deterministically and exclude introspection system types
whose names begin with `__`. Referenced built-in scalars remain available, and application-defined
custom scalars are preserved. The summary records root names; total, object, input-object,
scalar, custom-scalar, enum, interface, union, and directive counts; and field counts for the
query, mutation, and subscription roots.

An invalid or incomplete full response produces a controlled per-endpoint parsing failure and
does not stop another eligible endpoint. Successful parsing creates `SCHEMA_ARTIFACT` evidence
with roots and structural counts. Schema parsing itself does not classify, prioritize, or
execute any operation; Phase 7 consumes its project-owned result locally.

## 14. Operation classification

GQLSleuth should classify GraphQL operations based on their likely purpose. Example categories:

- Authentication.
- Authorization.
- User management.
- Administrative functionality.
- Tokens and sessions.
- Password management.
- Account recovery.
- Identity providers.
- Files and uploads.
- Integrations.
- Billing and payments.
- Personal information.
- Secrets and credentials.
- Configuration.
- Debugging.
- Internal functionality.
- Search.
- Reporting.
- Read-only business data.
- State-changing business operations.

The initial Phase 7 implementation is deterministic and rule-based. It analyzes Query and
Mutation root fields according to their actual schema roots; subscriptions are not analyzed.
Its shallow analysis surface uses:

- Operation names.
- Field names.
- Argument names.
- Return type names.
- Descriptions.
- One direct level of input-object fields and returned object/interface fields.
- Known security-sensitive keywords.

Examples of interesting terms include:

```text
admin
administrator
auth
authenticate
authorization
credential
debug
delete
download
email
export
file
impersonate
internal
invite
login
logout
password
permission
privilege
recover
reset
role
secret
session
sharepoint
token
upload
user
```

This list is illustrative. Phase 7 groups a curated subset into an auditable bundled YAML rule
file loaded with `importlib.resources`, so loading does not depend on the current working
directory. The loader also accepts an explicit local path for programmatic use, but no custom
rule CLI option exists yet.

Identifiers and descriptions are tokenized case-insensitively across camelCase, PascalCase,
snake_case, kebab-case, and normal text. Keywords match complete normalized tokens, not arbitrary
substrings. A rule contributes its weight at most once per operation while retaining every
matched keyword and surface location for explanation. Different rules contribute independently.
When no semantic rule matches, Query fields receive the `READ_ONLY_BUSINESS_DATA` fallback and
Mutation fields receive `STATE_CHANGING_BUSINESS_OPERATION`; both remain informational unless a
configured rule contributes a score.

## 15. Security prioritization

The tool should assign a priority or score to operations and fields. The purpose of the score is to help the tester decide what to review first. The score must not be presented as a vulnerability severity.

Phase 7 uses these project-owned priority levels:

- Critical interest.
- High interest.
- Medium interest.
- Low interest.
- Informational.

Factors may include:

- Presence of authentication-related keywords.
- Token or credential return types.
- Administrative terminology.
- Mutations affecting users, roles or permissions.
- Operations returning large or sensitive object graphs.
- Operations with no required arguments.
- Operations exposing internal identifiers.
- Deprecated but still accessible functionality.
- Debug or internal schema descriptions.
- File retrieval or export operations.
- Identity provider integrations.
- Connections to external services.

The bundled YAML defines the initial score thresholds: critical at 8, high at 5, medium at 3,
and low at 1; score zero is informational. Results are sorted by explicit priority rank, score
descending, then stable operation kind and name ordering. The numeric interest score and review
priority are not CVSS, vulnerability severity, exploitability, or proof of impact.

Only non-zero rule matches create `INTERESTING_OPERATION` evidence. The evidence records the
endpoint, actual Query or Mutation kind, operation name, categories, interest score, review
priority, matched rule IDs, and deterministic reasons. Phase 7 sends no HTTP request, generates
no GraphQL query, and executes no schema operation.

Reports must clearly state that prioritization identifies areas for manual review and does not prove exploitability.

## 16. Query generation

GQLSleuth should generate syntactically valid minimal GraphQL queries from the schema. The generator must:

- Select required arguments.
- Generate placeholder values based on scalar type.
- Select minimal response fields.
- Avoid excessive nesting.
- Avoid recursive type expansion.
- Apply a configurable depth limit.
- Handle lists and non-null types.
- Support custom scalars conservatively.
- Identify operations that cannot be generated automatically.
- Preserve the generated query as evidence.

Example:

```graphql
query GetCurrentUser {
  currentUser {
    id
    username
  }
}
```

For operations with required arguments:

```graphql
query UserById($id: ID!) {
  user(id: $id) {
    id
    username
  }
}
```

Variables:

```json
{
  "id": "1"
}
```

Generated values are placeholders and must not be assumed to be valid for the target application.

## 17. Safe query execution

Safe mode may execute generated read-only queries. The executor must verify that the selected operation belongs to the query root and is not a mutation.

It must preserve:

- Endpoint.
- HTTP method.
- Request headers.
- GraphQL query.
- Variables.
- Timestamp.
- Response status.
- Response headers when relevant.
- Response body.
- Execution duration.
- Error information.
- Classification and priority.

## 18. Authentication support

The MVP may support user-provided headers:

```bash
gqlsleuth scan https://example.com/graphql --header "Authorization: Bearer TOKEN"
```

Additional headers may be supplied more than once.

The tool should not attempt to obtain credentials automatically. The MVP will not perform differential authorization testing between anonymous, user and administrator contexts. Multi-context authorization comparison may be introduced in a later version.

## 19. Evidence model

Every relevant action should produce structured evidence. Evidence should include:

- Unique identifier.
- Evidence type.
- Target.
- Endpoint.
- Timestamp.
- Request summary.
- Response summary.
- Supporting raw data when configured.
- Confidence.
- Related operation or schema element.
- Source module.
- Notes.

Example evidence types:

- Endpoint candidate.
- GraphQL confirmation.
- Introspection result.
- Schema artifact.
- Interesting operation.
- Generated query.
- Query execution.
- Mutation execution.
- HTTP error.
- Parser error.

Evidence should be represented using typed Pydantic models.

AI-generated interpretation is not evidence and must remain separately labeled. Observation
and Finding models should be introduced only when deterministic analysis requires them; an
AI-generated interpretation model belongs to the AI phase.

## 20. Findings and observations

GQLSleuth must distinguish between:

**Evidence** — a directly observed technical fact.
> Example: The endpoint returned a valid response to the `__typename` query.

**Observation** — an interpretation derived from one or more pieces of evidence.
> Example: The endpoint is likely a GraphQL API.

**Finding** — a security-relevant conclusion that may require manual validation.
> Example: The schema exposes a login mutation returning a token object.

The tool must avoid declaring a vulnerability unless the available evidence supports that conclusion. Most automated results should be presented as observations or review candidates.

## 21. Reporting

The project should eventually support:

- Console output.
- JSON report.
- Markdown report.
- HTML report.

Initial development may begin with console and JSON output. Reports should contain:

- Scan metadata.
- Target information.
- Execution mode.
- Authorization acknowledgement status.
- Discovered endpoints.
- GraphQL confirmation evidence.
- Introspection status.
- Schema summary.
- Interesting operations.
- Generated queries.
- Execution results.
- Errors and limitations.
- Recommendations for manual review.
- Safety disclaimer.

HTML and Markdown reports may use Jinja2.

Report generation must consume structured scan results and must not depend directly on CLI output.

## 22. Optional AI assistance

AI functionality is optional and must not be required for the deterministic scanner to work.

The planned initial AI integration is Ollama running Qwen3 8B locally. Possible AI use cases:

- Prioritizing interesting schema elements.
- Explaining complex GraphQL operations.
- Summarizing schema relationships.
- Suggesting manual review paths.
- Interpreting GraphQL errors.
- Generating human-readable report summaries.
- Identifying suspicious combinations of fields, arguments and return types.

AI must not:

- Control the HTTP client directly.
- Execute operations independently.
- Bypass safe-mode controls.
- Invent evidence.
- Replace deterministic parsing.
- Mark an issue as confirmed without supporting evidence.
- Receive secrets.
- Be necessary for endpoint discovery or schema parsing.

AI output must be clearly labeled as model-generated interpretation. The deterministic engine remains the source of truth.

## 23. Configuration

The long-term configuration design should support:

- CLI arguments.
- Environment variables.
- Configuration files.
- Safe project defaults.

Precedence should be:

```text
CLI arguments
    ↓
Environment variables
    ↓
Configuration file
    ↓
Default values
```

Configuration models should use Pydantic and `pydantic-settings` when multiple configuration
sources are introduced.

The initial Phase 1 implementation supports only the explicit `--mode` CLI option and the
built-in safe default. Environment variables and configuration files are deferred until
configuration needs grow; no configuration file is discovered or loaded in Phase 1.

`active` is accepted as a configuration value during Phase 1, but it does not enable active
behavior. The `--authorized` gate and active execution remain Phase 10 responsibilities.

Possible settings include:

- Mode.
- Timeout.
- Maximum retries.
- Concurrency.
- User-Agent.
- TLS verification.
- Proxy.
- Headers.
- Wordlist path.
- Output directory.
- Report formats.
- Maximum query depth.
- Response size limit.
- Evidence storage.
- AI enabled or disabled.
- Ollama model.
- Ollama endpoint.

Secrets must not be stored in committed configuration files.

## 24. CLI design

The CLI will use Typer and Rich. The main executable will be:

```bash
gqlsleuth
```

Proposed high-level commands:

```bash
gqlsleuth scan
gqlsleuth discover
gqlsleuth introspect
gqlsleuth analyze
gqlsleuth generate
gqlsleuth report
gqlsleuth version
```

The exact command structure may evolve during implementation. The primary user workflow should remain simple:

```bash
gqlsleuth scan https://example.com
```

Possible options:

```text
--mode
--authorized
--header
--timeout
--proxy
--verify-tls
--wordlist
--output
--format
--max-depth
--ai
--verbose
--quiet
```

The CLI layer must:

- Parse input.
- Validate arguments.
- Call application services.
- Render results.
- Map internal exceptions to useful user messages.

The CLI layer must not contain core scanning logic.

## 25. Error handling

The tool must fail gracefully. Expected error categories include:

- Invalid URL.
- Unsupported scheme.
- DNS resolution failure.
- Connection timeout.
- TLS error.
- Proxy error.
- HTTP protocol error.
- Redirect loop.
- Response too large.
- Invalid JSON.
- Invalid GraphQL response.
- Introspection denied.
- Schema parsing failure.
- Query generation failure.
- Authentication failure.
- Configuration error.
- File system error.
- AI service unavailable.

Errors should be represented using project-specific exception classes.

The CLI must display concise messages by default and detailed diagnostic information in verbose mode. A failure in one endpoint candidate should not necessarily terminate the entire discovery process.

## 26. Logging

The project should support structured and human-readable logging. Log levels:

- DEBUG.
- INFO.
- WARNING.
- ERROR.
- CRITICAL.

Default console output should remain readable and focused. Verbose mode may show:

- Request decisions.
- Endpoint candidates.
- Detection signals.
- Parsing steps.
- Scoring decisions.
- Query generation decisions.
- Retry behavior.
- AI integration status.

Secrets and sensitive values must not be logged.

## 27. Project architecture

The project should use a modular layered architecture. Conceptual layers:

```text
CLI
    ↓
Application services
    ↓
Domain models and rules
    ↓
Infrastructure adapters
```

### CLI layer

Responsible for:

- Commands.
- Options.
- Input validation.
- Console rendering.
- Exit codes.

### Application layer

Responsible for:

- Coordinating workflows.
- Running discovery.
- Running introspection.
- Running analysis.
- Running query generation.
- Running safe execution.
- Building reports.

### Domain layer

Responsible for:

- Models.
- Rules.
- Scoring.
- Classification.
- Safety decisions.
- Evidence semantics.

### Infrastructure layer

Responsible for:

- HTTPX integration.
- File access.
- Configuration loading.
- Report serialization.
- Ollama integration.
- Time and system services.

Core domain logic must not depend directly on Typer, Rich or HTTPX.

## 28. Proposed repository structure

```text
gqlsleuth/
│
├── .github/
│   └── workflows/
│
├── .vscode/
│
├── config/
│
├── docs/
│   └── ARCHITECTURE.md
│
├── examples/
│
├── src/
│   └── gqlsleuth/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli/
│       ├── application/
│       ├── domain/
│       ├── infrastructure/
│       ├── discovery/
│       ├── graphql/
│       ├── rules/
│       ├── reporting/
│       └── ai/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
├── AGENTS.md
├── CHANGELOG.md
├── LICENSE
├── README.md
├── pyproject.toml
└── uv.lock
```

This structure is a target architecture. Directories and modules should only be created when required by the current development phase. The repository should not be filled with unnecessary empty files.

## 29. Technology stack

- **Language:** Python 3.13
- **Project and dependency management:** uv
- **CLI:** Typer, Rich
- **Data validation and configuration:** Pydantic, pydantic-settings
- **HTTP:** HTTPX
- **GraphQL:** graphql-core
- **Reporting:** Jinja2
- **JWT analysis:** PyJWT
- **Rules and configuration files:** PyYAML
- **Testing and quality:** pytest, pytest-cov, Ruff, mypy
- **Optional local AI:** Ollama, Qwen3 8B

Dependencies should be added only when required by the implementation phase.

## 30. Testing strategy

The project should prioritize unit testing. Tests must not depend on external public targets.

Network-related tests should use:

- Mocked HTTP transports.
- Local fixtures.
- Controlled test servers.
- Recorded non-sensitive responses when appropriate.

Important test areas include:

- URL normalization.
- Endpoint candidate generation.
- GraphQL confirmation signals.
- Introspection response handling.
- Schema parsing.
- Type unwrapping.
- Operation classification.
- Security scoring.
- Minimal query generation.
- Depth limiting.
- Safe-mode restrictions.
- Active-mode authorization checks.
- Report serialization.
- Configuration precedence.
- Error mapping.

Integration tests should verify complete local workflows without contacting real external systems.

## 31. Code quality requirements

All production code should:

- Use type hints.
- Have clear responsibilities.
- Prefer small cohesive functions and classes.
- Avoid unnecessary global state.
- Avoid duplicated networking logic.
- Avoid business logic inside CLI commands.
- Use meaningful names.
- Include docstrings where they add value.
- Handle expected errors explicitly.
- Preserve backward compatibility where practical.
- Remain readable to contributors.

The project should pass:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

The exact commands may be refined as the project configuration evolves.

## 32. Security requirements

GQLSleuth itself must follow secure development practices. Requirements include:

- No secrets committed to the repository.
- TLS verification enabled by default.
- Conservative timeout and concurrency defaults.
- No mutation execution in safe mode.
- Explicit authorization acknowledgement for active mode.
- No arbitrary shell execution.
- No unsafe deserialization.
- Controlled file paths.
- Maximum response size.
- Maximum query depth.
- Clear separation between generated suggestions and executed operations.
- No automatic transmission of scan data to external AI providers.
- Local AI disabled by default.
- Dependencies kept minimal and reviewed.

## 33. Performance considerations

The initial priority is correctness and safety rather than maximum speed. The tool should still avoid unnecessary work.

Possible controls include:

- Limited concurrency.
- Request deduplication.
- Endpoint candidate deduplication.
- Schema caching during a scan.
- Depth limits.
- Response size limits.
- Configurable request timeout.
- Controlled retry policies.
- Avoidance of repeated identical introspection requests.

Discovery should not generate excessive traffic.

## 34. Development roadmap

### Phase 0 — Project scaffold

Deliverables:

- Python package structure.
- Basic Typer CLI.
- Rich console output.
- Version command.
- Placeholder scan command.
- Project metadata.
- Development dependencies.
- Ruff configuration.
- mypy configuration.
- pytest configuration.
- Initial tests.
- CI workflow.
- README.
- License.
- AGENTS.md.
- ARCHITECTURE.md.

No network requests, GraphQL logic or AI integration.

### Phase 1 — Configuration and core models

Deliverables:

- Application settings.
- CLI configuration mapping.
- Target model.
- Scan mode model.
- Evidence model.
- Result models.
- Base exceptions.
- Configuration and model tests.

Phase 1 accepts SAFE and ACTIVE configuration values, but it performs no scanning, network
requests, authorization gating or active behavior. SAFE remains the default. The initial
implementation accepts configuration only from the CLI and built-in defaults; environment
variables and configuration files are deferred until configuration needs grow.

### Phase 2 — HTTP layer

Deliverables:

- Central HTTP client.
- Request and response models.
- Timeout handling.
- Redirect handling.
- TLS settings.
- Proxy settings.
- Header support.
- Response size limits.
- Mocked tests.

### Phase 3 — Endpoint discovery

Deliverables:

- Bundled GraphQL path wordlist.
- URL normalization.
- Candidate generation.
- Candidate probing.
- Deduplication.
- Discovery evidence.
- Unit and integration tests.

The initial implementation probes candidates sequentially with GET, retains all HTTP status
responses, isolates transport failures per candidate, and stops before GraphQL confirmation.

### Phase 4 — GraphQL detection

Deliverables:

- Minimal GraphQL probes.
- `__typename` probe.
- GraphQL response signal analysis.
- Confidence scoring.
- Detection evidence.
- False-positive handling.
- Tests using mocked responses.

The initial implementation reuses Phase 3 GET responses, sends at most one static `__typename`
POST for an inconclusive candidate, and preserves both discovery and confirmation evidence.

### Phase 5 — Introspection

Deliverables:

- Introspection availability test.
- Full schema retrieval.
- Introspection result models.
- Authentication and denial handling.
- Raw response evidence options.
- Tests.

The initial implementation introspects only confirmed or probable GraphQL endpoints, uses a
minimal `__schema` availability query before full retrieval, preserves raw HTTP responses, and
classifies denials, invalid responses, endpoint errors, and network failures independently.

### Phase 6 — Schema parsing

Deliverables:

- GraphQL schema parser.
- Internal schema models.
- Root operation detection.
- Type unwrapping.
- Field and argument representation.
- Schema summary.
- Tests using schema fixtures.

The initial implementation validates retained Phase 5 responses with `graphql-core`, maps them
to project-owned immutable models, excludes `__*` system types from application summaries, and
isolates malformed-schema failures per endpoint. The parser performs no additional network
requests; its project-owned schema result is the input to Phase 7.

### Phase 7 — Rules and prioritization

Deliverables:

- Rule format.
- Keyword rules.
- Operation classification.
- Priority scoring.
- Explanations for scores.
- Configurable YAML rules.
- Tests.

The initial implementation loads a bundled validated YAML rule set with package-safe resources,
normalizes schema identifiers and descriptions into exact tokens, and inspects each Query and
Mutation root field plus one direct level of input/output relationships. Rules contribute once
per operation, retain all match locations, and accumulate into YAML-defined interest thresholds.
It produces ordered project-owned analysis models and `INTERESTING_OPERATION` evidence only for
non-zero review candidates. The CLI shows the top ten candidates with explanations while the
structured result retains every analyzed root operation. This phase performs no additional HTTP
requests, query generation, operation execution, or vulnerability confirmation.

### Phase 8 — Query generation

Deliverables:

- Minimal field selection.
- Required argument detection.
- Placeholder generation.
- Variable generation.
- Depth limiting.
- Recursive type protection.
- Query rendering.
- Tests.

### Phase 9 — Safe execution

Deliverables:

- Read-only operation validation.
- Safe query execution.
- Request and response evidence.
- Execution limits.
- CLI integration.
- Tests.

### Phase 10 — Active mode

Deliverables:

- Active-mode authorization gate.
- Mutation identification.
- Mutation preview.
- Confirmation controls.
- Controlled execution.
- Active evidence labels.
- Safety tests.

This phase must only begin after safe mode is stable.

### Phase 11 — Reports

Deliverables:

- JSON report.
- Markdown report.
- HTML report.
- Report templates.
- Scan summary.
- Evidence sections.
- Manual review recommendations.
- Tests.

### Phase 12 — AI assistance

Deliverables:

- Ollama adapter.
- Qwen3 8B configuration.
- Structured prompts that exclude secrets.
- Schema prioritization.
- Operation explanations.
- Report summaries.
- Clear AI labeling.
- Graceful fallback when Ollama is unavailable.
- Tests using mocked model responses.

The deterministic scanner must remain fully operational without AI.

## 35. MVP definition

The first meaningful MVP should be able to:

- Accept a base URL or direct endpoint.
- Discover common GraphQL endpoint paths.
- Confirm probable GraphQL behavior.
- Test introspection.
- Retrieve and parse an available schema.
- List queries and mutations.
- Prioritize security-relevant operations.
- Generate minimal read-only queries.
- Execute selected safe queries.
- Preserve structured evidence.
- Generate a JSON or Markdown report.
- Operate without AI.
- Prevent mutation execution in safe mode.

The MVP does not require active mutation testing or AI integration.

## 36. Future possibilities

Potential future improvements include:

- Custom endpoint wordlists.
- JavaScript endpoint extraction.
- Authentication profiles.
- Anonymous versus authenticated comparisons.
- User versus administrator comparisons.
- Authorization differential analysis.
- Batch query analysis.
- Alias abuse detection.
- Query depth and complexity analysis.
- Rate-limit observation.
- GraphQL subscription support.
- File upload operation analysis.
- JWT inspection.
- Federation support.
- Apollo-specific checks.
- GraphQL over WebSocket.
- Burp Suite integration.
- SARIF output.
- Plugin system.
- Custom rule packs.
- External asset discovery integrations.
- Docker distribution.
- PyPI publication.
- Web interface.
- Collaborative reporting.
- CI/CD security testing mode.

These features are outside the initial scope and must not be implemented prematurely.

## 37. Key design decisions

### Deterministic engine first

The core scanner must work without AI.

### AI as an assistant

AI may interpret and prioritize but must not become the source of truth.

### Safe by default

Read-only behavior is the default. Active functionality requires explicit authorization.

### Evidence over claims

The tool should preserve what it observed and avoid unsupported vulnerability declarations.

### Modular architecture

HTTP, GraphQL parsing, rules, reporting, AI and CLI concerns must remain separated.

### Incremental implementation

Only the current roadmap phase should be implemented at a given time.

### Professional reporting

Results should be understandable by both technical reviewers and security stakeholders.

### Authorized testing only

The project must consistently communicate its intended lawful and ethical use.

## 38. Success criteria

GQLSleuth will be considered successful when it can reduce the time required to move from an unknown application URL to a prioritized and documented view of its GraphQL attack surface.

A successful result should help a tester answer:

- Is GraphQL present?
- Where is the endpoint?
- Is introspection available?
- What operations are exposed?
- Which operations deserve attention first?
- What valid minimal queries can be generated?
- What was actually observed?
- What requires manual validation?
- What actions were performed in safe or active mode?

The final tool should demonstrate both cybersecurity knowledge and professional software engineering practices.
