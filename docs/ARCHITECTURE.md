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
gqlsleuth scan https://example.com/graphql --mode active
```

Selecting `--mode active` explicitly acknowledges entry into active capabilities for an
authorized target. No Mutation executes without explicit selection and one final batch
confirmation. There is no `--authorized` flag or automatic-confirmation option.

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

It requires explicit `--mode active` selection:

```bash
gqlsleuth scan https://example.com/graphql --mode active
```

Phase 10 supports controlled Mutation execution after the complete existing safe Query workflow.
ACTIVE alone executes zero Mutations. SAFE never generates Mutation documents, enters Mutation
selection/confirmation UI, executes Mutations, or creates Mutation execution evidence.

Even in active mode, the tool must:

- Block clearly destructive primary Mutation-name action tokens with no override.
- Show the operation before executing it.
- Require explicit individual-index batch selection and one final confirmation, default NO.
- Preserve the exact request and response as evidence.
- Apply request limits and timeouts.
- Clearly label active results in reports.

There are no per-Mutation confirmation prompts. Non-interactive stdin never prompts, selects,
or confirms: previews are retained, a clear message is printed, and zero Mutations execute.
The hard limit is five attempted Mutation requests per scan. Subscriptions remain out of scope.

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
ACTIVE only: Query-Shape preview → explicit selection → default-NO confirmation → bounded probes
    ↓
ACTIVE only: Mutation generation → validation → safety classification → preview
    ↓
ACTIVE only: explicit batch selection → one final confirmation → sequential execution
    ↓
Evidence collection
    ↓
Optional AI-assisted interpretation of the completed result
    ↓
Report generation (deterministic facts plus optional labeled AI interpretation)
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

Discovery GET probes default to an eight-second per-request timeout (an explicit Phase 14
`--timeout` overrides this). The preferred candidate is requested
alone first. In the complete scan workflow, Phase 4 immediately analyzes and, when needed, probes
that result before additional discovery begins. If it reaches `CONFIRMED` or `PROBABLE`, remaining
candidates are never requested or represented in results. Otherwise, the remaining candidates are
probed with a synchronous pool of at most four workers. Completion order does not affect the
stable candidate, result, or evidence order, and one candidate failure does not stop the others.

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

`CONFIRMED` and `PROBABLE` GET results require no duplicate request. When Phase 3 retained an
HTTP response, `POSSIBLE` and `NOT_DETECTED` results receive one fallback POST to the same
candidate with the static JSON body `{"query": "query { __typename }"}`. When the discovery GET
failed with a normalized transport error and produced no HTTP response, Phase 4 does not repeat
the unavailable request as a POST. The failure remains represented and processing continues with
other candidates. The final confidence is the stronger explicit classification from the GET and
POST analyses. A normalized POST failure is retained for that candidate and does not stop later
candidates. No introspection fields or arbitrary operations are sent during Phase 4.

The preferred candidate is fully classified before concurrent GET discovery begins for remaining
paths. A final preferred-candidate classification of `CONFIRMED` or `PROBABLE`, whether obtained
from its retained GET or single fallback POST, ends discovery early. `POSSIBLE`, `NOT_DETECTED`,
or an unavailable preferred GET continues with the remaining candidates. An unavailable GET does
not itself trigger a fallback POST.

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
uses this client for safe GET-only endpoint candidate probes. Discovery uses bounded synchronous
concurrency; retries, rate limiting, and caching remain unimplemented.

The Phase 2 defaults are:

- TLS verification enabled.
- Redirects enabled.
- Maximum redirects set to 5.
- Timeout set to 10 seconds (discovery GET overrides this to 8 seconds).
- Maximum response body set to 5 MiB.
- No proxy.
- Environment-derived HTTP configuration disabled with `trust_env=False`.
- User-Agent set to `GQLSleuth/<current version>`.

Without an explicit timeout, the normal ten-second client timeout remains in effect for Phase 4
fallback POST requests and all Phase 5 minimal/full introspection requests. Only Phase 3 discovery GET requests override it with
the shorter eight-second timeout.

Phase 14 exposes the existing target HTTP adapter through repeated `--header` / `-H`,
`--timeout`, `--proxy`, and `--verify-tls` / `--no-verify-tls`. The application input mapper
builds one immutable `HttpClientSettings` value and passes it through the existing scan entry
points and ACTIVE execution. Existing client lifetimes remain; there is no phase-specific
header merging, new credential-validation request, or duplication of networking logic.

An explicit finite positive timeout sets both normal and discovery timeouts; omission retains
10/8 seconds. TLS verification stays enabled unless explicitly disabled, with one CLI warning
and no insecure retry. Only explicit HTTP(S) proxy origins are accepted (optional credentials
and port, no path except `/`, query, or fragment). SOCKS requires no new dependency because it
is not supported. `trust_env=False` remains authoritative; there is no environment/config-file
discovery. None of these settings affect the separate local Ollama adapter.

Custom headers split at the first colon; name/value boundary spaces and tabs are trimmed.
HTTP token names and ASCII text values are validated; CR/LF, other controls except internal
horizontal tabs, empty names, and missing separators fail before scanning. Errors identify
the argument number without echoing its value. Duplicate names retain separate fields in
supplied order rather than being comma-joined. Explicit User-Agent overrides the default.
Scanner-owned request fields take precedence case-insensitively; HTTPX supplies JSON POST
Content-Type and body length, ignoring supplied Content-Type on those requests. Custom Host,
Content-Length, Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Proxy-Authorization,
TE, Trailer, and Upgrade are rejected as transport-controlled fields.

The centralized adapter scopes supplied headers to the original request origin (scheme, host,
port) with per-request redirect state, safe for concurrent discovery. Same-origin redirects
retain authentication, including explicit Cookies. Crossing origins strips supplied headers
and credentials for the rest of that redirect chain, including redirects back; it never
reapplies them to unrelated destinations. HTTPX retains ownership of redirects, method/body
handling, and limits. Offline tests verify arbitrary API-key/custom header canaries as well
as Authorization/Cookie behavior; HTTPX's default Authorization stripping alone is insufficient.

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
substrings. Each bundled rule explicitly declares whether it applies to primary operation
surfaces, input surfaces, output/context surfaces, or a combination. Functional-purpose rules,
including authentication, authorization, password management, account recovery, administrative
functionality, and user management, require primary or input evidence. Output context may support
data-oriented categories such as tokens and sessions, personal information, secrets and
credentials, files and downloads, billing, configuration, debugging, internal functionality,
and reporting. Accepting a password or passcode is classified as credential handling; password
management requires an explicit action such as reset, change, update, forgot, or recover on a
primary operation surface. Generic `flag` fields do not imply configuration, while explicit
feature-flag terminology may still match. A rule contributes its weight at most once per operation
while retaining every matched keyword and surface location for explanation. Different rules
contribute independently.
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
query {
  currentUser {
    id
    username
  }
}
```

For operations with required arguments:

```graphql
query ($id: ID!) {
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

The initial Phase 8 implementation consumes only the project-owned Phase 6 schema and Phase 7
operation-analysis results and sends no HTTP requests. It attempts generation for every actual
Query-root field, normally omits optional arguments and non-null arguments with defaults, and creates
variables for outer-non-null arguments without defaults. Operations are anonymous and do not
use `operationName`.

Built-in placeholders default to `"test"` for String, `"1"` for ID, `1` for Int, `1.0` for Float, and
`false` for Boolean. Enum generation chooses the alphabetically first non-deprecated value, lists
contain one recursively generated item, and input objects contain required fields only. Custom
scalars receive the conservative string `"test"` plus a manual-adjustment note. Cyclic required
input objects produce an isolated generation failure.

For collection Queries only, generation may additionally populate one recognized schema quantity
bound with `1`. The shared pure `graphql/collection_schema.py` inspection serves Phase 8 and
Phase 16: direct composite lists or one high-signal page/connection wrapper, exact normalized
`first`, `last`, `limit`, `take`, `size`, `pageSize`, `perPage`, `maxResults` names, and cycle-safe
breadth-first input inspection capped at three input-object levels. Generation requires a
non-list `Int` leaf reached through non-list input objects, populating only its path plus required
siblings. It tries controls in deterministic discovery order and retains the original generation
if none can be safely populated. Required business arguments remain intact. It does not inject
optional bounds for Mutations, auto-paginate, retry, or validate runtime enforcement. Phase 16
continues to assess schema signals independently of generated documents and response sizes.

String-only semantic placeholders use exact normalized name tuples from the existing identifier
tokenizer. Email/mail and emailAddress/mailAddress use `"test@example.com"`; password/passwd/passcode
use `"TestPass123!"`; username/userName/loginName use `"testuser"`; name/fullName/displayName use
`"Test User"`; firstName/lastName use `"Test"`/`"User"`; url/uri/website/websiteUrl/callbackUrl/redirectUrl
use `"https://example.com"`; phone/phoneNumber/telephone use `"+15555550100"`. CamelCase, PascalCase
and snake_case are supported. Unmatched names such as passwordHint retain `"test"`. Direct
arguments, lists and nested inputs use the actual leaf input name. Type semantics take precedence;
custom scalars retain their existing fallback and note. The shared Query/Mutation generator
does not infer valid target data, and placeholders may require manual adjustment.

For object results, generation prefers a direct non-deprecated scalar/enum `id` field, then the
first deterministic eligible leaf, then one minimal nested child path. Nested fields requiring
arguments are skipped. Interface and union results use `__typename`; output recursion or the
internal default selection depth of three also falls back to `__typename`, keeping the document
valid and finite. Final documents are syntax-checked with `graphql-core`. Successful artifacts
create `GENERATED_QUERY` evidence containing the exact query and placeholder variables. Failed
generation creates no successful evidence and does not stop other operations or endpoints.

The CLI shows a generation count by default; Phase 13 verbose output shows retained artifacts
and adjustment notes while structured results retain every Query outcome. Phase 8 does not generate Mutations or Subscriptions and never executes any
generated operation; execution begins only in Phase 9.

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

The initial Phase 9 implementation executes only successful Phase 8 artifacts. Before HTTP, it
verifies that artifact metadata is Query, the operation exists on the retained parsed Query root,
the document parses, contains exactly one Query and no Mutation or Subscription, and selects
exactly the expected top-level Query field. An invalid artifact is skipped without a request.

A separate conservative name-only safety rule tokenizes the primary Query field name and skips
exact action tokens including `create`, `update`, `delete`, `remove`, `burn`, `write`, `set`,
`change`, `reset`, `revoke`, `invalidate`, `logout`, `upload`, `import`, `send`, `trigger`,
`execute`, and `consume`. It does not inspect arguments or return fields and does not reuse Phase 7
interest scoring. Matching Query operations are retained as `SKIPPED_SAFETY`.

Eligible artifacts are executed sequentially in existing Phase 7 priority order, with a hard
internal maximum of 20 requests per scan. Remaining safe artifacts become `SKIPPED_LIMIT` and are
never requested. Each execution sends exactly one POST through the centralized HTTP client using
`{"query": "...", "variables": {...}}`, without `operationName`, retries, batching, or
concurrency.

Statuses are `SUCCESS` for GraphQL JSON containing `data` without non-empty interpretable errors,
`GRAPHQL_ERROR` for GraphQL-shaped errors (including partial data), `HTTP_ERROR` for HTTP 4xx/5xx
without interpretable GraphQL errors, `INVALID_RESPONSE` for non-error non-GraphQL responses,
`NETWORK_FAILURE` for normalized transport failures, plus the two skipped statuses above. One
result never stops later eligible operations.

Every attempted request creates `QUERY_EXECUTION` evidence retaining the POST method, exact query
and variables, HTTP response status/headers/body/duration when available, normalized transport
failure details, and the associated classification and review priority. Skipped operations create
no fabricated HTTP evidence. Execution results are observations, not vulnerability confirmation.
SAFE and ACTIVE use the same Query-only behavior through Phase 9.

### 17.1 Controlled active Mutation execution (Phase 10)

The application API separates local preparation from selected execution:

```python
safe_result = run_safe_execution_scan(target, mode=ScanMode.ACTIVE)
preview = prepare_active_mutations(safe_result)
# CLI renders previews, reads explicit indices, renders the exact selected batch,
# and asks one final confirmation, default NO.
result = execute_selected_mutations(
    preview,
    selected_indices=selected_indices,
    confirmed=confirmed,
)
```

`ActiveMutationPreviewResult` composes the complete `SafeExecutionScanResult` with ordered
`MutationPreview` candidates. Each candidate contains a `MutationGenerationResult`, decision,
and reason. Query and Mutation generation results share the project-owned
`OperationGenerationResult` representation: Phase 7 analysis (including endpoint), exact
document in `query_text`, exact variables, manual-adjustment notes, and optional generation
failure. No earlier scan data is flattened or duplicated.

Generation uses the shared Phase 8 input-placeholder, required-argument, minimal-output,
recursion, depth-limit, and syntax-validation implementation. The existing `generate_query`
API remains Query-only; `generate_mutation` accepts Mutation metadata and resolves the actual
parsed Mutation root. Mutation operations are anonymous. Optional/default arguments stay omitted,
custom scalars retain manual-adjustment warnings, and one generation failure does not stop others.
Preparation makes no HTTP requests and returns no candidates in SAFE mode.

Defensive validation independently checks metadata kind, retained Mutation-root membership,
GraphQL syntax, exactly one operation of type Mutation with no Query or Subscription, and
exactly one top-level field matching the expected Mutation. Named Mutations and top-level aliases
are rejected. Query and Mutation validation share these structural checks without weakening
Phase 9. Execution revalidates artifacts and their retained Phase 7 metadata instead of trusting
preview eligibility flags; forged, duplicate, or inconsistent candidates never execute.

Safety uses only exact tokens in the primary Mutation field name. The blocked action tokens are
`delete`, `remove`, `destroy`, `purge`, `drop`, `wipe`, `erase`, `burn`, and `truncate`. Existing
camelCase/PascalCase/snake_case/kebab-case tokenization is reused, with no arbitrary substring
matches. Arguments, output fields, and Phase 7 interest scores do not determine safety.
`createUser`, `updateProfile`, and `setPreference` can remain executable; `deleteUser` and
`purgeAuditLog` cannot. There is no destructive-operation override.

The CLI previews all candidates, showing blocked/failed reasons. Executable previews include
endpoint, name, priority, categories, exact Mutation, variables, and adjustment warnings. Selection
accepts comma-separated individual executable indices only, with no default, `all`, wildcard,
or ranges. Duplicates are deduplicated. Invalid or blocked indices cause a concise error and
another selection attempt. Enter selects none. At most five unique candidates can be selected
in the CLI. After showing the exact selected batch, one final `[y/N]` confirmation authorizes it.
Cancellation or declining executes none; non-interactive input is never consumed for approval.

`ActiveExecutionScanResult` composes the preview with selection indices, strict Boolean
confirmation state, ordered `MutationExecutionResult` decisions, and actual execution evidence.
Decisions include `EXECUTABLE`, `BLOCKED_SAFETY`, `GENERATION_FAILED`, `INVALID_ARTIFACT`,
`NOT_SELECTED`, `DECLINED`, `MODE_DISABLED`, `SKIPPED_LIMIT`, and `EXECUTED`. Response status is
separate and reuses `QueryExecutionStatus` and the exact Phase 9 classifier. `data: null` without
interpretable non-empty errors remains `SUCCESS`; partial data plus errors is `GRAPHQL_ERROR`.

The application independently enforces ACTIVE mode, selection, strict `confirmed=True`, current
validity/safety, and at most five attempted requests. Selected candidates run in retained Phase 7
order regardless of index-input order. Unknown indices raise a controlled project exception;
blocked/invalid selections stay structured non-execution decisions. Only attempted requests count,
and excess valid selections are `SKIPPED_LIMIT`. Execution is sequential, one POST per Mutation
with `query` and `variables` only, through the existing synchronous `HttpClient`. TLS, timeout,
redirects, size limits, and normalized failures are preserved. There are no retries, concurrency,
GraphQL batching, aliases, `operationName`, pagination, or semantic placeholder retries.

Only attempted requests create `MutationExecutionEvidence` with type `MUTATION_EXECUTION` and
mode ACTIVE. It retains the exact document/variables, endpoint, POST method, request timestamp,
HTTP status/headers/body when available, duration (including transport failures), normalized error,
response classification, and composed Phase 7 analysis (priority, categories, score). All prior
Phase 3–9 evidence remains intact. Other decisions create no fabricated execution evidence.
Phase 13.1 displays bounded attempted Mutation responses in default console output and Query
responses with verbose output. Mutation success is execution evidence, never
automatically a vulnerability, Finding, authorization bypass, or proof of impact.

## 18. Authentication support

Phase 14 supports one user-supplied authentication/request context per scan:

```bash
gqlsleuth scan https://example.com/graphql --header "Authorization: Bearer TOKEN"
gqlsleuth scan https://example.com/graphql -H "Cookie: session=test-session"
gqlsleuth scan https://example.com/graphql -H "X-API-Key: test-api-key" -H "X-Tenant-ID: 123"
```

Headers apply to every target stage: discovery GET, fallback confirmation POST, both
introspection requests, safe Queries, and explicitly selected/confirmed ACTIVE Mutations.
This also applies to direct endpoints. No `--token` or separate User-Agent option is added.

The tool never obtains credentials, logs in, refreshes tokens, reads browser cookies, or performs
OAuth/OIDC flows automatically. Phase 15 adds generic named SAFE contexts below; it does not
infer identities or roles. SAFE and ACTIVE safety gates, validation, limits, and classifications
are unchanged.

Custom header values and proxy credentials are excluded from console/configuration errors and
are hidden in settings representations. They are not added to human reports or AI context.
There is no generic redaction subsystem. Existing canonical evidence does not record request
headers or target HTTP settings; Phase 14 does not add or remove evidence fields. Canonical JSON
still preserves exact variables and observed response headers/bodies, which may contain secrets
or echoed request configuration. Handle all reports securely as potentially sensitive pentest
artifacts; existing human-response sensitivity warnings remain applicable.

### Named contexts and differential authorization review (Phase 15)

GraphQL does not prescribe an authentication mechanism. `--auth-context LABEL[=NAME: VALUE]`
is repeatable and supports 2–3 unique user-defined, case-sensitive labels in first-seen order.
Names contain 1–64 ASCII letters/digits/dots/underscores/hyphens and start with a letter or digit.
The first `=` separates the label; repeated names accumulate headers through the existing Phase 14
first-colon parser. A bare label contributes no headers and never clears accumulated headers.
Bearer, Cookie, API key, tenant, and proprietary headers are examples; none receives role semantics.
No fixed names, hierarchy, JWT claims, or automatic authentication acquisition are inferred.

The CLI rejects fewer than two/more than three unique labels, invalid syntax, `--header` mixed
with contexts, ACTIVE mode, and `--ai` before starting work. Common timeout/proxy/TLS settings
are validated as usual. The application also enforces SAFE, valid context counts, independent
validated settings, and no common headers. Each context gets a distinct immutable settings value
and fresh clients through `run_safe_execution_scan`; no cookie jar or header state is reused across
contexts. The normal 20-Query attempt limit applies independently to each SAFE scan.

`DifferentialScanResult` composes ordered `ContextScanResult` objects (label plus the complete
existing `SafeExecutionScanResult`, or a controlled failure code) and `ContextPairReview` objects.
Settings and header values are not part of this result. A normalized failure in one context
does not cancel later contexts. The existing per-context evidence remains unchanged.

After scanning, `compare_context_scans` performs local symmetric comparisons for every unique pair
in input order. Matching uses exact candidate URLs and parsed root-field names, without consulting
response bodies. Candidate categories are `ENDPOINT_ACCESS_DIFFERENCE` (recorded GraphQL
confidence/HTTP outcome), `INTROSPECTION_DIFFERENCE`, `OPERATION_VISIBILITY_DIFFERENCE` (Query and
Mutation roots only), and `EXECUTION_OUTCOME_DIFFERENCE` (existing Query classification, attempt
state, HTTP status). Source evidence IDs belong to the respective named result; comparisons
create no HTTP evidence and send zero requests.

Visibility is compared only when both parsed schemas exist. Missing endpoint probes (including
preferred-endpoint short circuit), unavailable introspection/schema data, and missing execution
results produce explicit limitations, not fabricated absence. Different generated documents or
placeholder variables are flagged as non-equivalent requests. No variables are altered, retried,
or guessed. Subscriptions, Mutation generation/execution, returned business-data comparison,
ownership inference, ID enumeration, and BOLA/IDOR automation are outside this phase.

All differences are authorization review candidates requiring manual validation against intended
application policy. They may be legitimate behavior. GraphQL errors retain their existing
classification and may be due to placeholders, validation, business input, or other server logic;
they are never promoted to authorization weaknesses or Findings. Names imply no privilege order.

Console output provides structural context summaries and at most ten candidates by default;
verbose output shows all candidates and limitations. `DifferentialReportContext` wraps one
existing report projection per named scan plus pair results for canonical JSON. Dedicated human
sections show structural context facts, safe Query statuses, candidate observations, and source
evidence links; they do not render response bodies, raw error messages, or HTTP configuration.
This is a presentation projection, not redaction: JSON preserves the normal per-context evidence.
Safety Notice remains the final Markdown/HTML section. Differential AI is not implemented and
Ollama receives no requests or contexts; single-context AI remains unchanged.

`tests/fixtures/phase15_target.py` supplies a loopback-only manual target and a shared MockTransport
response fixture. `uv run python tests/fixtures/phase15_target.py --smoke` runs the complete local
three-context SAFE scan and writes reports without real credentials or public targets. Fixture
labels are test cases only and never become production role logic.

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

Phase 11 implements opt-in JSON, Markdown, and standalone HTML reports after the existing scan.
Reporting performs no network requests, GraphQL operations, response reclassification, or new
security decisions. It consumes project-owned results, never console text or Rich output.

```text
SafeExecutionScanResult | ActiveExecutionScanResult
    → application.reporting.generate_reports
    → reporting.builder.build_report → ReportContext
    → JSON renderer / shared human sections + Jinja2 templates
    → reporting.output.write_reports
```

`ReportContext` is a dedicated snapshot rather than a flattened copy of the complete scan graph.
It composes endpoint summaries, original Phase 7 review candidates, generated operation artifacts,
execution projections linked to existing evidence IDs, optional ACTIVE state, and retained evidence.
It includes schema version, GQLSleuth version, UTC generation timestamp, target/mode, deterministic
counts, detection confidence/signals/reasons, introspection status, schema and operation-analysis
summaries, generation failures/manual-adjustment notes, execution statuses/errors, observed
limitations, deterministic recommendations, and an authorized-use safety notice. Review candidates
retain their existing Phase 7 order, categories, scores, reasons, and matched rules.

JSON is canonical UTF-8, pretty printed with stable field names and `report_schema_version: 1`.
The same context serializes deterministically, including exact GraphQL documents/variables and
structured request/response evidence. Byte-valued bodies use explicit lossless base64 objects
(`encoding` and `data`); enums, timestamps, and IDs use JSON-compatible values. No graphql-core or
HTTPX objects, Python repr strings, full parsed-schema graph, or CLI formatting are serialized.
Existing evidence is preserved without adding redaction or silently discarding execution errors.

Markdown and HTML share a human presentation model for overview/counts, discovery, introspection,
schema summaries, security-review candidates, generated Queries, safe execution, optional ACTIVE
analysis, evidence counts, errors/limitations, recommendations, and safety notice. They show exact
generated Queries and attempted Query/Mutation requests in code blocks with variables. Phase 13.1
adds bounded observed response bodies, classification, HTTP status, and duration when available.
HTML uses native collapsible `details` sections; Markdown uses Response subsections and safe code
fences. Skipped/unselected operations have no response section. Network failures explicitly retain
the absence of an HTTP response. Canonical JSON and execution evidence remain lossless and unchanged.
Package-loaded Jinja2 templates work independently of the current directory. HTML uses
default escaping, semantic headings/tables/code blocks, minimal embedded CSS, and no external
resources or JavaScript. Markdown escapes untrusted prose and protects code-block delimiters.

`presentation/responses.py` supplies a small shared human-response formatter with
`MAX_HUMAN_RESPONSE_BODY_BYTES = 64 * 1024`. It bounds both the raw UTF-8 prefix and formatted output,
pretty-prints complete bounded valid JSON deterministically, displays non-JSON text, and identifies
binary/unrenderable content. Truncated views state that full bytes remain in canonical JSON evidence.
Presentation parsing never reclassifies execution, removes response fields, changes evidence IDs,
or alters authoritative bytes. Human reports may contain application data and must be handled as
potentially sensitive pentest artifacts. No redaction subsystem is added; raw responses remain
excluded from the unchanged AI allowlist.

ACTIVE reports distinguish candidates, generation outcomes, `BLOCKED_SAFETY` and reasons,
selection, final batch confirmation, non-execution decisions, and attempted outcomes. Only
existing `MUTATION_EXECUTION` / `QUERY_EXECUTION` evidence establishes actual attempted requests.
Missing execution evidence is reported as a limitation rather than fabricated. SAFE has no
active-analysis section and never implies Mutation execution.

Recommendations depend only on recorded priorities/categories, manual-adjustment notes, GraphQL
errors, safety blocks, and introspection/schema/transport failures. Review priority is interest,
never vulnerability severity. Enabled introspection and execution success are not vulnerability
findings or proof of exploitability. Phase 11 introduces no Finding models or AI interpretation.
Reports state that testing requires authorization and results require professional validation.

The CLI accepts repeated or comma-separated `--format` / `-f` values (`json`, `markdown`, `html`)
and an optional output-directory `--output` / `-o`. Phase 13 normalizes whitespace, rejects empty
or unknown entries before scanning, and deduplicates formats in first-occurrence order.
The default directory is `./gqlsleuth-reports`; no format means no report writes. `--output`
without a format is an input error. Duplicate formats produce one file each. The filesystem layer
creates directories and normalizes the target host into a safe filename with a UTC timestamp,
such as `gqlsleuth-example.com-20260908-231500.html`. Exclusive creation prevents overwrites;
collisions use deterministic numeric suffixes (`-2`, `-3`, ...). `ReportingError` normalizes
serialization, template, and filesystem failures without modifying the completed scan result.
The CLI only parses options, invokes the reporting service, and displays paths or concise errors.

## 22. Optional AI assistance

Phase 12 implements local, optional interpretation with `scan --ai`. Without the flag, no AI
request or interpretation is created, and Ollama/model availability is irrelevant. The sole
provider is the user's existing Ollama service at `http://127.0.0.1:11434`, using `qwen3:8b`.
Installation and model downloads are user-managed; GQLSleuth never installs, pulls, runs shell
commands, or exposes cloud providers, remote endpoint configuration, API keys, or model management.

The application flow is strictly one-way:

```text
Completed SafeExecutionScanResult | ActiveExecutionScanResult
    → application.ai_assistance.interpret_completed_scan
    → ai.context.build_ai_context → AIContext
    → infrastructure.ollama.OllamaClient (one local POST /api/chat)
    → validated AIInterpretationResult
    → CLI and optional reports
```

In ACTIVE, AI begins only after previews, selection, final confirmation, and any controlled
Mutation execution have finished. No interpretation can influence scanner generation, HTTP
decisions, operation selection, confirmation, safety gates, request limits/order, Phase 7
scores/priorities, execution classifications, or any later scanner action. The deterministic
engine remains authoritative. AI requests create no scanner Evidence or Findings.

`AIContext` is an explicit allowlist built directly from named project-owned result fields. It
includes mode, confirmation state, aggregate numeric schema/failure/request counts, anonymous
endpoint labels, root names, operation kind/name/base return-type name, existing Phase 7
priority/score/categories, generation/manual-adjustment flags, HTTP status, execution
classifications, and Mutation safety/selection/attempt/decision states. Query and Mutation
operations with the same field name remain independent.

It excludes URLs, all headers/authentication values, exact variables, raw request/response bodies,
arbitrary errors/reasons/stack traces, Evidence objects/payloads, raw introspection, full parsed
schemas, and schema descriptions. Generated documents are omitted because structural identifiers
are sufficient for this initial interpretation and require no review of embedded literal values.
Unsafe objects are never serialized and then redacted. There is no generic redaction subsystem.

Input has a hard maximum of 20 operations and 12,000 serialized UTF-8 bytes using the same
serialization path as the actual request. Stable Phase 7 priority/score ordering comes first;
at most ten schema summaries are retained, and byte-limit reduction removes summaries before
lower-priority operations. Identifiers must be valid GraphQL names of at most 128 characters;
otherwise they are omitted. Metadata records total/included/omitted operations, total/included
schemas, and whether context was truncated. No extra inference is made for omitted context.

The stable system prompt treats all target-derived strings as untrusted data and instructs the
model to ignore embedded instructions, use only supplied facts, distinguish interest from
severity and execution from vulnerability confirmation, and offer only non-destructive manual
review suggestions. It prohibits invented operations/evidence, unsafe testing, execution, Findings,
and scoring. Operation references must be placed in dedicated fields rather than free prose.

The adapter uses Ollama's JSON-schema `format`, `stream: false`, and `think: false`, with temperature
zero, an 8192-token model context, and a 2048-token output cap. This follows the local
[Ollama structured-output API](https://docs.ollama.com/capabilities/structured-outputs).
Pydantic strictly validates the final `message.content` into `AIInterpretation`: an execution
summary, up to ten operation-review entries, and ten limitations. Each Operation Review paragraph
combines the supplied review interest, apparent role, relevant recorded outcome, reason for
attention, and a concrete, non-destructive manual review direction. Priority wording explicitly
indicates review interest (for example, HIGH-interest), never vulnerability severity.
The validated Execution Summary and model-generated Limitations remain separate.
Text fields are limited to 600 characters; unknown properties
and invalid structures are rejected. Every dedicated operation reference, including those in
summary/review/limitations, must exactly match an endpoint/kind/name identifier supplied
in the bounded input. Unknown references reject the entire response, without partial acceptance
or retry. Model-generated prose is interpretation requiring manual validation, not verified fact.

Execution totals are calculated from the complete results before input truncation. A canonical
summary distinguishes attempted requests, SUCCESS, each error classification, Query safety/limit
skips, and unexecuted Mutation candidates. Its exact text is constrained in the per-request JSON
schema and checked again after parsing; modified counts or paraphrases reject the whole response.
The summary is labeled as validated facts. Other sections remain model-generated review
interpretation, instructed to preserve per-operation classifications and never treat HTTP 200,
GraphQL errors, skips, or mere attempts as successful execution.

`AIInterpretationResult` retains model, status, timestamp, measured duration, context metadata,
optional validated interpretation, and normalized error code/message. Statuses are `SUCCESS`,
`UNAVAILABLE`, `HTTP_ERROR`, and `INVALID_RESPONSE`; when disabled, no result is produced.
Thinking/reasoning and other raw envelope metadata are ignored, never logged, displayed, or
persisted. Malformed final content is rejected rather than extracting reasoning or partial JSON.

The dedicated HTTPX adapter is independent from target `HttpClient`. It uses a fixed loopback
destination, no redirects or environment proxies, one request, no retries, a finite 180-second
inference timeout with a five-second connection timeout, and a 128 KiB response limit. Model-not-
found, connection and timeout failures, HTTP errors, malformed envelopes, incomplete generation,
and invalid final answers become controlled AI-only statuses. They cannot fail the completed
deterministic scan or prevent report generation. No new Python dependencies are required.

Reports receive the already-produced result and perform no inference themselves. Optional JSON
`ai_interpretation` is an additive field under report schema version 1, absent without `--ai`.
Markdown/HTML and CLI clearly label AI-Assisted Interpretation as model-generated interpretation,
not evidence or vulnerability confirmation. HTML escapes model text. Deterministic sections,
counts, evidence, recommendations, and Errors and Limitations are unchanged; AI failures stay
in the separate AI section. Offline tests mock Ollama and capture exact requests to prove secret
canary exclusion, bounded input, reference validation, execution isolation, and graceful fallback.

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
Through Phase 15, configuration still uses CLI plus built-in defaults only. Target headers,
timeout, TLS policy, and proxy are mapped once into immutable HTTP settings; no environment,
`.env`, global/project configuration file, or multi-source precedence is implemented.

`active` is accepted as a configuration value during Phase 1, but it does not enable active
behavior until Phase 10. Phase 10 uses explicit ACTIVE mode, Mutation selection, and one final
batch confirmation; no separate authorization flag exists.

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

Through Phase 15, `scan` and `version` are implemented. Reporting is integrated into `scan`:

```bash
gqlsleuth scan https://example.com --format json --format markdown --format html --output ./reports
```

The separate `report` command and other proposed commands remain future work. Reporting options
do not change scanning, ACTIVE selection, or final confirmation behavior.
Optional `--ai` adds one local interpretation after the completed SAFE/ACTIVE result and before
requested reports. It is disabled by default and exposes no provider/model configuration flags.

Phase 13 provides `--help` / `-h` on root and subcommands using Typer context settings. Root help
includes quick starts and common scan options; scan help remains authoritative. `--format` / `-f`
accepts repeated, comma-separated, and mixed values with stable deduplication. `--output` / `-o`
only chooses the report directory. `--verbose` / `-v` is one Boolean console-detail option.

`cli.py` owns argument normalization, application calls, controlled errors, and the existing
ACTIVE selection/confirmation interaction. `presentation/console.py` owns Rich rendering of
completed results, with a small shared semantic theme, a target/mode panel, naturally wrapping
tables, status text, GraphQL syntax highlighting, and a prominent final state-change warning.
Application/domain modules remain independent from Rich. Console rendering performs no requests
or new classifications and does not build or alter reports.

Default output shows endpoint/confidence, introspection/schema status and counts, up to ten review
candidates per retained endpoint in existing Phase 7 order, generation totals, and execution totals
with up to five noteworthy non-success outcomes. Verbose shows all retained candidates with rule
matches, generated Query artifacts/notes/failures, schema roots, and detailed execution reasons.
Default Query output omits response bodies; verbose shows bounded observed responses. Attempted
Mutation responses are displayed even by default. ACTIVE previews always retain exact executable Mutation
documents, variables, priorities/categories, adjustment warnings, blocked reasons, and the exact
selected batch before one default-NO confirmation. AI output remains separately labeled with its
existing subsections; report paths are grouped by format. No scan, evidence, safety, AI, or report
semantics change with verbosity.

Phase 13.1 groups candidate and selected-batch endpoints in first-seen order while preserving
candidate indices and within-endpoint order. Post-Mutation output shows runtime counts and
observed responses, or a concise zero-execution/declined message, without repeating preview totals.
`presentation/priorities.py` centralizes CRITICAL magenta, HIGH red, MEDIUM yellow, LOW green,
and INFORMATIONAL bright blue for tables, verbose labels, previews, and selected batches. It also
styles standalone priority words/phrases in AI console text without substring replacement or
Rich markup parsing. The AI console consumes validated structured entries directly, with neutral
bold white subsection headings, cyan references, and wrapping tables. Validated canonical summary clauses are
aligned without recalculating counts. Stored interpretation, report AI prose, AI validation,
context, and inference behavior are unchanged.

Possible options:

```text
--mode
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
- Active-mode explicit gate, selection, and batch-confirmation checks.
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
- Explicit ACTIVE-mode acknowledgement plus Mutation selection and final batch confirmation.
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

The refined implementation probes the preferred candidate first with an eight-second GET timeout,
then uses at most four synchronous workers for remaining candidates. It retains all returned HTTP
statuses, isolates transport failures per candidate, and preserves stable result/evidence order.
The complete scan coordinates immediate Phase 4 classification of the preferred result so a
confirmed or probable endpoint stops further discovery.

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
POST for an inconclusive HTTP response, and preserves both discovery and confirmation evidence.
Transport failures without an HTTP response do not trigger a POST. The normal ten-second timeout
remains on legitimate POST requests. Preferred-candidate confirmation is evaluated before
remaining discovery candidates are scheduled.

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
per operation, declare their applicable primary/input/output surfaces, retain all match locations,
and accumulate into YAML-defined interest thresholds. The bundled rule set does not score generic
`create`, `update`, or `delete` terminology: actual root structure determines Query versus
Mutation, and unmatched Mutations receive the informational state-changing fallback category.
It produces ordered project-owned analysis models and `INTERESTING_OPERATION` evidence only for
non-zero review candidates. The CLI shows the top ten candidates in a compact table; verbose output
includes all retained candidates and explanations. The structured result retains every analyzed
root operation. This phase performs no additional HTTP
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

The initial implementation generates anonymous read-only documents only for Query-root fields,
uses deterministic required-input placeholders, selects a minimal finite response path with an
internal depth limit of three, validates syntax with `graphql-core`, and preserves exact query and
variable artifacts as evidence. Per-operation failures are isolated. No generated operation is
sent or executed, and no Mutation or Subscription document is generated.

### Phase 9 — Safe execution

Deliverables:

- Read-only operation validation.
- Safe query execution.
- Request and response evidence.
- Execution limits.
- CLI integration.
- Tests.

The initial implementation defensively revalidates generated artifacts, conservatively skips
obviously side-effecting Query names, and sequentially executes no more than 20 Query operations.
It classifies GraphQL, HTTP, invalid-response, and normalized network outcomes independently,
preserves exact request/response evidence for attempted operations, and isolates failures. It
never executes Mutations or Subscriptions; the Query stage remains identical in SAFE and ACTIVE.

### Phase 10 — Active mode

Deliverables:

- Active-mode explicit gate.
- Mutation identification.
- Shared minimal Mutation generation and defensive validation.
- Deterministic destructive-name safety classification.
- Mutation preview.
- Explicit batch selection and one final confirmation, default NO.
- Sequential execution with a five-request hard limit.
- Active evidence labels.
- Safety tests.

Implemented after the stable Phase 9 workflow, which remains unchanged. ACTIVE alone never
executes Mutations. Non-interactive scans retain previews and execute zero Mutations. Actual
Mutation execution tests are offline; public smoke tests use previews and select none. Reporting,
Finding generation, authentication-context comparisons, and AI remain outside Phase 10.

### Phase 11 — Reports

Implemented:

- Dedicated report context built from SAFE or ACTIVE structured results without new requests.
- Canonical versioned JSON preserving exact artifacts and existing execution/evidence facts.
- Markdown and standalone escaped HTML using shared human sections and package-loaded Jinja2.
- Deterministic summaries, evidence counts, observed limitations, and manual-review recommendations.
- Separate Mutation generation, safety, selection, confirmation, and execution reporting states.
- Opt-in repeated `scan --format` options, output directories, safe filenames, and no overwrites.
- Controlled reporting errors and offline report/CLI regression tests.

Reporting creates no Findings, vulnerability severities, AI summaries, or new security decisions.
Optional AI interpretations are produced separately by Phase 12 and passed into reporting.

### Phase 12 — AI assistance

Implemented:

- Opt-in `--ai`, after the complete deterministic SAFE/ACTIVE workflow and before reports.
- Fixed local Ollama adapter using installed `qwen3:8b`, with one bounded structured inference.
- Explicit allowlisted context, maximum 20 operations and 12,000 serialized UTF-8 bytes.
- Strict typed output and supplied-operation reference validation across all sections.
- Separate AI interpretation/status models, with no Evidence or Findings.
- Ignored thinking/reasoning metadata and escaped, clearly labeled CLI/report presentation.
- Non-fatal connection, timeout, model-not-found, HTTP, and invalid-response handling.
- Offline privacy-canary, boundary, failure, reporting, and SAFE/ACTIVE regression tests.

AI cannot control the scanner. No installation/download automation, remote providers, generic
redaction, tool calls, feedback loops, or future-roadmap features are implemented.

### Phase 13 — CLI & Console UX Overhaul

Implemented:

- Root/scan help aliases, concise quick starts, and common scan options in root help.
- `-f` / `--format`: repeated, comma-separated, and mixed formats, trimming and stable deduplication.
- Controlled errors for empty/unknown formats and output directories without formats.
- `-o` / `--output` for directories; independent `-v` / `--verbose` for detailed console output.
- Compact default Rich summaries and detailed verbose output in a dedicated console presentation layer.
- Complete ACTIVE previews/selected batches and unchanged explicit selection/default-NO confirmation.
- Separate labeled AI subsections and grouped report paths, preserving existing result semantics.
- Offline CLI parsing, rendering, narrow-terminal, ACTIVE/AI, and report-equivalence regression tests.

No new dependencies, scanner requests, generation/execution behavior, scores, evidence, AI context,
AI validation, report semantics, or future-roadmap capabilities are introduced.

### Phase 13.1 — Execution Evidence & Console Presentation Polish

Implemented:

- Shared bounded human response formatting for attempted Queries and Mutations.
- Exact requests/variables and observed response details in Markdown and collapsible HTML.
- Verbose Query responses and default ACTIVE Mutation responses, preserving compact SAFE output.
- One 64 KiB human presentation limit, clear truncation/binary notices, and lossless canonical JSON.
- Central priority colors, grouped Mutation endpoints, and concise runtime-only Mutation summaries.
- Structured AI console tables with safe priority-term spans and consistent informational styling.
- Offline evidence, escaping, size-boundary, priority, grouping, AI immutability, and safety regressions.

No scanner, safety, execution, evidence, canonical JSON, AI context/validation/call-count, dependency,
or Phase 14+ changes are introduced.

### Phase 14 — Target HTTP Configuration & Authentication Support

Implemented:

- One immutable target HTTP settings value, mapped once from CLI plus built-in defaults.
- Repeated `-H` / `--header`, first-colon parsing, duplicate preservation, and controlled validation.
- User-supplied authentication throughout discovery, confirmation, introspection, Query and
  separately confirmed Mutation execution; one request context per scan.
- Explicit finite positive `--timeout` for all target stages, preserving omitted 8/10-second defaults.
- HTTP(S) `--proxy`, no environment proxies, and secure-default target TLS Boolean options.
- Central header merge/framing rules and same-origin/cross-origin redirect protection.
- Secret-free configuration presentation and unchanged evidence/report/AI allowlist boundaries.
- Offline propagation, redirect, transport, secret-canary, CLI, and Ollama-isolation tests.

No dependencies, credential preflights, authentication acquisition, retries, multiple identities,
configuration sources, authorization comparison, generic redaction, or Phase 15+ behavior added.

### Phase 15 — Named Authentication Contexts & Differential Authorization Review

Implemented:

- Repeatable `--auth-context LABEL[=NAME: VALUE]`, 2–3 opaque labels, ordered aggregation,
  and reuse of Phase 14 header parsing and validation.
- Independent immutable HTTP settings and complete SAFE pipelines per context, including
  isolated clients/cookie jars, common transport policy, and unchanged Query validation/limits.
- Pre-scan rejection of common headers, ACTIVE, and AI combined with named contexts.
- Local symmetric pairwise endpoint, introspection, Query/Mutation visibility, and Query outcome
  comparisons; explicit missing-data/non-equivalent-request limitations and source evidence IDs.
- Composed per-context results and conservative authorization review candidates, never Findings.
- Compact/verbose console summaries and deterministic JSON/Markdown/HTML reports, with no
  configuration values in result projections and Safety Notice last in human reports.
- Offline tests for isolation, redirects, cookies, secret canaries, failures, exact SAFE request
  equivalence, local-only comparison/reporting, and Windows console compatibility.
- A test-only loopback target and reproducible manual smoke with three contexts, six review
  candidates, 13 normal target requests, and zero Mutation requests.

No dependencies, AI differential interpretation, hierarchy inference, automatic authentication,
BOLA/IDOR automation, variable substitution, business-data comparison, or Phase 16+ behavior added.

### Phase 16 — Deterministic GraphQL Security Analysis

Implemented as a local stage in `generate_analyzed_queries`, after retained Phase 6/7 data exists
and before the unchanged generation loop. `QueryGenerationScanResult.security_review` composes
a `GraphQLSecurityReviewResult` with immutable candidates, limitations, and analyzed endpoints.
`application.security_review` coordinates retained schemas and schema-evidence references;
`rules.security_review` and `rules.schema_graph` consume project-owned metadata only. Neither
analysis module depends on HTTPX, Rich, Typer, Jinja2, or Ollama. No new Evidence or Finding type
is created. Schema artifact IDs remain source references; related `OperationAnalysis` preserves
its existing priority, categories, score, and matches without modification.

Implemented candidates and conservative rules:

- `FILE_UPLOAD_SURFACE`: exact custom scalar `Upload`; one Mutation candidate when reachable
  directly or through input objects, otherwise one declaration-only candidate. String filenames
  or upload terminology alone do not qualify; runtime support remains unverified.
- `FEDERATION_SURFACE`: `_service` returning an object `_Service` with `sdl: String`, or a list
  `_entities(representations: [_Any])` returning union `_Entity` with scalar `_Any`. Coherent
  structures qualify, not arbitrary underscore names. No vendor inference or new probes.
- `SUBSCRIPTION_SURFACE`: a retained Subscription root with exposed fields. No WebSockets or
  subscription requests are introduced.
- `OBJECT_LOOKUP_REVIEW`: top-level Query returns object/interface/union (possibly list-wrapped),
  with an argument typed `ID` and normalized final identifier token `id` or `ids`. No substring
  matching, guessed identifier scalar semantics, ID changes, ownership inference or exploitation.
- `LIST_BOUNDING_REVIEW`: top-level Query returns a composite list directly or through one
  high-signal wrapper level, with no obvious quantity control in its schema inputs. A wrapper
  qualifies through an exact normalized direct list-field name (`data`, `items`, `nodes`, `edges`,
  `results`, `records`, `entries`) OR a normalized type suffix (`Page`, `Connection`, `Collection`,
  `Results`, `ResultSet`). List elements must be objects, interfaces or unions. There is no
  arbitrary substring matching, deeper output traversal, scalar-list detection or generic
  incidental-list rule (for example, `User.roles` alone does not qualify).
  Quantity names are exactly normalized `first`, `last`, `limit`, `take`, `size`, `pageSize`,
  `perPage`, and `maxResults`, including snake-case equivalents. Position/filter/sort names
  (`page`, `offset`, `after`, `before`, `cursor`, `search`, `filter`, `sort`) alone do not qualify.
  Inspect root arguments first, then input objects breadth-first at up to three levels, counting
  the root argument's object as level one. Visit each type once at its shortest depth, with the
  existing 512-type/4,096-relationship budgets. Optional/defaulted inputs count as exposed controls;
  cycles terminate, and bounds beyond the depth limit are not inferred. One candidate per root
  Query retains up to three collection paths/element types in sorted field order and the count of
  additional qualifying fields. No candidate is created when an obvious bound is found.
  Generated Queries normally omit optional arguments, except recognized quantity bounds. Phase 16 inspects schema arguments rather than
  generated documents when determining whether an obvious bounding mechanism exists.
  Pagination/bounding arguments are schema signals only; presence does not prove runtime
  enforcement, and absence does not prove unlimited results. Runtime response sizes are never input.
- `RECURSIVE_GRAPH_REVIEW`: Query-reachable output cycle containing a list-valued composite
  edge. Object/interface fields and abstract possible-type relationships are represented. One
  deterministic cycle witness per strongly connected component avoids equivalent-path noise.
- `FLEXIBLE_SCALAR_INPUT_REVIEW`: exact `JSON`, `JSONObject`, `Any`, or `Map` used directly or
  indirectly as Query/Mutation input. Other custom scalars and output-only uses do not qualify.
- `COMPLEX_INPUT_REVIEW`: reachable recursive input-object relationships, or more than four
  required input objects starting at a required root argument. Defaults/optional edges break
  required chains; ordinary nesting alone does not qualify. One candidate per root operation.
- `DEPRECATED_SECURITY_RELEVANT_OPERATION`: deprecated root Query/Mutation with existing
  non-zero Phase 7 interest. Retains deprecation reason; no new score or priority.

Each input/output graph admits at most 512 relevant types and inspects at most 4,096 relationships
(including leaf fields). Truncation records a partial-analysis limitation. Graph construction and
iterative strongly connected component passes avoid recursive Python traversal and exponential
path enumeration. Breadth-first witnesses visit each type once; required-depth states are capped
at five input objects. Scalar paths retain the first deterministic witness per scalar and operation.
Candidate identity is type/endpoint/subject, ordered by enum declaration rank (the list above),
then exact endpoint and subject. Sets never determine output ordering. No parsed schema produces
an explicit unassessed result, not an empty-schema or absence-of-risk conclusion.

SAFE/ACTIVE and named-context scans retain identical generation, request order/counts, validation,
execution limits and classifications. Phase 15 compares the same original observations, without
new pairwise candidate-set comparisons. AI allowlisting and single-context inference counts are
unchanged; differential AI remains unsupported. Phase 16 adds zero HTTP requests and zero GraphQL
operations. It does not generate payloads, test IDOR/BOLA, perform cost/depth/DoS attacks, upload
files, execute subscriptions, or add federation/subgraph probes.

Console adds **GraphQL Security Review** for observed candidates/partial analysis, bounded to ten
rows by default, with supporting facts and manual guidance in verbose output. Canonical JSON adds
`graphql_security_review` to each existing scan report (additive schema version 1). Human reports
use shared projections, bounded supporting facts and collapsed HTML source references; named
contexts retain their own review sections. Safety Notice remains final. Review candidates are
not vulnerabilities; schema absence of a control is not proof of absent runtime enforcement.

`tests/fixtures/phase16_schema.graphql` and the metadata-only command
`uv run python tests/fixtures/phase16_smoke.py --output ./reports/phase16-smoke` demonstrate all
nine types with no target requests, no executed operations, and JSON/Markdown/HTML output.
Offline tests also compare complete SAFE/ACTIVE request sequences with local review omitted,
verify immutable evidence/Phase 7/AI input, and retain all Phase 14/15 regression checks.
Phase 16 itself adds no runtime requests or dependencies.

### Phase 17 — Controlled GraphQL Multiplicity Validation

Implemented as a separate ACTIVE-only stage after ordinary Phase 9 Queries and before the
unchanged Phase 10 Mutation interaction. SAFE and ACTIVE without explicit selection/confirmation
send no Phase 17 requests. Non-interactive scans may show previews but cannot select or confirm.
Named HTTP contexts remain SAFE-only, with no differential multiplicity analysis.

`application/multiplicity.py` composes the retained safe scan with local previews, selects one
representative attempted valid Query per endpoint (SUCCESS first, then retained Phase 7 order),
and coordinates sequential requests through the existing `HttpClient`. No new interest scoring
is introduced. Missing eligible Queries produce structured limitations.

`graphql/multiplicity.py` reuses Phase 9 structural/name-only safety validation and graphql-core
ASTs. It rejects ambiguous existing aliases, named operations and extra definitions. Alias
generation deep-copies the exact top-level field three times as `gqlsleuthAlias1` through
`gqlsleuthAlias3`, preserving arguments, directives, nested selections and variable definitions.
Batching sends two exact existing Query/variables objects in one JSON array. Neither operation
regenerates inputs, removes bounds, changes business values, or increases nested selection depth.
The central HTTP model already supports top-level JSON arrays; transport settings and redirect
credential protection remain unchanged.

Hard constants are `ALIAS_COUNT=3`, `BATCH_SIZE=2`, and `MAX_PHASE17_REQUESTS=2`. The execution
service independently checks ACTIVE, selected indices, strict `confirmed is True`, exact candidate
identity against locally rebuilt previews, and at most one attempt per type across all endpoints.
Duplicate selected indices are deduplicated; excess requests are skipped deterministically. There
are no retries, concurrency, count options, threshold searches or Mutation probes. CLI interaction
uses explicit comma-separated indices, Enter for none, and one final default-NO batch confirmation
separate from the existing Mutation batch confirmation.

Immutable project-owned preview, decision, observation and validation models live in
`domain/multiplicity.py`. Decisions distinguish NOT_SELECTED, DECLINED, MODE_DISABLED,
INVALID_ARTIFACT, SKIPPED_LIMIT and EXECUTED. Observations distinguish ACCEPTED, REJECTED,
INDETERMINATE and NETWORK_FAILURE. Alias acceptance requires a successful GraphQL-shaped data
object containing all three alias keys. Batch acceptance requires exactly two GraphQL-shaped
objects in a successful HTTP array response, allowing per-entry GraphQL errors. Explicit
shape-related rejection messages establish REJECTED; generic errors or incomplete shapes are
INDETERMINATE. No business response values are compared. Normal Phase 9/10 object-response
classification remains unchanged.

Every attempted request creates `GRAPHQL_BEHAVIOR_PROBE` evidence: ACTIVE mode, representative
operation, probe type/count, timestamp, POST, exact document/variables/JSON request, response status,
headers/bytes/duration, normalized error and observation. No unexecuted decision creates evidence.
`ActiveExecutionScanResult.multiplicity` retains the new result without duplicating the safe scan;
its evidence property preserves safe, probe and Mutation evidence in stage order.

Console previews/results use neutral headings and cyan references. An additive `multiplicity`
report field follows report schema version 1's optional-field convention, absent when irrelevant.
Markdown/HTML show Controlled GraphQL Multiplicity Validation and reuse bounded response display;
Safety Notice remains final. Evidence is canonical and lossless in JSON. These observations are
not Findings or vulnerability claims and cannot establish higher limits or global resolver policy.
AIContext, prompts, schema, validation and the single optional Ollama inference remain unchanged;
Phase 17 data is deliberately excluded. Phase 16 remains solely schema-derived.

`tests/fixtures/phase17_target.py` is a loopback-only development target sharing deterministic
accepted/rejected/ambiguous handlers with offline MockTransport tests. Its `--smoke` exercises
real local HTTP and CLI confirmation with exactly two probes per run and no Mutations. No public
target is required for testing or CI, and no runtime dependency was added.

Phase 18 adds the separate bounded depth check below. General cost/complexity analysis, rate
limiting, subscriptions, uploads and federation runtime behavior remain future possibilities.

### Phase 18 — Controlled Query Depth Validation

Implemented as an independent ACTIVE stage: Phase 9 → Phase 17 → Phase 18 → Phase 10 Mutation
interaction. Each active stage has separate selections, default-NO confirmations, results and
budgets. SAFE, unselected, declined and non-interactive scans issue no Phase 18 requests. Named
contexts remain SAFE-only. No public target is needed for development or acceptance.

`application/query_depth.py` composes a retained safe scan with immutable previews. Preparation
is local: recover the same typed cycle witnesses using the existing Phase 16 `schema_graph`
helpers, requiring a matching retained RECURSIVE_GRAPH_REVIEW subject and cycle fact. No second
recursion detector is introduced and Phase 16 candidate semantics remain unchanged. Per endpoint,
choose at most one attempted representative in retained Query order, preferring SUCCESS, with a
structurally valid GRAPHQL_ERROR attempt as a conservative fallback. Unsupported schemas, missing
retained introspection, missing attempts and unsafe paths become structured limitations.

`graphql/query_depth.py` parses and validates the baseline, rotates one retained cycle to its
closest reachable entry, and extends only that path using graphql-core AST nodes. It keeps the
original root, arguments, variables, semantic placeholders and collection bounds intact, and
ends with `__typename`. The validated native schema is rebuilt locally from already-retained
introspection via the shared Phase 6 loader; no native objects enter domain models or reports.
Phase 8's existing bound-generation helper is exposed for reuse without changing its algorithm.
New optional bounds must be a minimal input-object path ending in integer 1, without unrelated
inputs or adjustment notes. Existing bound values are never changed. Required nested business
arguments, deprecated/unsafe field names, unsupported abstract edges and new unbounded composite
lists decline generation. No HTTP occurs during preparation.

Internal constants are `MAX_PHASE18_REQUESTS=1`, `MAX_LIST_EDGES=1`, and
`MAX_CONSTRUCTED_SELECTION_DEPTH=6`. Selection depth counts every root-to-leaf field node,
including the terminal scalar/`__typename`. This is GQLSleuth's metric, not a claim about a server
framework's depth metric. The list budget conservatively counts the entire constructed document,
including a list root, and distinguishes nested list wrappers from non-null wrappers. One cycle
is traversed once: no repeated fan-out, added collection branches, progressive-depth search,
threshold discovery, retries, batching, aliases or concurrency. No additional baseline is sent.

Before any request, the application rebuilds candidates and independently verifies ACTIVE mode,
explicit valid indices, `confirmed is True`, exact candidate/source/variables/path identity and
all AST bounds. Duplicate indices are deduplicated. Selections execute in retained order, and
only one attempted request (including transport failures) consumes the separate global Phase 18
budget; remaining eligible selections are SKIPPED_LIMIT. The existing synchronous HttpClient
retains target headers, timeouts, proxy/TLS, trust_env=False, redirect protection and response
limits. No HTTP or Mutation execution logic changes are introduced.

`domain/query_depth.py` contains preview, decision, observation, execution and aggregate models.
Decisions distinguish NOT_SELECTED, DECLINED, MODE_DISABLED, INVALID_ARTIFACT, SKIPPED_LIMIT and
EXECUTED. ACCEPTED requires successful GraphQL-shaped data containing the expected root key.
REJECTED requires explicit normalized depth/complexity/query-cost rule language and no partial
data. Generic validation/business/HTTP errors and malformed responses are INDETERMINATE;
normalized transport failures are NETWORK_FAILURE. Neither observation establishes a target-wide
policy, vulnerability, absence of controls or resource-exhaustion risk. No response business
values, durations or thresholds are compared.

Only attempts produce typed GRAPHQL_BEHAVIOR_PROBE evidence with probe type
`controlled_query_depth`: ACTIVE mode, source evidence IDs, representative operation, baseline
outcome/depth, constructed depth/path/list count, exact Query/variables, POST, timestamp,
response status/headers/bytes/duration, normalized error and observation.
`ActiveExecutionScanResult.query_depth` composes this result; all previous evidence is preserved
in workflow order. JSON schema version 1 gains an optional `query_depth` field (omitted when
absent), preserving exact bytes through the existing serializer. Markdown/HTML add Controlled
Query Depth Validation and reuse bounded human response rendering only for attempts. Safety
Notice is still the final section exactly once. Console previews use neutral headings and cyan
references; verbose results include bounded responses. No Findings are created.

AIContext, prompt, schema, allowlist, transport and the single optional inference remain untouched.
Phase 18 data is excluded from AI. Phase 9, Mutation controls and the Phase 17 two-request budget
remain independent. `tests/fixtures/phase18_target.py --smoke` provides deterministic loopback
accepted/rejected/indeterminate and unselected runs; MockTransport covers network failure and
request isolation. No dependencies were added. General cost analysis, rate limits, uploads,
subscriptions and federation remain unimplemented. Phase 19's separate SAFE named-context
workflow is described below.

### Phase 19 — Nested Authorization Review

Implemented as an explicit `--nested-auth-review` extension to the SAFE named-context workflow:
independent Phase 15 scans → unchanged Phase 15 pair comparisons → optional nested review →
differential reports. It does not follow Phase 18 at runtime. The flag requires 2–3 named contexts
and preserves all existing pre-network rejection of ACTIVE, common headers and differential AI.
No flag means the previous request sequence, comparisons, evidence and serialized fields remain
unchanged. The flag itself opts in; no interactive prompts are added.

`application/nested_authorization.py` consumes retained per-context SAFE results. Runtime paths
require the root in every schema, attempted SUCCESS baselines everywhere, structurally equivalent
generated documents and type-sensitive identical variables. It sends no new baseline. Candidate
preparation and pairwise comparison perform zero HTTP. Missing schemas or unsuccessful/different
baselines produce limitations; missing introspection never implies absent nested fields.

`graphql/nested_authorization.py` performs deterministic breadth-first inspection of project-owned
Phase 6 output types. A path must include a composite relationship before its terminal scalar/enum.
The small `match_output_field` API reuses Phase 7's existing tokenizer, OUTPUT applicability,
keyword matching and bundled rules without changing root scores/priorities or allowing input-only
rules on output. Candidate ordering is root Phase 7 priority rank, strongest applicable output-rule
weight, endpoint, root name and nested path. Traversal avoids revisiting a type within a path,
stops at constructed depth five, and shares the 4,096-relationship work cap; skipped paths are
recorded. Abstract type resolution is deliberately unsupported rather than guessed.

`graphql/selection_paths.py` extracts the existing Phase 18 AST path extension and structural
helpers without changing its six-level wrapper API or behavior. Phase 19 uses the same extension,
Phase 9 Query validation and Phase 8 quantity-bound helper. One Query is constructed once from
compatible retained data and validated against every context's retained native schema. Coerced
inputs, including input defaults, must agree. Root arguments, exact variables, placeholders and
existing selections/bounds remain intact; only the selected path is added. Required nested
business inputs, deprecated/unsafe names, aliases, fragments, multiple roots and unbounded new
lists are rejected. A new optional bound must be a minimal single input path ending at integer 1,
without unrelated optional inputs. No IDs are learned or substituted.

Hard bounds are `MAX_PHASE19_CANDIDATES=3` globally, `MAX_NESTED_AUTH_SELECTION_DEPTH=5`,
`MAX_NESTED_AUTH_LIST_EDGES=1` across the complete document, and `MAX_PHASE19_REQUESTS=9`.
Each candidate/context attempt is revalidated against locally rebuilt candidates, strict explicit
enablement, SAFE source mode, context identity/count/order, exact document/variables and all
structural bounds. Execution is candidate order then context input order. Every attempt uses a
fresh HttpClient/session/cookie jar with independently validated context settings and unchanged
Phase 14 timeout/TLS/proxy/redirect/header policy. Transport failures count and do not cancel later
contexts. No retries, concurrency, fallback values, response-derived requests or new baseline.

Immutable `domain/nested_authorization.py` models retain candidate paths, matched rules, source
references, exact documents/variables, attempted state, per-context outcomes, pair reviews and
limitations. RETURNED means a non-null terminal occurrence was reached, respecting JSON presence
semantics rather than truthiness. Empty parent collections and null terminals are INDETERMINATE.
EXPLICIT_DENIAL requires HTTP 401/403 or exact normalized authorization codes/phrases applicable
to the tested path (numeric list indices are removed for structural matching). Unrelated error
paths, generic errors and ambiguous partial data are INDETERMINATE. NETWORK_FAILURE preserves
normalized transport state. Human reasons do not echo raw server messages.

Local comparison uses outcome enums and source IDs only. RETURNED ↔ EXPLICIT_DENIAL produces
NESTED_ACCESS_DIFFERENCE. Other outcome combinations never imply an authorization weakness.
Compatible missing nested paths may produce NESTED_FIELD_VISIBILITY_DIFFERENCE without requests,
linked to existing schema evidence. Contexts are symmetric opaque labels. No returned scalar
values, IDs, list sizes, hashes or ownership assumptions enter comparison logic. All candidates
require manual validation against intended policy and are not Findings.

Only attempted requests produce SAFE `NESTED_AUTHORIZATION_PROBE` evidence with context label,
root/path/rules/categories, timestamp, exact Query/variables, POST, response status/headers/bytes,
duration, normalized transport error and outcome. No outgoing authentication headers, proxy
credentials or settings objects are stored. The additive optional `nested_authorization_review`
field on DifferentialScanResult and DifferentialReportContext follows schema version 1, omitted
when disabled. JSON retains exact response evidence; console/Markdown/HTML present structural
outcomes and never raw business responses from these probes. Safety Notice remains final once.

The loopback-only `tests/fixtures/phase19_target.py` provides successful common baselines, returned,
explicitly forbidden, null/empty-list and nested-visibility cases using fake headers. Its smoke
compares opt-in and ordinary request sequences and validates all report formats. Offline tests
cover transport failure, canaries, client/cookie isolation, redirect scope, candidate tampering,
exact input preservation and prior-phase regressions. No dependencies, differential AI, Mutation
execution, role hierarchy, ownership inference, object substitution, ID enumeration or Phase 20+
functionality are introduced. Phases 16/17/18 and existing single-context AI remain independent.

### Phase 20 ? Controlled Object Authorization Validation

Implemented as a separate opt-in SAFE stage, never as a Phase 17/18 ACTIVE probe:

- Single SAFE scan ? Phase 16 local analysis ? optional object review ? optional existing AI ? reports.
- Named SAFE scans ? Phase 15 comparison ? optional Phase 19 ? optional object review ? reports.

`--object-auth-review` requires repeated `--object-auth-case` values. Anonymous-only syntax is
`OPERATION:ARGUMENT=VALUE`, with no named contexts or common headers. Exactly one bare context is
also accepted only through the Phase 20 entry point; ordinary Phase 15 cardinality remains 2?3.
Differential syntax requires `DECLARED_CONTEXT:OPERATION:ARGUMENT=VALUE` for 2?3 named contexts.
That label is an operator declaration of expected legitimate access, not discovered ownership.
Context names are opaque; only a safe `has_supplied_context_headers` Boolean describes supplied
material. Bare labels never imply server policy, and no anonymous context is added automatically.

Examples (only authorized targets and exact known IDs):

```bash
gqlsleuth scan https://example.com/graphql --object-auth-review --object-auth-case "order:id=123"
gqlsleuth scan https://example.com/graphql --auth-context public --object-auth-review --object-auth-case "order:id=123"
gqlsleuth scan https://example.com/graphql --auth-context "clienteA=Authorization: Bearer TOKEN_A" --auth-context "clienteB=Cookie: session=TOKEN_B" --auth-context public --object-auth-review --object-auth-case "clienteA:order:id=123"
```

`domain/object_authorization.py` owns frozen cases/probes/executions/candidates, outcome enums and
hard limits: `MAX_PHASE20_CASES=3`, `MAX_PHASE20_CONTEXTS=3`, `MAX_PHASE20_REQUESTS=9`. Anonymous-only
maximum is three requests. Parsing partitions on the first `=` before splitting the left side;
values remain textual, non-empty, at most 256 UTF-8 bytes, without unsafe controls. Exact duplicates
are deduplicated in first-seen order. Invalid input errors identify the argument index without
echoing IDs. CLI and application independently validate operating forms and limits before HTTP.
ACTIVE, common headers and missing flag/case combinations are rejected. Existing named-context AI
restrictions remain. Single anonymous SAFE AI remains unchanged and excludes all Phase 20 data.

`application/object_authorization.py` composes existing SAFE/DifferentialScanResult instances with
an optional `object_authorization_review`; it does not implement another scanner. Preparation is
local and requires a retained OBJECT_LOOKUP_REVIEW source, the exact Query root/argument, direct
ID or ID! input, one concrete non-list object, and direct scalar id:ID/ID! output. Nested ID inputs,
ID lists, abstract output resolution, unsafe Query names and alternate identity fields are skipped.
Missing/incompatible schemas and ambiguous endpoints produce structured limitations. An artifact
at the exact normalized target URL is preferred; otherwise one unambiguous artifact is required.
No Phase 9 placeholder SUCCESS is required; unsuccessful/null synthetic IDs are not evidence about
operator-supplied objects. Phase 16 detection, rankings and zero-request semantics are unchanged.

`graphql/object_authorization.py` builds the Query once using graphql-core AST nodes. It resolves
the selected root argument's actual variable name and changes only that value. Shared variable
uses are rejected to avoid changing unrelated inputs. Literal/omitted optional IDs receive one
deterministic collision-free variable with the schema ID type. Existing inputs, bounds, selections
and directives remain; only a missing direct id selection may be appended. Conditional identity
fields are unsupported. Final documents must validate locally against every participating schema,
including compatible effective coerced inputs, with exactly one anonymous Query/root, no aliases,
fragments, unexpected definitions or unsafe fields. No operationName is sent.

Anonymous-only execution makes one POST per eligible case. Differential execution first attempts
the operator-declared context; only TARGET_RETURNED permits remaining contexts in their original
order. The exact same Query and variables are reused. Owner denial/ambiguity/transport failure
records skipped outcomes and a limitation, never an ownership claim. Later non-owner failures do
not prevent remaining contexts. Every attempt rebuilds/compares the canonical probe, rechecks
SAFE inputs, explicit enablement, exact variables/case identity and the independent hard budget.
Clients/cookie jars are fresh per request, with immutable independent Phase 14 settings, existing
TLS/proxy/timeouts/trust_env=False and same-/cross-origin header protections. No retries or fallbacks.

TARGET_RETURNED requires a GraphQL data object with the tested root object and direct id matching
the supplied text. Only strings and integers (decimal text) qualify; Boolean, float, null, missing
or mismatched IDs are indeterminate. No whitespace, leading-zero, case or Unicode normalization.
The unchanged Phase 19 exact code/phrase/path denial helper is extracted into
`graphql/authorization_response.py`. HTTP 401/403 or unambiguous applicable authorization errors
produce EXPLICIT_DENIAL; generic errors, 404, malformed responses and ambiguous partial data remain
INDETERMINATE. Normalized transport errors are NETWORK_FAILURE. No unrelated business values,
list lengths, response sizes/hashes, roles or ownership claims enter classification.

Only confirmed matching access creates UNAUTHENTICATED_OBJECT_ACCESS for a context without supplied
headers, or CROSS_CONTEXT_OBJECT_ACCESS for an additional header-bearing context after the declared
context returns the object. Supplied material does not prove authentication. Candidates require
manual validation against intended policy; they are not Findings, BOLA/IDOR or vulnerability proof.
Denial does not establish global protection. The sole business-value comparison is returned root ID
against the exact operator input. Cases are never derived from responses, Phase 9/19 evidence or
other cases: no ID discovery, harvesting, enumeration, increment/decrement, randomization, UUID
mutation, automatic swapping, nested ID substitution, tenant/role/ownership inference or threshold
search. No Mutation, Subscription, alias, batching, concurrency, AI extension or Phase 21+ behavior.

Actual attempts alone create SAFE OBJECT_AUTHORIZATION_PROBE evidence with context labels, safe
supplied-material metadata, operator declarations, exact ID/Query/variables, source IDs, timestamp,
POST, response status/headers/bytes/duration, normalized error and identity/outcome state. Outgoing
authentication settings are not stored. Raw target responses remain potentially sensitive canonical
evidence. Optional report fields are omitted when disabled, preserving existing JSON semantics.
Human reports add Controlled Object Authorization Validation after nested review when present,
without dumping business response bodies. Safety Notice remains final exactly once. AIContext,
prompts, model calls and transport are untouched.

`tests/fixtures/phase20_target.py --smoke` provides anonymous returns/denials, shared exact objects,
enforced policy, owner-null short circuit, mismatched IDs and unrelated varying business data on
loopback only. Offline tests cover parsing, AST identity, compatibility, tampering, isolation,
redirects, lossless evidence, report privacy and separate Phase 19/20 request budgets. No dependency
is added. The default-off path retains previous scanner, request, evidence and presentation behavior.

### Phase 21 — Explicit Authorization Policy Validation

Implemented as an opt-in **local-only** stage over retained Phase 20 outcomes:

- Anonymous: normal SAFE scan → Phase 16 → optional Phase 20 → optional Phase 21 → reports.
- Named: independent SAFE scans → Phase 15 → optional Phase 19 → optional Phase 20 →
  optional Phase 21 local evaluation → reports.

**Phase 21 target request count = 0.** It creates no operations, retries or Evidence objects,
does not rerun Phase 20, and never changes/discovers identifiers. The exact target request
sequence remains identical with and without policy evaluation for identical Phase 20 inputs.
Phase 19/20 budgets and all Phase 20 classifications, candidates and source evidence stay intact.

`--auth-policy-review` requires `--object-auth-review` plus at least one repeated `--expect-deny`.
Anonymous syntax is `CASE_INDEX`; named syntax is `CASE_INDEX:CONTEXT_LABEL`. A sole bare context
also accepts the unambiguous compact index. Zero-context mode rejects explicit label syntax.
References use Phase 20's normalized 1-based case order, including existing duplicate-case
normalization, and exact case-sensitive Phase 15 labels. They do not repeat object identifiers.

```bash
gqlsleuth scan https://example.com/graphql --object-auth-review --object-auth-case "order:id=123" --auth-policy-review --expect-deny "1"
gqlsleuth scan https://example.com/graphql --auth-context "clienteA=Authorization: Bearer TOKEN_A" --auth-context "clienteB=Cookie: session=TOKEN_B" --object-auth-review --object-auth-case "clienteA:order:id=123" --auth-policy-review --expect-deny "1:clienteB"
```

`domain/authorization_policy.py` owns frozen assertion, evaluation, violation and aggregate models
and input normalization. Assertions record stable index, case reference, target context, explicit
implicit-anonymous metadata, expected DENY and OPERATOR_SUPPLIED provenance. The hard ceiling is
`MAX_PHASE21_ASSERTIONS=9`; duplicates are rejected, including equivalent decimal spellings or
compact/explicit sole-context references. Zero/negative/nondecimal indices, ranges, wildcards,
comma-packed lists, missing cases/contexts, absent required flags and DENY against the same case's
operator-declared authorized context fail before scanning. Errors never echo raw supplied values.

`application/authorization_policy.py` is a pure evaluator with only standard-library and domain
dependencies. It independently checks explicit Phase 20/21 enablement, SAFE mode, typed DENY and
OPERATOR_SUPPLIED fields, limits, normalized case/assertion identity and contradiction rules.
For each assertion it verifies retained probe/context identity, execution accounting, unique
Phase 20 evidence association, SAFE evidence type, exact case/operation/identifier, request
association and normalized outcome agreement. Differential attempts also require a valid retained
declared-context TARGET_RETURNED baseline. Missing/inconsistent retained sources produce controlled
UNRESOLVED limitations without fabricated outcomes or requests. It does not read raw response
bodies, recalculate authorization denial, regenerate documents or compare business values.

The complete local outcome matrix is:

- DENY + TARGET_RETURNED: VIOLATED, with AUTHORIZATION_POLICY_VIOLATION.
- DENY + EXPLICIT_DENIAL: SATISFIED for that exact object/context/request only.
- DENY + INDETERMINATE or NETWORK_FAILURE: UNRESOLVED.
- DENY + unattempted context (including owner short-circuit): UNRESOLVED, no evidence reference.
- Missing/inconsistent source: UNRESOLVED with a limitation, never a new target request.

Violations compose the evaluation's case identity, target context, expected policy, observed
outcome, source IDs and deterministic wording. Their precise meaning is that observed access
contradicts **operator-supplied DENY policy**, whose correctness is not independently established.
Phase 20 CROSS_CONTEXT_OBJECT_ACCESS/UNAUTHENTICATED_OBJECT_ACCESS results are preserved alongside
the stronger explicit-policy result. Neither violations nor satisfaction introduce vulnerability
Findings, taxonomy, severity, CVSS/CWE, BOLA/IDOR confirmation or global enforcement conclusions.
No ownership, privilege order, role, tenant or intended-policy inference occurs.

SAFE and differential results/report contexts gain optional `authorization_policy_validation`,
omitted from canonical JSON when disabled. Existing evidence properties remain unchanged. Policy
JSON retains references rather than copying Phase 20 response bytes. Console and shared human
report presentation add Authorization Policy Validation immediately after object review; reports
keep Safety Notice final exactly once. Authentication values/configuration and raw business bodies
are absent from policy projections. AIContext, prompts, transport, validation and call counts are
untouched, and named-context AI stays unsupported. The disabled path retains previous behavior.

`tests/fixtures/phase21_smoke.py` reuses the existing Phase 20 loopback server. Offline tests and
local smoke compare exact request sequences for anonymous, single bare, two/three named contexts,
owner short-circuit and combined Phase 19/20/21. They cover the outcome matrix, source tampering,
duplicate/owner assertions, privacy, raw-body independence and all report formats. No dependency
is added. ALLOW, policy files/DSLs, role/tenant matrices, nested-path or Mutation policies,
enumeration/harvesting, automatic remediation and Phase 22+ remain outside scope.

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
- Persisted authentication context profiles (CLI-only named contexts are implemented in Phase 15).
- Batch query analysis.
- Alias abuse detection.
- General query-cost/complexity analysis beyond the single bounded Phase 18 depth probe.
- Rate-limit observation.
- GraphQL subscription support.
- Active file-upload checks (local schema indicators are implemented in Phase 16).
- JWT inspection.
- Active federation checks (local schema indicators are implemented in Phase 16).
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
