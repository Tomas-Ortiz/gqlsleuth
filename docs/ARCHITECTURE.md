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
- For generic Mutations, require explicit individual-index batch selection and one final
  confirmation, default NO. Mutation authorization uses its own exact case and confirmation.
- Preserve the exact request and response as evidence.
- Apply request limits and timeouts.
- Clearly label active results in reports.

There are no per-Mutation confirmation prompts. Non-interactive stdin never prompts, selects,
or confirms: previews are retained, a clear message is printed, and zero Mutations execute.
Generic Mutation execution has a hard limit of five attempted requests per scan. Phase 23 has
an independent one-attempt budget and consent boundary. Phase 30 separately gates one bounded
Subscription behind `--subscription-review`, individual selection and its own default-NO consent.

Phase 22 adds a separate read-only ACTIVE capability behind `--idor-discovery` and explicit
numeric `--idor-seed` values. Its own default-NO confirmation permits only a seed baseline and
fixed immediate neighbors, with a six-request hard budget. It does not alter Mutation gates or
SAFE named-context restrictions. See the Phase 22 roadmap entry for exact bounds and semantics.

Phase 25 composes those bounded object primitives behind `--idor-review`. It adds explicit
anonymous DENY or supplied-context ALLOW-baseline/DENY-alternate policy and evidence-linked
IDOR/BOLA Findings. A narrow ACTIVE exception permits one header-bearing named context for
this capability only. Normal Phase 15 restrictions remain intact; see the Phase 25 entry.

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
ACTIVE only: Query-Depth preview → explicit selection → separate confirmation → bounded probe
    ↓
Optional ACTIVE Phase 22: supplied seeds → local preview → separate confirmation → baseline/adjacent probes
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

Before discovery, `Target.parse` rejects URL user information identified by the standard URL
parser, including username-only and percent-encoded credentials. Errors do not echo the URL or
credentials. Authentication remains explicit through `--header` or supported `--auth-context`
options; embedded credentials are never converted to headers or silently stripped to proceed.

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

Phase 23 adds optional Mutation authorization in a single ordinary HTTP context. The operator
supplies one exact Mutation/ID and asserts DENY; full request preview and independent default-NO
confirmation are mandatory. No cross-context Mutation replay is supported. See its roadmap entry.

Phase 24 adds zero-request Sensitive Input Review and a separate opt-in Sensitive Input Validation
stage. The operator supplies one exact field/value and any required target ID. Its one-attempt
budget and default-NO confirmation are independent from all other ACTIVE capabilities.

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

Phase 12 introduced local, optional interpretation with `scan --ai`; Phase 31 extends its
original operation-focused context to whole-scan security facts. Without the flag, no AI
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
operations with the same field name remain independent. Phase 31 additionally projects typed
security facts and capability coverage from retained single-context results through Phase 30
(see the dedicated roadmap entry). No differential/named-context AI is enabled.

It excludes URLs, all headers/authentication values, exact variables, raw request/response bodies,
arbitrary errors/reasons/stack traces, Evidence objects/payloads, raw introspection, full parsed
schemas, and schema descriptions. Generated documents are omitted because structural identifiers
are sufficient for this initial interpretation and require no review of embedded literal values.
Unsafe objects are never serialized and then redacted. There is no generic redaction subsystem.

Input has a hard maximum of 12 ordinary operations and 12,000 serialized UTF-8 bytes, including
metadata, using the same serializer as the outgoing request. Stable tiers retain Findings before
policy violations without Findings, scoped controls/satisfied policies, unresolved/runtime
observations, structural candidates and ordinary operations. Ordinary operations are removed
first, then schema summaries, then security facts from the lowest remaining tier. Phase 7 order
is retained within operations; at most ten schema summaries remain. Valid GraphQL names are
limited to 128 characters and paths to eight names. Metadata records complete numeric Finding/
policy totals, total/included/omitted security facts and operations, schema counts, exact byte
size and truncation. There is no second inference for omitted data.

The stable system prompt treats all target-derived strings as untrusted data and instructs the
model to ignore embedded instructions, use only supplied facts, distinguish interest from
severity and execution from vulnerability confirmation, and offer only non-destructive manual
review suggestions. It prohibits invented operations/evidence, unsafe testing, execution, Findings,
and scoring. Operation references must be placed in dedicated fields rather than free prose.

The adapter uses Ollama's JSON-schema `format`, `stream: false`, and `think: false`, with temperature
zero, an 8192-token model context, and a 2048-token output cap. This follows the local
[Ollama structured-output API](https://docs.ollama.com/capabilities/structured-outputs).
Pydantic strictly validates final `message.content` into `AIInterpretation`: the canonical
ordinary execution summary plus Security Summary, Security Fact Reviews, Security Controls
Observed, Cross-Capability Analysis, Operation Review and Limitations. The Phase 31 roadmap entry
specifies per-section bounds. Operation reviews combine supplied review interest, apparent role,
recorded outcome and non-destructive follow-up; interest never becomes severity. Only supplied
operation refs and locally generated `SF1`, `SF2`, ... references are accepted. Unknown/missing
references, duplicates within a section, extra fields and invalid structures reject the entire
response. Correlations require distinct facts from at least two capabilities. Control entries
must reference an existing explicit control or satisfied policy. Model prose remains unverified
interpretation requiring manual validation, not fact or proven causality.

Ordinary Phase 9/10 execution totals are calculated from complete results before truncation;
specialized probe outcomes remain separate security facts and coverage counts. A canonical
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
ACTIVE selection/confirmation interaction. Phase 32 renders the completed result once through
`presentation/completed.py`, using a pure shared assessment projection. The existing capability
renderers still own exact pre-send consent previews; every independent default-NO confirmation
remains in its original workflow position. Application/domain modules remain independent of Rich.

Default output presents a compact GraphQL overview, distinct security-result counts, existing
Findings, capped Manual Review, Query outcome aggregates, attempted Mutation statuses and relevant
limitations. Response bodies and detailed capability sections move to grouped verbose output.
Default AI shows Security Summary and at most three cross-capability insights; verbose and reports
retain all validated AI sections. Report paths remain grouped by format. The Phase 32 roadmap
entry defines the caps, ordering and human-report hierarchy. No scan, evidence, safety, AI-context,
request or canonical JSON semantics change with verbosity.

Phase 13.1 groups candidate and selected-batch endpoints in first-seen order while preserving
candidate indices and within-endpoint order. Post-Mutation detail retains runtime counts and
observed responses; Phase 32 moves this detail into the completed verbose assessment.
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

GraphQL detection, introspection and execution share a small response-object JSON decoder that
treats decoding, Unicode and recursion failures as uninterpretable JSON. Callers retain their
existing confidence/status precedence (including HTTP error statuses); no network failure or
Finding is inferred from invalid JSON. Schema decoding/reconstruction normalizes excessive
nesting into `SchemaParsingError`, preserving prior results. Response-size limits and raw
response/evidence retention remain unchanged. Human response formatting shows a concise notice
when nesting cannot be handled. WebSocket and Ollama retain their existing guarded JSON paths,
without retries, extra connections or inference calls. This adds no generic redaction.

Transport diagnostics present actionable URL/network/proxy/TLS guidance from normalized error
codes, without rendering supplied credentials or raw exception text. Detailed output retains
normalized technical codes. Current CLI exit behavior is preserved: completed scans exit 0 even
when no endpoint is confirmed or every target request fails; invalid input exits 2 and reporting
failures exit 1. A distinct total-operational-failure exit status is deferred to an explicit
release-contract decision, not inferred from absence of Findings or endpoint confirmation.

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
- WebSocket transport integration.
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
- **Data validation and configuration:** Pydantic
- **HTTP:** HTTPX
- **WebSocket:** websockets
- **GraphQL:** graphql-core
- **Reporting:** Jinja2
- **JWT inspection:** bounded standard-library decoding; no PyJWT dependency
- **Rules and configuration files:** PyYAML
- **Testing and quality:** pytest, pytest-cov, Ruff, mypy
- **Optional local AI:** Ollama, Qwen3 8B

Dependencies should be added only when required by the implementation phase.

### Release identity and distribution validation

`[project].version` in `pyproject.toml` is the version authority. Package `__version__`, CLI,
reports and the HTTP user agent derive the installed version through `importlib.metadata`.
Source-only imports without metadata report `0+unknown`; development environments should use
`uv sync --locked`. A version edit requires regenerating lock/install metadata, not a second
version literal in Python. The current package remains a Beta development version.

The existing uv build backend packages Python sources, YAML rules and Jinja2 templates. The
sdist also includes the changelog, release checklist and artifact-validation scripts. CI has
separate source-quality and installed-artifact jobs for Python 3.13 on Ubuntu and Windows;
passing both platforms is a release prerequisite. macOS and newer Python interpreters are not
in this test matrix, despite the package's `>=3.13` installation requirement.

The artifact gate builds fresh wheel/sdist files, checks their contents and metadata, and
rebuilds a wheel from the extracted sdist. Both wheels undergo normal dependency resolution
in independent environments outside the checkout. Installed CLI, rules and all report formats
are exercised through a mocked SAFE workflow with socket/DNS guards. Only dependency resolution
needs package-index access; ordinary pytest remains offline. No publishing is configured.
See [RELEASING.md](RELEASING.md) for the maintainer procedure.

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

Implemented originally as operation-focused assistance. Phase 31 extends its safe context and
structured output; the provider, optional behavior and single-inference boundary are retained.

Original deliverables:

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

#### Object Lookup follow-up guidance (presentation enhancement)

This is a Phase 16 UX/integration refinement, not a new roadmap phase. The pure
`presentation/object_lookup.py` projection combines existing OBJECT_LOOKUP_REVIEW candidates
with retained ParsedSchema objects. It calls `graphql.object_authorization.object_fields`, the
same structural gate used by both Phase 20 and Phase 22 through `build_object_query`. No separate
compatibility algorithm, network call, Query generation, execution or Evidence is introduced.

Each root argument is checked through that gate. Exactly one accepted argument yields a hint;
zero accepted arguments or multiple equally eligible arguments omit guidance rather than guess.
Runtime callers still explicitly choose their argument and their eligibility is unchanged.
Compatibility describes structure only: later runtime identifiers, artifact validation, context
configuration and consent remain necessary. Sequential compatibility is valid because both
current capabilities use this same gate, not because object authorization implies it in general.

The projection preserves endpoint, root/argument and rendered types, capability-named compatibility
fields and literal templates `operation:argument=<ID>`, `<CONTEXT>:operation:argument=<ID>` and
`operation:argument=<NUMERIC_ID>`. No Phase 8 value or response data is consulted. Neither valid
IDs nor numeric/sequential identity semantics, object ownership or intended policy are inferred.

Compact console output remains unchanged. Verbose review shows Suggested follow-up with short
CLI fragments and a reminder to supply known identifiers. Markdown/HTML share the same projection
and templates. Report schema version 1 gains optional `object_lookup_follow_up` metadata, omitted
when empty; named-context reports derive it separately for each retained schema. The original
candidate objects, ordering, scores, facts, evidence references and canonical review data remain
unchanged. Safety Notice stays final once; AIContext and inference counts remain unchanged.

Human terminology deliberately uses **Object authorization**, **Differential object authorization**,
**Authorization policy validation**, and **Sequential object discovery**, never roadmap numbers.
Legacy stage labels in related human notices/reasons are translated only at presentation boundaries;
canonical retained results/evidence keep their original text. README usage follows capability names;
architecture/developer history may continue using phase numbers. No Phase 23+ behavior is added.

### Phase 17 — Controlled GraphQL Multiplicity Validation

Implemented as a separate ACTIVE-only stage after ordinary Phase 9 Queries and before the
unchanged Phase 10 Mutation interaction. SAFE and ACTIVE without explicit selection/confirmation
send no Phase 17 requests. Non-interactive scans may show previews but cannot select or confirm.
Named HTTP contexts do not enter multiplicity analysis, including the separate Phase 25 exception.

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
Phase 31 projects only safe probe types/counts/outcomes into the existing single AI inference. Phase
16 remains solely schema-derived.

`tests/fixtures/phase17_target.py` is a loopback-only development target sharing deterministic
accepted/rejected/ambiguous handlers with offline MockTransport tests. Its `--smoke` exercises
real local HTTP and CLI confirmation with exactly two probes per run and no Mutations. No public
target is required for testing or CI, and no runtime dependency was added.

Phase 18 adds the separate bounded depth check below. General cost/complexity analysis remains
future work. Separate bounded rate, upload, federation and Subscription capabilities are documented
in Phases 27–30; none are part of these multiplicity probes.

### Phase 18 — Controlled Query Depth Validation

Implemented as an independent ACTIVE stage: Phase 9 → Phase 17 → Phase 18 → Phase 10 Mutation
interaction. Each active stage has separate selections, default-NO confirmations, results and
budgets. SAFE, unselected, declined and non-interactive scans issue no Phase 18 requests. Named
contexts do not enter depth validation. No public target is needed for development or acceptance.

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

Phase 31 projects only safe depth numbers/outcomes into the existing single AI inference. Phase 9,
Mutation controls and the Phase 17 two-request budget
remain independent. `tests/fixtures/phase18_target.py --smoke` provides deterministic loopback
accepted/rejected/indeterminate and unselected runs; MockTransport covers network failure and
request isolation. No dependencies were added in Phase 18. General cost analysis remains
unimplemented; bounded rate, upload, federation and Subscription capabilities are separate Phases 27–30.
Phase 19's separate SAFE named-context
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
restrictions remain. Phase 31 allows safe single-context object outcome facts in AI without IDs.

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
without dumping business response bodies. Safety Notice remains final exactly once. Phase 31
adds safe single-context operation/argument/outcome facts, never object IDs or business responses.

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
are absent from policy projections. Phase 31 projects single-context policy enums/provenance
without identifiers. Named-context AI stays unsupported and inference count stays one. The disabled
path retains previous behavior.

`tests/fixtures/phase21_smoke.py` reuses the existing Phase 20 loopback server. Offline tests and
local smoke compare exact request sequences for anonymous, single bare, two/three named contexts,
owner short-circuit and combined Phase 19/20/21. They cover the outcome matrix, source tampering,
duplicate/owner assertions, privacy, raw-body independence and all report formats. No dependency
is added. ALLOW, policy files/DSLs, role/tenant matrices, nested-path or Mutation policies,
enumeration/harvesting and automatic remediation remain outside Phase 21. Phase 22 is independent;
it never creates Phase 20 cases or Phase 21 assertions automatically.

### Phase 22 — Bounded Sequential Object Discovery

Implemented as a separate, default-off, read-only ACTIVE stage:

`Phase 9 → Phase 17 → Phase 18 → optional Phase 22 → optional Phase 23 → Phase 10 Mutations → optional AI/reports`.

CLI requires `--mode active --idor-discovery` and one or two repeated
`--idor-seed OPERATION:ARGUMENT=VALUE` entries. Names are GraphQL identifiers. Parsing splits on
the first `=`, with exactly two colon components on the left and the complete remainder as the
value. Only canonical unsigned ASCII decimals `0` or `[1-9][0-9]*`, in `0..2^63-1`, are accepted.
This range is below the 64-byte input ceiling. Whitespace is never trimmed; signs, leading zeroes,
controls, UUIDs, encoded/prefixed IDs, decimals and overflow fail before scanning with indexed
errors that do not echo values. Original seed order is preserved; no configurable range or radius.

```bash
gqlsleuth scan https://example.com/graphql --mode active --idor-discovery --idor-seed "order:id=123"
gqlsleuth scan https://example.com/graphql --mode active -H "Authorization: Bearer TOKEN" --idor-discovery --idor-seed "order:id=123"
```

`domain/sequential_discovery.py` contains frozen seed, prepared probe, execution, candidate and
aggregate models, plus dedicated ACTIVE `SequentialDiscoveryEvidence`. Hard constants are
`MAX_PHASE22_SEEDS=2`, `MAX_PHASE22_NEIGHBORS_PER_SEED=2`, `MAX_PHASE22_REQUESTS=6`,
`MAX_PHASE22_IDENTIFIER=2**63-1`, and `PHASE22_OFFSETS=(-1, 1)`. Numeric boundaries omit invalid
neighbors without wraparound: zero plans only `0,1`, the maximum only `max,max-1`.

`application/sequential_discovery.py` prepares locally from retained Phase 8/schema/Phase 16
data. Shared `application/object_lookup.py` selects the exact target artifact or one unambiguous
endpoint and its OBJECT_LOOKUP_REVIEW source, preserving Phase 20 selection semantics.
The existing pure `graphql/object_authorization.py` helpers supply structural eligibility,
AST substitution, schema/input validation and response classification. No Phase 20 scan is run
or result manufactured; only its pure helper input shape is adapted internally.

Eligibility requires one safe Query root, the requested direct ID/ID! argument, a concrete
non-list object and direct output id:ID/ID!. ID lists, nested inputs, custom scalars, abstract
type guessing, Mutation/Subscription roots and missing identity fields produce limitations.
The actual argument-to-variable mapping is recovered from the AST. Other variables, arguments,
directives, selections, placeholders and bounds remain unchanged; an omitted ID input or direct
id selection may be added by the existing helper. All variants validate locally, with one
anonymous Query/root and no aliases, fragments, batching or unexpected definitions. Preparation
sends zero requests; SAFE/disabled callers derive no adjacent identifiers.

Console previews show operator seed, root/argument, baseline and generated IDs, offsets and
maximum planned requests. ONE separate `Execute bounded sequential object discovery? [y/N]`
confirmation is required. Non-interactive runs retain previews but send zero Phase 22 requests.
Phase 17/18 and Mutation consent/budgets are independent. Declining or a normalized failure in
this stage does not cancel later Mutation interaction.

For each seed, the baseline runs first. Only TARGET_RETURNED permits seed−1 then seed+1; denial,
ambiguity or network failure skips neighbors with structured reasons and no HTTP evidence. A
neighbor failure does not cancel the other neighbor or a later seed. Every request independently
rebuilds the complete local plan and checks strict ACTIVE enablement/confirmation, typed seed
identity/count/range, exact offset/origin, endpoint/root/schema/AST/variable mapping and budget.
Caller-mutated/reordered/duplicated previews cannot select new requests. Only canonical rebuilt
requests are sent. The hard six-request budget counts attempted sends, including transport
failures, with no retries/concurrency/fallbacks. Existing centralized redirect handling is retained.

The ordinary Phase 14 HTTP context is reused (no supplied headers or repeated `-H`), with a fresh
isolated client/cookie jar per attempt. TLS, timeout, proxy, trust_env=False, response limits,
same-origin credentials and cross-origin stripping are unchanged. Supplied headers are described
as request context, not proof of authentication. Named auth contexts cannot
be combined with Phase 22. No outgoing header values or settings objects enter its result models.

Classifications are exactly Phase 20's TARGET_RETURNED / EXPLICIT_DENIAL / INDETERMINATE /
NETWORK_FAILURE. Direct returned root.id must match the requested text (JSON integers use decimal
text; Boolean, float, missing/null/mismatched IDs do not establish identity). Only that identity
and existing authorization/error shape affect outcomes, never unrelated business values, response
size, ownership, roles or tenants. Neighbor TARGET_RETURNED creates ADJACENT_OBJECT_ACCESS,
referencing its seed, generated ID/offset, context metadata and structural/baseline/attempt IDs.
This is a manual-review candidate, not BOLA/IDOR confirmation, a Finding or severity assignment.
Predictable IDs alone do not establish an authorization weakness.

Only attempted requests create `SEQUENTIAL_OBJECT_PROBE` evidence: ACTIVE, endpoint, root/argument,
operator seed, actual requested ID/offset, exact Query/variables, POST, timestamp, response status,
headers/bytes, duration, normalized transport failure, outcome and identity-match state. Canonical
response evidence remains potentially sensitive. Results retain configured seeds, exact plans,
confirmation, executions, candidates, limitations and attempted count. Active results compose this
as optional `sequential_object_discovery`, with evidence ordered after Phase 18 and before Mutations.
JSON omits the field when disabled; human reports distinguish supplied/generated IDs without raw
business-body dumps. Safety Notice remains final once. Phase 31 includes bounded counts/outcomes
in the existing AI inference, never seeds, neighbors or returned IDs.

There is no recursive expansion (a returned 124 never yields 125 from seed 123), response-ID
harvesting, random/UUID mutation, range scanning, business-value comparison or automatic follow-up.
The intentional boundary is: Phase 22 observes adjacent 124 → tester explicitly supplies 124 to a
separate SAFE Phase 20 scan → optional Phase 21 DENY assertion. Phase 21 still consumes only Phase 20.
No cross-context probing, case creation, policy creation, ownership inference or nested policies
are triggered by discovery. All prior requests, evidence ordering, console/report fields and AI
behavior remain unchanged with Phase 22 disabled.

`tests/fixtures/phase22_target.py --smoke` runs only on loopback, with fake headers and fixed
returned/null/denied/zero-boundary cases; transport failure uses MockTransport. Offline tests cover
exact request IDs/counts, no recursive expansion/harvesting, AST preservation, strict consent,
tampering, context isolation, report/privacy boundaries and prior-phase regressions. No dependency
is added. Configurable windows/ranges, enumeration/harvesting, automatic Phase 20/21 handoffs,
Mutation IDOR checks, BOLA/IDOR Findings, CWE/CVSS and severity remain outside Phase 22. Phase 23
requires its own operator-supplied case; discovered IDs are never transferred automatically.

### Phase 23 — Controlled Mutation Authorization Validation

Implemented as a separate opt-in ACTIVE capability in one ordinary current HTTP context:
`Phase 9 → Phase 17 → Phase 18 → optional Phase 22 → optional Phase 23 → Phase 10 → AI/reports`.
CLI requires `--mode active --mutation-auth-review --mutation-auth-case OPERATION:ARGUMENT=ID`.
The flag intrinsically asserts **operator-supplied DENY** for that exact Mutation/object. There is
no ALLOW policy or extra `--expect-deny` requirement. Anonymous requests and Phase 14 `-H` headers
are supported; named `--auth-context` remains SAFE-only and is rejected before scanning.

`domain/mutation_authorization.py` owns frozen cases, prepared probes, executions, evaluations,
violations and aggregate results. `MAX_PHASE23_CASES=1` and `MAX_PHASE23_REQUESTS=1` are hard limits.
The parser reuses Phase 20 textual ID validation, but rejects a second entry even if identical.
It partitions on the first `=`, requires exactly two GraphQL names on the left, and retains the
exact non-empty ID (maximum 256 UTF-8 bytes, no controls). UUID/string IDs are accepted without
numeric conversion, normalization or expansion. Invalid input errors never echo supplied values.

`application/mutation_authorization.py` prepares locally from retained Phase 7 Mutation analysis
and matching parsed/raw introspection schema. It prefers the exact target endpoint or requires one
unambiguous alternative. It calls the existing `generate_mutation`, preserving all required
business inputs and semantic/nested placeholders. The new pure Mutation eligibility adapter
requires direct ID/ID!, one concrete non-list output and direct output id:ID/ID! without arguments.
Interfaces/unions, nested/list IDs, guessed scalars and destructive primary-name tokens are
unsupported. Destructive-name classification and artifact validation reuse Phase 10 helpers.
Phase 16 sources/scores are not eligibility prerequisites and remain unchanged.

The existing Phase 20 AST identifier substitution is extracted as `substitute_object_identifier`.
Both callers preserve actual argument-to-variable mappings and reject a variable reused by
unrelated inputs. Only the selected ID changes; an omitted ID argument or output id selection may
be added. Shared schema/input validation defaults to its unchanged Query behavior; Mutation callers
explicitly request Mutation validation. One anonymous operation/root, no aliases/fragments,
no conditional Mutation selections, valid variables and exact schema membership are checked.
No regex replacement, second generator, baseline, no-op guessing or read-before-write is added.

`MutationAuthorizationSession` owns the application-level request budget, separate from immutable
report data and HTTP configuration. Its preview is copied for the CLI. Immediately before sending,
it rebuilds the entire plan, rechecks ACTIVE/explicit enablement, typed DENY case/count, schema,
generator, AST, destructive safety and exact variables (including JSON types). A missing/altered
preview, declined/non-Boolean confirmation, unavailable structure or changed retained data sends
nothing. Only the canonical rebuilt request is sent. The attempt is reserved before transport;
repeated execution calls on the session return its existing result, including after transport
failure. No caller-supplied result count can reset the budget.

The CLI shows the full exact Mutation and all variables, identifier, DENY expectation, safe
current-context description, one-request maximum and state-change warning, then asks one dedicated
`Execute mutation authorization validation? [y/N]`. Non-interactive stdin retains the preview and
never confirms. Generic Mutation and sequential-discovery approvals do not authorize this stage;
declining it still permits later generic Mutation interaction. Existing five-Mutation budget and
selection semantics remain intact and independent.

One POST contains only `query` and `variables`, using the centralized HttpClient and unchanged
Phase 14 TLS/proxy/timeout/redirect/header/cookie/size-limit protections. There is no retry, fallback,
second context, second identifier or compensating write. The existing conservative object-response
classifier supplies exact-ID and explicit-denial semantics; only TARGET_RETURNED is renamed
TARGET_MUTATION_RETURNED. JSON integers compare through decimal text; Boolean/float, missing/null,
mismatched ID, business errors, partial data and generic HTTP errors cannot confirm the object.

- DENY + TARGET_MUTATION_RETURNED → VIOLATED and MUTATION_AUTHORIZATION_POLICY_VIOLATION.
- DENY + EXPLICIT_DENIAL → SATISFIED for the exact request only.
- DENY + INDETERMINATE / NETWORK_FAILURE / no attempt → UNRESOLVED.

The violation means the Mutation returned the exact target object in a context for which the
operator asserted DENY. It does not prove every intended side effect occurred or independently
verify the policy. Manual state/policy validation is required. No ownership, identity, roles,
hierarchy, tenants, BOLA/IDOR taxonomy, vulnerability Findings, severity, CVSS or CWE are inferred.

Only actual attempts create typed ACTIVE `MUTATION_AUTHORIZATION_PROBE` evidence: endpoint, root,
argument, exact supplied ID/document/variables, DENY policy, POST, timestamp, bounded raw response
bytes/status/headers/duration, normalized transport error, outcome, ID-match state and schema source
references. The violation references this evidence, not new fabricated HTTP evidence. Unsupported,
declined and preview-only results retain limitations without request evidence. Outgoing header
values/settings never enter new domain models or presentation; exact Mutation variables are
intentionally fully visible for consent and remain potentially sensitive scan data.

Active scan/report results compose optional `mutation_authorization`, omitted from JSON when
disabled. Evidence order is previous SAFE/probes → sequential discovery → Mutation authorization
→ generic Mutation executions. Console and Markdown/HTML use capability names, preserve complete
request facts without unrelated raw business bodies, and keep Safety Notice final exactly once.
Phase 31 adds safe policy/outcome facts without IDs/variables to the same AI inference. Phase 20/21
cases/policies and Phase 22 discovered IDs are never automatically consumed.

`tests/fixtures/phase23_target.py --smoke` validates loopback success, explicit denial, business
rejection, mismatched ID, declined consent and destructive rejection, plus mocked transport failure.
Tests cover strict independent gates, one-attempt enforcement, AST/preview/schema tampering,
exact request/evidence, secret canaries, reports, AI exclusion and disabled-path regressions.
No public target or new dependency is required. Automatic Mutation follow-up hints are deferred.
Differential Mutation replay, delete testing, rollback and automatic baseline/ID handoff remain
out of scope. Phase 24 adds only explicit, single-field/value validation; no automatic field/value
exploration or role changes are introduced.

### Phase 24 — Sensitive Input Discovery and Controlled Validation

Implemented as two separate result paths: **Sensitive Input Review** (always local) and optional
ACTIVE **Sensitive Input Validation**. The runtime order is Phase 9 → Phase 17 → Phase 18 →
optional Phase 22 → optional Phase 23 → optional Phase 24 validation → generic Mutations → AI/reports.
All ACTIVE consent boundaries and budgets are independent. Earlier cases, assertions, discovered
IDs and Mutation authorization targets are never consumed automatically.

`application/sensitive_input_review.py` runs with existing local analysis/query generation,
retaining an immutable candidate tuple separately from Phase 16's unchanged candidates. It walks
only Mutation-root direct non-list input-object arguments and their direct scalar/enum leaves.
It does not traverse nested input objects, inspect runtime bodies, generate values or add HTTP
Evidence. Ordering is endpoint, operation, input argument, then leaf name. Query inputs are excluded.

`rules/sensitive_input.py` uses the entire token tuple returned by Phase 7 `normalize_terms`, with
no substring/partial-token match. The bundled exact names (including equivalent normalized casing
and separators) are:

- PRIVILEGE_CONTROL: admin, isAdmin, staff, isStaff, role, roles, permission, permissions,
  privilege, privileges, accessLevel.
- OWNERSHIP_CONTROL: ownerId, userId, accountId.
- TENANCY_CONTROL: tenantId, organizationId, orgId.
- TRUST_STATE: verified, isVerified, approved, isApproved, enabled, isEnabled.

Generic status/type/level and longer identifiers such as administratorEmail, roleDescription and
ownershipNote do not match. Categories are review concepts, not severity. Candidates retain
endpoint, Mutation, argument/leaf, rendered input type, category, deterministic reason and schema
facts. A shared pure structural gate adds only literal `<VALUE>`/`<ID>` follow-up templates when
compatible. This is a schema hint, not proof of valid runtime data or a generated executable plan.

CLI validation requires `--mode active --sensitive-input-review` with exactly one repeated-option
entry `--sensitive-input-case OPERATION:ARGUMENT.FIELD=VALUE`, optionally accompanied by
`--sensitive-input-target ARGUMENT=ID`. The flag intrinsically asserts operator-supplied DENY for
control of that exact field/value. Parsing splits on the first `=`, validates exactly one dotted
field level and GraphQL names, and reuses the object-case text bounds (non-empty, at most 256 UTF-8
bytes, no control characters). Error messages omit malformed values. Repeated cases, deeper/indexed
paths, SAFE enablement, missing flags/cases and named contexts are rejected before scanning.
Schema-dependent eligibility failures are controlled preparation limitations after schema discovery.

Initial ACTIVE validation intentionally supports **detected fields only**, with provenance
`detected_sensitive_input`; arbitrary operator-selected non-rule fields are deferred. Supported
types are Boolean (`true`/`false` only), Int (canonical signed 32-bit decimal, no -0/leading zero/+),
String and ID (exact text), and exact enum members. Float, lists, nested objects and custom scalar
inference are unsupported. The concrete non-list output must expose a direct, argument-free field
with the same name and named scalar/enum type. Nullability may differ. No mapping is guessed.

Exactly one direct root ID/ID! argument requires the operator to supply that target, even when
optional. Multiple possible ID arguments and ID-list targets are rejected; no direct ID means
no target may be supplied. A target also requires direct output id:ID/ID! without arguments.
The current destructive-name helper rejects destructive Mutations without changing generic rules.

`application/mutation_preparation.py` extracts Phase 23's existing exact-endpoint/unambiguous
Mutation selection and parsed/raw schema consistency checks, shared by both capabilities.
Both still call the current deterministic Mutation generator. The Phase 20 AST root-argument
substitution and direct-output selection helpers are shared without changing Query defaults.
`graphql/sensitive_input.py` preserves the actual input argument's variable mapping, updates just
the selected leaf, substitutes only an explicit target, and adds required confirmation selections.
Unrelated generated inputs, optional omissions, semantic placeholders and selections remain.
An omitted optional input object is supported only if the minimal inserted object validates;
the stage does not invent missing unrelated required siblings. Inline/default inputs retain their
effective schema values. Variables reused by unrelated arguments, aliases, fragments, conditional
selections, extra operations/roots and invalid input types are rejected locally.

`SensitiveInputSession` independently rebuilds the canonical plan before its one POST. It checks
ACTIVE/enablement, typed case/DENY, exact path/value/target, schema/generator/AST, output compatibility,
destructive safety, exact variables including JSON types, strict confirmation and available budget.
Prepared snapshots cannot change unrelated inputs or reset the budget. `MAX_PHASE24_CASES=1` and
`MAX_PHASE24_REQUESTS=1` are not configurable. Attempts are reserved before transport; repeated
session execution returns the retained result, including after transport failure. No alternate
field/value, baseline, re-fetch, persistence Query, rollback or second context is attempted.

The preview prints the complete final GraphQL and all variables, exact field/value/target,
operator DENY assertion, context description, one-request maximum, state-change warning and
persistence limitation. `Execute sensitive input validation? [y/N]` defaults to NO. Non-interactive
input never confirms. Declining does not cancel generic Mutation interaction and no prior consent
can authorize this stage. The centralized HttpClient retains all Phase 14 settings/credential and
redirect protections; HTTP configuration is never stored in the new result models.

Outcomes inspect only the expected root, selected output leaf and optional target identity:

- TARGET_VALUE_RETURNED requires a successful GraphQL response without non-empty errors, exact
  type-aware selected-value equality, and exact target ID match when configured.
- EXPLICIT_DENIAL reuses the existing conservative HTTP 401/403 and scoped normalized GraphQL
  authorization signal helper. Ambiguous partial data never confirms acceptance.
- INDETERMINATE includes wrong/missing ID/value, null, unsupported forms, business/validation
  errors and generic HTTP failures. NETWORK_FAILURE uses normalized transport failures.

Boolean/Int equality distinguishes JSON types; String/Enum equality is exact, and ID comparison
reuses the extracted Phase 20 exact textual/integer-JSON helper. Unrelated business values and
response size never influence decisions. DENY plus TARGET_VALUE_RETURNED produces VIOLATED and
SENSITIVE_INPUT_POLICY_VIOLATION; explicit denial is SATISFIED for that request; all other/unattempted
states are UNRESOLVED. A violation only states that the response returned the supplied value under
an operator DENY assertion. Persistence, prior value, privilege change and broader impact are not
verified. No mass-assignment/privilege-escalation classification, Findings, CWE/CVSS or severity.

Only attempts create ACTIVE `SENSITIVE_INPUT_PROBE` evidence with endpoint/Mutation/input path,
typed supplied value, optional target, exact document/variables, POST/timestamp, bounded raw response
bytes/status/headers/duration, normalized transport error, ID/value match states, outcome, DENY and
schema source references. Local detection/unsupported/declined results create no network Evidence.
Frozen capability models compose case, prepared request, execution evidence, local evaluation,
violation, consent, limitations and attempt count. Outgoing Authorization/Cookie/API-key/proxy
configuration is excluded; canonical business response data follows existing evidence semantics.

Reports add `sensitive_input_review` only when candidates exist and `sensitive_input_validation`
only when enabled. Named SAFE reports retain local review per context without ACTIVE validation.
Human output uses capability names and keeps Safety Notice final exactly once. Phase 31 includes
safe input paths/categories and policy/outcome facts, never supplied or business values. Existing
request sequences, Phase
16 semantics and all authorization/discovery behavior remain unchanged when validation is disabled.

`tests/fixtures/phase24_target.py --smoke` is loopback-only with fake headers; it covers Boolean/enum
returns, current-object Mutation, denial, business error, mismatched value/ID, declined confirmation,
destructive rejection and mocked transport failure. Offline tests cover exact matching/typing,
single-field scope, AST/preview tampering, independent consent, no exploration/read-after-write,
evidence/privacy, AI isolation, reports and prior-capability regressions. No dependency is added.
Recursive input fuzzing, automatic value guessing, enum exploration, multiple fields/
cases/requests, differential input testing, automatic ID/target handoff, rollback and persistence
verification remain out of scope.

### Phase 25 — End-to-End IDOR / BOLA Detection

Implemented as a separate opt-in ACTIVE policy workflow, composing existing object lookup and
bounded sequential primitives. It does not replace Phase 20, Phase 21 or Phase 22, manufacture
their result graphs, or transfer identifiers into Mutation Authorization/Sensitive Input Validation.

CLI requires `--mode active --idor-review --idor-seed OPERATION:ARGUMENT=VALUE`. The unchanged
Phase 22 seed parser accepts one or two canonical unsigned decimal IDs in `0..2^63-1`, preserving
input order. Fixed plans are seed, seed-1, seed+1, omitting invalid numeric neighbors without
wraparound. No larger window, radius, ranges, recursive expansion, response-derived identifiers,
UUID/random mutation, retries or concurrency exist. `--idor-review` and `--idor-discovery` are
mutually exclusive; both reuse the same bounds and six-attempt maximum.

Policy is explicit and capability-specific:

- No supplied target headers: anonymous seed and alternates are expected DENY.
- Supplied target headers: seed is an expected ALLOW baseline; alternates are expected DENY.
- Header presence selects the supplied-context policy, not proof of valid server authentication.
  There is no token inspection, authentication mechanism inference, role order or ownership model.
- Exact TARGET_RETURNED on the seed gates neighbors in both modes. Authenticated seed success
  is BASELINE_CONFIRMED only. Denied/ambiguous/failed authenticated baselines are BASELINE_UNUSABLE,
  with zero neighbors and no Finding. Anonymous denial is SATISFIED; ambiguity/failure UNRESOLVED.
- DENY + TARGET_RETURNED produces VIOLATED and a focused immutable
  OBJECT_LEVEL_AUTHORIZATION_FAILURE Finding classified IDOR / BOLA. DENY + EXPLICIT_DENIAL is
  SATISFIED. INDETERMINATE/NETWORK_FAILURE/skipped requests remain UNRESOLVED without Findings.

Findings explicitly depend on operator policy. Anonymous wording says the exact object was
returned without supplied authentication contrary to DENY. Authenticated wording says the exact
alternate object was returned under the current supplied context contrary to DENY. No ownership,
other-user identity, tenancy or independently verified business policy is claimed. Intentionally
public or legitimately shared objects invalidate the operator assumption. No severity/CVSS/CWE,
exploitability score, business-impact score or generic vulnerability hierarchy is introduced.

`map_auth_context_inputs` reuses its existing grouping/name/header validation with a narrow
`idor_review is True` + ACTIVE exception for exactly one unique header-bearing context. Repeated
entries for that label accumulate headers. Bare labels are rejected with guidance to omit the
option for anonymous testing. Mixing `-H` with named contexts remains invalid. Normal Phase 15
still requires 2–3 SAFE contexts; normal Phase 20's existing bare-context exception is unchanged.
The single named IDOR route uses immutable settings carrying only that context's headers for the
normal safe scan and IDOR probes. It creates no DifferentialScanResult, runs no pairwise analysis,
does not enter Phase 17/18 or generic Mutations, and rejects incompatible named-context stages.
Named-context AI remains rejected. Ordinary `-H` ACTIVE orchestration remains available.

`application/bounded_object.py` extracts the existing Phase 22 pure plan construction, seed
validation, fresh-client single-probe transport and baseline/request accounting. Phase 22 retains
its public preparation/execution API, evidence, decisions and classifications. Phase 25 reuses
the same `SequentialDiscoverySeed`/`SequentialDiscoveryProbe` value types and constants, without
fabricating SequentialDiscoveryResult objects. Existing `retained_object_lookup` selects the
unambiguous artifact and OBJECT_LOOKUP_REVIEW source. Existing Phase 20 `build_object_query`
enforces direct ID, safe concrete output, direct output id, native schema validation and actual
AST argument-to-variable mapping. Unrelated variables, directives, fields, placeholders and
collection bounds remain intact. No second Query generator or response classifier is introduced.

`IdorSession` owns the attempt budget and snapshots its preview. Immediately before each send it
rebuilds the complete canonical plan and compares strict enablement/ACTIVE mode, seed identity,
context metadata, ordering, offsets, document, variables (including JSON types), retained schema
and structural source. Strict `confirmed is True`, baseline eligibility and the shared remaining
budget are required. Only freshly rebuilt requests are transmitted. Caller-edited previews cannot
choose IDs or alter policy. Repeated calls on a used session return the retained result without
more HTTP. Failures consume attempts; failed neighbors do not cancel later eligible neighbors.

Preview shows context type/opaque label, operator policy, seed and planned baseline/alternate IDs,
maximum requests, returned-data notice and policy limitation. Separate default-NO
`Execute IDOR / BOLA detection?` consent cannot be substituted by any other confirmation.
Non-interactive, declined, disabled and unsupported cases add zero IDOR probes.

HTTP uses the centralized client unchanged: timeout/proxy/TLS, trust_env=False, response limits,
same-origin credentials and cross-origin stripping remain intact. Each probe has a fresh client
and cookie state. Phase 20 exact root-ID classification is reused: matching text/integer JSON can
confirm access; Boolean/float/missing/null/mismatched IDs cannot. No business-body comparisons.

Frozen project-owned models in `domain/idor.py` retain context, seeds, bounded plans, confirmation,
executions, policies, findings, limits and counts. Attempt-only `IDOR_BOLA_PROBE` evidence retains
ACTIVE, endpoint, context metadata, root/argument, seed/requested ID, offset, role, expected policy,
policy result, source references, exact Query/variables and complete existing bounded HTTP facts.
No evidence is fabricated for previews or skips. Findings reference the exact causing attempt;
authenticated Findings also reference their successful baseline. Outgoing headers/settings/proxy
credentials are never serialized into these models. No generic redaction is added.

`ActiveExecutionScanResult.idor_bola_detection` composes the result. Existing evidence ordering
is preserved, adding IDOR evidence before later Mutation capabilities when enabled. Canonical
JSON omits the field when disabled. Shared human presentation adds IDOR / BOLA Detection and
conditional IDOR / BOLA Findings, without raw business-body dumps. Safety Notice remains final
once and qualifies policy-backed Findings when this capability is present. Renderers create no
Findings or new classifications. Phase 31 projects existing IDOR Finding types, context mode and
policy outcomes, never identifiers or ownership data, within the same single inference.

`tests/fixtures/phase25_target.py --smoke` reuses the Phase 22 schema/loopback server infrastructure
with explicit test scenarios and fake headers. It covers anonymous/supplied-context success,
denial, unusable baseline, mismatched alternate ID, failed baseline/neighbor transport, zero
boundary, disabled and declined execution. Offline tests cover strict consent, forged plans,
revalidation between sends, prior workflow preservation, narrow context scope, cookie/redirect
isolation, evidence provenance, reporting, AI exclusion and secret canaries. No external target,
runtime dependency or later vulnerability family is introduced.

### Phase 26 — Authentication & Token Security

Implemented as one opt-in ACTIVE capability: `--auth-security-review`, using exactly one existing
Phase 14 `Authorization: Bearer TOKEN` header. Carrier errors are controlled and never echo values.
Opaque tokens are supported for the generic control. Named contexts are rejected for this
capability without changing Phase 15 cardinality or the narrow Phase 25 exception. No new runtime
dependency, token option, credential source or configuration system is introduced.

`rules/token_security.py` performs bounded stdlib-only, unverified JWT structural inspection.
It accepts canonical three-segment base64url JSON objects, rejects ambiguous duplicate keys and
unsupported JWS extensions, and falls back to opaque tokens. Safe metadata consists of recognized
algorithm labels (other text becomes `unrecognized`), presence-only header/claim facts and temporal
states. NumericDate requires finite, supported numeric UTC timestamps, excluding booleans and
strings. The skew is 60 seconds. Key-reference presence, absent claims and common algorithms
produce no Findings by themselves. No signing keys are fetched or verified locally.

`application/authentication.py` composes immutable project-owned Phase 26 results with the existing
Phase 9 results. Candidate order follows retained execution order. Eligibility requires an actual
SUCCESS Query, matching request/response evidence, native schema/variable validation, Phase 9 safe
artifact validation, and an unambiguous non-null result for the expected root field. The latter
does not change Phase 9's existing `data:null` SUCCESS classification. Queries with missing,
inconsistent, cross-origin or ambiguous baseline data are ineligible. There is no Query generation
or extra authenticated-baseline request.

CLI selection declares one exact Query expected to require Bearer authentication. Optional JWT
probes are selected upfront, conditional on later control denial, so the single default-NO
`Execute authentication and token security probes?` confirmation precedes every Phase 26 request.
The preview displays the exact Query/variables, operator policy, retained baseline, hidden carrier,
selected probes and maximum request count. No selection, non-interactive execution or declined
confirmation sends a Phase 26 request. Other capability confirmations cannot authorize this stage.
It runs after Phase 9 and before unrelated ACTIVE Query/object/Mutation stages.

`AuthenticationSecuritySession` owns the canonical selection, settings and three-attempt budget.
It revalidates the current retained baseline, exact request, metadata, selection, ACTIVE/enablement
gates and literal `confirmed=True` immediately before each send. Caller-edited previews cannot
supply request/token material. One mandatory Authorization-removed control executes first, retaining
every other supplied header. This is not necessarily anonymous access. Only EXPLICIT_DENIAL permits
selected JWT probes: deterministic one-character signature tampering with byte-identical original
header/payload, and `alg=none` with copied header and exact original payload plus empty signature.
An originally unsigned token needs no equivalent replay. Claims are never modified. No retries,
concurrency, alternate operations, claim fuzzing or token discovery occurs.

Fresh centralized HttpClient instances preserve all existing timeout, TLS, proxy, trust_env=False,
body limits and redirect/header protections. Generated variants cannot cross the original target
origin. Cross-origin final responses remain INDETERMINATE. Transport failures consume attempts;
the session cannot replay attempted work. Control failure/access/ambiguity skips selected variants.
A failed optional probe does not prevent a later independently eligible selected probe.

`graphql/authentication.py` reuses the existing Phase 9 classifier and exact Phase 19 authorization
error helper. Existing `NestedOutcome.RETURNED` is displayed as ACCESS_RETURNED. Null/ambiguous
states, generic GraphQL errors and non-authorization HTTP failures are INDETERMINATE. HTTP 401/403
and applicable exact authorization errors are EXPLICIT_DENIAL; normalized transport errors are
NETWORK_FAILURE. The existing DENY policy matrix is VIOLATED/SATISFIED/UNRESOLVED respectively.

Five scoped Finding conditions are supported:

- AUTHENTICATION_ENFORCEMENT_FAILURE: successful baseline and Authorization-removed access.
- JWT_SIGNATURE_VALIDATION_FAILURE: denied control and altered-signature access.
- JWT_NONE_ALGORITHM_ACCEPTED: denied control and unsigned variant access, or an already unsigned
  original token accepted in the baseline.
- EXPIRED_JWT_ACCEPTED: original token expired before baseline start beyond skew, plus denied control.
- NOT_YET_VALID_JWT_ACCEPTED: original nbf later than baseline completion plus skew, plus denied control.

The baseline request interval is reconstructed from retained evidence completion timestamp and
duration. Conservative interval edges avoid borderline temporal claims. Missing/malformed claims
never create temporal Findings. Each Finding retains endpoint, operation, condition, operator-policy
provenance and baseline/control/probe evidence references. Its exact Query/variables are retained
once in the selected candidate and actual probe evidence. No severity, CVSS/CWE, role hierarchy,
application-wide compromise or business-impact inference is added.

Only attempted requests create `AUTHENTICATION_SECURITY_PROBE` evidence, with exact Query/variables,
POST, UTC timestamp, safe JWT metadata, baseline reference, HTTP status, duration, normalized errors,
outcome and policy. Outgoing Authorization, tokens/variants, Cookie values and proxy credentials
are transient private request material, never normal Phase 26 models. This capability explicitly
withholds a whole response body containing known supplied/generated credential material, records
`response_material_withheld`, and allowlists non-credential response metadata. It introduces no
generic redaction and does not rewrite prior evidence. Normal baseline response bytes are referenced
only, not duplicated into the Phase 26 projection.

`ActiveExecutionScanResult.authentication_token_security` and the additive report field preserve
local metadata, selection, consent, attempted counts, decisions and Findings. Disabled reports omit
the field. Shared human presentation adds Authentication & Token Security and conditional
Authentication & Token Findings before the final single Safety Notice. Phase 31 projects safe
token kind/algorithm/presence/temporal enums and outcomes/Findings, never token/claim values.
The local provider and single-inference boundary are unchanged.

Offline tests use mock transports and `tests/fixtures/phase26_target.py --smoke`, a loopback-only
target with fake signing material. Coverage includes strict consent, exact replay, canonical-plan
revalidation, all probe/Finding gates, temporal boundaries, unsupported tokens, redirect/cookie
isolation, request limits, privacy canaries, CLI and reports. No external target, login flow, key
attack, OAuth/OIDC, password/account-recovery testing or future vulnerability family is implemented.

### Phase 27 — Rate Limiting & Abuse Controls

Implemented as optional `--rate-limit-review` in ACTIVE mode, with anonymous or existing `-H`
headers. Named authentication contexts and SAFE mode are rejected before scanning. Disabled
scans preserve their workflow, requests, reports and AI behavior. This is bounded validation of
one operator policy, not threshold discovery, brute force, denial-of-service testing or evasion.

`application/abuse_controls.py` builds candidates locally from actual ordinary Phase 9 Query and
generic Phase 10 Mutation execution containers, never the aggregated security-probe evidence.
It matches the exact retained request and response provenance, native schema/variables, Phase 7
metadata, parsed root, source EvidenceType and application source. It reuses existing artifact,
Query side-effect, destructive-Mutation and Phase 20 document validators. No operations are
generated for this stage. Unexecuted or unsafe Mutations never qualify. Usable SUCCESS,
GRAPHQL_ERROR (including invalid-login outcomes), and structured HTTP 401/403 error baselines
can qualify. Missing/malformed responses, transport errors, outages, cross-origin baselines and
already-observed control signals are ineligible. Baseline selection sends zero requests.

Immutable domain models compose OperationAnalysis and retain exact request material, source
evidence reference, baseline classification/status and fixed planned count. Existing authentication,
password-management, recovery and token/session categories take precedence, followed by existing
interest priority and stable Phase 7 order; there is no new score or vulnerability severity.

The CLI runs this stage after generic Mutation execution. One explicit index (Enter for none),
an exact selected preview, operator-policy declaration and one separate default-NO
`Execute rate limiting / abuse-control validation?` confirmation are required. The preview warns
that a Mutation may cause repeated side effects without rollback or deduplication. Other ACTIVE
confirmations do not authorize Phase 27. Non-interactive, declined or unselected runs send zero
repeats. All input interaction remains in the CLI.

`AbuseControlSession` owns one canonical selection and a terminal fixed budget: at most five
additional Query attempts or three additional Mutation attempts. Before every send it revalidates
enablement, ACTIVE mode, current eligible ordinary baseline, exact typed variables/document,
selection, safety and unchanged target settings. Caller-modified previews cannot expand the plan.
Literal confirmation is required; a completed or declined session cannot restart. Requests are
sequential identical POST payloads without operationName. Fresh centralized clients prevent
response Cookies from changing the next request context. Phase 14 timeouts, proxy, TLS,
trust_env=False, body limits and redirect/header stripping apply unchanged. Cross-origin final
responses are indeterminate. Network attempts consume the budget. No retries, replacement
attempts, sleeps, concurrency, additional operations, credential guesses, header/token rotation,
automatic login, threshold ramps or changed variables are supported.

`graphql/abuse_controls.py` reuses Phase 9 execution classification. Explicit signals are HTTP 429
or exact normalized GraphQL extension codes RATE_LIMITED / TOO_MANY_REQUESTS / THROTTLED,
ACCOUNT_LOCKED / USER_LOCKED, and CAPTCHA_REQUIRED / CHALLENGE_REQUIRED. Exact whole-message
fallbacks without an explicit code are: too many requests, rate limit exceeded, too many attempts,
try again later, account locked, temporarily locked, captcha required. Existing identifier
normalization handles spelling separators/case without arbitrary substring matching. Retry-After
alone, timing, body sizes/hashes and returned business data are never detection inputs.

Repeat outcomes are CONTROL_SIGNAL_OBSERVED, NO_CONTROL_SIGNAL, INDETERMINATE or NETWORK_FAILURE.
Without an explicit signal, a usable response must preserve the baseline HTTP status and execution
classification to count as NO_CONTROL_SIGNAL. A material status/shape change is indeterminate.
The first signal satisfies the policy and stops; ambiguity or transport failure stops unresolved.
Only a full consistent fixed sequence without a signal violates the operator expectation and
creates ABUSE_CONTROL_POLICY_VIOLATION. Findings reference the baseline, all actual attempts,
policy and planned/actual count, with no CVSS, CWE, severity or global-security conclusion.
Mandatory limitations explain higher thresholds/other windows were not tested, earlier scan
requests may affect server state and a signal's attempt index is not the server threshold.

Only actual attempts create ABUSE_CONTROL_PROBE evidence: exact document/variables, POST,
timestamp, duration, bounded response/status/allowlisted headers, normalized transport error,
baseline reference, execution classification, signal and operator policy reference. No evidence
is fabricated for selection, decline or unsent repeats. The existing Phase 26 privacy capture
boundary is shared in `infrastructure/probe_evidence.py`: no outgoing request-header values or
proxy credentials are persisted; a response containing known request-secret material is withheld
whole with an explicit marker. This is not generic redaction and does not rewrite prior evidence.
Exact GraphQL variables and existing baseline artifacts remain potentially sensitive.

`ActiveExecutionScanResult.rate_limiting_abuse_controls` and the optional canonical report field
retain candidates, selection, confirmation, attempt results, first-signal index, scoped Findings
and limitations. Disabled JSON omits the field. Console and human reports add Rate Limiting &
Abuse Controls and conditional Rate Limiting / Abuse-Control Findings, before the final single
Safety Notice. Phase 31 projects safe counts/control types/policy outcomes and Findings into the
same AI inference, never credentials, variables or response messages.

Offline mock tests and `tests/fixtures/phase27_target.py --smoke` cover exact replay, independent
consent, strict budgets and canonical-plan checks, prior-probe exclusion, all control classes,
invalid-login baselines, early stops, secret canaries, redirects, unchanged cookie/header context,
CLI and all reports. The loopback-only fixture uses fake inputs and no real accounts or external
target. No later vulnerability families or unbounded abuse automation are included.

### Phase 28 — File Upload Security

Implemented as opt-in ACTIVE `--file-upload-review`, requiring exactly one strict
`--upload-case OPERATION:ARGUMENT[.FIELD...]` and one `--upload-file PATH`. At most three nested
field levels follow the root argument; arrays, wildcards, ranges, alternate grammar and whitespace
normalization are unsupported. Optional `--upload-content-type` accepts a plain MIME type/subtype.
Named authentication contexts are rejected; ordinary anonymous/Phase 14 header contexts are reused.
Invalid CLI combinations and unusable/oversized local files fail before scanning.

`application/file_upload.py` composes an immutable upload plan/result and owns a terminal session.
It selects the existing retained Mutation/schema through the Phase 23/24 helper, requires retained
Phase 16 FILE_UPLOAD_SURFACE provenance for that operation, and independently resolves the exact
non-list Upload scalar path. Phase 16 semantics and zero-request analysis are unchanged. Lists,
multiple populated Upload leaves, non-Upload custom scalars and Query/Subscription roots are
unsupported. Optional unrelated Upload inputs remain absent.

Phase 10 generation supplies required business inputs, deterministic semantic placeholders and
minimal output selection. A small shared Phase 8 input-path helper uses the existing placeholder
algorithm for the selected optional path and any required siblings. No second Mutation generator
is introduced. The Phase 20 AST substitution helper recovers actual variable names, rejects shared
variables and preserves unrelated values/types. Existing anonymous single-Mutation/root, native
schema validation and destructive-name safety checks apply. No aliases, fragments, directives,
unexpected definitions or roots are accepted. The selected placeholder alone becomes null for
multipart mapping; native validation occurs on the canonical placeholder representation before
that protocol-required substitution.

`infrastructure/upload_file.py` reads only regular readable nonempty files, with a fixed 1 MiB
ceiling and at most limit+1 bytes read. MIME inference uses Python's built-in filename mappings
without platform-specific MIME overrides; fallback is application/octet-stream. Basenames are
unchanged for baseline requests; path separators, control characters and encoded separators are
rejected. Full paths and bytes remain runtime-only. Persistent metadata is basename, MIME, size
and SHA-256. The operator supplies a known-valid benign file; this is not a malware-analysis engine.

The target HTTP adapter gains only `SingleFileMultipart`: text fields and one binary file part,
restricted to POST without a JSON body. HTTPX frames the multipart boundary/content length/type;
caller Content-Type cannot override it. Logical GraphQL `operations` and `map` JSON plus file part
`0` follow the multipart convention, without operationName. Existing JSON requests are unchanged.
TLS, timeout, proxy, trust_env=False, User-Agent, custom headers, body limits, redirect limits,
same-origin credentials and cross-origin stripping remain centralized. Cross-origin final upload
responses are indeterminate. No upload-response URL or ID causes additional requests.

The ACTIVE CLI inserts File Upload Security after generic Mutation interaction and before the
existing abuse-control stage. Generic Mutation execution is not a prerequisite. A local plan
preview, explicit variant selection and one separate default-NO `Execute file upload security
validation?` confirmation are required. Enter selects baseline only; comma-separated 1/2/3 indices
are deduplicated and ordered canonically. No earlier confirmation authorizes uploads. The final
plan shows the logical request/map, safe file metadata, policies, selected probes and maximum count,
with an explicit warning about Mutation side effects and absent cleanup/rollback. Non-interactive
or declined execution adds zero uploads.

The fixed sequence is one ALLOW baseline followed, only when confirmed, by selected DENY variants:

- CONTENT_MISMATCH: identical filename/MIME, fixed benign text plus newline.
- MIME_MISMATCH: identical bytes/filename, text/plain or application/octet-stream alternate.
- EXTENSION_MISMATCH: identical bytes/MIME, safe .txt or .bin extension, no double extensions.

Maximum four attempts, sequentially, no retries or fallback. Size/hash, current schema/provenance,
generator output, destructive safety, exact variables/map, selected probes, settings and strict
confirmation are revalidated before every send against the original approved plan. Changed files
or caller-edited previews cannot supply new request material. Session completion/decline is terminal.
Failures consume attempts. A baseline rejection, ambiguity or transport failure stops all variants.
After a confirmed baseline, independently selected variants continue after an ambiguous/failed
variant, within the original budget; the failed probe is never retried.

The upload-specific classifier accepts only successful HTTP/GraphQL responses containing the
selected non-null Mutation root without nonempty errors. Explicit rejection uses HTTP 413/415
or normalized exact INVALID_FILE_TYPE, FILE_TYPE_NOT_ALLOWED, UNSUPPORTED_FILE_TYPE,
UNSUPPORTED_MEDIA_TYPE, INVALID_UPLOAD, FILE_EXTENSION_NOT_ALLOWED codes on this single-file request.
An unrelated error path never qualifies. Exact message fallback (without an explicit code) requires
the selected root or Upload input path: unsupported file type, file type not allowed, invalid file
type, unsupported media type, file extension not allowed, invalid file extension. Partial non-null
data/errors, generic authorization/business errors, null/missing roots and malformed responses
remain INDETERMINATE. Normalized transport errors are NETWORK_FAILURE. Authorization denial
semantics are not repurposed for file validation.

Baseline evaluations are BASELINE_CONFIRMED or BASELINE_UNUSABLE, with NOT_EXECUTED before attempts.
DENY variants use existing PolicyStatus: acceptance VIOLATED, explicit file rejection SATISFIED,
otherwise UNRESOLVED. FILE_UPLOAD_VALIDATION_POLICY_VIOLATION Findings require both a confirmed
baseline and an accepted selected DENY variant. They retain operation/path, subtype, operator-policy
provenance and baseline/variant evidence references. Every Finding states that application policy
was operator supplied, and persistence/retrieval/rendering/execution were not verified. No severity,
CVSS/CWE, executable-upload, stored-XSS or global-validation inference is introduced.

Only attempted requests create FILE_UPLOAD_PROBE evidence. It preserves ACTIVE mode, exact logical
document/operations/map, variable path, file metadata/hash, schema source IDs, probe/policy, timestamp,
HTTP status, bounded response/header facts, duration, normalized error and outcome/evaluation. It
does not serialize multipart boundaries, raw file bytes, full local paths or outgoing headers/settings.
The shared probe capture boundary withholds whole responses echoing known supplied file/path or
credential material and marks the omission; this is not generic redaction and does not alter prior
evidence. Remaining response artifacts may still be sensitive.

`ActiveExecutionScanResult.file_upload_security` and the optional report projection are additive;
disabled JSON omits the field. Human sections are File Upload Security and conditional File Upload
Findings, before the final single Safety Notice. Phase 31 adds safe paths, variant enums, baseline
and policy outcomes/Findings, excluding files, MIME values, hashes, variables and responses. Phase
27 consumes only ordinary
execution containers, so upload probes cannot become repetition baselines. No cross-capability
handoff, authentication change, response-derived file fetch, dangerous payload generation, filename
traversal, overwrite/polyglot/archive/size abuse or later upload family is implemented.

Tests use MockTransport and a stdlib multipart-parsing loopback fixture:
`uv run python tests/fixtures/phase28_target.py --smoke`. It handles a tiny PNG entirely in memory,
with fake headers, deterministic baseline and variant acceptance/rejection, ambiguity, exact budgets,
changed files and independent consent. No public target, real credentials or new dependency is needed.

### Phase 29 — Federation Security

Implemented as an opt-in ACTIVE capability. `--federation-review` uses existing Phase 16
`FEDERATION_SURFACE` candidates, schema evidence and retained introspection. The shared pure
`federation_surfaces` helper preserves Phase 16 detection facts and ordering; runtime compatibility
checks validate the exact fixed requests against that schema. No second name/vendor heuristic is
introduced. Preparation and canonical revalidation are local and send no requests.

The CLI requires explicit selection of one retained endpoint (including a single available endpoint)
and explicit service/entity probe indices, followed by a separate default-NO
`Execute federation security validation?` confirmation. Empty selection, non-interactive execution,
decline or disabled capability sends zero Phase 29 requests. Ordinary anonymous and Phase 14
header contexts are supported; named contexts and SAFE mode are rejected for this opt-in capability.

`domain/federation.py` owns typed candidates, plans, outcomes, policies, evidence and scoped Findings.
`graphql/federation.py` builds anonymous documents using graphql-core AST nodes and validates them
against the native retained schema. The application-owned terminal `FederationSecuritySession`
rebuilds selected canonical plans before every send and checks schema/source provenance, request
settings, strict variables, selection and its hard two-attempt budget. Caller previews cannot
introduce additional fields/types/representations or documents. A finished session cannot run again.

The service probe is exactly `query { _service { sdl } }`, without variables or operationName.
Default OBSERVE never evaluates DENY or creates a Finding. `--federation-sdl-expect-deny` explicitly
asserts DENY. SDL_RETURNED requires successful HTTP/GraphQL, no errors and nonempty String SDL;
EXPLICIT_DENIAL reuses exact authorization signals; null/empty/missing/malformed/generic-error
responses are INDETERMINATE; normalized transport failure is NETWORK_FAILURE. Semantic metadata
retains only returned state, UTF-8 byte length and SHA-256. Full SDL remains only in bounded response
evidence; it is not parsed for keys, URLs, subgraphs or further requests.

`--federation-entity-case` accepts exactly one 1024-byte UTF-8 JSON object: valid GraphQL `__typename`
and one to three flat direct string/integer/Boolean keys; no duplicate keys, floats, nulls, lists
or nested values. It carries explicit operator DENY. The typename must be a concrete retained
`_Entity` member. Keys must be direct argument-free ID/String/Int/Boolean/Enum output fields and
schema-compatible values. Int is signed 32-bit excluding bool, String and Enum use exact matching,
and ID reuses Phase 20 textual identity (`001` is distinct from `1`). Custom scalars and composite,
list, Float or argument-bearing key fields are not supported. The tool does not discover `@key`.

The entity probe uses the actual schema representations argument type, a one-element variables
array and one inline fragment selecting `__typename` plus every supplied key in deterministic
order. Successful HTTP/GraphQL without errors, a one-element non-null entity array, exact typename
and every typed key match are required for ENTITY_RETURNED. Mismatched/missing keys or typename,
wrong scalar types, unexpected array sizes and generic business errors are INDETERMINATE.
Applicable explicit authorization signals reuse the existing denial helper.

DENY plus returned SDL/entity is VIOLATED; explicit denial is SATISFIED; other outcomes UNRESOLVED.
Only those violations produce `FEDERATION_SDL_POLICY_VIOLATION` (Federation service metadata exposure)
or `FEDERATION_ENTITY_AUTHORIZATION_FAILURE` (Federation entity authorization weakness). Policies are
operator supplied and need independent validation. No ownership, tenant, role hierarchy, cross-user
policy, privacy assumption, IDOR/BOLA label, severity/CVSS/CWE or federation-wide claim is inferred.

The centralized HttpClient sends at most one service and one entity JSON POST, sequentially in that
order. Attempts include failures; one failed probe does not prevent the other selected probe. There
are no retries, concurrency, enumeration, key guessing, ID mutation, multi-representation requests,
response-derived IDs, SDL-driven follow-ups, subgraph discovery or vendor-specific checks. Existing
timeout, proxy, TLS, redirect and response bounds remain intact. Cross-origin final responses cannot
establish access; existing credential stripping and request-context response capture are reused.

Only attempted requests create `FEDERATION_SECURITY_PROBE` Evidence with ACTIVE mode, selected
endpoint/probe, Phase 16 and schema source references, exact query/variables, timestamp, POST,
bounded response/status/headers/duration, normalized error, outcome, policy and optional evaluation.
Entity keys are deliberate operator request data; outgoing auth headers and proxy credentials are
not persisted. Known credential echoes are withheld by the existing probe-specific capture boundary,
without generic redaction or changes to earlier evidence.

`ActiveExecutionScanResult.federation_security` and reporting composition are additive and omitted
from canonical JSON when disabled. The stage follows earlier independently consented active stages;
evidence ordering for those stages is preserved. Human sections are Federation Security and
conditional Federation Security Findings, always before the final single Safety Notice. Phase 31
projects safe service/entity policy facts, typename/key names and Findings, never SDL/key values.
Phase 27
continues consuming only ordinary execution containers, never federation probes.

MockTransport tests and `uv run python tests/fixtures/phase29_target.py --smoke` exercise only loopback
with fake headers: observation, DENY violations, denials, null/wrong identity, independent network
failure, exact budgets and zero-request disabled/declined/non-interactive paths. No dependency,
public target or real credentials are required. Apollo-specific functionality, query-cost analysis
and other future federation families remain out of scope. Phase 30 independently introduces bounded
Subscription/WebSocket validation.

### Phase 30 — Subscriptions & GraphQL over WebSocket Security

Implemented as an additive ACTIVE capability, disabled by default. `--subscription-review` requires
ordinary anonymous or Phase 14 header context; named authentication contexts are rejected. Dependent
options are `--subscription-expect-deny`, `--subscription-variables`, `--subscription-init-payload`
and `--subscription-ws-url`. The CLI explicitly selects one eligible retained Subscription and shows
its exact document, variables, policy, endpoint, protocol offers and bounds before the independent
**Execute subscription / WebSocket security validation? [y/N]** prompt. Non-interactive, empty,
declined and disabled paths open zero connections. Other phases' consent never authorizes Phase 30.

`graphql/subscriptions.py` validates local inputs/documents; `application/subscriptions.py` composes
the existing safe result into a terminal `SubscriptionSecuritySession`. Candidate sources are exact
retained Phase 16 `SUBSCRIPTION_SURFACE` records, rechecked against the Phase 6 parsed schema and raw
introspection. Query/Mutation fields cannot become candidates and Phase 7 interest rules are unchanged.
The shared Phase 8 field-document generator handles required inputs, semantic placeholders, minimal
selections and recursion guards. Subscription generation is local, independent per field and never
adds collection bounds. Native schema validation checks exactly one anonymous Subscription root.

Variables overrides replace only existing generated keys after selection. Native input coercion is
used for validation; original valid JSON types/values remain the transmitted request. Variables and
init inputs each accept one object, at most 4096 UTF-8 bytes, without duplicate keys or non-finite
values. Init values remain private session state and appear only in `connection_init.payload`.
No default auth keys are invented and headers are not copied into init. Public models retain only
the presence/byte count of init material. Handshake headers remain private under Phase 14 rules.

WebSocket URLs derive by http→ws / https→wss with the retained port/path/query. Explicit overrides
must match the selected HTTP credential origin (host, effective port and security scheme), with no
userinfo or fragment. No endpoint/path discovery, cross-origin forwarding or redirect following is
allowed. Origin and WebSocket negotiation headers supplied through `-H` are rejected before connect;
this phase is not Origin/CSWSH testing. The centralized `infrastructure/websocket.py` adapter uses
the synchronous `websockets` API, the only added dependency, rather than custom WebSocket framing.
It offers `graphql-transport-ws`, then `graphql-ws`, in one handshake, honors explicit HTTP(S) proxy,
TLS and headers, disables environment proxies, compression and periodic client pings, and uses a
private non-propagating logger. Unsupported/no protocol terminates without fallback or reconnect.

The modern sequence is init → ACK → subscribe (`id=1`) → next/error/complete; supported JSON pings
receive canonical empty pong responses and terminal cleanup sends complete. Legacy uses init → ACK
→ start (`id=1`) → data/error/complete, counts keepalives and cleans up with stop/connection_terminate.
Both send the exact document and variables without operationName. Hard budgets are one connection,
one selected Subscription, one start and at most one application event. Twenty inbound frames,
including transport controls/keepalives, and a maximum 1 MiB message size bound the exchange. Excess
traffic terminates as indeterminate. Handshake, ACK and first-event waits are capped at 10 seconds
each or the smaller target timeout; an 11-second socket write guard avoids an unbounded send while
allowing application receive deadlines to classify silence. Close has a one-second timeout.

Canonical schema/provenance/plan/variables/private init/settings are rebuilt and compared immediately
before connection and again after ACK before start. A changed plan or request context cannot obtain
an additional start. The session is terminal even after decline/failure; no retries, concurrency,
reconnects, multiplexing or downstream stage handoffs exist. It never triggers a Mutation/event,
enumerates subscriptions/IDs, or derives follow-ups from response data.

`EVENT_RETURNED` requires GraphQL data containing the selected root with a non-null value and no
errors. ACK alone, start alone, null, complete-before-event, malformed frames and generic errors do
not establish access. `EXPLICIT_DENIAL` requires HTTP 401/403, modern protocol close 4401/4403, or the
existing exact authorization-error classifier. Generic legacy close codes aren't promoted to denial.
`NO_EVENT_BEFORE_TIMEOUT` means no event was observed, never protection; protocol ambiguity is
`INDETERMINATE` and normalized transport failure is `NETWORK_FAILURE`.

Default OBSERVE retains observations without policy evaluation or Findings. Explicit operator DENY
plus EVENT_RETURNED is VIOLATED and produces only `SUBSCRIPTION_AUTHORIZATION_FAILURE`, human label
**Subscription authorization weakness**. Explicit denial satisfies DENY; other outcomes remain
UNRESOLVED. Wording is scoped to the selected endpoint/field/current supplied context and operator
expectation, without inferred ownership, identity, tenancy, roles or global subscription policy.
No severity/CVSS/CWE is assigned.

Only an actual connection attempt creates `SUBSCRIPTION_SECURITY_PROBE`, preserving exact query and
variables, source schema references, time/duration, safe handshake status, negotiated protocol,
ACK/start/event/frame counts, close code, outcome/evaluation and one bounded terminal frame. Init,
handshake credentials and arbitrary wire logs are excluded; the established explicit request-secret
boundary withholds a complete echoed frame rather than editing its contents. Prior evidence remains
unchanged. `ActiveExecutionScanResult.subscription_security` and its report counterpart are omitted
when disabled. Console/Markdown/HTML add **Subscriptions & GraphQL over WebSocket**, with conditional
**Subscription Security Findings**; Safety Notice remains last and appears once. Phase 31 includes
safe protocol/presence/ACK/event-count/outcome/policy facts and Findings, never URLs, variables,
init values or frames. Inference count and Phase 27 HTTP baselines remain unchanged.

Offline tests combine mocked transports with `tests/fixtures/phase30_target.py`, which mocks HTTP
schema acquisition and serves real loopback WebSockets. Its `--smoke` path exercises both protocols,
OBSERVE, DENY violation, explicit denial, null/error/malformed/timeout/disconnect/unsupported protocol
and private init/header authentication, plus zero-connection disabled/declined/non-interactive cases.
No public target or real credentials are needed. Origin attacks, protocol fuzzing, duplicate init,
ID collisions, flooding, cross-user comparisons, JWT mutation, event triggering and general
WebSocket scanning remain future work.

### Phase 31 — Whole-Scan AI Security Interpretation

Implemented as an additive interpretation-only extension of optional `--ai`, after all
single-context deterministic work. It adds no target HTTP/WebSocket activity, probes, payloads,
Findings, Evidence, scores or security decisions. The deterministic engine remains authoritative.
Named-context/differential AI (including Phase 19 and the special named IDOR route) remains
unsupported. No new dependency or command/option is introduced.

`ai/security_context.py` explicitly reads named project-owned fields into typed `AISecurityFact`
and `AICapabilityCoverage` models. It never serializes a result graph/report/Evidence and redacts
it afterward. `ai/context.py` composes these with existing operation/schema context. Safe fields
are enums, validated GraphQL identifiers/paths, bounded counts, presence Booleans, operator-policy
provenance and local references. Structural reason prose and target values are excluded.

| Source | Safe semantic projection |
| --- | --- |
| Phase 16 | All nine candidate enums, related operation kind/name/type; review candidates only |
| Phase 17/18 | Probe type, fixed multiplicity/depth/list-edge counts, classified outcome |
| Phase 20/21/22 | Operation/argument, object outcome, expected policy/evaluation/provenance, seed/attempt/candidate counts |
| Phase 23/24 | Mutation/input path/category, expected DENY and outcome/evaluation; no automatic Finding |
| Phase 25 | Existing IDOR Finding type, anonymous/supplied-context mode, baseline/policy outcomes |
| Phase 26 | JWT/opaque kind, allowlisted algorithm, presence-only header/claim names, temporal enums, probe outcomes/Findings |
| Phase 27 | Ordinary baseline classification, fixed planned/actual counts, scoped control type, policy and Finding |
| Phase 28 | Mutation/Upload path, variant, baseline state, policy outcome/Finding |
| Phase 29 | Service SDL-returned Boolean/policy; entity typename/key names, outcome/policy/Findings |
| Phase 30 | Subscription name/protocol, header/init presence, ACK/start Booleans, event count, outcome/policy/Finding |
| Ordinary Phase 9/10 | Existing priorities/categories, generation, selection, decision and exact execution classification |

Coverage distinguishes not_enabled, not_present, prepared, partial, executed and local_only.
No unsupported differential coverage is manufactured. AI fact categories are FINDING,
POLICY_VIOLATION, POLICY_SATISFIED, SECURITY_OBSERVATION, UNRESOLVED and REVIEW_CANDIDATE, not
severities. Tier assignment only arranges existing classifications for presentation; it does not
reevaluate policies or create Findings. Existing Finding references are used locally to avoid
prioritizing the same associated violation twice. Policy counts count evaluations, not their
accompanying Finding twice.

Each fact receives a stable locally generated `SF1`, `SF2`, ... reference after deterministic
tier ordering. Findings precede unaccompanied policy violations, explicit controls/satisfied
policies, unresolved/runtime observations, structural reviews and ordinary operations. Retained
workflow order is stable within each tier; ordinary operations retain Phase 7 ordering. Reduction
removes operations first, schema summaries second, lowest-tier facts last. Exact outgoing UTF-8
serialization, including self-counting metadata, must be at most **12,000 bytes**, with at most
**12 ordinary operations**. The unchanged 8192-token context/2048-token output settings are kept;
the original byte cap is deliberately not increased while prompt/schema grow. Bytes are a hard
payload bound, not an exact tokenizer measurement. Oversized context is reduced deterministically
rather than sent; truncated model output is rejected without another call.

Output retains the canonical ordinary execution summary and adds security_summary (800 chars),
security_fact_reviews (8 entries, interpretation 450/manual follow-up 350 chars),
control_observations (6 entries/400 chars), cross_capability_insights (4 entries/500 chars,
2–4 distinct fact references across capabilities), operation_review (8 entries/600 chars), and
limitations (8 entries/500 chars). Every reference must exist in the final bounded input;
unknown/missing/duplicate references, extra fields or oversized output reject the whole response.
Controls must reference supplied explicit controls/satisfied policies. Aggregate security counts
are local metadata outside model prose; ordinary execution counts require exact canonical text.
Model correlations remain uncertain interpretations requiring manual validation, never new facts,
Findings, severity, CWE, CVSS or proven causality.

AI receives no credentials, tokens/claim values/signatures, object or neighbor IDs, business
values, variables/documents, upload paths/names/bytes/hashes, federation SDL, target/WebSocket
URLs, init/event/frame values, raw responses/errors, schema descriptions or Evidence UUIDs/objects.
GraphQL names remain untrusted data. The same local-only Ollama adapter makes at most one call,
with stream=false, think=false, temperature=0, no retries, finite timeout and no tools. Invalid
projection, unavailable provider or invalid output is non-fatal to scanning and reporting.

Shared `ai/sections.py` supplies only the existing AI section in console and human reports:
validated execution facts, Security Summary, Security Fact Reviews, Security Controls Observed,
Cross-Capability Analysis, Operation Review and Limitations. JSON persists validated interpretation
and safe context metadata under optional `ai_interpretation`; raw AI input/result graphs are not
persisted there. Report schema version remains 1. Safety Notice stays final exactly once.

Offline `tests/fixtures/whole_scan_ai.py` composes real project-owned results with fake canaries;
`tests/unit/test_whole_scan_ai.py` captures the exact mocked Ollama request and exercises all
supported capabilities, privacy, stable truncation, scoped outcomes, reference rejection and
report/isolation behavior. Existing CLI regressions cover disabled AI, one inference and identical
scanner request sequences. No public target or real credentials are used. Phase 32 changes only the human presentation described below; no future vulnerability
functionality is implemented.

### Phase 32 — CLI & Human Reporting UX Simplification

Implemented as a presentation-only progressive-disclosure layer. `build_assessment` consumes the
existing report-facing projection of completed project-owned results and returns one immutable
`AssessmentPresentationSummary`. It holds small labels, counts and scoped references, never raw
Evidence, transport objects or copied capability graphs. It does not inspect response bodies,
evaluate policy, reinterpret schemas/JWTs/frames, or call AI. Existing report projections provide
technical details; no second capability analysis is introduced.

Findings count only retained Finding objects. Additional violations exclude policy events already
represented by those Findings. Scoped controls come from existing satisfied policies, explicit
denials or supported rejection/control outcomes. Unresolved includes enabled checks with existing
unresolved/indeterminate/network/timeout/baseline-unusable outcomes, not disabled capabilities or
schema review candidates. No severity, grade, score or global protection conclusion is created.

Capability order is explicit: Authentication & Tokens, Object Authorization, IDOR / BOLA, Mutation
Authorization, Sensitive Inputs, Rate Limiting & Abuse Controls, File Upload Security, Federation
Security, Subscriptions & WebSocket, Query Multiplicity, Query Depth, Sequential Object Discovery.
Within each source, retained result order is preserved. Structural candidates appear in Manual
Review. Default caps are 10 Findings, 8 Manual Review items, 5 limitations and 3 AI insights;
omissions are counted explicitly and verbose output is uncapped. Manual Review prioritizes
additional policy violations, unresolved attempted checks, structural candidates, then ordinary
CRITICAL/HIGH-interest operations not already represented more strongly. Findings preserve
workflow/source order rather than receiving a new severity ranking.

Verbose output and human reports group Discovery & Schema, Attack Surface, Operations & Execution,
Authentication & Authorization, GraphQL Runtime Controls, Specialized Surfaces and Evidence /
Errors / Limitations. Existing privacy-aware technical projections and bounded response displays
are reused. Human reports lead with Assessment Summary, GraphQL Attack Surface and existing
Security Findings, followed by validation/review and full AI interpretation when present, then
technical groups. HTML uses native closed `details`; Markdown uses nested headings. Safety Notice
is final exactly once. Named-context differential presentation remains pairwise.

Canonical JSON/model/evidence relationships and Phase 31 AIContext, prompts, validation, serialized
Ollama request and inference count are unchanged. No new networking or dependencies. Exact selected
ACTIVE requests remain visible before each separate default-NO consent, even without verbose.
Offline tests preserve request traces, privacy canaries, source data, report JSON and AI payloads;
`uv run python tests/fixtures/phase32_smoke.py` creates eight representative presentation artifacts
under ignored `reports/phase32`, using only mocked transports and fake data. No Phase 33 scope.

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
- General query-cost/complexity analysis beyond the single bounded Phase 18 depth probe.
- Broader rate-limit analysis beyond the fixed operator-policy sequence implemented in Phase 27.
- Further Subscription security checks beyond the single bounded Phase 30 policy probe.
- Further file-upload checks beyond the benign, bounded policy validation implemented in Phase 28.
- Further federation checks beyond the bounded SDL/entity policy probes implemented in Phase 29.
- Apollo-specific checks.
- Further WebSocket-specific security testing beyond Phase 30's two supported GraphQL protocols.
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
