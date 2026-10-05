# GQLSleuth

GQLSleuth is an open-source Python CLI for **authorized GraphQL security assessment**.
It helps application-security testers discover endpoints, inspect schemas, execute conservative
Queries and review evidence-backed results.

**SAFE is the default.** ACTIVE capabilities require explicit entry, scoped inputs/selection
and separate confirmation. Optional local AI explains retained facts; it does not control testing.

Current release candidate: **1.0.0 (Beta)**. This candidate has not been published.

> Use only against systems you are explicitly authorized to assess. Even read-only requests
> reach the target application. ACTIVE Mutations may change state; assess their impact before
> confirming them.

Start with [Installation](#installation), [Quick Start](#quick-start), or the
[fake local demonstration](examples/README.md).

- [Understanding output](#understanding-output)
- [Authentication and target HTTP settings](#authentication-and-target-http-settings)
- [Reports](#reports)
- [ACTIVE capabilities](#active-capabilities)
- [Optional local AI](#optional-local-ai)
- [Capability reference](#capability-reference)
- [Safety, limits and privacy](#safety-limits-and-privacy)
- [Python and platform support](#python-and-platform-support)
- [Contributing and releases](#contributing-and-releases)

## Installation

### Installed users: use a local wheel

Python **>=3.13** is required; the current validation matrix uses Python 3.13.
Public PyPI installation is **not currently documented as available**. Obtain a wheel from a
trusted maintainer build, or build it from the source checkout below with `uv build`.
The current artifact is `dist/gqlsleuth-1.0.0-py3-none-any.whl`.

Create an environment in the directory where you want to work:

```bash
python -m venv .venv
```

Activate it in **PowerShell**:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or in a **POSIX shell**:

```bash
source .venv/bin/activate
```

Install the local artifact, replacing this relative path with your wheel's location:

```bash
python -m pip install ./dist/gqlsleuth-1.0.0-py3-none-any.whl
gqlsleuth --help
gqlsleuth version
```

If PowerShell activation is restricted, invoke the environment's Python/launcher directly,
for example `.\.venv\Scripts\python.exe -m pip install .\dist\gqlsleuth-1.0.0-py3-none-any.whl`.
Do not change system execution policy just for this installation.

Installed users run **`gqlsleuth` directly**. `python -m gqlsleuth` is also supported.
Normal wheel installation resolves runtime dependencies; it does not require developer tools.

### Contributors: run from the repository

Use Python 3.13 and [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/Tomas-Ortiz/gqlsleuth.git
cd gqlsleuth
uv sync --locked
uv run gqlsleuth --help
```

`uv run` is the repository-development workflow. Use it before the commands below when working
from this checkout. `uv build` creates the wheel and source archive in `dist/`.
See [CONTRIBUTING.md](CONTRIBUTING.md) for tests and [RELEASING.md](docs/RELEASING.md) for the
fresh installed-artifact gate.

## Quick Start

The following commands are single-line examples usable in PowerShell and POSIX shells.
Replace `https://authorized.example/graphql` with an endpoint you are authorized to test.
The example domain is a placeholder, not a public test target.

### 1. First SAFE scan

```bash
gqlsleuth scan https://authorized.example/graphql
```

SAFE performs discovery, GraphQL confirmation, introspection, schema analysis and conservative
read-only Query execution. It never executes Mutations or Subscriptions. A base application URL
is also accepted; a direct GraphQL URL is tried before fallback endpoint discovery.
`--mode safe` explicitly selects the same default.

Introspection support and full schema retrieval are shown separately. An enabled minimal probe
can coexist with `Schema retrieval: BLOCKED`, for example when a server rejects the full query
with a depth limit. Details retain the server reason; without a valid schema, operation analysis
cannot proceed. This observation is not a vulnerability finding.

To try the workflow without any external target, run the [local demo](examples/README.md):

```bash
uv run python examples/local_demo.py --output ./reports/local-demo
```

That source-checkout helper starts a temporary loopback-only fake service, runs SAFE, writes an
HTML report and stops the service. It sends four local requests and executes zero Mutations.

### 2. See technical details

```bash
gqlsleuth scan https://authorized.example/graphql --verbose
```

Default output is an assessment-oriented summary. `--verbose` (or `-v`) adds discovery signals,
review reasons, generated documents/variables and bounded execution-response detail.
It changes presentation, not the requests or consent requirements.

### 3. Generate a report

```bash
gqlsleuth scan https://authorized.example/graphql --format html --output ./reports
```

Open the printed HTML path directly in a browser. Reports may contain application data;
store them as sensitive assessment artifacts.

### 4. Add authentication

```bash
gqlsleuth scan https://authorized.example/graphql -H "Authorization: Bearer TOKEN"
```

`TOKEN` is a fake placeholder. Supply credentials only for your authorized assessment.
Target URLs containing username/password information are rejected, including username-only
userinfo. Use `--header` or supported `--auth-context` syntax, never embedded URL credentials.
Header arguments can be sensitive in shell history and process listings.

### 5. Add optional local interpretation

```bash
gqlsleuth scan https://authorized.example/graphql --ai
```

Prepare the local Ollama service and `qwen3:8b` first, as described [below](#optional-local-ai).
GQLSleuth does not install Ollama or pull models. At most one inference interprets retained scan
facts; the deterministic engine remains authoritative. AI creates no Findings or Evidence.

## Understanding output

The assessment separates conclusions from observations and missing information:

| Output | Meaning |
| --- | --- |
| Findings | Existing deterministic security conclusions supported by scanner evidence. Some rely on your explicit policy expectation; verify that expectation. |
| Additional policy violations | Observed contradictions of operator-supplied policy that are intentionally not represented as Findings. Violations already represented by a Finding are not counted again here. |
| Scoped controls observed | Enforcement observed for the exact tested request/case. Not a global security guarantee. |
| Unresolved checks | Enabled checks whose retained outcomes cannot establish expected behavior, such as ambiguous errors, unusable baselines or timeouts. |
| Manual Review | Structural/operation review candidates and relevant unresolved or policy observations requiring tester analysis. |

**Review interest is not vulnerability severity.** CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL
priorities rank manual-review interest, not exploitability. Introspection being enabled or an
operation returning SUCCESS does not by itself establish a vulnerability.

Execution counts distinguish attempted requests, SUCCESS, GRAPHQL_ERROR, HTTP_ERROR,
INVALID_RESPONSE, NETWORK_FAILURE and unexecuted safety/limit skips. HTTP 200 alone is not
operation success. GraphQL errors can come from placeholders, business rules or other server
logic; they are not automatically authentication failures.

Default single-context output caps long lists and states how many items were omitted.
Use `--verbose` or a report for full retained detail. Named-context output remains a
pairwise Authorization Differential Review.

### Transport failures and process status

Connection failures provide URL/network/proxy/TLS guidance. Malformed or excessively nested
response JSON and schema parsing failures become controlled results/limitations.

A **completed scan exits 0 even if all target requests failed or no endpoint was confirmed**.
Inspect results and limitations rather than treating exit status as availability or vulnerability
status. Invalid input exits 2; report-generation failure exits 1. AI unavailability does not
invalidate the deterministic scan.

## Authentication and target HTTP settings

GraphQL does not prescribe Bearer tokens, JWTs or any role model. A request context is simply
the HTTP headers you supply; header presence does not prove accepted authentication.

### One request context

Repeat `-H` / `--header` to send multiple headers:

```bash
gqlsleuth scan https://authorized.example/graphql -H "Cookie: session=TEST_SESSION"
gqlsleuth scan https://authorized.example/graphql -H "X-API-Key: TEST_KEY" -H "X-Tenant-ID: TEST_TENANT"
```

Bearer, Cookie, API-key and proprietary header values are supported. Names are case-insensitive
and duplicate names use the last supplied value. Transport-controlled headers such as Host,
Content-Length and Proxy-Authorization are rejected. GraphQL JSON requests use the scanner's
JSON Content-Type.

Supplied headers remain on same-origin redirects. If scheme, host or port changes, they are
removed and not restored later in that redirect chain—even if it returns to the original origin.
There is no automatic login, token refresh, credential acquisition or browser-cookie access.

### Named contexts for differential review

Compare independent SAFE scans under **2–3 tester-named contexts**, then review local,
deterministic differences in endpoints, introspection, operation visibility and Query outcomes.
Names are opaque labels, not roles or a privilege hierarchy. Differences can be legitimate.

```bash
gqlsleuth scan https://authorized.example/graphql --auth-context public --auth-context "customer=Cookie: session=TEST_A" --auth-context "support=X-API-Key: TEST_B"
```

A bare label supplies no headers. Repeat a label to add headers to that same context:

```bash
gqlsleuth scan https://authorized.example/graphql --auth-context public --auth-context "customer=Authorization: Bearer TOKEN" --auth-context "customer=X-Tenant-ID: TEST_TENANT"
```

First-seen order is preserved. Each context gets isolated headers/settings and cookie state.
Pairwise comparison itself adds no requests and does not compare raw business response bodies.
Do not mix `--auth-context` with `-H` or `--ai`.

Ordinary differential review is SAFE-only. Two narrow exceptions are described in the capability
reference: one bare label for SAFE object authorization, and one header-bearing label for ACTIVE
IDOR/BOLA validation. Neither enables general single-context differential review.

### Timeouts, proxy and TLS

| Option | Behavior |
| --- | --- |
| `--timeout SECONDS` | Finite positive value for all target stages. Omitted: discovery GETs use 8s; other target requests use 10s. |
| `--proxy URL` | Explicit HTTP(S) proxy origin, optionally with credentials/port. No default proxy; environment proxies are ignored. SOCKS and proxy paths/queries/fragments are unsupported. |
| `--verify-tls` / `--no-verify-tls` | Verification is enabled by default. Disabling it is insecure; there is no automatic insecure retry. |

These settings apply to target traffic, not Ollama. Target URLs must have no userinfo.
Proxy credentials use only the explicit proxy configuration and are not displayed.
Configuration uses CLI options and built-in defaults; no configuration-file or environment
configuration system is implemented.

## Reports

```bash
gqlsleuth scan https://authorized.example/graphql -f json,markdown,html -o ./reports
gqlsleuth scan https://authorized.example/graphql --format json --format html
```

- **JSON:** canonical machine-readable report, including exact generated documents/variables,
  execution classifications, source references and retained evidence. Byte-valued bodies use
  lossless base64 objects.
- **Markdown / HTML:** human-readable assessments with technical details. HTML is standalone,
  using embedded CSS and native expandable details, with no CDN or external JavaScript.
- `--format` / `-f` accepts comma-separated or repeated formats. Each requested format is written
  once. `--output` / `-o` is a directory, created when needed; default: `./gqlsleuth-reports`.
- No format means no report files/directories. `--output` without `--format` is an input error.
  Safe host/timestamp filenames get a numeric suffix on collision instead of silently overwriting.
- Reporting performs **zero additional requests, GraphQL operations or AI calls**. It consumes
  retained results. Safety Notice is the final Markdown/HTML section.

**Reports may be sensitive.** JSON can include raw application responses and exact variables.
Human reports can also retain sensitive request values or bounded response excerpts.
Store artifacts appropriately; do not casually attach them to public issues.

## ACTIVE capabilities

```bash
gqlsleuth scan https://authorized.example/graphql --mode active
```

ACTIVE explicitly enters active functionality for an authorized target. It first performs the
ordinary SAFE workflow. **ACTIVE does not mean “run all tests.”**

Query-shape, Query-depth and generic Mutation candidates are previewed in ordinary ACTIVE
interaction; you explicitly select indices or press Enter for none. Other capabilities require
their opt-in flags and exact cases. Each active capability has its **own default-NO confirmation**;
one confirmation never authorizes another capability. Non-interactive stdin executes no active
probes or Mutations. There is no automatic-confirmation or execute-all switch.

Generic Mutations require successful generation, defensive validation and safety classification,
explicit selection of at most **five**, then **one final batch confirmation**. Destructive primary
action tokens remain blocked with no override. Mutation success means execution, not a confirmed
vulnerability. Previewed placeholders may need adjustment and are not guaranteed valid target data.

### Capability index

Limits below are capability-specific additional budgets, not a single global scan budget.
All active requests need separate consent. The SAFE authorization options have their own
explicit opt-in/case requirements and **do not prompt**.

| Capability | Main option / entry | Mode | Purpose | Main limit |
| --- | --- | --- | --- | --- |
| [Query Multiplicity](#query-multiplicity) | `--mode active` + Query-Shape selection | ACTIVE | Observe alias/batch handling | 1 three-alias request + 1 two-item batch |
| [Query Depth](#query-depth) | `--mode active` + Query-Depth selection | ACTIVE | Observe one bounded deeper shape | 1 request; depth 6; 1 composite list |
| [Object Authorization](#object-authorization) | `--object-auth-review` | SAFE | Validate exact supplied objects | 3 cases; up to 9 requests across contexts |
| [Nested Authorization](#nested-authorization) | `--nested-auth-review` | SAFE | Compare nested-path access | 3 paths; depth 5; up to 9 requests |
| [Authorization Policy](#authorization-policy-validation) | `--auth-policy-review` | SAFE | Evaluate supplied DENY assertions | 9 assertions; zero new requests |
| [Sequential Object Discovery](#sequential-object-discovery) | `--idor-discovery` | ACTIVE | Observe immediate numeric neighbors | 2 seeds; at most 6 requests |
| [Mutation Authorization](#mutation-authorization) | `--mutation-auth-review` | ACTIVE | Test exact Mutation/object DENY | 1 case/request |
| [Sensitive Input Validation](#sensitive-input-validation) | `--sensitive-input-review` | ACTIVE | Test exact field/value DENY | 1 case/request |
| [IDOR / BOLA](#idor--bola-validation) | `--idor-review` | ACTIVE | Test operator-expected object denial | 2 seeds; at most 6 requests |
| [Authentication & Tokens](#authentication-and-token-security) | `--auth-security-review` | ACTIVE | Test selected Query's Bearer requirement | Up to 3 additional probes |
| [Rate Limiting & Abuse](#rate-limiting-and-abuse-controls) | `--rate-limit-review` | ACTIVE | Test explicit repetition expectation | Up to 5 Query or 3 Mutation repeats |
| [File Upload](#file-upload-security) | `--file-upload-review` | ACTIVE | Benign baseline and selected variants | 1 file, 1 MiB, 4 requests |
| [Federation](#federation-security) | `--federation-review` | ACTIVE | Service/entity policy observations | 1 endpoint; up to 2 requests |
| [Subscriptions / WebSocket](#subscriptions-and-websocket) | `--subscription-review` | ACTIVE | One bounded Subscription | 1 socket, 1 Subscription, 1 event |

## Optional local AI

Install and run Ollama yourself. Prepare the expected model:

```bash
ollama pull qwen3:8b
gqlsleuth scan https://authorized.example/graphql --ai
```

GQLSleuth talks to the local service/API at **http://127.0.0.1:11434**, using **qwen3:8b**.
If the service is already running, no interactive `ollama run` chat session is necessary.
Otherwise start your normal Ollama service (for a manual installation, `ollama serve`).
GQLSleuth does not start/install Ollama or download models.

Local inference waits up to **600 seconds by default**. CPU-only machines may need longer:

```bash
gqlsleuth scan https://authorized.example/graphql --ai --ai-timeout 1200
```

`--ai-timeout` accepts finite positive seconds and is used only with `--ai`; it does not enable
AI itself. It changes only local Ollama read/write/pool waits; the connection timeout remains
5 seconds. It is a network wait timeout, not a total scan deadline. Target `--timeout` and
discovery/introspection/Query/Mutation requests are unaffected. AI timeouts remain non-fatal.

At most **one inference** interprets the completed single-context scan. It can discuss retained
Findings, policy outcomes, controls, unresolved checks, structural candidates and operations.
Deterministic execution facts remain authoritative. AI adds no target requests, Findings,
Evidence, scores or consent. Its prose and cross-capability correlations still require review.

The allowlist excludes credentials/tokens, URLs, variables, object IDs, raw responses/errors,
Evidence, upload material, SDL and WebSocket frames. Target HTTP settings never configure
Ollama. Input is bounded and may omit facts; no second call fills gaps. Full differential/named-context
AI, including the special named IDOR route, is unsupported.

An unavailable service, missing model, timeout or invalid output becomes an AI-only status.
The completed deterministic assessment and requested reports remain available. Default output
shows concise AI highlights; verbose output and human reports show the complete retained
interpretation. AI is optional and disabled without `--ai`.

Developers can check the real local model without scanning a target:
`uv run python scripts/check_ollama.py`. This optional acceptance script uses a mocked SAFE scan
and one real local inference, validates structured output and supplied references, and never
downloads a model. It is not part of normal pytest/CI.

## Capability reference

Examples use fake values and assume the named operation exists in the target's retained schema.
Each active example still performs the normal SAFE workflow and its own preview/confirmation;
it is not permission to execute automatically. Press Enter to skip unrelated active selections.
See the [architecture](docs/ARCHITECTURE.md) for internal models and exact classifier rules.

### Schema review and generated Queries

Local structural analysis and Sensitive Input Review run on retained schemas without extra
requests. Candidates include object lookups, collections without obvious quantity controls,
recursive graphs, sensitive outputs/inputs and specialized surfaces. They are manual-review
prompts, not Findings. Public reference-data lookups are not inherently suspicious.

Queries normally omit optional inputs. For recognized application collections, a conservative
optional quantity bound may be populated with **1**, including `options.paginate.limit`.
Inspection supports direct lists, one wrapper level and up to three input-object levels.
A schema size-control argument does not prove runtime enforcement, and generated omissions do
not prove absence of pagination. There is no automatic pagination or limit escalation.

Required values use deterministic placeholders. Examples: String defaults to `"test"`, email to
`"test@example.com"`, password to `"TestPass123!"`, username to `"testuser"`, name to
`"Test User"`, URL to `"https://example.com"`, phone to `"+15555550100"`, and ID to `"1"`.
Matching uses exact normalized leaf names; other scalar types retain type-specific behavior.
Unknown custom scalars require manual adjustment. These values are not real credentials or
discovered application data. Generic Query execution is sequential, capped at **20 per scan**,
and skips unsafe action names. Named-context scans run that workflow independently per context.

### Query Multiplicity

**Entry:** ordinary `--mode active` Query-Shape selection; no dedicated enable flag.
Select up to two individual candidates and confirm the batch. Each reuses one retained attempted
safe Query, its exact variables and bounds. One request uses exactly three aliases; another
uses a two-item HTTP batch. No new baseline, retries or threshold search.

**Meaning:** ACCEPTED/REJECTED/INDETERMINATE describes only that exact shape. Batch acceptance
does not mean every individual entry succeeded. Neither acceptance nor rejection proves a
vulnerability or application-wide cost/rate protection.

### Query Depth

**Entry:** ordinary `--mode active` Query-Depth selection, then separate confirmation.
One eligible retained recursive path is expanded once, with at most selection depth **6** and
**one composite list** in the complete Query. New unbounded lists and required nested business
inputs are skipped. At most one request; no progressive search or new baseline.

**Meaning:** acceptance is not a DoS finding; explicit depth/complexity rejection is a scoped
control. Generic errors are unresolved, not proof of enforcement.

### Object Authorization

**Required:** `--object-auth-review --object-auth-case OPERATION:ARGUMENT=ID` in SAFE.
Anonymous-only review uses no `-H`; one bare `--auth-context` label is optionally allowed.
For 2–3 contexts, prefix each case with its declared authorized label:

```bash
gqlsleuth scan https://authorized.example/graphql --auth-context "customer=Cookie: session=TEST_A" --auth-context public --object-auth-review --object-auth-case "customer:order:id=123"
```

Direct `ID` input, concrete object output and direct `id: ID` output are required.
Up to **3 exact cases**, **9 additional requests** across contexts (3 anonymous-only).
The declared authorized context must return the exact supplied object before other contexts run.
No IDs are generated, no real ownership inferred. Common `-H` and ACTIVE are unsupported.

**Meaning:** a matching direct returned ID establishes object access, not intended policy.
Cross-context/unauthenticated access is a review candidate; generic errors or mismatches are
unresolved. This SAFE opt-in executes eligible cases without an interactive confirmation.

### Nested Authorization

**Required:** `--nested-auth-review` with 2–3 SAFE `--auth-context` labels.
Compatible successful Query baselines are reused to test up to **3 nested paths**, depth **5**
and one composite list per Query, at most **9 additional requests**. New lists need a quantity
bound; required nested business input and incompatible schemas are skipped. No confirmation
prompt, retries, ID substitution or Mutation execution.

**Meaning:** returned-versus-explicitly-denied paths and schema visibility differences require
policy review. Labels do not encode privilege; no BOLA/IDOR Finding follows automatically.

### Authorization Policy Validation

**Required:** object authorization plus `--auth-policy-review --expect-deny CASE[:CONTEXT]`.
Use a 1-based case index after deduplication; named comparisons also need the exact label.

```bash
gqlsleuth scan https://authorized.example/graphql --object-auth-review --object-auth-case "order:id=123" --auth-policy-review --expect-deny 1
```

At most **9 explicit DENY assertions** are evaluated locally against retained outcomes,
with **zero additional requests**. Missing/ambiguous results are UNRESOLVED. Exact object return
contradicts DENY; explicit denial satisfies it for this case. Duplicate assertions and DENY
against the declared authorized context are rejected.

**Meaning:** violations contradict your supplied policy but create no automatic Finding.
The tool does not independently determine ownership or whether your policy is correct.

### Sequential Object Discovery

**Required:** `--mode active --idor-discovery --idor-seed OPERATION:ARGUMENT=ID`.
At most two canonical unsigned decimal seeds in `0..9223372036854775807`. No leading zeroes
except `0`, UUIDs, signs or ranges. Use ordinary `-H` if needed; no named contexts.

After preview and separate confirmation, the exact baseline must return before its immediate
valid **-1/+1** neighbors run. At most **6 attempts**. No recursive expansion, response-derived
IDs, range scans or automatic follow-up.

**Meaning:** adjacent object access is a review candidate, not an IDOR/BOLA Finding.
Explicit policy testing is the separate capability below; these flags cannot be combined.

### IDOR / BOLA Validation

**Required:** `--mode active --idor-review --idor-seed OPERATION:ARGUMENT=ID`.

```bash
gqlsleuth scan https://authorized.example/graphql --mode active --idor-review --idor-seed "order:id=123"
gqlsleuth scan https://authorized.example/graphql --mode active --auth-context "customer=Cookie: session=TEST_A" --idor-review --idor-seed "order:id=123"
```

Without supplied headers, you assert **DENY for seed and neighbors**. With supplied headers,
the seed is an expected **ALLOW baseline**; only an exact matching return enables neighbors,
which you assert must be **DENIED**. Ordinary `-H` or exactly one header-bearing named context
is supported. Header presence selects the policy; it does not prove server authentication.

Limits match bounded discovery: **2 numeric seeds, at most 6 attempts, immediate -1/+1 only**.
Separate default-NO confirmation is mandatory. The one-named-context route runs no differential,
other ACTIVE stages, generic Mutations or AI.

**Meaning:** exact object return under DENY produces an evidence-linked IDOR/BOLA Finding.
It depends on your expectation: shared/public objects may legitimately be accessible. No ownership,
tenant or role hierarchy is inferred; an unusable authenticated baseline skips its neighbors.

### Mutation Authorization

**Required:** `--mode active --mutation-auth-review --mutation-auth-case OPERATION:ARGUMENT=ID`.
This declares **DENY** for one exact Mutation/object in the ordinary HTTP context; no named contexts.
Direct ID input and returned object ID are required. Destructive names remain blocked.
Preview all variables, then give separate confirmation: **1 case, 1 attempt**, no retries,
read-before-write, rollback or persistence check.

**Meaning:** exact returned target ID contradicts your DENY policy; explicit denial satisfies
only this case. The result is a policy violation, not an automatic vulnerability Finding.
The Mutation may modify state even though denial is expected.

### Sensitive Input Validation

**Required:** `--mode active --sensitive-input-review --sensitive-input-case OPERATION:INPUT.FIELD=VALUE`.
Add `--sensitive-input-target ARGUMENT=ID` when the Mutation exposes exactly one direct ID argument.

```bash
gqlsleuth scan https://authorized.example/graphql --mode active --sensitive-input-review --sensitive-input-case "updateProfile:input.isStaff=true" --sensitive-input-target "id=123"
```

Only an already-detected direct sensitive input leaf and compatible direct returned field qualify.
Supply one exact Boolean, Int, String, ID or enum value; no nested-path guessing, list/Float/custom
scalar validation or alternate values. Destructive names and named contexts are unsupported.
Preview and confirm independently: **1 case, 1 attempt**. Local Sensitive Input Review itself
requires no flag, no test value and no requests.

**Meaning:** the exact returned value (and target ID when supplied) contradicts your DENY assertion.
This is a policy violation, not proof of persistence, privilege escalation or an automatic Finding.

### Authentication and Token Security

**Required:** `--mode active --auth-security-review` with exactly one nonempty
`-H "Authorization: Bearer TOKEN"`, a retained successful safe Query and separate selection/consent.
No named contexts. Local JWT inspection does not verify signatures; unsupported tokens remain opaque.

Select a Query that you expect to require Bearer authentication. Up to **3 additional attempts**:
remove only Authorization, then selected signature/unsigned-token variants only after explicit
control denial. Other headers remain, so the first control is not necessarily anonymous.
The original baseline is not resent. No login, token acquisition, refresh or claim guessing.

**Meaning:** Findings are scoped to that Query and supplied expectation. Missing claims alone
are not vulnerabilities. Null data, generic errors and transport failure remain unresolved.

### Rate Limiting and Abuse Controls

**Required:** `--mode active --rate-limit-review`, one selected previously attempted ordinary
Query or generic Mutation, and separate confirmation. You assert that a control should appear
within the fixed sequence. GraphQL-error baselines may qualify; no new baseline request.

At most **5 additional Query or 3 Mutation requests**, identical to the retained request.
Stop on an explicit control, indeterminate change or network failure. No credential rotation,
concurrency, retries, threshold search or challenge bypass. No named contexts.

**Meaning:** completion without the expected signal can produce a Finding scoped to this
operator-defined bound, not proof that all rate limiting is absent. Repeating Mutations may
repeat side effects; no cleanup or deduplication is performed.

### File Upload Security

**Required:** `--mode active --file-upload-review --upload-case OPERATION:ARGUMENT[.FIELD...] --upload-file PATH`.

```bash
gqlsleuth scan https://authorized.example/graphql --mode active --file-upload-review --upload-case "uploadAvatar:input.file" --upload-file ./avatar.png
```

Use one known-valid benign file, nonempty and at most **1 MiB**, with a retained non-list
`Upload` scalar path (up to three nested fields). An optional `--upload-content-type` overrides
filename-derived MIME. Preview the exact Mutation/map/metadata, select fixed benign
content/MIME/extension variants, then confirm independently. Enter at variant selection means
**baseline only**, not cancellation; final confirmation still defaults NO.

The successful baseline gates selected DENY variants: **at most 4 attempts**. No executable
payloads, archive bombs, path traversal, fallback files or retrieval of returned URLs. No named
contexts; destructive rules remain active. Uploads may create records/files without rollback.

**Meaning:** a confirmed baseline plus accepted DENY variant can produce a scoped file-validation
Finding. Response acceptance does not prove persistence, rendering or code execution.

### Federation Security

**Required:** `--mode active --federation-review`, explicit endpoint/probe selection and separate consent.
Uses retained federation surfaces. The service SDL probe defaults to OBSERVE; returning SDL alone
is not a Finding. `--federation-sdl-expect-deny` supplies explicit DENY for that probe.

`--federation-entity-case` accepts one flat JSON representation (`__typename` plus 1–3 direct
typed keys), at most 1024 bytes, and declares DENY. It must match the retained schema; no key
guessing or entity enumeration. JSON quoting varies by shell; supply it as one argument.

**Bounds:** one endpoint, at most **2 sequential requests**, service then entity. No named contexts,
retries, subgraph discovery or response-derived requests.

**Meaning:** successful SDL under DENY or an exact matching entity under DENY can produce scoped
Findings. No private-service policy, ownership or application-wide authorization conclusion is inferred.

### Subscriptions and WebSocket

**Required:** `--mode active --subscription-review`, select one retained Subscription and confirm separately.
The endpoint maps to ws/wss; optional `--subscription-ws-url` must share its HTTP credential origin.
No redirects, path guessing or reconnect. Modern and legacy GraphQL WebSocket protocols are supported.

Optional `--subscription-variables` replaces only existing generated variables after schema validation.
`--subscription-init-payload` supplies private connection-init data. Each accepts one JSON object,
at most 4096 bytes. They and `--subscription-expect-deny` require the review flag.

**Bounds:** **1 connection, 1 Subscription, 1 application event**, 20 inbound frames, 1 MiB message
cap; handshake/ACK/event waits each at most 10s or the smaller explicit timeout. No named contexts,
event-trigger Mutations, multiplexing or flooding.

**Meaning:** default OBSERVE produces no Finding. Explicit `--subscription-expect-deny` plus
successful non-null selected-root data can produce a scoped authorization Finding. ACK alone is
not access; silence is unresolved, not proof of protection.

## Safety, limits and privacy

- SAFE is read-only and never executes Mutations/Subscriptions. Optional SAFE object and nested
  review add only their documented bounded Query requests. Query names and generated documents
  undergo safety checks; target resolvers must still be assessed within your authorization.
- Active budgets are independent. Combining capabilities can add their separate request counts.
  There are no automatic retries, unlimited ranges or automatic follow-up based on returned IDs.
- Ordinary Query placeholders and all explicit active cases are visible where previewed. Inspect
  exact requests and potential side effects before consent. There is no generic rollback.
- Structural review, local differential comparison, policy evaluation, reports and AI do not
  themselves send additional target requests. Their input workflows may do so as documented.
- Execution/probe evidence is retained only for actual attempts; generation, selection or consent is not execution.
  Scoped controls and no Findings do not mean the application is secure.

### Privacy boundary

Request headers, proxy credentials and selected private runtime inputs are excluded from
result/report/AI models where designed. They are not rendered merely to describe a context.
This is **not generic automatic redaction**.

Canonical evidence can retain response headers/bodies, exact documents and variables, including
application data or echoed sensitive material. Some specialized probes withhold a whole
response/frame when it echoes known private request material and record that omission.
That selective protection does not sanitize earlier or unrelated evidence.

Store reports securely and review them before sharing. Do not upload real scan artifacts,
credentials or customer data to public issues. AI uses its separate strict allowlist, not a
sanitized copy of evidence. See [SECURITY.md](SECURITY.md) for reporting flaws in GQLSleuth itself.

## Python and platform support

- Installation requirement: **Python >=3.13**.
- CI source-quality and installed-artifact gates are configured for **Python 3.13 on Windows and
  Linux (Ubuntu)**. Passing matrix runs are required for release; configuration alone is not a
  claim that every run has passed.
- macOS is **not currently CI-validated**. Newer Python interpreters are not in the current matrix.
- No browser, Docker or Ollama is required for deterministic scans. Ollama is optional.

## Contributing and releases

Read [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, offline testing and pull requests.
[AGENTS.md](AGENTS.md) provides repository working rules; [ARCHITECTURE.md](docs/ARCHITECTURE.md)
contains implementation detail and the internal roadmap.

[CHANGELOG.md](CHANGELOG.md) records user-visible changes and the prepared release entry.
[RELEASING.md](docs/RELEASING.md) documents version authority, artifact verification and the future
manual publication procedure. Preparing this candidate does not publish it or reserve a package name.
Report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

GQLSleuth is licensed under the [MIT License](LICENSE).
