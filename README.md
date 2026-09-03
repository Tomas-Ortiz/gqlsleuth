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

The repository is currently at **Phase 8 — query generation**. It provides the Phase 0
and Phase 1 foundation, the centralized Phase 2 HTTP layer, Phase 3 endpoint discovery, Phase 4
GraphQL behavior detection, Phase 5 introspection retrieval, Phase 6 deterministic schema
parsing, Phase 7 operation analysis, and Phase 8 local read-only query generation.

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
adjustment. Mutation and Subscription operations are not generated.

Discovery gives the preferred candidate a five-second GET timeout and immediately applies the
existing GraphQL detection logic. A confirmed or probable preferred candidate stops discovery;
otherwise, the remaining candidates use at most four synchronous workers while retaining their
stable candidate order. GraphQL POST probes and introspection continue using the normal ten-second
HTTP timeout. A fallback POST is sent only when discovery received an inconclusive HTTP response;
transport failures without a response proceed directly to the next candidate.

These priorities are manual-review aids, not vulnerability severities or proof of a
vulnerability. Phase 8 preserves generated queries and placeholder variables as local evidence,
but it does not send or execute any generated Query, Mutation, or Subscription operation.

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
prioritization, and local query generation with the default mode:

```bash
uv run gqlsleuth scan https://example.com
```

Choose a mode explicitly:

```bash
uv run gqlsleuth scan https://example.com --mode safe
uv run gqlsleuth scan https://example.com --mode active
```

ACTIVE performs the same safe discovery, detection, read-only introspection, local schema
parsing, local rule-based analysis, and non-executing query generation as SAFE during Phase 8.
It does not enable active-only behavior.

The CLI displays at most the ten highest-priority review candidates while the structured
application result retains every analyzed Query and Mutation root field. Each displayed
candidate includes its interest score, categories, matched rules, and deterministic reason.
The CLI also shows at most five generated Query examples. Structured results retain every
successful or failed Query-generation result. Generated variables are placeholders and may need
manual adjustment before a future execution phase.

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
