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

The repository is currently at **Phase 2 — HTTP layer**. It provides the Phase 0 and Phase 1
foundation plus a centralized synchronous HTTPX client, GQLSleuth-owned request and response
models, conservative transport settings, response-size enforcement, and normalized HTTP
errors.

The internal HTTP layer is ready for use by future phases, but endpoint discovery and scanning
network behavior are not implemented yet. The `scan` command remains a placeholder that exits
successfully after clearly reporting that it performed no scan and made no network request.
ACTIVE mode remains configuration-only and does not enable active behavior.

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

Run the retained placeholder command with the safe default mode:

```bash
uv run gqlsleuth scan https://example.com
```

Choose a configuration-only mode explicitly:

```bash
uv run gqlsleuth scan https://example.com --mode safe
uv run gqlsleuth scan https://example.com --mode active
```

ACTIVE does not perform active scanning during Phase 2. The command still makes zero network
requests.

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
