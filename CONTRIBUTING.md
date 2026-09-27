# Contributing

GQLSleuth is for authorized GraphQL assessment. Keep changes focused, deterministic and safe by
default. Discuss substantial new capabilities before implementing them.

## Development environment

Use Python 3.13 and [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/Tomas-Ortiz/gqlsleuth.git
cd gqlsleuth
uv sync --locked
uv run gqlsleuth --help
```

Installed users run `gqlsleuth` directly; `uv run` is the repository-development workflow.
Try the [local demonstration](examples/README.md) without any public target or real credentials.

## Checks and pull requests

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
uv build
git diff --check
```

Tests must be offline: mocked transports or controlled loopback fixtures, fake credentials and
bounded requests only. Do not add public targets to pytest or CI. Include a meaningful regression
for a bug fix, relevant documentation, and a concise description of behavior and validation.
Never commit reports, credentials, environment files, caches or generated build artifacts.

Keep CLI presentation, application coordination, domain decisions and infrastructure separate.
Preserve SAFE/ACTIVE consent, request budgets, evidence provenance and deterministic classifications.
Review interest is not vulnerability severity; AI cannot invent Findings or Evidence. Do not
introduce generic redaction or silently sanitize canonical evidence. Preserve credential isolation
and the existing explicit whole-response withholding boundaries. Reports can contain application
data and exact variables, so use fake data in examples and handle real artifacts privately.

The [architecture](docs/ARCHITECTURE.md) explains implementation details; [AGENTS.md](AGENTS.md)
contains repository working rules. Report vulnerabilities in the tool through [SECURITY.md](SECURITY.md),
not public issues containing sensitive material. Version changes and package/resource changes
must follow the [release procedure](docs/RELEASING.md), including its fresh installed-artifact gate.
Publishing, tagging and release approval are separate maintainer decisions.
