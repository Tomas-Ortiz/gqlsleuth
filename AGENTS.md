# AGENTS.md

## 1. Purpose

This file defines the instructions that AI coding agents must follow when working on the GQLSleuth repository.

GQLSleuth is an open-source Python CLI for authorized GraphQL security discovery and analysis.

The project specification is located at:

```text
docs/ARCHITECTURE.md
```

Before making significant changes, read this file and use it as the primary source of truth for:

- Project goals.
- Scope.
- Architecture.
- Security requirements.
- Operating modes.
- Technology choices.
- MVP definition.
- Development roadmap.

This file defines how agents should work. `docs/ARCHITECTURE.md` defines what the project is intended to become.

## 2. Instruction priority

When instructions conflict, follow this order:

1. The user's current explicit request.
2. This `AGENTS.md` file.
3. `docs/ARCHITECTURE.md`.
4. Existing repository conventions.
5. General software engineering practices.

Do not silently ignore conflicts.

When a requested change contradicts the project specification, explain the conflict before implementing it unless the user explicitly confirms that the specification should also be updated.

## 3. General working principles

Agents must:

- Understand the requested task before editing files.
- Inspect the existing implementation before introducing new code.
- Make the smallest coherent change that satisfies the task.
- Preserve existing working behavior unless a change is explicitly required.
- Keep the implementation aligned with the current development phase.
- Prefer clarity, correctness and maintainability over cleverness.
- Avoid speculative features.
- Avoid unnecessary abstractions.
- Avoid unrelated refactoring.
- Keep changes easy to review.
- Update tests when behavior changes.
- Update documentation when public behavior or architecture changes.

Agents must not:

- Implement functionality outside the requested scope.
- Rewrite large parts of the project without a clear reason.
- Add dependencies only for convenience.
- Duplicate existing logic.
- Introduce dead code or placeholder modules without an immediate purpose.
- Claim that code was tested when it was not.
- Hide errors or failing checks.
- Commit secrets, tokens, credentials or sensitive target information.

## 4. Phase-based development

GQLSleuth is developed incrementally.

Only functionality belonging to the current requested phase should be implemented.

The roadmap is defined in:

```text
docs/ARCHITECTURE.md
```

When working on a phase:

- Implement only the deliverables required for that phase.
- Do not pre-implement future phases.
- Do not create empty directories or modules solely because they appear in the target architecture.
- Add dependencies only when the current phase requires them.
- Keep future integrations behind clear interfaces only when such an interface is needed now.
- Ensure the project remains runnable at the end of the phase.

For example, during Phase 0, do not implement:

- Real HTTP requests.
- Endpoint discovery.
- GraphQL introspection.
- Schema parsing.
- Query execution.
- Ollama integration.
- Docker support.
- Real scanning logic.

Placeholder CLI behavior is acceptable only when explicitly required by the phase.

## 5. Technology requirements

Use the technology stack defined in `docs/ARCHITECTURE.md`.

Current core choices include:

- Python 3.13.
- `uv` for project and dependency management.
- Typer for the CLI.
- Rich for terminal presentation.
- Pydantic for typed models.
- `pydantic-settings` for configuration.
- HTTPX for HTTP functionality.
- `graphql-core` for GraphQL schema handling.
- pytest for testing.
- Ruff for linting and formatting.
- mypy for static type checking.

Do not replace these technologies without an explicit architectural decision.

Do not install dependencies with `pip` directly.

Use:

```bash
uv add <package>
```

For development dependencies, use:

```bash
uv add --dev <package>
```

Run project commands through `uv` when appropriate.

Examples:

```bash
uv run gqlsleuth --help
uv run pytest
uv run ruff check .
uv run mypy src
```

## 6. Architecture rules

GQLSleuth follows a modular layered architecture.

Conceptual flow:

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

The CLI layer may:

- Define commands and options.
- Validate basic user input.
- Invoke application services.
- Render results.
- Convert internal exceptions into useful terminal messages.
- Define process exit codes.

The CLI layer must not:

- Contain HTTP request logic.
- Parse GraphQL schemas.
- Implement scoring rules.
- Contain core business logic.
- Directly manage evidence persistence.
- Directly call AI services.

### Application layer

The application layer should:

- Coordinate workflows.
- Connect domain logic with infrastructure.
- Define use cases.
- Remain independent from terminal rendering.

### Domain layer

The domain layer should contain:

- Typed models.
- Business rules.
- Classification logic.
- Scoring logic.
- Safety decisions.
- Evidence semantics.
- Project-specific exceptions where appropriate.

Domain code must not depend directly on:

- Typer.
- Rich.
- HTTPX.
- File system details.
- Ollama-specific APIs.

### Infrastructure layer

The infrastructure layer should contain adapters for:

- HTTPX.
- Configuration sources.
- File access.
- Report serialization.
- External services.
- Ollama.
- Time and system functions when abstraction is useful.

Infrastructure details must not leak unnecessarily into domain models.

## 7. Package structure

Use the `src` layout.

The package root is:

```text
src/gqlsleuth/
```

The target repository structure is described in `docs/ARCHITECTURE.md`, but directories should be created only when required.

Prefer cohesive modules over a large number of tiny files.

Avoid generic modules such as:

```text
utils.py
helpers.py
common.py
misc.py
```

unless their purpose is genuinely clear and stable.

Prefer descriptive module names such as:

```text
url_normalization.py
header_redaction.py
endpoint_candidates.py
schema_models.py
```

## 8. Python coding standards

All production code must use type hints.

Prefer:

- Explicit return types.
- Small and cohesive functions.
- Clear names.
- Immutable data where practical.
- Composition over deep inheritance.
- Standard library functionality when sufficient.
- Dataclasses or Pydantic models for structured data.
- Project-specific exceptions for expected failure cases.

Avoid:

- Unnecessary global state.
- Broad `except Exception` blocks.
- Silent exception handling.
- Mutable default arguments.
- Deep nesting.
- Boolean parameters with unclear meaning.
- Functions with many unrelated responsibilities.
- Premature optimization.
- Dynamic typing when a clear type can be expressed.

Use modern Python 3.13 syntax when it improves readability.

Example:

```python
def normalize_url(value: str) -> str: ...
```

Prefer:

```python
list[str]
dict[str, str]
str | None
```

instead of legacy typing aliases unless compatibility requires otherwise.

## 9. Naming conventions

Use:

- `snake_case` for functions, variables and modules.
- `PascalCase` for classes and Pydantic models.
- `UPPER_SNAKE_CASE` for constants.
- Clear and descriptive CLI option names.
- Domain-specific terminology from `docs/ARCHITECTURE.md`.

Avoid abbreviations unless they are widely understood in the project domain.

Preferred:

```python
introspection_result
endpoint_candidate
authorization_acknowledged
```

Avoid:

```python
intro_res
ep_cand
auth_ack
```

## 10. Documentation standards

Public modules, classes and functions should include docstrings when they add meaningful context.

Do not add docstrings that merely restate the function name.

Good documentation should explain:

- Purpose.
- Important constraints.
- Security assumptions.
- Non-obvious behavior.
- Expected failure modes.

Comments should explain why something exists, not narrate obvious code.

Update the relevant documentation when changing:

- CLI commands.
- CLI options.
- Configuration.
- Project architecture.
- Public behavior.
- Safety guarantees.
- Development phases.
- Dependencies.

Use:

- `README.md` for user-facing installation and usage.
- `docs/ARCHITECTURE.md` for project design and scope.
- `AGENTS.md` for agent working rules.
- Code comments and docstrings for implementation details.

`docs/ARCHITECTURE.md` is a living document and may be updated as the project evolves.

## 11. CLI requirements

The CLI must use Typer and Rich.

The primary executable is:

```bash
gqlsleuth
```

CLI output should be:

- Clear.
- Professional.
- Consistent.
- Useful in both success and failure cases.
- Free from unnecessary decoration.
- Suitable for a cybersecurity tool.

Commands should return meaningful exit codes.

Suggested categories:

- `0`: Success.
- `1`: General execution failure.
- `2`: Invalid user input or configuration.
- Additional codes may be introduced when they provide real value.

Do not expose Python tracebacks by default.

Detailed diagnostic information may be shown in verbose or debug mode.

Core logic must remain testable without invoking Typer commands.

## 12. Configuration requirements

Configuration precedence should follow:

```text
CLI arguments
    ↓
Environment variables
    ↓
Configuration file
    ↓
Default values
```

Use Pydantic and `pydantic-settings` when configuration functionality is implemented.

Configuration must:

- Have safe defaults.
- Validate invalid combinations.
- Avoid storing secrets in committed files.
- Keep CLI mapping separate from domain logic.
- Be testable without reading the real user environment.

Do not access environment variables throughout unrelated modules.

Centralize configuration loading.

## 13. HTTP requirements

All HTTP behavior must be centralized.

Do not call HTTPX directly from unrelated modules.

The HTTP layer must eventually support:

- Timeouts.
- Redirect handling.
- TLS verification.
- Proxy configuration.
- Custom headers.
- Authentication headers.
- Request limits.
- Response size limits.
- Error normalization.
- Evidence capture.
- Controlled retries.
- Conservative concurrency.

Defaults must be safe and non-aggressive.

TLS verification must remain enabled by default.

Tests must not contact real public targets.

Use mocked transports, fixtures or controlled local test servers.

## 14. GraphQL requirements

GraphQL detection must not rely only on HTTP status codes.

A response with status `200` does not prove that an endpoint is GraphQL.

Detection should use multiple signals and preserve supporting evidence.

Schema parsing must be deterministic.

Generated queries must:

- Be syntactically valid.
- Use minimal field selections.
- Respect configurable depth limits.
- Avoid recursive expansion.
- Handle required arguments.
- Use conservative placeholder values.
- Preserve the generated query as evidence.

Safe mode must never execute mutations.

## 15. Security and authorization requirements

GQLSleuth is intended only for authorized security testing.

Agents must preserve this principle across:

- CLI help.
- Documentation.
- Active-mode controls.
- Reports.
- Examples.
- Default behavior.

Safe mode is the default.

Safe mode must not:

- Execute mutations.
- Modify application state.
- Perform brute force.
- Perform denial-of-service testing.
- Generate excessive traffic.
- Attempt automatic authorization bypasses.
- Execute destructive operations.

Active behavior must require explicit user acknowledgement.

The expected authorization gate is:

```bash
--mode active --authorized
```

Do not weaken or bypass this requirement.

Do not introduce functionality that automatically:

- Exploits a target.
- Escalates privileges.
- Brute-forces credentials.
- Exfiltrates sensitive data.
- Performs destructive mutations.
- Generates denial-of-service conditions.

Security findings must be supported by evidence.

The tool should distinguish between:

- Evidence.
- Observation.
- Finding.
- AI-generated interpretation.

Do not label something as a confirmed vulnerability when the evidence only supports a review candidate.

## 16. Sensitive data handling

Never commit:

- API keys.
- Access tokens.
- Passwords.
- Session cookies.
- Private endpoints.
- Customer information.
- Real scan evidence containing sensitive data.
- Secrets in test fixtures.

Sensitive headers must be redacted.

At minimum, redact:

```text
Authorization
Cookie
Proxy-Authorization
X-API-Key
```

Redaction utilities should be centralized and tested.

Use clearly fake values in examples:

```text
TOKEN
example.com
test-token
user@example.com
```

Do not include real targets in automated tests or documentation examples.

## 17. AI integration requirements

AI functionality is optional.

The deterministic engine must remain fully functional without AI.

The planned local AI integration must not:

- Control the HTTP client.
- Execute GraphQL operations.
- Bypass safe-mode restrictions.
- Invent evidence.
- Replace schema parsing.
- Make final security decisions without supporting evidence.
- Receive unredacted secrets.
- Be required for core functionality.

AI-generated content must be clearly labeled.

Ollama unavailability must not break deterministic scanning behavior.

Do not implement AI functionality before its roadmap phase unless explicitly requested.

## 18. Testing requirements

Use pytest.

Tests must be:

- Deterministic.
- Independent.
- Fast enough for regular development.
- Free from external public network dependencies.
- Focused on behavior rather than internal implementation details.

Organize tests under:

```text
tests/
├── unit/
├── integration/
└── fixtures/
```

Create only the directories currently needed.

Each bug fix should include a regression test when practical.

Important areas to test include:

- URL normalization.
- Configuration validation.
- Configuration precedence.
- Header redaction.
- Endpoint candidate generation.
- GraphQL detection signals.
- Introspection result handling.
- Schema parsing.
- Type unwrapping.
- Operation classification.
- Priority scoring.
- Query generation.
- Depth limits.
- Safe-mode restrictions.
- Active-mode authorization.
- Report serialization.
- Error mapping.

Do not reduce test coverage merely to make a failing implementation pass.

## 19. Quality checks

Before considering a task complete, run the checks relevant to the modified code.

Standard checks:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
```

To apply formatting:

```bash
uv run ruff format .
```

Run a narrower test command during development when useful, but run the complete relevant suite before finishing.

Examples:

```bash
uv run pytest tests/unit/test_header_redaction.py
uv run pytest -k "redaction"
```

Do not claim that checks passed unless they were actually executed successfully.

When a check cannot be run, clearly state:

- Which check was not run.
- Why it was not run.
- What remains unverified.

## 20. Dependency policy

Keep dependencies minimal.

Before adding a dependency, determine whether:

- The standard library is sufficient.
- An existing dependency already solves the problem.
- The dependency belongs to the current roadmap phase.
- The dependency is maintained.
- The dependency has an acceptable license.
- The dependency meaningfully reduces complexity.

Do not add dependencies for trivial helpers.

Separate runtime and development dependencies correctly.

Whenever dependencies change:

- Update `pyproject.toml`.
- Update `uv.lock`.
- Ensure installation still works with `uv sync`.
- Document the dependency when user-facing setup changes.

## 21. Error handling

Expected failures should use clear project-specific exceptions.

Avoid exposing low-level infrastructure exceptions directly to CLI users.

Errors should carry enough context for:

- Useful terminal messages.
- Structured evidence.
- Debugging in verbose mode.
- Test assertions.

Do not silently continue after an error when doing so would produce misleading results.

A failure involving one endpoint candidate should not necessarily terminate an entire discovery workflow.

Partial results should be preserved when safe and meaningful.

## 22. Logging and console output

Logging must never expose secrets.

Use appropriate levels:

- DEBUG for implementation details.
- INFO for normal progress.
- WARNING for recoverable problems.
- ERROR for failed operations.
- CRITICAL only for unrecoverable project-level failures.

Do not use `print()` throughout application logic.

Use:

- Rich for user-facing CLI rendering.
- The logging system for diagnostic information.
- Structured models for data passed between layers.

Avoid mixing terminal presentation with domain decisions.

## 23. File and repository hygiene

Do not commit:

- `.venv/`
- Python cache files.
- Local IDE state that is not intentionally shared.
- Test output.
- Coverage output.
- Local secrets.
- Generated reports containing target data.
- Temporary scan artifacts.
- Local Ollama data.

Keep `.gitignore` updated when new generated files are introduced.

Do not modify:

- `uv.lock` manually.
- Generated files manually when they have a defined generation process.

Avoid creating unnecessary files.

Every committed file should have a clear purpose.

## 24. Git changes

Keep changes focused on the requested task.

Do not:

- Reformat unrelated files.
- Rename unrelated modules.
- Modify unrelated documentation.
- Change project-wide conventions without explicit approval.
- Include generated artifacts unless required.

Before finishing, review the diff and check for:

- Accidental secrets.
- Debugging code.
- Temporary comments.
- Unrelated edits.
- Missing tests.
- Missing documentation updates.
- Inconsistent naming.

Suggested commit style:

```text
feat: add initial Typer CLI
fix: redact authorization headers
test: add URL normalization cases
docs: update project roadmap
refactor: centralize configuration loading
chore: configure Ruff and mypy
```

Do not create commits unless explicitly requested.

## 25. Updating the specification

`docs/ARCHITECTURE.md` is a living document.

Update it when a change affects:

- Project scope.
- Architecture.
- Operating modes.
- Safety requirements.
- Technology choices.
- CLI design.
- MVP definition.
- Development roadmap.
- Major functional behavior.

Do not update it for minor implementation details.

When code and specification disagree, do not silently leave them inconsistent.

Either:

- Adjust the implementation to match the specification, or
- Update the specification when the design decision has intentionally changed.

## 26. Completion criteria

A task is complete when:

- The requested behavior is implemented.
- The implementation matches the current phase.
- Relevant tests exist and pass.
- Formatting and linting pass.
- Type checking passes for the affected code.
- Public behavior is documented.
- No secrets or temporary artifacts were introduced.
- The change remains consistent with `docs/ARCHITECTURE.md`.
- Remaining limitations are clearly stated.
- No unrelated functionality was added.

The final response should summarize:

- What changed.
- Which files changed.
- Which checks were run.
- Whether the checks passed.
- Any limitations or follow-up work that remains.

Do not exaggerate the completeness of the implementation.

## 27. Core project principles

All contributions must preserve these principles:

### Deterministic engine first

Core functionality must not depend on AI.

### Safe by default

Read-only and conservative behavior is the default.

### Evidence over claims

Observed evidence must be preserved, and unsupported vulnerability claims must be avoided.

### Authorized testing only

The tool must consistently communicate and enforce its intended lawful use.

### Modular architecture

CLI, domain, application and infrastructure concerns must remain separated.

### Incremental development

Only the requested phase and scope should be implemented.

### Professional quality

The project should demonstrate both cybersecurity knowledge and strong software engineering practices.
