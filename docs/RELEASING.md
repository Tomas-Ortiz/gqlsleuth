# Release procedure

This is a manual maintainer checklist, not publishing automation. No v1.0 release is declared
by adding this document. PyPI project-name availability and publication rights must be checked
separately when publication is planned; do not assume `pip install gqlsleuth` is available.

## Version authority

Edit only `[project].version` in `pyproject.toml` to change the product version. Installed
`gqlsleuth.__version__`, `gqlsleuth version`, report metadata and the HTTP user agent read the
distribution metadata through `importlib.metadata`. There is no root `--version` option.
After a version edit run `uv lock` and `uv sync --locked` to regenerate lock/install metadata;
never manually edit the lockfile or insert another version literal in Python code.

Source-only imports without distribution metadata report `0+unknown`, not a guessed release.
Use `uv sync --locked` for normal development. An existing editable environment must be
resynchronized after a version bump. The artifact gate rejects mismatched versions.

## Validation and artifact gate

Use Python 3.13 and uv. CI configures source-quality and installed-package jobs on both
`ubuntu-latest` and `windows-latest`. macOS is not CI-validated. `Requires-Python >=3.13` describes
installation eligibility, not a claim that newer interpreters have been validated. Successful
matrix runs are required for release; adding the workflow alone is not evidence of a passing run.

From a clean checkout:

```bash
uv lock --check
uv sync --locked
uv run gqlsleuth --help
uv run gqlsleuth scan --help
uv run gqlsleuth version
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
uv build
git diff --check
uv run python scripts/check_release_artifacts.py
```

The artifact checker uses a fresh temporary directory outside the checkout. It builds and
inspects a wheel and sdist, extracts the sdist using the standard safe tar filter, and builds
another wheel from those extracted sources. For **each** wheel it creates a separate environment,
performs normal dependency resolution/installation, checks dependency consistency, runs the
installed console commands, loads rules/templates and renders JSON/Markdown/HTML from a mocked
SAFE scan. It verifies the import location, version agreement and absence of developer tools.

The smoke uses only a fake loopback target. All pipeline HTTP transports are mocked. Python
audit hooks block socket/DNS activity in the smoke and its console-command children; the guard
is checked before scanning. Four mock requests execute one Query. Report generation adds none.
No Ollama service, real credentials, live target or publisher is involved. The checker needs
package-index access for build dependencies/runtime resolution, **not** for target scanning.

For a cached-only local run:

```bash
uv run python scripts/check_release_artifacts.py --offline
```

Missing dependency archives make that command fail. Do not replace the release gate with
`--no-deps`, copied dependencies or an editable checkout. Normal pytest remains offline: its
artifact regression builds/inspects locally without performing fresh dependency installation.
Temporary gate artifacts are removed on exit; the separately built `dist/` files remain available
for inspection. The source archive includes this checklist, the changelog and release scripts.

## Future publication checklist — manual, separately authorized

1. Confirm a clean working tree, intended source revision and passing source/artifact CI jobs on
   both operating systems. Review unresolved release-readiness items.
2. Run the validation above; review wheel metadata, contents and the installed smoke output.
3. Confirm metadata/package/CLI versions agree. Check package ownership/name availability and
   the chosen publishing process separately; do not create credentials as part of validation.
4. When release criteria pass, move relevant `[Unreleased]` changes into a dated release entry.
5. Set the intended release version in the single authority described above; regenerate metadata.
   Keep the Beta classifier until stability criteria justify changing it.
6. Re-run validation and the artifact gate at the final version. Build into a new empty output
   directory, inspect those exact wheel/sdist files and record their hashes. Do not reuse stale
   artifacts from an earlier version or source revision.
7. After explicit release approval, commit the reviewed release changes and create the matching
   version tag. This checklist does not authorize those actions by itself.
8. Publish only the reviewed artifacts using the approved manual process. Publishing credentials,
   trusted publishing and write-enabled CI are deliberately not configured here.
9. After publication, resolve/install the public version into a fresh environment and repeat the
   offline CLI/resource/report smoke. Verify the published version and hashes, then update user
   installation documentation to describe commands that actually work.

Runtime lower bounds remain intentional and unchanged. The lockfile governs repository testing;
the separate artifact gate exercises normal resolution of public package constraints. It must
pass again for the final release artifacts.
