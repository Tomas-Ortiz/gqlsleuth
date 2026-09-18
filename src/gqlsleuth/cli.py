"""CLI options, workflow orchestration, and explicit ACTIVE user interaction."""

import re
import sys
from copy import copy
from dataclasses import replace
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from typer._click import Context, HelpFormatter
from typer.core import TyperGroup

from gqlsleuth import __version__
from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.application.active_execution import (
    ActiveExecutionScanResult,
    ActiveMutationPreviewResult,
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.authorization_policy import evaluate_authorization_policy
from gqlsleuth.application.differential_review import DifferentialScanResult, run_differential_scan
from gqlsleuth.application.multiplicity import execute_multiplicity, prepare_multiplicity
from gqlsleuth.application.mutation_authorization import MutationAuthorizationSession
from gqlsleuth.application.object_authorization import run_object_authorization_scan
from gqlsleuth.application.query_depth import execute_query_depth, prepare_query_depth
from gqlsleuth.application.reporting import generate_reports
from gqlsleuth.application.safe_execution import SafeExecutionScanResult, run_safe_execution_scan
from gqlsleuth.application.scan_configuration import map_auth_context_inputs, map_target_http_inputs
from gqlsleuth.application.sequential_discovery import (
    execute_sequential_discovery,
    prepare_sequential_discovery,
)
from gqlsleuth.domain.active import MAX_MUTATION_EXECUTIONS
from gqlsleuth.domain.authorization_policy import parse_policy_assertions
from gqlsleuth.domain.exceptions import GQLSleuthError, ReportingError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.multiplicity import MultiplicityValidationResult
from gqlsleuth.domain.mutation_authorization import (
    MutationAuthorizationCase,
    MutationAuthorizationResult,
    parse_mutation_cases,
)
from gqlsleuth.domain.object_authorization import parse_object_cases
from gqlsleuth.domain.query_depth import QueryDepthValidationResult
from gqlsleuth.domain.sequential_discovery import (
    SequentialDiscoveryResult,
    SequentialDiscoverySeed,
    parse_discovery_seeds,
)
from gqlsleuth.infrastructure.http import HttpClientSettings
from gqlsleuth.presentation.authorization_policy import render_authorization_policy
from gqlsleuth.presentation.console import (
    CONSOLE_THEME,
    render_active_execution,
    render_active_gate,
    render_ai,
    render_differential,
    render_error,
    render_mutations,
    render_reports,
    render_root_help,
    render_scan,
    render_state_warning,
)
from gqlsleuth.presentation.multiplicity import render_multiplicity, render_probe_previews
from gqlsleuth.presentation.mutation_authorization import render_mutation_authorization
from gqlsleuth.presentation.query_depth import render_depth_previews, render_query_depth
from gqlsleuth.presentation.sequential_discovery import render_sequential_discovery
from gqlsleuth.reporting.models import ReportFormat


class RootHelpGroup(TyperGroup):
    """Keep Typer's header/options and group scan guidance in root command help."""

    def format_help(self, ctx: Context, formatter: HelpFormatter) -> None:
        commands = []
        for name in self.list_commands(ctx):
            command = self.get_command(ctx, name)
            if command is not None and not command.hidden:
                description = command.short_help or command.help or ""
                commands.append((name, " ".join(description.split("\n\n", 1)[0].split())))
        # Suppress only the generated command panel on a presentation copy. The real
        # command registry and each subcommand's help remain untouched.
        header = copy(self)
        header.commands = {}
        TyperGroup.format_help(header, ctx, formatter)
        render_root_help(console, tuple(commands))


app = typer.Typer(
    cls=RootHelpGroup,
    name="gqlsleuth",
    help=(
        "Authorized GraphQL security discovery and analysis. "
        "Use only against systems you are explicitly authorized to test."
    ),
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["--help", "-h"]},
    no_args_is_help=True,
    add_completion=False,
)
console = Console(theme=CONSOLE_THEME)
error_console = Console(stderr=True, theme=CONSOLE_THEME)


@app.command()
def version() -> None:
    """Show the installed GQLSleuth version."""
    console.print(f"GQLSleuth {__version__}")


def _parse_formats(values: list[str] | None) -> tuple[ReportFormat, ...]:
    """Normalize CLI syntax only; serialization remains owned by reporting."""
    formats: list[ReportFormat] = []
    for value in values or ():
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                raise typer.BadParameter(
                    "Empty report format; choose json, markdown, or html.",
                    param_hint="--format / -f",
                )
            try:
                format = ReportFormat(entry)
            except ValueError:
                raise typer.BadParameter(
                    f"Unsupported report format '{entry}'; choose json, markdown, or html.",
                    param_hint="--format / -f",
                ) from None
            if format not in formats:
                formats.append(format)
    return tuple(formats)


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            metavar="TARGET", help="HTTP(S) application URL or direct GraphQL endpoint."
        ),
    ],
    mode: Annotated[
        ScanMode,
        typer.Option(
            "--mode",
            help=(
                "Scan mode: safe | active. Default: safe. "
                "ACTIVE acknowledges active capabilities for an authorized "
                "target; Query-Shape checks, Query-Depth checks and Mutations "
                "require separate explicit "
                "selection and one final batch confirmation."
            ),
            case_sensitive=False,
            show_default=False,
        ),
    ] = ScanMode.SAFE,
    formats: Annotated[
        list[str] | None,
        typer.Option(
            "--format",
            "-f",
            metavar="json|markdown|html",
            help=(
                "Report format: json | markdown | html; comma-separated or repeated. Default: none."
            ),
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "Report output directory. Default: ./gqlsleuth-reports when reports are requested."
            ),
        ),
    ] = None,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai",
            help=("Optional local Ollama/qwen3:8b interpretation. Default: disabled."),
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Detailed analysis, generated Queries, and execution outcomes. Default: disabled.",
        ),
    ] = False,
    headers: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            "-H",
            metavar="NAME: VALUE",
            rich_help_panel="Target HTTP",
            help=(
                "Add a target HTTP header (user-supplied authentication); repeatable. "
                "Default: none. Never sent to Ollama."
            ),
        ),
    ] = None,
    auth_context: Annotated[
        list[str] | None,
        typer.Option(
            "--auth-context",
            metavar="LABEL[=NAME: VALUE]",
            rich_help_panel="Authorization Differential Review",
            help=(
                "Compare 2–3 user-named HTTP contexts in SAFE mode. Repeat a label to add headers; "
                "a bare label has no supplied headers. Labels imply no privilege order. "
                "Cannot combine with --header, ACTIVE, or --ai. Default: disabled."
            ),
        ),
    ] = None,
    timeout: Annotated[
        str | None,
        typer.Option(
            "--timeout",
            metavar="SECONDS",
            rich_help_panel="Target HTTP",
            help=(
                "Positive target HTTP timeout. An explicit value applies to all target stages. "
                "Default: discovery 8s, other target requests 10s. Does not affect Ollama."
            ),
        ),
    ] = None,
    proxy: Annotated[
        str | None,
        typer.Option(
            "--proxy",
            metavar="URL",
            rich_help_panel="Target HTTP",
            help=("Explicit HTTP(S) target proxy. Default: none. Environment proxies are ignored."),
        ),
    ] = None,
    verify_tls: Annotated[
        bool,
        typer.Option(
            "--verify-tls/--no-verify-tls",
            rich_help_panel="Target HTTP",
            help=(
                "Enable or disable target TLS verification. Default: enabled. "
                "Disabling is insecure. Does not affect Ollama."
            ),
            show_default=False,
        ),
    ] = True,
    nested_auth_review: Annotated[
        bool,
        typer.Option(
            "--nested-auth-review",
            rich_help_panel="Authorization Differential Review",
            help="Opt-in SAFE nested-path review across named contexts. Default: disabled.",
            show_default=False,
        ),
    ] = False,
    object_auth_review: Annotated[
        bool,
        typer.Option(
            "--object-auth-review",
            rich_help_panel="Authorization Differential Review",
            help="SAFE validation of exact operator-supplied objects. Default: disabled.",
            show_default=False,
        ),
    ] = False,
    object_auth_case: Annotated[
        list[str] | None,
        typer.Option(
            "--object-auth-case",
            rich_help_panel="Authorization Differential Review",
            metavar="[CONTEXT:]OPERATION:ARGUMENT=ID",
            help="Exact object case; repeat up to three. Requires --object-auth-review.",
        ),
    ] = None,
    auth_policy_review: Annotated[
        bool,
        typer.Option(
            "--auth-policy-review",
            rich_help_panel="Authorization Differential Review",
            help="Local DENY policy validation; requires --object-auth-review. Default: disabled.",
            show_default=False,
        ),
    ] = False,
    expect_deny: Annotated[
        list[str] | None,
        typer.Option(
            "--expect-deny",
            metavar="CASE[:CONTEXT]",
            rich_help_panel="Authorization Differential Review",
            help=(
                "Operator-supplied DENY for an object authorization case; repeat up to nine. "
                "Requires --auth-policy-review."
            ),
        ),
    ] = None,
    mutation_auth_review: Annotated[
        bool,
        typer.Option(
            "--mutation-auth-review",
            rich_help_panel="Mutation Authorization Validation",
            help=(
                "Assert DENY for one exact Mutation/object in the current HTTP context. "
                "ACTIVE and independent confirmation required. Default: disabled."
            ),
            show_default=False,
        ),
    ] = False,
    mutation_auth_case: Annotated[
        list[str] | None,
        typer.Option(
            "--mutation-auth-case",
            metavar="OPERATION:ARGUMENT=ID",
            rich_help_panel="Mutation Authorization Validation",
            help=(
                "One exact textual object ID; requires --mutation-auth-review. "
                "Maximum one case/request."
            ),
        ),
    ] = None,
    idor_discovery: Annotated[
        bool,
        typer.Option(
            "--idor-discovery",
            rich_help_panel="Active Object Discovery",
            help=(
                "Bounded adjacent numeric object discovery; ACTIVE and separate confirmation "
                "required. Default: disabled."
            ),
            show_default=False,
        ),
    ] = False,
    idor_seed: Annotated[
        list[str] | None,
        typer.Option(
            "--idor-seed",
            metavar="OPERATION:ARGUMENT=ID",
            rich_help_panel="Active Object Discovery",
            help="Canonical unsigned decimal seed; repeat up to two. Requires --idor-discovery.",
        ),
    ] = None,
) -> None:
    """Discover and analyze GraphQL; safely execute validated Query operations."""
    report_formats = _parse_formats(formats)
    if output is not None and not report_formats:
        render_error(error_console, "--output / -o requires at least one --format / -f.")
        raise typer.Exit(code=2)
    try:
        if mutation_auth_case is not None and not mutation_auth_review:
            raise GQLSleuthError("--mutation-auth-case requires --mutation-auth-review.")
        if mutation_auth_review and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError(
                "Mutation authorization requires ACTIVE single-context mode without --auth-context."
            )
        mutation_cases = (
            parse_mutation_cases(mutation_auth_case or []) if mutation_auth_review else ()
        )
        if idor_seed is not None and not idor_discovery:
            raise GQLSleuthError("--idor-seed requires --idor-discovery.")
        if idor_discovery and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError(
                "--idor-discovery requires ACTIVE single-context mode without --auth-context."
            )
        discovery_seeds = parse_discovery_seeds(idor_seed or []) if idor_discovery else ()
        if expect_deny is not None and not auth_policy_review:
            raise GQLSleuthError("--expect-deny requires --auth-policy-review.")
        if auth_policy_review and not object_auth_review:
            raise GQLSleuthError("--auth-policy-review requires --object-auth-review.")
        if object_auth_case and not object_auth_review:
            raise GQLSleuthError("--object-auth-case requires --object-auth-review.")
        if object_auth_review and (mode is not ScanMode.SAFE or headers):
            raise GQLSleuthError(
                "Object authorization review requires SAFE mode without common --header values."
            )
        if nested_auth_review and auth_context is None:
            raise GQLSleuthError(
                "--nested-auth-review requires --auth-context (2–3 SAFE contexts)."
            )
        contexts = (
            map_auth_context_inputs(
                auth_context, headers=headers, mode=mode, ai=ai, object_review=object_auth_review
            )
            if auth_context is not None
            else None
        )
        object_cases = (
            parse_object_cases(object_auth_case or [], tuple(item.name for item in contexts or ()))
            if object_auth_review
            else ()
        )
        policy_assertions = (
            parse_policy_assertions(
                expect_deny or [],
                cases=object_cases,
                context_names=tuple(item.name for item in contexts or ()),
            )
            if auth_policy_review
            else ()
        )
        if nested_auth_review and len(contexts or ()) < 2:
            raise GQLSleuthError("Nested review requires 2–3 named contexts.")
    except GQLSleuthError as error:
        render_error(error_console, str(error))
        raise typer.Exit(code=2) from None
    if mode is ScanMode.ACTIVE:
        render_active_gate(console)
    try:
        http_settings = map_target_http_inputs(
            headers=headers, timeout=timeout, verify_tls=verify_tls, proxy=proxy
        )
        if not http_settings.verify_tls:
            console.print(
                "WARNING: TLS certificate verification is disabled for target requests.",
                style="gql.warning",
            )
        result: DifferentialScanResult | SafeExecutionScanResult
        if object_auth_review:
            result = run_object_authorization_scan(
                target,
                cases=object_cases,
                contexts=contexts or (),
                mode=mode,
                http_settings=http_settings,
                nested_auth_review=nested_auth_review,
            )
        elif contexts is not None:
            if nested_auth_review:
                result = run_differential_scan(
                    target,
                    contexts=contexts,
                    http_settings=http_settings,
                    mode=mode,
                    nested_auth_review=True,
                )
            else:
                result = run_differential_scan(
                    target, contexts=contexts, http_settings=http_settings, mode=mode
                )
        else:
            result = run_safe_execution_scan(target, mode=mode, http_settings=http_settings)
        if auth_policy_review:
            result = replace(
                result,
                authorization_policy_validation=evaluate_authorization_policy(
                    result.object_authorization_review,
                    assertions=policy_assertions,
                    cases=object_cases,
                    context_names=tuple(item.name for item in contexts or ()),
                    enabled=True,
                    object_review_enabled=object_auth_review,
                    mode=mode,
                ),
            )
    except GQLSleuthError as error:
        render_error(error_console, str(error))
        raise typer.Exit(code=2) from None

    if isinstance(result, DifferentialScanResult):
        render_differential(console, result, verbose=verbose)
        if result.nested_authorization_review is not None:
            from gqlsleuth.presentation.nested_authorization import render_nested_authorization

            render_nested_authorization(
                console, result.nested_authorization_review, verbose=verbose
            )
        if result.object_authorization_review is not None:
            from gqlsleuth.presentation.object_authorization import render_object_authorization

            render_object_authorization(
                console, result.object_authorization_review, verbose=verbose
            )
        if result.authorization_policy_validation is not None:
            render_authorization_policy(
                console, result.authorization_policy_validation, verbose=verbose
            )
        _finish_reports(result, report_formats, output)
        return
    render_scan(console, result, verbose=verbose)
    if result.object_authorization_review is not None:
        from gqlsleuth.presentation.object_authorization import render_object_authorization

        render_object_authorization(console, result.object_authorization_review, verbose=verbose)
    if result.authorization_policy_validation is not None:
        render_authorization_policy(
            console, result.authorization_policy_validation, verbose=verbose
        )
    schema_scan = result.query_generation.operation_analysis.schema_scan
    mode = schema_scan.introspection.detection.discovery.mode
    report_result: SafeExecutionScanResult | ActiveExecutionScanResult = result
    if mode is ScanMode.ACTIVE:
        multiplicity = _run_multiplicity_stage(result, http_settings=http_settings, verbose=verbose)
        query_depth = _run_depth_stage(result, http_settings=http_settings, verbose=verbose)
        sequential = (
            _run_sequential_stage(
                result, seeds=discovery_seeds, http_settings=http_settings, verbose=verbose
            )
            if idor_discovery
            else None
        )
        mutation_authorization = (
            _run_mutation_authorization_stage(
                result, cases=mutation_cases, http_settings=http_settings
            )
            if mutation_auth_review
            else None
        )
        report_result = replace(
            _run_active_stage(result, http_settings=http_settings),
            multiplicity=multiplicity,
            query_depth=query_depth,
            sequential_object_discovery=sequential,
            mutation_authorization=mutation_authorization,
        )
    ai_result = None
    if ai:
        console.print("AI assistance: interpreting the completed scan with local qwen3:8b...")
        ai_result = interpret_completed_scan(report_result)
        render_ai(console, ai_result, verbose=verbose)
    _finish_reports(report_result, report_formats, output, ai_result)


def _finish_reports(
    result: SafeExecutionScanResult | ActiveExecutionScanResult | DifferentialScanResult,
    report_formats: tuple[ReportFormat, ...],
    output: Path | None,
    ai_result: AIInterpretationResult | None = None,
) -> None:
    if report_formats:
        try:
            paths = generate_reports(
                result,
                formats=report_formats,
                output_directory=output,
                ai_interpretation=ai_result,
            )
        except ReportingError as error:
            render_error(error_console, str(error), label="Reporting error")
            raise typer.Exit(code=1) from None
        render_reports(console, paths)


def _interactive_stdin() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def _run_multiplicity_stage(
    safe: SafeExecutionScanResult,
    *,
    http_settings: HttpClientSettings | None = None,
    verbose: bool = False,
) -> MultiplicityValidationResult:
    preview = prepare_multiplicity(safe)
    render_probe_previews(
        console, tuple(enumerate(preview.candidates, 1)), title="Active Query-Shape candidates"
    )
    selected: tuple[int, ...] = ()
    confirmed = False
    if not preview.candidates:
        console.print("No eligible Query-Shape candidates.")
    elif not _interactive_stdin():
        console.print(
            "Interactive selection and confirmation are required; zero Query-Shape checks execute."
        )
    else:
        try:
            while True:
                value = typer.prompt(
                    "Select active Query-Shape checks to execute (max 2, Enter for none)",
                    default="",
                    show_default=False,
                ).strip()
                if not value:
                    selected = ()
                    break
                indices = {str(index): index for index in range(1, len(preview.candidates) + 1)}
                tokens = tuple(token.strip().lstrip("0") or "0" for token in value.split(","))
                if re.fullmatch(r"[0-9]+(?:\s*,\s*[0-9]+)*", value) is None or any(
                    token not in indices for token in tokens
                ):
                    console.print(
                        "Choose individual comma-separated Query-Shape candidate indices."
                    )
                    continue
                selected = tuple(sorted({indices[token] for token in tokens}))
                if len(selected) > 2:
                    console.print("Select at most 2 Query-Shape checks.")
                    continue
                render_probe_previews(
                    console,
                    tuple((index, preview.candidates[index - 1]) for index in selected),
                    title="Selected Query-Shape checks",
                )
                confirmed = typer.confirm(
                    f"Execute these {len(selected)} selected active Query-Shape checks?",
                    default=False,
                )
                break
        except (typer.Abort, EOFError, KeyboardInterrupt):
            selected, confirmed = (), False
            console.print("Query-Shape selection/confirmation cancelled.")
    result = execute_multiplicity(
        preview, selected_indices=selected, confirmed=confirmed, http_settings=http_settings
    )
    render_multiplicity(console, result, verbose=verbose)
    return result


def _run_sequential_stage(
    safe: SafeExecutionScanResult,
    *,
    seeds: tuple[SequentialDiscoverySeed, ...],
    http_settings: HttpClientSettings,
    verbose: bool = False,
) -> SequentialDiscoveryResult:
    preview = prepare_sequential_discovery(
        safe, seeds=seeds, enabled=True, http_settings=http_settings
    )
    render_sequential_discovery(console, preview, preview=True, verbose=verbose)
    confirmed = False
    if not preview.probes:
        console.print("No eligible sequential-discovery requests.")
    elif not _interactive_stdin():
        console.print(
            "Interactive confirmation is required; zero sequential-discovery requests execute."
        )
    else:
        try:
            confirmed = typer.confirm("Execute bounded sequential object discovery?", default=False)
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("Sequential-discovery confirmation cancelled.")
    result = execute_sequential_discovery(
        safe,
        seeds=seeds,
        enabled=True,
        confirmed=confirmed,
        preview=preview,
        http_settings=http_settings,
    )
    render_sequential_discovery(console, result, verbose=verbose)
    return result


def _run_mutation_authorization_stage(
    safe: SafeExecutionScanResult,
    *,
    cases: tuple[MutationAuthorizationCase, ...],
    http_settings: HttpClientSettings,
) -> MutationAuthorizationResult:
    session = MutationAuthorizationSession(
        safe, cases=cases, enabled=True, http_settings=http_settings
    )
    preview = session.preview
    render_mutation_authorization(console, preview, preview=True)
    confirmed = False
    if preview.probe is None:
        console.print("No eligible Mutation authorization request.")
    elif not _interactive_stdin():
        console.print(
            "Interactive confirmation is required; zero Mutation authorization requests execute."
        )
    else:
        try:
            confirmed = typer.confirm("Execute mutation authorization validation?", default=False)
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("Mutation authorization confirmation cancelled.")
    result = session.execute(preview=preview, confirmed=confirmed)
    render_mutation_authorization(console, result)
    return result


def _run_active_stage(
    safe_result: SafeExecutionScanResult, *, http_settings: HttpClientSettings | None = None
) -> ActiveExecutionScanResult:
    preview = prepare_active_mutations(safe_result)
    render_mutations(
        console, tuple(enumerate(preview.candidates, start=1)), title="Active Mutation candidates:"
    )
    selected: tuple[int, ...] = ()
    confirmed = False
    if not preview.candidates:
        console.print("No Mutation candidates.")
    elif not _interactive_stdin():
        console.print(
            "Interactive selection and confirmation are required; zero Mutations will execute."
        )
    elif not any(candidate.selectable for candidate in preview.candidates):
        console.print("No executable Mutation candidates.")
    else:
        try:
            selected = _select_mutations(preview)
            if selected:
                render_mutations(
                    console,
                    tuple((index, preview.candidates[index - 1]) for index in selected),
                    title="Selected Mutations:",
                )
                render_state_warning(console)
                confirmed = typer.confirm(
                    f"Execute these {len(selected)} selected Mutations?", default=False
                )
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("Mutation selection/confirmation cancelled; zero Mutations will execute.")
    result = execute_selected_mutations(
        preview, selected_indices=selected, confirmed=confirmed, http_settings=http_settings
    )
    render_active_execution(console, result)
    return result


def _run_depth_stage(
    safe: SafeExecutionScanResult,
    *,
    http_settings: HttpClientSettings | None = None,
    verbose: bool = False,
) -> QueryDepthValidationResult:
    preview = prepare_query_depth(safe)
    render_depth_previews(
        console, tuple(enumerate(preview.candidates, 1)), title="Active Query-Depth candidates"
    )
    selected: tuple[int, ...] = ()
    confirmed = False
    if not preview.candidates:
        console.print("No eligible Query-Depth candidates.")
    elif not _interactive_stdin():
        console.print(
            "Interactive selection and confirmation are required; zero Query-Depth checks execute."
        )
    else:
        try:
            while True:
                value = typer.prompt(
                    "Select active Query-Depth checks to execute (max 1, Enter for none)",
                    default="",
                    show_default=False,
                ).strip()
                if not value:
                    selected = ()
                    break
                indices = {str(index): index for index in range(1, len(preview.candidates) + 1)}
                tokens = tuple(token.strip().lstrip("0") or "0" for token in value.split(","))
                if re.fullmatch(r"[0-9]+(?:\s*,\s*[0-9]+)*", value) is None or any(
                    token not in indices for token in tokens
                ):
                    console.print("Choose an individual Query-Depth candidate index.")
                    continue
                selected = tuple(sorted({indices[token] for token in tokens}))
                if len(selected) > 1:
                    console.print("Select at most 1 Query-Depth check.")
                    continue
                render_depth_previews(
                    console,
                    tuple((index, preview.candidates[index - 1]) for index in selected),
                    title="Selected Query-Depth check",
                )
                confirmed = typer.confirm(
                    "Execute this selected active Query-Depth check?", default=False
                )
                break
        except (typer.Abort, EOFError, KeyboardInterrupt):
            selected, confirmed = (), False
            console.print("Query-Depth selection/confirmation cancelled.")
    result = execute_query_depth(
        preview, selected_indices=selected, confirmed=confirmed, http_settings=http_settings
    )
    render_query_depth(console, result, verbose=verbose)
    return result


def _select_mutations(preview: ActiveMutationPreviewResult) -> tuple[int, ...]:
    while True:
        value = typer.prompt(
            "Select Mutations to execute (max 5, Enter for none)", default="", show_default=False
        ).strip()
        if not value:
            return ()
        if re.fullmatch(r"[0-9]+(?:\s*,\s*[0-9]+)*", value) is None:
            console.print("Enter individual comma-separated indices only (for example, 1,3).")
            continue
        # Compare normalized decimal strings first to avoid unbounded integer conversion.
        indices = {str(index): index for index in range(1, len(preview.candidates) + 1)}
        tokens = tuple(token.strip().lstrip("0") or "0" for token in value.split(","))
        if any(token not in indices for token in tokens):
            console.print("Unknown Mutation index; choose only executable candidate indices.")
            continue
        selected = tuple(sorted({indices[token] for token in tokens}))
        if len(selected) > MAX_MUTATION_EXECUTIONS:
            console.print("Select at most 5 Mutations.")
            continue
        if any(not preview.candidates[index - 1].selectable for index in selected):
            console.print("Blocked or failed Mutation candidates cannot be selected.")
            continue
        return selected


def main() -> None:
    """Run the command-line application."""
    app()
