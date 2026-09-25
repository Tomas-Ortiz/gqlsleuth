"""CLI options, workflow orchestration, and explicit ACTIVE user interaction."""

import re
import sys
from copy import copy
from dataclasses import replace
from pathlib import Path
from typing import Annotated

import typer
from pydantic import JsonValue
from rich.console import Console
from rich.text import Text
from typer._click import Context, HelpFormatter
from typer.core import TyperGroup

from gqlsleuth import __version__
from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.application.abuse_controls import AbuseControlSession, prepare_abuse_controls
from gqlsleuth.application.active_execution import (
    ActiveExecutionScanResult,
    ActiveMutationPreviewResult,
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.authentication import (
    AuthenticationSecuritySession,
    bearer_token,
    prepare_authentication_security,
)
from gqlsleuth.application.authorization_policy import evaluate_authorization_policy
from gqlsleuth.application.differential_review import DifferentialScanResult, run_differential_scan
from gqlsleuth.application.federation import FederationSecuritySession
from gqlsleuth.application.file_upload import FileUploadSecuritySession
from gqlsleuth.application.idor import IdorSession
from gqlsleuth.application.multiplicity import execute_multiplicity, prepare_multiplicity
from gqlsleuth.application.mutation_authorization import MutationAuthorizationSession
from gqlsleuth.application.object_authorization import run_object_authorization_scan
from gqlsleuth.application.query_depth import execute_query_depth, prepare_query_depth
from gqlsleuth.application.reporting import generate_reports
from gqlsleuth.application.safe_execution import SafeExecutionScanResult, run_safe_execution_scan
from gqlsleuth.application.scan_configuration import map_auth_context_inputs, map_target_http_inputs
from gqlsleuth.application.sensitive_input import SensitiveInputSession
from gqlsleuth.application.sequential_discovery import (
    execute_sequential_discovery,
    prepare_sequential_discovery,
)
from gqlsleuth.application.subscriptions import SubscriptionSecuritySession
from gqlsleuth.domain.abuse_controls import AbuseControlResult
from gqlsleuth.domain.active import MAX_MUTATION_EXECUTIONS
from gqlsleuth.domain.authentication import AuthenticationProbe, AuthenticationSecurityResult
from gqlsleuth.domain.authorization_policy import parse_policy_assertions
from gqlsleuth.domain.exceptions import GQLSleuthError, ReportingError
from gqlsleuth.domain.federation import FederationSecurityResult, parse_entity_case
from gqlsleuth.domain.file_upload import (
    UPLOAD_VARIANTS,
    FileUploadCase,
    FileUploadSecurityResult,
    parse_upload_case,
)
from gqlsleuth.domain.idor import IdorDetectionResult
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.multiplicity import MultiplicityValidationResult
from gqlsleuth.domain.mutation_authorization import (
    MutationAuthorizationCase,
    MutationAuthorizationResult,
    parse_mutation_cases,
)
from gqlsleuth.domain.object_authorization import parse_object_cases
from gqlsleuth.domain.query_depth import QueryDepthValidationResult
from gqlsleuth.domain.sensitive_input import (
    SensitiveInputCase,
    SensitiveInputValidationResult,
    parse_sensitive_case,
)
from gqlsleuth.domain.sequential_discovery import (
    SequentialDiscoveryResult,
    SequentialDiscoverySeed,
    parse_discovery_seeds,
)
from gqlsleuth.domain.subscriptions import SubscriptionSecurityResult
from gqlsleuth.graphql.subscriptions import parse_subscription_object
from gqlsleuth.infrastructure.http import HttpClientSettings
from gqlsleuth.infrastructure.upload_file import read_upload_file
from gqlsleuth.presentation.abuse_controls import render_abuse_controls
from gqlsleuth.presentation.authentication import PROBE_LABELS, render_authentication
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
from gqlsleuth.presentation.federation import render_federation
from gqlsleuth.presentation.file_upload import render_file_upload
from gqlsleuth.presentation.idor import render_idor
from gqlsleuth.presentation.multiplicity import render_multiplicity, render_probe_previews
from gqlsleuth.presentation.mutation_authorization import render_mutation_authorization
from gqlsleuth.presentation.query_depth import render_depth_previews, render_query_depth
from gqlsleuth.presentation.sensitive_input import render_sensitive_validation
from gqlsleuth.presentation.sequential_discovery import render_sequential_discovery
from gqlsleuth.presentation.subscriptions import render_subscriptions
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
                "One header-bearing label is allowed with ACTIVE --idor-review only. "
                "Cannot combine with --header or --ai. Default: disabled."
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
    sensitive_input_review: Annotated[
        bool,
        typer.Option(
            "--sensitive-input-review",
            rich_help_panel="Sensitive Input Validation",
            help=(
                "Assert DENY for one explicit field/value. ACTIVE and independent "
                "confirmation required. Default: disabled."
            ),
            show_default=False,
        ),
    ] = False,
    sensitive_input_case: Annotated[
        list[str] | None,
        typer.Option(
            "--sensitive-input-case",
            metavar="CASE",
            rich_help_panel="Sensitive Input Validation",
            help=(
                "OPERATION:INPUT.FIELD=VALUE; one detected direct input leaf and exact value. "
                "Requires --sensitive-input-review."
            ),
        ),
    ] = None,
    sensitive_input_target: Annotated[
        str | None,
        typer.Option(
            "--sensitive-input-target",
            metavar="ARGUMENT=ID",
            rich_help_panel="Sensitive Input Validation",
            help=(
                "Exact target ID, required when the Mutation exposes one direct ID argument. "
                "Default: none."
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
    subscription_review: Annotated[
        bool,
        typer.Option(
            "--subscription-review",
            rich_help_panel="Subscriptions & GraphQL over WebSocket",
            show_default=False,
            help=(
                "ACTIVE: one selected Subscription, one socket, one event; "
                "separate confirmation. Default: disabled."
            ),
        ),
    ] = False,
    subscription_expect_deny: Annotated[
        bool,
        typer.Option(
            "--subscription-expect-deny",
            rich_help_panel="Subscriptions & GraphQL over WebSocket",
            show_default=False,
            help="Explicit operator DENY policy; requires --subscription-review. Default: observe.",
        ),
    ] = False,
    subscription_variables: Annotated[
        list[str] | None,
        typer.Option(
            "--subscription-variables",
            rich_help_panel="Subscriptions & GraphQL over WebSocket",
            show_default=False,
            help="One JSON object replacing generated variables only; maximum 4096 bytes.",
        ),
    ] = None,
    subscription_init_payload: Annotated[
        list[str] | None,
        typer.Option(
            "--subscription-init-payload",
            rich_help_panel="Subscriptions & GraphQL over WebSocket",
            show_default=False,
            help="One private connection_init JSON object, maximum 4096 bytes; never reported.",
        ),
    ] = None,
    subscription_ws_url: Annotated[
        str | None,
        typer.Option(
            "--subscription-ws-url",
            rich_help_panel="Subscriptions & GraphQL over WebSocket",
            show_default=False,
            help="Explicit ws/wss path on the retained HTTP origin; no endpoint discovery.",
        ),
    ] = None,
    federation_review: Annotated[
        bool,
        typer.Option(
            "--federation-review",
            rich_help_panel="Federation Security",
            show_default=False,
            help=(
                "ACTIVE federation validation, one selected endpoint, at most two requests; "
                "separate confirmation. Default: disabled."
            ),
        ),
    ] = False,
    federation_sdl_expect_deny: Annotated[
        bool,
        typer.Option(
            "--federation-sdl-expect-deny",
            rich_help_panel="Federation Security",
            show_default=False,
            help=(
                "Explicit operator DENY policy for SDL; requires --federation-review. "
                "Default: observe only."
            ),
        ),
    ] = False,
    federation_entity_case: Annotated[
        list[str] | None,
        typer.Option(
            "--federation-entity-case",
            rich_help_panel="Federation Security",
            show_default=False,
            help=(
                "One flat JSON representation (__typename plus 1–3 keys), expected DENY; "
                "requires --federation-review."
            ),
        ),
    ] = None,
    file_upload_review: Annotated[
        bool,
        typer.Option(
            "--file-upload-review",
            rich_help_panel="File Upload Security",
            show_default=False,
            help=(
                "ACTIVE single-file baseline and selected DENY variants; separate confirmation. "
                "Default: disabled."
            ),
        ),
    ] = False,
    upload_case: Annotated[
        list[str] | None,
        typer.Option(
            "--upload-case",
            rich_help_panel="File Upload Security",
            show_default=False,
            help="One OPERATION:ARGUMENT[.FIELD...] Upload path; requires --file-upload-review.",
        ),
    ] = None,
    upload_file: Annotated[
        list[Path] | None,
        typer.Option(
            "--upload-file",
            rich_help_panel="File Upload Security",
            show_default=False,
            help="One benign known-valid local file, maximum 1 MiB; requires --file-upload-review.",
        ),
    ] = None,
    upload_content_type: Annotated[
        str | None,
        typer.Option(
            "--upload-content-type",
            rich_help_panel="File Upload Security",
            show_default=False,
            help=(
                "Baseline MIME type/subtype; otherwise inferred from filename, "
                "then application/octet-stream."
            ),
        ),
    ] = None,
    rate_limit_review: Annotated[
        bool,
        typer.Option(
            "--rate-limit-review",
            rich_help_panel="Rate Limiting & Abuse Controls",
            help=(
                "ACTIVE exact-request repeats: max 5 Query or 3 Mutation requests. "
                "Separate selection/confirmation required. Default: disabled."
            ),
            show_default=False,
        ),
    ] = False,
    auth_security_review: Annotated[
        bool,
        typer.Option(
            "--auth-security-review",
            rich_help_panel="Authentication & Token Security",
            help=(
                "Inspect supplied Bearer token; ACTIVE, one successful Query and separate "
                "confirmation required for up to three probes. Default: disabled."
            ),
            show_default=False,
        ),
    ] = False,
    idor_review: Annotated[
        bool,
        typer.Option(
            "--idor-review",
            rich_help_panel="IDOR / BOLA Detection",
            help=(
                "ACTIVE bounded IDOR/BOLA testing with separate confirmation. Anonymous: seed "
                "and neighbors expected DENY. Supplied context: seed ALLOW baseline, neighbors "
                "DENY. These are operator policy assumptions. Default: disabled."
            ),
            show_default=False,
        ),
    ] = False,
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
            help=(
                "Canonical unsigned decimal seed; repeat up to two. "
                "Requires --idor-discovery or --idor-review."
            ),
        ),
    ] = None,
) -> None:
    """Discover and analyze GraphQL; safely execute validated Query operations."""
    report_formats = _parse_formats(formats)
    if output is not None and not report_formats:
        render_error(error_console, "--output / -o requires at least one --format / -f.")
        raise typer.Exit(code=2)
    try:
        selected_upload_case = None
        if (
            subscription_expect_deny
            or subscription_variables is not None
            or subscription_init_payload is not None
            or subscription_ws_url is not None
        ) and not subscription_review:
            raise GQLSleuthError("Subscription options require --subscription-review.")
        if subscription_review and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError("Subscription review requires ACTIVE mode without --auth-context.")
        subscription_overrides = parse_subscription_object(subscription_variables or [])
        subscription_init = parse_subscription_object(subscription_init_payload or [])
        if (
            federation_sdl_expect_deny or federation_entity_case is not None
        ) and not federation_review:
            raise GQLSleuthError("Federation policy/case requires --federation-review.")
        if federation_review and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError("Federation review requires ACTIVE mode without --auth-context.")
        federation_case = parse_entity_case(federation_entity_case or [])
        if (
            upload_case is not None or upload_file is not None or upload_content_type is not None
        ) and not file_upload_review:
            raise GQLSleuthError("Upload options require --file-upload-review.")
        if file_upload_review:
            if mode is not ScanMode.ACTIVE or auth_context is not None:
                raise GQLSleuthError(
                    "File upload review requires ACTIVE mode without --auth-context."
                )
            selected_upload_case = parse_upload_case(upload_case or [])
            if not upload_file or len(upload_file) != 1:
                raise GQLSleuthError("File upload review requires exactly one --upload-file.")
            read_upload_file(upload_file[0], upload_content_type)
        if rate_limit_review and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError("--rate-limit-review requires ACTIVE mode without --auth-context.")
        if auth_security_review and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError(
                "--auth-security-review requires ACTIVE mode without --auth-context."
            )
        if (
            sensitive_input_case is not None or sensitive_input_target is not None
        ) and not sensitive_input_review:
            raise GQLSleuthError("Sensitive input case/target requires --sensitive-input-review.")
        if sensitive_input_review and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError(
                "Sensitive input validation requires ACTIVE single-context mode "
                "without --auth-context."
            )
        sensitive_case = (
            parse_sensitive_case(sensitive_input_case or [], sensitive_input_target)
            if sensitive_input_review
            else None
        )
        if mutation_auth_case is not None and not mutation_auth_review:
            raise GQLSleuthError("--mutation-auth-case requires --mutation-auth-review.")
        if mutation_auth_review and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError(
                "Mutation authorization requires ACTIVE single-context mode without --auth-context."
            )
        mutation_cases = (
            parse_mutation_cases(mutation_auth_case or []) if mutation_auth_review else ()
        )
        if idor_review and (mode is not ScanMode.ACTIVE or idor_discovery):
            raise GQLSleuthError(
                "--idor-review requires ACTIVE mode and cannot combine with --idor-discovery."
            )
        if idor_review and not idor_seed:
            raise GQLSleuthError("--idor-review requires --idor-seed.")
        if idor_review and nested_auth_review:
            raise GQLSleuthError("IDOR/BOLA does not perform named-context differential review.")
        if idor_seed is not None and not (idor_discovery or idor_review):
            raise GQLSleuthError("--idor-seed requires --idor-discovery or --idor-review.")
        if idor_discovery and (mode is not ScanMode.ACTIVE or auth_context is not None):
            raise GQLSleuthError(
                "--idor-discovery requires ACTIVE single-context mode without --auth-context."
            )
        discovery_seeds = (
            parse_discovery_seeds(idor_seed or []) if idor_discovery or idor_review else ()
        )
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
                auth_context,
                headers=headers,
                mode=mode,
                ai=ai,
                object_review=object_auth_review,
                idor_review=idor_review,
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
        if auth_security_review:
            bearer_token(http_settings)
        idor_context_label = None
        if idor_review and contexts is not None:
            idor_context_label = contexts[0].name
            http_settings = http_settings.model_copy(update={"custom_headers": contexts[0].headers})
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
        elif contexts is not None and not idor_review:
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
    if idor_context_label is not None:
        # This exception enters only the IDOR capability, never other named-context ACTIVE stages.
        detection = _run_idor_stage(
            result,
            seeds=discovery_seeds,
            http_settings=http_settings,
            context_label=idor_context_label,
            verbose=verbose,
        )
        report_result = ActiveExecutionScanResult(
            ActiveMutationPreviewResult(result, ()),
            (),
            False,
            (),
            (),
            idor_bola_detection=detection,
        )
        _finish_reports(report_result, report_formats, output)
        return
    if mode is ScanMode.ACTIVE:
        authentication = (
            _run_authentication_stage(result, http_settings=http_settings, verbose=verbose)
            if auth_security_review
            else None
        )
        multiplicity = _run_multiplicity_stage(result, http_settings=http_settings, verbose=verbose)
        query_depth = _run_depth_stage(result, http_settings=http_settings, verbose=verbose)
        sequential = (
            _run_sequential_stage(
                result, seeds=discovery_seeds, http_settings=http_settings, verbose=verbose
            )
            if idor_discovery
            else None
        )
        idor_detection = (
            _run_idor_stage(
                result, seeds=discovery_seeds, http_settings=http_settings, verbose=verbose
            )
            if idor_review
            else None
        )
        mutation_authorization = (
            _run_mutation_authorization_stage(
                result, cases=mutation_cases, http_settings=http_settings
            )
            if mutation_auth_review
            else None
        )
        sensitive_validation = (
            _run_sensitive_stage(result, case=sensitive_case, http_settings=http_settings)
            if sensitive_case
            else None
        )
        report_result = replace(
            _run_active_stage(result, http_settings=http_settings),
            multiplicity=multiplicity,
            query_depth=query_depth,
            sequential_object_discovery=sequential,
            mutation_authorization=mutation_authorization,
            sensitive_input_validation=sensitive_validation,
            idor_bola_detection=idor_detection,
            authentication_token_security=authentication,
        )
        if selected_upload_case is not None and upload_file:
            report_result = replace(
                report_result,
                file_upload_security=_run_file_upload_stage(
                    result,
                    case=selected_upload_case,
                    file_path=upload_file[0],
                    content_type=upload_content_type,
                    http_settings=http_settings,
                ),
            )
        if rate_limit_review:
            report_result = replace(
                report_result,
                rate_limiting_abuse_controls=_run_abuse_control_stage(
                    report_result, http_settings=http_settings, verbose=verbose
                ),
            )
        if federation_review:
            report_result = replace(
                report_result,
                federation_security=_run_federation_stage(
                    result,
                    entity_case=federation_case,
                    deny_sdl=federation_sdl_expect_deny,
                    http_settings=http_settings,
                ),
            )
        if subscription_review:
            report_result = replace(
                report_result,
                subscription_security=_run_subscription_stage(
                    result,
                    deny=subscription_expect_deny,
                    overrides=subscription_overrides,
                    init_payload=subscription_init,
                    ws_url=subscription_ws_url,
                    http_settings=http_settings,
                ),
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


def _run_subscription_stage(
    safe: SafeExecutionScanResult,
    *,
    deny: bool,
    overrides: dict[str, JsonValue] | None,
    init_payload: dict[str, JsonValue] | None,
    ws_url: str | None,
    http_settings: HttpClientSettings,
) -> SubscriptionSecurityResult:
    session = SubscriptionSecuritySession(
        safe,
        enabled=True,
        deny=deny,
        overrides=overrides,
        init_payload=init_payload,
        ws_url=ws_url,
        http_settings=http_settings,
    )
    preview = session.preview
    render_subscriptions(console, preview)
    if not any(c.failure is None for c in preview.candidates):
        console.print("No executable retained Subscriptions; zero WebSocket connections.")
        return preview
    if not _interactive_stdin():
        message = (
            "Interactive Subscription selection and confirmation required; "
            "zero WebSocket connections."
        )
        console.print(message)
        return replace(preview, limitations=(*preview.limitations, message))
    try:
        while True:
            value = typer.prompt(
                "Select one Subscription (Enter for none)", default="", show_default=False
            ).strip()
            if not value:
                return preview
            if value not in {
                str(i)
                for i, candidate in enumerate(preview.candidates, 1)
                if candidate.failure is None
            }:
                console.print("Choose one executable Subscription index, or Enter for none.")
                continue
            try:
                preview = session.select(int(value))
            except GQLSleuthError as error:
                message = str(error)
                console.print(Text(message))
                return replace(preview, limitations=(*preview.limitations, message))
            break
        render_subscriptions(console, preview)
        confirmed = typer.confirm(
            "Execute subscription / WebSocket security validation?", default=False
        )
    except (typer.Abort, EOFError, KeyboardInterrupt):
        console.print("Subscription confirmation cancelled; zero WebSocket connections.")
        return preview
    result = session.execute(preview=preview, confirmed=confirmed)
    render_subscriptions(console, result)
    return result


def _run_federation_stage(
    safe: SafeExecutionScanResult,
    *,
    entity_case: dict[str, JsonValue] | None,
    deny_sdl: bool,
    http_settings: HttpClientSettings,
) -> FederationSecurityResult:
    session = FederationSecuritySession(
        safe, enabled=True, entity_case=entity_case, deny_sdl=deny_sdl, http_settings=http_settings
    )
    preview = session.preview
    render_federation(console, preview, preview=True)
    if not preview.candidates:
        console.print("No retained federation candidates; zero federation requests.")
        return preview
    if not _interactive_stdin():
        message = (
            "Interactive federation endpoint/probe selection and confirmation required; "
            "zero federation requests."
        )
        console.print(message)
        return replace(preview, limitations=(*preview.limitations, message))
    try:
        while True:
            value = typer.prompt(
                "Select one federation endpoint (Enter for none)", default="", show_default=False
            ).strip()
            if not value:
                return preview
            if value in {str(i) for i in range(1, len(preview.candidates) + 1)}:
                break
            console.print("Choose one listed endpoint index, or Enter for none.")
        candidate = preview.candidates[int(value) - 1]
        for index, plan in enumerate(candidate.plans, 1):
            console.print(f"[{index}] {plan.probe.value}; policy {plan.expected.value.upper()}")
        if not candidate.plans:
            console.print("No compatible federation probes for this endpoint.")
            return preview
        while True:
            value = typer.prompt(
                "Select federation probes (comma-separated, max 2, Enter for none)",
                default="",
                show_default=False,
            ).strip()
            if not value:
                return session.select(candidate.endpoint, ())
            tokens = [token.strip() for token in value.split(",")]
            if (
                len(tokens) <= 2
                and len(set(tokens)) == len(tokens)
                and all(
                    token in {str(i) for i in range(1, len(candidate.plans) + 1)}
                    for token in tokens
                )
            ):
                break
            console.print("Choose only listed probe indices, without duplicates or ranges.")
        preview = session.select(
            candidate.endpoint, tuple(candidate.plans[int(token) - 1].probe for token in tokens)
        )
        render_federation(console, preview, preview=True)
        confirmed = typer.confirm("Execute federation security validation?", default=False)
    except (typer.Abort, EOFError, KeyboardInterrupt):
        console.print("Federation confirmation cancelled; zero federation requests.")
        return preview
    result = session.execute(preview=preview, confirmed=confirmed)
    render_federation(console, result)
    return result


def _run_file_upload_stage(
    safe: SafeExecutionScanResult,
    *,
    case: FileUploadCase,
    file_path: Path,
    content_type: str | None,
    http_settings: HttpClientSettings,
) -> FileUploadSecurityResult:
    try:
        session = FileUploadSecuritySession(
            safe,
            case=case,
            file_path=file_path,
            content_type=content_type,
            http_settings=http_settings,
            enabled=True,
        )
    except GQLSleuthError:
        result = FileUploadSecurityResult(
            case, limitations=("Upload file is no longer usable; zero uploads sent.",)
        )
        render_file_upload(console, result)
        return result
    preview = session.preview
    render_file_upload(console, preview, preview=True)
    if not preview.plan:
        return preview
    if not _interactive_stdin():
        message = "Interactive upload selection and confirmation required; zero uploads execute."
        console.print(message)
        return replace(preview, limitations=(*preview.limitations, message))
    descriptions = (
        "Same filename/MIME, fixed benign content",
        "Same bytes/filename, altered MIME",
        "Same bytes/MIME, safe alternate extension",
    )
    for index, (probe, description) in enumerate(
        zip(UPLOAD_VARIANTS, descriptions, strict=True), 1
    ):
        console.print(
            f"[{index}] {probe.value.replace('_', ' ').title()} — {description}; expected DENY"
        )
    try:
        while True:
            value = typer.prompt(
                "Select upload-validation probes (comma-separated, max 3, Enter for baseline only)",
                default="",
                show_default=False,
            ).strip()
            tokens = value.split(",") if value else []
            if all(token.strip() in {"1", "2", "3"} for token in tokens):
                break
            console.print(
                "Choose only listed indices separated by commas, or Enter for baseline only."
            )
        preview = session.select_variants(
            tuple(UPLOAD_VARIANTS[int(token.strip()) - 1] for token in tokens)
        )
        render_file_upload(console, preview, preview=True)
        confirmed = typer.confirm("Execute file upload security validation?", default=False)
    except (typer.Abort, EOFError, KeyboardInterrupt):
        console.print("Upload confirmation cancelled; zero uploads sent.")
        return preview
    result = session.execute(preview=preview, confirmed=confirmed)
    render_file_upload(console, result)
    return result


def _run_abuse_control_stage(
    active: ActiveExecutionScanResult,
    *,
    http_settings: HttpClientSettings,
    verbose: bool = False,
) -> AbuseControlResult:
    preview = prepare_abuse_controls(active, enabled=True)
    render_abuse_controls(console, preview, preview=True)
    if not preview.candidates:
        return preview
    if not _interactive_stdin():
        message = (
            "Interactive selection and confirmation required; zero abuse-control repeats execute."
        )
        console.print(message)
        return replace(preview, limitations=(*preview.limitations, message))
    try:
        while True:
            value = typer.prompt(
                "Select one operation for bounded abuse-control testing (Enter for none)",
                default="",
                show_default=False,
            ).strip()
            if not value:
                return preview
            indices = {str(item.index): item.index for item in preview.candidates}
            if value in indices:
                break
            console.print("Choose exactly one listed candidate index, or Enter for none.")
        session = AbuseControlSession(
            active, http_settings=http_settings, enabled=True, selected_index=indices[value]
        )
        preview = session.preview
        render_abuse_controls(console, preview, preview=True)
        confirmed = typer.confirm(
            "Execute rate limiting / abuse-control validation?", default=False
        )
    except (typer.Abort, EOFError, KeyboardInterrupt):
        console.print("Abuse-control selection/confirmation cancelled; zero repeats execute.")
        return preview
    result = session.execute(preview=preview, confirmed=confirmed)
    render_abuse_controls(console, result, verbose=verbose)
    return result


def _run_authentication_stage(
    safe: SafeExecutionScanResult,
    *,
    http_settings: HttpClientSettings,
    verbose: bool = False,
) -> AuthenticationSecurityResult:
    preview = prepare_authentication_security(safe, http_settings=http_settings, enabled=True)
    render_authentication(console, preview, preview=True)
    if not preview.candidates:
        return preview
    if not _interactive_stdin():
        message = (
            "Interactive selection and confirmation required; zero authentication probes execute."
        )
        console.print(message)
        return replace(preview, limitations=(*preview.limitations, message))
    selected_probes: tuple[AuthenticationProbe, ...] = ()
    try:
        while True:
            value = typer.prompt(
                "Select one Query expected to require the supplied Bearer token (Enter for none)",
                default="",
                show_default=False,
            ).strip()
            if not value:
                return preview
            indices = {str(item.index): item.index for item in preview.candidates}
            if value in indices:
                selected_index = indices[value]
                break
            console.print("Choose exactly one listed Query index, or Enter for none.")
        if preview.available_probes:
            console.print(
                "Optional JWT probes run only if the control establishes explicit denial."
            )
            for index, probe in enumerate(preview.available_probes, 1):
                console.print(Text(f"[{index}] {PROBE_LABELS[probe]}", style="cyan"))
            while True:
                value = typer.prompt(
                    "Select JWT probes (max 2, Enter for none)", default="", show_default=False
                ).strip()
                if not value:
                    break
                tokens = tuple(token.strip() for token in value.split(","))
                allowed = {
                    str(index): probe for index, probe in enumerate(preview.available_probes, 1)
                }
                if (
                    len(tokens) <= 2
                    and len(set(tokens)) == len(tokens)
                    and all(token in allowed for token in tokens)
                ):
                    selected_probes = tuple(allowed[token] for token in tokens)
                    break
                console.print(
                    "Choose up to two distinct individual JWT probe indices, or Enter for none."
                )
        session = AuthenticationSecuritySession(
            safe,
            http_settings=http_settings,
            enabled=True,
            selected_index=selected_index,
            selected_probes=selected_probes,
        )
        preview = session.preview
        render_authentication(console, preview, preview=True)
        confirmed = typer.confirm(
            "Execute authentication and token security probes?", default=False
        )
    except (typer.Abort, EOFError, KeyboardInterrupt):
        console.print(
            "Authentication security selection/confirmation cancelled; zero probes execute."
        )
        return preview
    result = session.execute(preview=preview, confirmed=confirmed)
    render_authentication(console, result, verbose=verbose)
    return result


def _run_idor_stage(
    safe: SafeExecutionScanResult,
    *,
    seeds: tuple[SequentialDiscoverySeed, ...],
    http_settings: HttpClientSettings,
    context_label: str | None = None,
    verbose: bool = False,
) -> IdorDetectionResult:
    session = IdorSession(
        safe,
        seeds=seeds,
        enabled=True,
        http_settings=http_settings,
        context_label=context_label,
    )
    preview = session.preview
    render_idor(console, preview, preview=True, verbose=verbose)
    confirmed = False
    if not preview.probes:
        console.print("No eligible IDOR/BOLA requests.")
    elif not _interactive_stdin():
        console.print("Interactive confirmation is required; zero IDOR/BOLA requests execute.")
    else:
        try:
            confirmed = typer.confirm("Execute IDOR / BOLA detection?", default=False)
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("IDOR/BOLA confirmation cancelled.")
    result = session.execute(preview=preview, confirmed=confirmed)
    render_idor(console, result, verbose=verbose)
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


def _run_sensitive_stage(
    safe: SafeExecutionScanResult,
    *,
    case: SensitiveInputCase,
    http_settings: HttpClientSettings,
) -> SensitiveInputValidationResult:
    session = SensitiveInputSession(safe, case=case, enabled=True, http_settings=http_settings)
    preview = session.preview
    render_sensitive_validation(console, preview, preview=True)
    confirmed = False
    if preview.probe is None:
        console.print("No eligible sensitive input request.")
    elif not _interactive_stdin():
        console.print(
            "Interactive confirmation is required; zero sensitive input requests execute."
        )
    else:
        try:
            confirmed = typer.confirm("Execute sensitive input validation?", default=False)
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("Sensitive input confirmation cancelled.")
    result = session.execute(preview=preview, confirmed=confirmed)
    render_sensitive_validation(console, result)
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
