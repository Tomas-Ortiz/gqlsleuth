"""Concise issue summaries for human assessments; never alter canonical issue records."""

import re
from urllib.parse import urlsplit

from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.limits import is_safe_budget_reason
from gqlsleuth.presentation.responses import success_with_null_data
from gqlsleuth.reporting.models import ReportContext, ReportIssue

MAX_LIMITATION_OPERATION_NAMES = 3
_ACTION_REASON = re.compile(
    r"Query name contains explicit state-changing action token\(s\): [a-z]+(?:, [a-z]+)*\."
)
_TRANSPORT = {
    "HttpTransportError": (
        "transport failures",
        "Check the URL, network reachability, proxy and TLS settings.",
    ),
    "HttpTimeoutError": ("timeouts", "Check network reachability and the target timeout setting."),
    "HttpProxyError": ("proxy failures", "Check the proxy configuration and reachability."),
    "HttpRedirectError": ("redirect-limit failures", "Check the target URL and redirects."),
}
_OUTCOMES = {"graphql_error", "http_error", "invalid_response"}


def null_data_limitations(report: ReportContext) -> tuple[str, ...]:
    """One human-only qualification for ordinary attempted Query/Mutation responses."""
    operations = (*report.queries, *(report.active.candidates if report.active else ()))
    affected = [
        item
        for item in operations
        if item.execution
        and item.execution.attempted
        and item.execution.response
        and success_with_null_data(item.execution.status, item.execution.response.body)
    ]
    if not affected:
        return ()
    names = ", ".join(
        f"{item.generated.operation_kind.value} {item.generated.operation_name}"
        for item in affected[:MAX_LIMITATION_OPERATION_NAMES]
    )
    if len(affected) > MAX_LIMITATION_OPERATION_NAMES:
        names += f", and {len(affected) - MAX_LIMITATION_OPERATION_NAMES} more"
    return (
        f"{len(affected)} execution response(s) classified SUCCESS contained top-level "
        f"GraphQL data: null ({names}). No GraphQL error was classified; "
        "these responses do not establish meaningful application data.",
    )


def summarize_issues(report: ReportContext) -> tuple[str, ...]:
    """Group equivalent reasons, or outcomes without attributing a shared root cause.

    Discovery paths share origin-level coverage context; operation groups retain exact
    endpoints. A primary network outcome and its transport diagnostic count only once.
    """
    issues = report.errors_and_limitations
    network_subjects = {
        (i.stage, i.endpoint, i.operation_name)
        for i in issues
        if i.code == "network_failure" and i.stage in {"query", "mutation"}
    }
    transport_subjects = {
        (i.stage, i.endpoint, i.operation_name) for i in issues if i.code in _TRANSPORT
    }
    groups: dict[tuple[str, str, str, str], list[ReportIssue]] = {}
    for issue in issues:
        if issue.code in {"not_selected", "blocked_safety", "partial"}:
            continue
        if (
            issue.code == "network_failure"
            and issue.stage not in {"query", "mutation"}
            and (issue.stage, issue.endpoint, issue.operation_name) in transport_subjects
        ):
            continue  # Prefer the retained transport category for non-operation failures.
        if (
            issue.code in _TRANSPORT
            and (issue.stage, issue.endpoint, issue.operation_name) in network_subjects
        ):
            continue
        reason = " ".join(issue.message.split())
        if issue.code in _OUTCOMES and issue.stage in {"query", "mutation"}:
            reason = ""  # Count execution outcomes, not individual errors or inferred causes.
        elif issue.code == "skipped_safety" and _ACTION_REASON.fullmatch(reason):
            reason = "state-changing action tokens"
        scope = issue.endpoint
        if issue.stage in {"discovery", "detection"}:
            url = urlsplit(scope)
            scope = f"{url.scheme}://{url.netloc}"
        groups.setdefault((scope, issue.stage, issue.code, reason), []).append(issue)
    # Material outcomes cannot be buried behind hundreds of administrative skips.
    keys = sorted(groups, key=lambda k: k[2] == "skipped_limit")
    scopes = {e.endpoint for e in report.endpoints if e.schema_summary}
    scopes.update(k[0] for k in keys if k[1] not in {"discovery", "detection"})
    origins = {k[0] for k in keys if k[1] in {"discovery", "detection"}}
    summaries = []
    for scope, stage, code, reason in keys:
        group = groups[(scope, stage, code, reason)]
        text = _summarize_group(stage, code, reason, group)
        scoped = len(origins) > 1 if stage in {"discovery", "detection"} else len(scopes) > 1
        summaries.append(f"{scope}: {text}" if scope and scoped else text)
    return tuple(summaries)


def _names(group: list[ReportIssue]) -> str:
    names = tuple(dict.fromkeys(i.operation_name for i in group if i.operation_name))
    if not names:
        return "."
    if len(names) <= MAX_LIMITATION_OPERATION_NAMES:
        return " (" + ", ".join(names) + ")."
    return "; see detailed results for the affected operations."


def _summarize_group(stage: str, code: str, reason: str, group: list[ReportIssue]) -> str:
    # The builder emits one primary outcome per endpoint/kind/operation. Secondary
    # diagnostics and individual GraphQL error objects must not inflate that count.
    count = len({(i.endpoint, i.operation_name) for i in group})
    if stage in {"query", "mutation"}:
        kind = stage
        noun = "query" if stage == "query" else "mutation"
        plural = "queries" if stage == "query" else "mutations"
        operations = f"{count} {noun if count == 1 else plural}"
        executions = f"{count} {kind} execution{'s' if count != 1 else ''}"
        if code == "graphql_error":
            return (
                executions
                + (" returned a GraphQL error" if count == 1 else " returned GraphQL errors")
                + _names(group)
            )
        if code == "http_error":
            return executions + " failed at the HTTP layer" + _names(group)
        if code == "invalid_response":
            return (
                executions
                + (" returned a response" if count == 1 else " returned responses")
                + " that could not be interpreted as GraphQL"
                + _names(group)
            )
        if code == "network_failure":
            failure = next(
                (
                    v[0]
                    for k, v in _TRANSPORT.items()
                    if reason == f"{kind.title()} request failed with {k}."
                ),
                "transport failures",
            )
            return executions + f" could not complete because of {failure}" + _names(group)
        if code == "skipped_limit":
            explanation = (
                reason
                if stage == "query" and is_safe_budget_reason(reason)
                else "Five-Mutation scan limit reached."
                if stage == "mutation" and reason == "Five-Mutation scan limit reached."
                else "See detailed results for the retained execution-limit reason."
            )
            return operations + f" {'was' if count == 1 else 'were'} not executed. " + explanation
        if code == "skipped_safety":
            explanation = (
                "as a precaution because their names contain actions that may modify data"
                if reason == "state-changing action tokens"
                else "because the parsed schema was unavailable for validation"
                if reason == "Parsed schema is unavailable for this endpoint."
                else "by execution safety validation; see detailed results for the retained reason"
            )
            return (
                operations
                + f" {'was' if count == 1 else 'were'} not executed {explanation}"
                + _names(group)
            )
        if code == "generation_failed":
            return (
                f"Generation failed for {operations}; those operations could not be exercised"
                + _names(group)
            )
    if code in _TRANSPORT:
        failure, guidance = _TRANSPORT[code]
        if stage in {"discovery", "detection"}:
            task = "endpoint discovery" if stage == "discovery" else "GraphQL confirmation"
            return (
                f"{failure.capitalize()} prevented responses during {task} for "
                f"{count} probed path{'s' if count != 1 else ''}. {guidance}"
            )
        return f"{capability_wording(stage).capitalize()} was limited by {failure}. {guidance}"
    if stage in {"schema", "analysis", "introspection"}:
        task = {
            "schema": "Schema parsing",
            "analysis": "Operation analysis",
            "introspection": "Introspection/schema retrieval",
        }[stage]
        return (
            f"{task} was unavailable or incomplete for "
            f"{count} endpoint{'s' if count != 1 else ''}; "
            f"see detailed results ({code.replace('_', ' ').upper()})."
        )
    return (
        f"{len(group)} limitation record{'s' if len(group) != 1 else ''} affected "
        f"{capability_wording(stage)} ({code.replace('_', ' ').upper()}); see detailed results."
    )
