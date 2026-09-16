"""Opt-in SAFE named-context review; preparation and comparisons are entirely local."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from itertools import combinations
from time import perf_counter
from typing import TYPE_CHECKING

from graphql import GraphQLError, parse, print_ast

from gqlsleuth.domain.analysis import PRIORITY_RANK, OperationKind, RuleMatch
from gqlsleuth.domain.differential import NamedAuthContext, validate_context_names
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.nested_authorization import (
    MAX_PHASE19_CANDIDATES,
    MAX_PHASE19_REQUESTS,
    NestedAuthorizationEvidence,
    NestedAuthorizationResult,
    NestedDifference,
    NestedExecution,
    NestedOutcome,
    NestedPairReview,
    NestedPathCandidate,
)
from gqlsleuth.graphql.nested_authorization import (
    build_nested_query,
    classify_nested_response,
    discover_nested_paths,
    field_signature,
    path_fields,
    validate_common_document,
)
from gqlsleuth.graphql.safe_execution import validate_safe_artifact
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.graphql.selection_paths import schema_field
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest
from gqlsleuth.rules.loader import load_bundled_rules
from gqlsleuth.rules.schema_graph import TypeEdge

if TYPE_CHECKING:
    from gqlsleuth.application.differential_review import DifferentialScanResult


def _validate_scan(result: DifferentialScanResult) -> None:
    validate_context_names(tuple(item.name for item in result.contexts))
    for context in result.contexts:
        if context.scan:
            schema_scan = context.scan.query_generation.operation_analysis.schema_scan
            discovery = schema_scan.introspection.detection.discovery
            if discovery.mode is not ScanMode.SAFE or discovery.target != result.target:
                raise HttpConfigurationError(
                    "Nested review requires retained SAFE scans for the same target."
                )


def exact_variables(value: object) -> str:
    """Type-sensitive JSON equality, including bool versus int; no request secrets involved."""
    return json.dumps(value, sort_keys=True, allow_nan=False)


def prepare_nested_authorization(result: DifferentialScanResult) -> NestedAuthorizationResult:
    """Select up to three common nested paths; never treat missing schemas as field absence."""
    _validate_scan(result)
    if any(item.scan is None for item in result.contexts):
        return NestedAuthorizationResult(
            limitations=("Completed SAFE results are unavailable in at least one context.",)
        )
    scans = tuple(item.scan for item in result.contexts if item.scan)
    schema_scans = tuple(item.query_generation.operation_analysis.schema_scan for item in scans)
    mappings = tuple(
        {item.endpoint: item.schema for item in scan.schemas if item.success and item.schema}
        for scan in schema_scans
    )
    endpoints = sorted(set().union(*(mapping.keys() for mapping in mappings)))
    if not endpoints:
        return NestedAuthorizationResult(limitations=("No retained parsed schemas are available.",))
    rules = load_bundled_rules()
    planned = []
    limitations = []
    for endpoint in endpoints:
        if any(endpoint not in mapping for mapping in mappings):
            limitations.append(
                f"{endpoint}: parsed schema missing in at least one context; visibility is unknown."
            )
            continue
        schemas = tuple(mapping[endpoint] for mapping in mappings)
        for base in scans[0].query_generation.queries:
            if base.endpoint != endpoint or base.operation.kind is not OperationKind.QUERY:
                continue
            try:
                for schema in schemas:
                    validate_safe_artifact(schema, base)
            except SafeExecutionValidationError:
                limitations.append(
                    f"{endpoint} / {base.operation_name}: no common valid root Query baseline."
                )
                continue
            baseline_ok = True
            for schema, scan in zip(schemas, scans, strict=True):
                attempt = next(
                    (
                        item
                        for item in scan.executions
                        if item.endpoint == endpoint and item.operation_name == base.operation_name
                    ),
                    None,
                )
                if (
                    attempt is None
                    or not attempt.attempted
                    or attempt.status is not QueryExecutionStatus.SUCCESS
                ):
                    baseline_ok = False
                    continue
                try:
                    validate_safe_artifact(schema, attempt.generated_query)
                    equivalent = print_ast(
                        parse(attempt.generated_query.query_text or "")
                    ) == print_ast(parse(base.query_text or "")) and exact_variables(
                        attempt.generated_query.variables
                    ) == exact_variables(base.variables)
                except (
                    SafeExecutionValidationError,
                    GraphQLError,
                    ValueError,
                    TypeError,
                    RecursionError,
                ):
                    equivalent = False
                if not equivalent:
                    baseline_ok = False
            if not baseline_ok:
                limitations.append(
                    f"{endpoint} / {base.operation_name}: runtime review requires equivalent "
                    "documents/variables and attempted SUCCESS baselines in every context."
                )
            source_ids = tuple(
                dict.fromkeys(
                    item.evidence_id
                    for scan in scans
                    for item in scan.evidence
                    if item.endpoint == endpoint
                    and (
                        item.evidence_type is EvidenceType.SCHEMA_ARTIFACT
                        or item.evidence_type is EvidenceType.QUERY_EXECUTION
                        and item.query == base.query_text
                        and exact_variables(item.variables) == exact_variables(base.variables)
                    )
                )
            )
            paths: dict[tuple[str, ...], tuple[tuple[TypeEdge, ...], tuple[RuleMatch, ...]]] = {}
            for schema in schemas:
                discovered, skipped = discover_nested_paths(schema, base.operation_name, rules)
                limitations.extend(
                    f"{endpoint} / {base.operation_name}: {reason}" for reason in skipped
                )
                for path, matches in discovered:
                    names = tuple(edge.label.split(".", 1)[1] for edge in path)
                    paths.setdefault(names, (path, matches))
            if not paths:
                limitations.append(
                    f"{endpoint} / {base.operation_name}: no eligible output-rule path "
                    "within the depth/cycle budget; abstract resolution is not guessed."
                )
            for names, (path, matches) in sorted(paths.items()):
                try:
                    fields = tuple(
                        path_fields(schema, base.operation_name, names) for schema in schemas
                    )
                    if any(item is None for item in fields):
                        # A common root must be structurally compatible even for local visibility.
                        roots = [
                            schema_field(schema, schema.query_root, base.operation_name)
                            for schema in schemas
                        ]
                        if any(
                            field_signature(root) != field_signature(roots[0]) for root in roots
                        ):
                            raise SafeExecutionValidationError(
                                "Root structures differ; nested visibility is not comparable."
                            )
                        for length in range(1, len(names)):
                            prefixes = [
                                path_fields(schema, base.operation_name, names[:length])
                                for schema in schemas
                            ]
                            signatures = [
                                tuple(field_signature(field) for field in prefix)
                                for prefix in prefixes
                                if prefix is not None
                            ]
                            if signatures and any(item != signatures[0] for item in signatures):
                                raise SafeExecutionValidationError(
                                    "Nested parent types differ; visibility is not comparable."
                                )
                        present_index = next(
                            index for index, item in enumerate(fields) if item is not None
                        )
                        retained = schema_scans[present_index].introspection.introspections
                        response = next(
                            (
                                item.full_response
                                for item in retained
                                if item.endpoint == endpoint and item.full_response
                            ),
                            None,
                        )
                        if response is None:
                            raise SafeExecutionValidationError(
                                "Retained schema validation data is unavailable."
                            )
                        _, depth, lists = build_nested_query(
                            schemas[present_index],
                            load_introspection_schema(response.body),
                            base,
                            path,
                        )
                        visibility_ids = tuple(
                            item.evidence_id
                            for scan in scans
                            for item in scan.evidence
                            if item.endpoint == endpoint
                            and item.evidence_type is EvidenceType.SCHEMA_ARTIFACT
                        )
                        candidate = NestedPathCandidate(
                            deepcopy(base),
                            names,
                            path[-1].target,
                            matches,
                            None,
                            depth,
                            lists,
                            visibility_ids,
                        )
                        planned.append((candidate, tuple(item is not None for item in fields)))
                        continue
                    signatures = [
                        tuple(field_signature(field) for field in item)
                        for item in fields
                        if item is not None
                    ]
                    if any(item != signatures[0] for item in signatures):
                        raise SafeExecutionValidationError(
                            "Nested field/type/argument structures differ between contexts."
                        )
                    if not baseline_ok:
                        continue
                    natives = []
                    for retained_schema_scan in schema_scans:
                        response = next(
                            (
                                item.full_response
                                for item in retained_schema_scan.introspection.introspections
                                if item.endpoint == endpoint and item.full_response
                            ),
                            None,
                        )
                        if response is None:
                            raise SafeExecutionValidationError(
                                "Retained schema validation data is unavailable."
                            )
                        natives.append(load_introspection_schema(response.body))
                    query, depth, lists = build_nested_query(schemas[0], natives[0], base, path)
                    inputs = [
                        exact_variables(validate_common_document(native, query, base.variables))
                        for native in natives
                    ]
                    if any(item != inputs[0] for item in inputs):
                        raise SafeExecutionValidationError(
                            "Schema defaults/coerced inputs differ between contexts."
                        )
                    candidate = NestedPathCandidate(
                        deepcopy(base),
                        names,
                        path[-1].target,
                        matches,
                        query,
                        depth,
                        lists,
                        source_ids,
                    )
                    planned.append((candidate, ()))
                except (SafeExecutionValidationError, SchemaParsingError) as error:
                    limitations.append(
                        f"{endpoint} / {base.operation_name}.{'.'.join(names)}: {error}"
                    )
    planned.sort(
        key=lambda item: (
            PRIORITY_RANK[item[0].base.operation.priority],
            -max(match.weight for match in item[0].matched_rules),
            item[0].base.endpoint,
            item[0].base.operation_name,
            item[0].path,
        )
    )
    if len(planned) > MAX_PHASE19_CANDIDATES:
        limitations.append("Additional paths omitted by the global three-candidate limit.")
    candidates, pairs = [], []
    for index, (candidate, visibility) in enumerate(planned[:MAX_PHASE19_CANDIDATES], 1):
        candidates.append(candidate)
        if visibility:
            for a, b in combinations(range(len(result.contexts)), 2):
                if visibility[a] != visibility[b]:
                    pairs.append(
                        NestedPairReview(
                            index,
                            result.contexts[a].name,
                            result.contexts[b].name,
                            NestedDifference.NESTED_FIELD_VISIBILITY_DIFFERENCE,
                            "visible" if visibility[a] else "absent",
                            "visible" if visibility[b] else "absent",
                            candidate.source_evidence_ids,
                            "Nested schema visibility differs; intentional schema variation "
                            "is possible. Manual policy validation is required.",
                        )
                    )
    return NestedAuthorizationResult(
        tuple(candidates), pairs=tuple(pairs), limitations=tuple(dict.fromkeys(limitations))
    )


def compare_nested_outcomes(
    executions: tuple[NestedExecution, ...],
) -> tuple[NestedPairReview, ...]:
    """Compare outcome enums and source references only, never response data."""
    pairs = []
    for a, b in combinations(executions, 2):
        if a.candidate_index != b.candidate_index or not a.attempted or not b.attempted:
            continue
        if {a.outcome, b.outcome} == {NestedOutcome.RETURNED, NestedOutcome.EXPLICIT_DENIAL}:
            assert a.outcome and b.outcome and a.evidence and b.evidence
            pairs.append(
                NestedPairReview(
                    a.candidate_index,
                    a.context,
                    b.context,
                    NestedDifference.NESTED_ACCESS_DIFFERENCE,
                    a.outcome.value,
                    b.outcome.value,
                    (a.evidence.evidence_id, b.evidence.evidence_id),
                    "The same nested field request produced different authorization-relevant "
                    "behavior. Validate against the application's intended access policy.",
                )
            )
    return tuple(pairs)


def execute_nested_authorization(
    result: DifferentialScanResult,
    *,
    contexts: tuple[NamedAuthContext, ...],
    enabled: bool = False,
    http_settings: HttpClientSettings | None = None,
    preview: NestedAuthorizationResult | None = None,
) -> NestedAuthorizationResult:
    """Fresh session per candidate/context; explicit opt-in and bounded candidates rechecked."""
    from gqlsleuth.application.differential_review import context_http_settings

    _validate_scan(result)
    if tuple(item.name for item in contexts) != tuple(item.name for item in result.contexts):
        raise HttpConfigurationError(
            "Nested review configuration must match retained context order."
        )
    settings = context_http_settings(contexts, http_settings or HttpClientSettings())
    if enabled is not True:
        return NestedAuthorizationResult(
            limitations=("Nested authorization review was not explicitly enabled.",)
        )
    canonical = prepare_nested_authorization(result)
    supplied = preview or canonical
    executions = []
    for index, candidate in enumerate(supplied.candidates, 1):
        for context, configured in zip(contexts, settings, strict=True):
            # Rebuild immediately before each attempt from the retained SAFE source.
            trusted = prepare_nested_authorization(result).candidates
            valid = index <= len(trusted) and _candidate_matches(candidate, trusted[index - 1])
            if not valid:
                executions.append(
                    NestedExecution(
                        index,
                        context.name,
                        False,
                        None,
                        "INVALID_ARTIFACT: candidate does not match retained bounded paths.",
                    )
                )
            elif candidate.query is None:
                executions.append(
                    NestedExecution(
                        index,
                        context.name,
                        False,
                        None,
                        "Schema visibility comparison only; no request.",
                    )
                )
            elif (
                sum(item.attempted for item in executions) >= MAX_PHASE19_REQUESTS
                or index > MAX_PHASE19_CANDIDATES
            ):
                executions.append(
                    NestedExecution(
                        index, context.name, False, None, "SKIPPED_LIMIT: request budget reached."
                    )
                )
            else:
                with HttpClient(configured) as client:
                    executions.append(_execute_one(result, index, candidate, context.name, client))
    return replace(
        supplied,
        executions=tuple(executions),
        pairs=canonical.pairs + compare_nested_outcomes(tuple(executions)),
        limitations=canonical.limitations,
    )


def _candidate_matches(candidate: NestedPathCandidate, trusted: NestedPathCandidate) -> bool:
    try:
        return (
            candidate.base.operation.kind is OperationKind.QUERY
            and type(candidate.selection_depth) is int
            and type(candidate.list_edges) is int
            and candidate == trusted
            and exact_variables(candidate.base.variables) == exact_variables(trusted.base.variables)
        )
    except (ValueError, TypeError, RecursionError):
        return False


def _execute_one(
    result: DifferentialScanResult,
    index: int,
    candidate: NestedPathCandidate,
    context: str,
    client: HttpClient,
) -> NestedExecution:
    started, timestamp = perf_counter(), datetime.now(UTC)
    response = None
    error_type = error_message = None
    variables = deepcopy(candidate.base.variables)
    try:
        response = client.send(
            HttpRequest(
                method="POST",
                url=candidate.base.endpoint,
                json_body={"query": candidate.query, "variables": variables},
            )
        )
    except HttpError as error:
        outcome, reason = (
            NestedOutcome.NETWORK_FAILURE,
            "Normalized transport failure; later contexts remain eligible.",
        )
        error_type = type(error).__name__
        error_message = "Target transport failed."
    else:
        outcome, reason = classify_nested_response(
            response.status_code, response.body, (candidate.base.operation_name, *candidate.path)
        )
    evidence = NestedAuthorizationEvidence(
        target=result.target,
        endpoint=candidate.base.endpoint,
        timestamp=timestamp,
        source="gqlsleuth.application.nested_authorization",
        summary=reason,
        context=context,
        root_operation=candidate.base.operation_name,
        nested_path=candidate.path,
        rule_ids=tuple(item.rule_id for item in candidate.matched_rules),
        categories=tuple(dict.fromkeys(item.category.value for item in candidate.matched_rules)),
        outcome=outcome,
        query=candidate.query,
        variables=variables,
        request_method="POST",
        response_status_code=response.status_code if response else None,
        response_headers=response.headers if response else None,
        response_body=response.body if response else None,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message=error_message,
    )
    return NestedExecution(index, context, True, outcome, reason, evidence)
