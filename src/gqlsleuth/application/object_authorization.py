"""Explicit object cases: local preparation, owner-first execution, isolated SAFE clients."""

from copy import deepcopy
from dataclasses import replace
from uuid import UUID

from graphql import GraphQLError

from gqlsleuth.application.differential_review import (
    DifferentialScanResult,
    context_http_settings,
    run_differential_scan,
)
from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.object_lookup import retained_object_lookup
from gqlsleuth.application.safe_execution import SafeExecutionScanResult, run_safe_execution_scan
from gqlsleuth.domain.differential import NamedAuthContext, validate_context_names
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.models import EvidenceType, ScanMode, Target
from gqlsleuth.domain.object_authorization import (
    MAX_PHASE20_REQUESTS,
    ObjectAccessCandidate,
    ObjectAccessKind,
    ObjectAuthorizationCase,
    ObjectAuthorizationEvidence,
    ObjectAuthorizationMode,
    ObjectAuthorizationResult,
    ObjectContext,
    ObjectExecution,
    ObjectOutcome,
    PreparedObjectProbe,
    parse_object_cases,
)
from gqlsleuth.graphql.nested_authorization import field_signature
from gqlsleuth.graphql.object_authorization import (
    build_object_query,
    classify_object_response,
    object_fields,
    validate_object_document,
)
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest

type ObjectScan = SafeExecutionScanResult | DifferentialScanResult


def _configuration(
    cases: tuple[ObjectAuthorizationCase, ...],
    contexts: tuple[NamedAuthContext, ...],
    base: HttpClientSettings,
) -> tuple[HttpClientSettings, ...]:
    if any(
        not isinstance(item, ObjectAuthorizationCase)
        or type(item.mode) is not ObjectAuthorizationMode
        or type(item.index) is not int
        or any(type(value) is not str for value in (item.operation, item.argument, item.identifier))
        or (
            item.declared_authorized_context is not None
            and type(item.declared_authorized_context) is not str
        )
        for item in cases
    ):
        raise HttpConfigurationError("Object-auth cases must contain validated typed input.")
    names = tuple(item.name for item in contexts)
    if base.custom_headers:
        raise HttpConfigurationError(
            "Object authorization review cannot use common --header values."
        )
    if len(contexts) == 1:
        validate_context_names(names, check_count=False)
        if contexts[0].headers:
            raise HttpConfigurationError("Single-context object review requires a bare context.")
    elif contexts:
        validate_context_names(names)
    entries = [
        (
            item.declared_authorized_context + ":"
            if item.declared_authorized_context is not None
            else ""
        )
        + f"{item.operation}:{item.argument}={item.identifier}"
        for item in cases
    ]
    canonical = parse_object_cases(entries, names)
    if canonical != cases or any(
        type(item.index) is not int or item.mode is not expected.mode
        for item, expected in zip(cases, canonical, strict=True)
    ):
        raise HttpConfigurationError(
            "Object-auth cases must retain their validated input identity/order."
        )
    return context_http_settings(contexts, base) if len(contexts) > 1 else (base.model_copy(),)


def _sources(
    result: ObjectScan, contexts: tuple[NamedAuthContext, ...]
) -> tuple[SafeExecutionScanResult | None, ...]:
    if isinstance(result, DifferentialScanResult):
        if len(contexts) < 2 or tuple(item.name for item in result.contexts) != tuple(
            item.name for item in contexts
        ):
            raise HttpConfigurationError("Object review contexts must match the retained scans.")
        scans = tuple(item.scan for item in result.contexts)
        target = result.target
    else:
        if len(contexts) > 1:
            raise HttpConfigurationError(
                "Differential object review requires retained context scans."
            )
        scans = (result,)
        schema_scan = result.query_generation.operation_analysis.schema_scan
        target = schema_scan.introspection.detection.discovery.target
    for scan in scans:
        if scan:
            schema_scan = scan.query_generation.operation_analysis.schema_scan
            discovery = schema_scan.introspection.detection.discovery
            if discovery.mode is not ScanMode.SAFE or discovery.target != target:
                raise HttpConfigurationError(
                    "Object review requires SAFE scans for the same target."
                )
    return scans


def prepare_object_authorization(
    result: ObjectScan,
    *,
    cases: tuple[ObjectAuthorizationCase, ...],
    contexts: tuple[NamedAuthContext, ...] = (),
    http_settings: HttpClientSettings | None = None,
) -> ObjectAuthorizationResult:
    """No HTTP and no placeholder-success prerequisite; ambiguous endpoints are skipped."""
    _configuration(cases, contexts, http_settings or HttpClientSettings())
    scans = _sources(result, contexts)
    metadata = tuple(ObjectContext(item.name, bool(item.headers)) for item in contexts) or (
        ObjectContext("anonymous", False),
    )
    probes: list[PreparedObjectProbe] = []
    limitations: list[str] = []
    for case in cases:
        try:
            if any(scan is None for scan in scans):
                raise SafeExecutionValidationError("A retained context scan is unavailable.")
            retained = tuple(scan for scan in scans if scan is not None)
            owner_index = next(
                (
                    index
                    for index, item in enumerate(metadata)
                    if item.name == case.declared_authorized_context
                ),
                0,
            )
            owner = retained[owner_index]
            artifact, source = retained_object_lookup(owner, case.operation)
            schemas = []
            natives = []
            ids: list[UUID] = []
            for scan in retained:
                schema_scan = scan.query_generation.operation_analysis.schema_scan
                schema = next(
                    (
                        item.schema
                        for item in schema_scan.schemas
                        if item.endpoint == artifact.endpoint
                        and item.schema is not None
                        and item.success
                    ),
                    None,
                )
                response = next(
                    (
                        item.full_response
                        for item in schema_scan.introspection.introspections
                        if item.endpoint == artifact.endpoint and item.full_response is not None
                    ),
                    None,
                )
                if schema is None or response is None:
                    raise SafeExecutionValidationError(
                        "Retained parsed schema is unavailable in a participating context."
                    )
                schemas.append(schema)
                natives.append(load_introspection_schema(response.body))
                ids.extend(
                    item.evidence_id
                    for item in scan.evidence
                    if item.endpoint == artifact.endpoint
                    and (
                        item.evidence_type is EvidenceType.SCHEMA_ARTIFACT
                        or item.evidence_type is EvidenceType.GENERATED_QUERY
                        and item.query == artifact.query_text
                    )
                )
            signatures = [
                tuple(field_signature(field) for field in object_fields(schema, case))
                for schema in schemas
            ]
            if any(item != signatures[0] for item in signatures):
                raise SafeExecutionValidationError(
                    "Object lookup/identity structures differ between contexts."
                )
            query, variables = build_object_query(
                schemas[owner_index], natives[owner_index], artifact, case
            )
            effective = [validate_object_document(native, query, variables) for native in natives]
            if any(exact_variables(item) != exact_variables(effective[0]) for item in effective):
                raise SafeExecutionValidationError(
                    "Effective schema inputs/selections differ between contexts."
                )
            probes.append(
                PreparedObjectProbe(
                    case,
                    artifact.endpoint,
                    query,
                    variables,
                    (case.operation, "id"),
                    metadata,
                    source,
                    tuple(dict.fromkeys(ids)),
                )
            )
        except (
            SafeExecutionValidationError,
            SchemaParsingError,
            GraphQLError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            # Never expose schema errors that might quote supplied values.
            limitations.append(
                f"Case {case.index}: compatible direct ID object lookup, identity field "
                "or valid retained Query/schema is unavailable."
            )
    return ObjectAuthorizationResult(
        cases[0].mode, cases, tuple(probes), limitations=tuple(limitations)
    )


def _request(
    probe: PreparedObjectProbe, context: ObjectContext, settings: HttpClientSettings, target: Target
) -> ObjectExecution:
    response = None
    error_type = None
    try:
        with HttpClient(settings) as client:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=probe.endpoint,
                    json_body={"query": probe.query, "variables": deepcopy(probe.variables)},
                )
            )
    except HttpError as error:
        error_type = type(error).__name__
        outcome, matches, reason = ObjectOutcome.NETWORK_FAILURE, None, "Target transport failed."
    else:
        outcome, matches, reason = classify_object_response(
            response.status_code, response.body, probe.case.operation, probe.case.identifier
        )
    evidence = ObjectAuthorizationEvidence(
        target=target,
        endpoint=probe.endpoint,
        summary=reason,
        source="gqlsleuth.application.object_authorization",
        object_mode=probe.case.mode,
        context=context.name,
        has_supplied_context_headers=context.has_supplied_context_headers,
        declared_authorized_context=probe.case.declared_authorized_context,
        root_operation=probe.case.operation,
        identifier_argument=probe.case.argument,
        identifier=probe.case.identifier,
        source_evidence_ids=probe.source_evidence_ids,
        query=probe.query,
        variables=deepcopy(probe.variables),
        request_method="POST",
        outcome=outcome,
        returned_id_matches=matches,
        response_status_code=response.status_code if response else None,
        response_headers=response.headers if response else None,
        response_body=response.body if response else None,
        duration_seconds=response.duration_seconds if response else None,
        error_type=error_type,
        error_message="Target transport failed." if error_type else None,
    )
    return ObjectExecution(probe.case.index, context, True, outcome, matches, reason, evidence)


def execute_object_authorization(
    result: ObjectScan,
    *,
    cases: tuple[ObjectAuthorizationCase, ...],
    contexts: tuple[NamedAuthContext, ...] = (),
    enabled: bool = False,
    http_settings: HttpClientSettings | None = None,
    preview: ObjectAuthorizationResult | None = None,
) -> ObjectAuthorizationResult:
    """Rebuild before each attempt and stop each differential case unless its owner returns it."""
    base = http_settings or HttpClientSettings()
    settings = _configuration(cases, contexts, base)
    _sources(result, contexts)
    canonical = prepare_object_authorization(
        result, cases=cases, contexts=contexts, http_settings=base
    )
    if enabled is not True:
        return replace(
            canonical,
            limitations=(
                *canonical.limitations,
                "Object authorization review was not enabled; zero probes attempted.",
            ),
        )
    planned = preview if preview is not None else canonical
    executions: list[ObjectExecution] = []
    candidates: list[ObjectAccessCandidate] = []
    limitations = list(canonical.limitations)
    if isinstance(result, DifferentialScanResult):
        target = result.target
    else:
        schema_scan = result.query_generation.operation_analysis.schema_scan
        target = schema_scan.introspection.detection.discovery.target
    for position, probe in enumerate(planned.probes):
        order = sorted(
            range(len(probe.contexts)),
            key=lambda index: (
                probe.contexts[index].name != probe.case.declared_authorized_context,
                index,
            ),
        )
        owner_execution = None
        for index in order:
            context = probe.contexts[index]
            fresh = prepare_object_authorization(
                result, cases=cases, contexts=contexts, http_settings=base
            )
            try:
                valid = (
                    enabled is True
                    and planned.mode is canonical.mode
                    and planned.cases == cases
                    and position < len(fresh.probes)
                    and probe == fresh.probes[position]
                    and all(
                        type(item.has_supplied_context_headers) is bool for item in probe.contexts
                    )
                    and exact_variables(probe.variables)
                    == exact_variables(fresh.probes[position].variables)
                )
            except (TypeError, ValueError, RecursionError):
                valid = False
            if not valid or sum(item.attempted for item in executions) >= MAX_PHASE20_REQUESTS:
                executions.append(
                    ObjectExecution(
                        probe.case.index,
                        context,
                        False,
                        None,
                        None,
                        "Invalid prepared probe or request budget reached.",
                    )
                )
                continue
            settings = _configuration(cases, contexts, base)
            execution = _request(probe, context, settings[index], target)
            executions.append(execution)
            if probe.case.mode is ObjectAuthorizationMode.DIFFERENTIAL and owner_execution is None:
                owner_execution = execution
                if execution.outcome is not ObjectOutcome.TARGET_RETURNED:
                    reason = (
                        "The operator-declared authorized context did not return the requested "
                        "object, so cross-context validation was not performed."
                    )
                    limitations.append(f"Case {probe.case.index}: {reason}")
                    executions.extend(
                        ObjectExecution(
                            probe.case.index, probe.contexts[other], False, None, None, reason
                        )
                        for other in order
                        if other != index
                    )
                    break
                continue
            if execution.outcome is ObjectOutcome.TARGET_RETURNED:
                assert execution.evidence is not None
                ids: tuple[UUID, ...] = (execution.evidence.evidence_id,)
                if owner_execution and owner_execution.evidence:
                    ids = (owner_execution.evidence.evidence_id, *ids)
                kind = (
                    ObjectAccessKind.CROSS_CONTEXT_OBJECT_ACCESS
                    if context.has_supplied_context_headers
                    else ObjectAccessKind.UNAUTHENTICATED_OBJECT_ACCESS
                )
                reason = (
                    (
                        "The exact operator-supplied object was also returned to another supplied "
                        "request/authentication context. Validate the application's intended "
                        "object-level access policy."
                    )
                    if context.has_supplied_context_headers
                    else (
                        "The exact operator-supplied object was returned without a user-supplied "
                        "authentication context. Validate whether anonymous access to this "
                        "object is intended."
                    )
                )
                candidates.append(
                    ObjectAccessCandidate(kind, probe.case, context.name, ids, reason)
                )
    return replace(
        canonical,
        executions=tuple(executions),
        candidates=tuple(candidates),
        limitations=tuple(limitations),
        attempted_request_count=sum(item.attempted for item in executions),
    )


def run_object_authorization_scan(
    target_url: str,
    *,
    cases: tuple[ObjectAuthorizationCase, ...],
    contexts: tuple[NamedAuthContext, ...] = (),
    mode: ScanMode = ScanMode.SAFE,
    http_settings: HttpClientSettings | None = None,
    nested_auth_review: bool = False,
) -> ObjectScan:
    """Phase 20 entry point; the single bare-context exception never enters Phase 15."""
    if mode is not ScanMode.SAFE:
        raise HttpConfigurationError("Object authorization review supports SAFE mode only.")
    if nested_auth_review and len(contexts) < 2:
        raise HttpConfigurationError("Nested review still requires 2–3 named contexts.")
    base = http_settings or HttpClientSettings()
    _configuration(cases, contexts, base)
    result: ObjectScan
    if len(contexts) > 1:
        result = run_differential_scan(
            target_url,
            contexts=contexts,
            mode=mode,
            http_settings=base,
            nested_auth_review=nested_auth_review,
        )
    else:
        result = run_safe_execution_scan(target_url, mode=mode, http_settings=base)
    review = execute_object_authorization(
        result, cases=cases, contexts=contexts, enabled=True, http_settings=base
    )
    return replace(result, object_authorization_review=review)
