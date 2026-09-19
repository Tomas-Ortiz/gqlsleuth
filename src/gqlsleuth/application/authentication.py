"""One selected retained baseline and at most three independently consented header-only probes."""

import json
import re
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import perf_counter

from graphql import GraphQLError

from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.authentication import (
    MAX_PHASE26_REQUESTS,
    AuthenticationFindingKind,
    AuthenticationProbe,
    AuthenticationProbeEvidence,
    AuthenticationProbeExecution,
    AuthenticationQueryCandidate,
    AuthenticationSecurityFinding,
    AuthenticationSecurityResult,
)
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import EvidenceType, ScanMode, Target
from gqlsleuth.domain.nested_authorization import NestedOutcome
from gqlsleuth.graphql.authentication import classify_authentication_response
from gqlsleuth.graphql.object_authorization import validate_object_document
from gqlsleuth.graphql.safe_execution import classify_execution_response, validate_safe_artifact
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest
from gqlsleuth.infrastructure.probe_evidence import (
    capture_probe_response,
    request_context_material,
)
from gqlsleuth.infrastructure.probe_evidence import (
    contains_request_material as _contains_material,
)
from gqlsleuth.infrastructure.probe_evidence import (
    same_origin as _same_origin,
)
from gqlsleuth.rules.token_security import available_jwt_probes, inspect_bearer, token_variant


def bearer_token(settings: HttpClientSettings) -> str:
    """Read existing validated header settings; errors never interpolate input material."""
    values = tuple(
        value for name, value in settings.custom_headers if name.lower() == "authorization"
    )
    if len(values) != 1:
        raise HttpConfigurationError(
            "Authentication security requires exactly one Authorization Bearer header."
        )
    match = re.fullmatch(r"(?i:Bearer)[ \t]+([^\s]+)", values[0], flags=re.ASCII)
    if match is None:
        raise HttpConfigurationError(
            "Authentication security requires a non-empty Authorization Bearer token."
        )
    return match[1]


def _request_material(settings: HttpClientSettings) -> tuple[str, ...]:
    """Transient carrier/variant material for this capability's explicit capture boundary."""
    token = bearer_token(settings)
    values = list(request_context_material(settings))
    values.append(token)
    values.extend(token_variant(token, probe) for probe in available_jwt_probes(token))
    return tuple(value for value in values if value)


def prepare_authentication_security(
    safe: SafeExecutionScanResult,
    *,
    http_settings: HttpClientSettings,
    enabled: bool = False,
    selected_index: int | None = None,
    selected_probes: tuple[AuthenticationProbe, ...] = (),
    inspected_at: datetime | None = None,
) -> AuthenticationSecurityResult:
    token = bearer_token(http_settings)
    now = inspected_at or datetime.now(UTC)
    review = inspect_bearer(token, now)
    result = AuthenticationSecurityResult(review)
    scan = safe.query_generation.operation_analysis.schema_scan
    if enabled is not True or scan.introspection.detection.discovery.mode is not ScanMode.ACTIVE:
        return replace(
            result,
            limitations=("Authentication security requires explicit enablement and ACTIVE mode.",),
        )
    available = available_jwt_probes(token)
    if any(
        type(probe) is not AuthenticationProbe or probe not in available
        for probe in selected_probes
    ) or len(set(selected_probes)) != len(selected_probes):
        raise HttpConfigurationError(
            "Select only eligible individual JWT probes, at most once each."
        )
    material = _request_material(http_settings)
    candidates: list[AuthenticationQueryCandidate] = []
    for execution in safe.executions:
        artifact, response = execution.generated_query, execution.response
        if (
            execution.status is not QueryExecutionStatus.SUCCESS
            or execution.attempted is not True
            or response is None
        ):
            continue
        try:
            if artifact not in safe.query_generation.queries or not _same_origin(
                artifact.endpoint, response.final_url
            ):
                continue
            if artifact.operation not in tuple(
                op
                for endpoint in safe.query_generation.operation_analysis.endpoints
                for op in endpoint.operations
            ):
                continue
            schemas = [
                item.schema
                for item in scan.schemas
                if item.endpoint == artifact.endpoint and item.success and item.schema is not None
            ]
            raw = [
                item.full_response
                for item in scan.introspection.introspections
                if item.endpoint == artifact.endpoint and item.full_response is not None
            ]
            if len(schemas) != 1 or len(raw) != 1:
                continue
            validate_safe_artifact(schemas[0], artifact)
            validate_object_document(
                load_introspection_schema(raw[0].body),
                artifact.query_text or "",
                artifact.variables,
            )
            if (
                classify_execution_response(response.status_code, response.body).status
                is not QueryExecutionStatus.SUCCESS
                or classify_authentication_response(
                    response.status_code, response.body, artifact.operation_name
                )
                is not NestedOutcome.RETURNED
            ):
                continue
            evidence = [
                item
                for item in safe.execution_evidence
                if item.evidence_type is EvidenceType.QUERY_EXECUTION
                and item.endpoint == artifact.endpoint
                and item.query == artifact.query_text
                and exact_variables(item.variables) == exact_variables(artifact.variables)
                and item.request_method == "POST"
                and item.error_type is None
                and item.response_body == response.body
                and item.response_status_code == response.status_code
            ]
            if len(evidence) != 1 or _contains_material(
                json.dumps(
                    (
                        scan.introspection.detection.discovery.target.original_url,
                        artifact.endpoint,
                        artifact.query_text,
                        artifact.variables,
                    )
                ),
                material,
            ):
                continue
            baseline = evidence[0]
            duration = baseline.duration_seconds
            if duration is None or duration < 0:
                continue
            candidates.append(
                AuthenticationQueryCandidate(
                    len(candidates) + 1,
                    artifact.endpoint,
                    artifact.operation_name,
                    artifact.query_text or "",
                    deepcopy(artifact.variables),
                    baseline.evidence_id,
                    baseline.timestamp - timedelta(seconds=duration),
                    baseline.timestamp,
                )
            )
        except (
            SafeExecutionValidationError,
            SchemaParsingError,
            GraphQLError,
            ValueError,
            TypeError,
            RecursionError,
            OverflowError,
        ):
            continue
    if selected_index is not None and (
        type(selected_index) is not int or not 1 <= selected_index <= len(candidates)
    ):
        raise HttpConfigurationError("Select exactly one retained successful Query index, or none.")
    selected = candidates[selected_index - 1] if selected_index is not None else None
    if selected is None and selected_probes:
        raise HttpConfigurationError("JWT probe selection requires one selected Query.")
    if selected:
        review = inspect_bearer(
            token, selected.baseline_started_at, completed_at=selected.baseline_completed_at
        )
    return replace(
        result,
        token_review=review,
        candidates=tuple(candidates),
        available_probes=available,
        selected_query=selected,
        selected_probes=tuple(probe for probe in available if probe in selected_probes),
        limitations=()
        if candidates
        else ("No unambiguous retained successful safe Query baseline is eligible.",),
    )


def _matches(left: AuthenticationSecurityResult, right: AuthenticationSecurityResult) -> bool:
    try:
        return (
            type(left) is AuthenticationSecurityResult
            and left == right
            and type(left.confirmed) is bool
            and exact_variables(tuple(item.variables for item in left.candidates))
            == exact_variables(tuple(item.variables for item in right.candidates))
            and exact_variables(left.selected_query.variables if left.selected_query else None)
            == exact_variables(right.selected_query.variables if right.selected_query else None)
        )
    except (TypeError, ValueError, RecursionError):
        return False


class AuthenticationSecuritySession:
    """Private settings own transient token access; normal results contain no token material."""

    def __init__(
        self,
        safe: SafeExecutionScanResult,
        *,
        http_settings: HttpClientSettings,
        selected_index: int | None = None,
        selected_probes: tuple[AuthenticationProbe, ...] = (),
        enabled: bool = False,
    ) -> None:
        self._safe, self._settings, self._enabled = safe, http_settings, enabled
        self._index, self._probes = selected_index, selected_probes
        self._inspected_at = datetime.now(UTC)
        self._attempts = 0
        self._preview = self._prepare()
        self._result = self._preview

    def _prepare(self) -> AuthenticationSecurityResult:
        return prepare_authentication_security(
            self._safe,
            http_settings=self._settings,
            enabled=self._enabled,
            selected_index=self._index,
            selected_probes=self._probes,
            inspected_at=self._inspected_at,
        )

    @property
    def preview(self) -> AuthenticationSecurityResult:
        return deepcopy(self._preview)

    def execute(
        self, *, preview: AuthenticationSecurityResult, confirmed: bool = False
    ) -> AuthenticationSecurityResult:
        if self._attempts:
            return deepcopy(self._result)
        try:
            canonical = self._prepare()
        except HttpConfigurationError:
            return replace(
                self._preview,
                confirmed=confirmed is True,
                executions=tuple(
                    AuthenticationProbeExecution(
                        probe, "Retained baseline or carrier changed; authentication probe skipped."
                    )
                    for probe in (AuthenticationProbe.AUTHORIZATION_REMOVED, *self._probes)
                ),
            )
        selected = canonical.selected_query
        if selected is None:
            return replace(canonical, confirmed=confirmed is True)
        executions = []
        findings = []
        control = None
        for probe in (AuthenticationProbe.AUTHORIZATION_REMOVED, *canonical.selected_probes):
            try:
                fresh = self._prepare()
            except HttpConfigurationError:
                fresh = None
            reason = None
            if confirmed is not True:
                reason = "Separate authentication security confirmation was not given."
            elif fresh is None or not all(
                _matches(plan, fresh) for plan in (canonical, self._preview, preview)
            ):
                reason = (
                    "Authentication plan no longer matches the retained baseline and selection."
                )
            elif self._attempts >= MAX_PHASE26_REQUESTS:
                reason = "Three-attempt authentication security limit reached."
            elif probe is not AuthenticationProbe.AUTHORIZATION_REMOVED and (
                control is None or control.outcome is not NestedOutcome.EXPLICIT_DENIAL
            ):
                reason = (
                    "JWT probe skipped: Authorization-removed control did not establish "
                    "explicit denial."
                )
            if reason:
                executions.append(AuthenticationProbeExecution(probe, reason))
                continue
            assert fresh is not None and fresh.selected_query is not None
            self._attempts += 1
            evidence = _request(self._safe, fresh, probe, self._settings)
            executions.append(AuthenticationProbeExecution(probe, evidence.summary, evidence))
            if probe is AuthenticationProbe.AUTHORIZATION_REMOVED:
                control = evidence
            assert control is not None
            kinds = []
            if evidence.outcome is NestedOutcome.RETURNED:
                kinds.append(
                    {
                        AuthenticationProbe.AUTHORIZATION_REMOVED: (
                            AuthenticationFindingKind.AUTHENTICATION_ENFORCEMENT_FAILURE
                        ),
                        AuthenticationProbe.JWT_SIGNATURE_TAMPERED: (
                            AuthenticationFindingKind.JWT_SIGNATURE_VALIDATION_FAILURE
                        ),
                        AuthenticationProbe.JWT_ALG_NONE: (
                            AuthenticationFindingKind.JWT_NONE_ALGORITHM_ACCEPTED
                        ),
                    }[probe]
                )
            if (
                probe is AuthenticationProbe.AUTHORIZATION_REMOVED
                and evidence.outcome is NestedOutcome.EXPLICIT_DENIAL
            ):
                temporal = dict(canonical.token_review.temporal_states)
                if canonical.token_review.unsigned:
                    kinds.append(AuthenticationFindingKind.JWT_NONE_ALGORITHM_ACCEPTED)
                if temporal.get("exp") == "expired":
                    kinds.append(AuthenticationFindingKind.EXPIRED_JWT_ACCEPTED)
                if temporal.get("nbf") == "not yet valid":
                    kinds.append(AuthenticationFindingKind.NOT_YET_VALID_JWT_ACCEPTED)
            for kind in kinds:
                condition, explanation = _FINDING_TEXT[kind]
                findings.append(
                    AuthenticationSecurityFinding(
                        kind,
                        selected.endpoint,
                        selected.operation,
                        selected.baseline_evidence_id,
                        evidence.evidence_id,
                        control.evidence_id,
                        condition,
                        explanation,
                    )
                )
        self._result = replace(
            canonical,
            confirmed=confirmed is True,
            executions=tuple(executions),
            findings=tuple(findings),
        )
        return deepcopy(self._result)


_FINDING_TEXT = {
    AuthenticationFindingKind.AUTHENTICATION_ENFORCEMENT_FAILURE: (
        "Authorization removed",
        "The operator selected this Query as requiring Bearer authentication. "
        "The exact same Query and variables returned successful GraphQL data "
        "after Authorization was removed.",
    ),
    AuthenticationFindingKind.JWT_SIGNATURE_VALIDATION_FAILURE: (
        "Deliberately altered JWT signature",
        "The selected Query was denied without Authorization but returned "
        "successful GraphQL data with unchanged JWT header/payload and a "
        "deliberately altered signature.",
    ),
    AuthenticationFindingKind.JWT_NONE_ALGORITHM_ACCEPTED: (
        "Unsigned JWT using alg=none",
        "The selected Query was denied without Authorization but returned "
        "successful GraphQL data with an unsigned JWT using alg=none, "
        "in the baseline or selected probe.",
    ),
    AuthenticationFindingKind.EXPIRED_JWT_ACCEPTED: (
        "Supplied JWT expired before baseline",
        "The successful retained Query used a supplied JWT already expired "
        "beyond the conservative clock-skew allowance; removing Authorization "
        "produced explicit denial.",
    ),
    AuthenticationFindingKind.NOT_YET_VALID_JWT_ACCEPTED: (
        "Supplied JWT not yet valid at baseline",
        "The successful retained Query used a supplied JWT whose nbf "
        "was beyond the baseline and clock-skew allowance; removing Authorization "
        "produced explicit denial.",
    ),
}


def _request(
    safe: SafeExecutionScanResult,
    plan: AuthenticationSecurityResult,
    probe: AuthenticationProbe,
    settings: HttpClientSettings,
) -> AuthenticationProbeEvidence:
    selected = plan.selected_query
    assert selected is not None
    token = bearer_token(settings)
    variant = (
        token_variant(token, probe)
        if probe is not AuthenticationProbe.AUTHORIZATION_REMOVED
        else None
    )
    headers = tuple(
        (name, value if name.lower() != "authorization" else "Bearer " + (variant or ""))
        for name, value in settings.custom_headers
        if name.lower() != "authorization" or variant is not None
    )
    changed = settings.model_copy(update={"custom_headers": headers})
    timestamp, started = datetime.now(UTC), perf_counter()
    response = None
    error_type = None
    try:
        with HttpClient(changed) as client:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=selected.endpoint,
                    json_body={"query": selected.query, "variables": deepcopy(selected.variables)},
                )
            )
    except HttpError as error:
        error_type = type(error).__name__
        outcome = NestedOutcome.NETWORK_FAILURE
    else:
        outcome = (
            classify_authentication_response(
                response.status_code, response.body, selected.operation
            )
            if _same_origin(selected.endpoint, response.final_url)
            else NestedOutcome.INDETERMINATE
        )
    status = (
        PolicyStatus.VIOLATED
        if outcome is NestedOutcome.RETURNED
        else PolicyStatus.SATISFIED
        if outcome is NestedOutcome.EXPLICIT_DENIAL
        else PolicyStatus.UNRESOLVED
    )
    response_headers, body, withheld = capture_probe_response(response, _request_material(settings))
    discovery = (
        safe.query_generation.operation_analysis.schema_scan.introspection.detection.discovery
    )
    target: Target = discovery.target
    return AuthenticationProbeEvidence(
        target=target,
        endpoint=selected.endpoint,
        timestamp=timestamp,
        source="gqlsleuth.application.authentication",
        summary=f"Authentication probe observed {outcome.value.upper()}.",
        operation=selected.operation,
        baseline_evidence_id=selected.baseline_evidence_id,
        probe_type=probe,
        token_review=plan.token_review,
        outcome=outcome,
        policy_result=status,
        query=selected.query,
        variables=deepcopy(selected.variables),
        request_method="POST",
        response_status_code=response.status_code if response else None,
        response_headers=response_headers,
        response_body=body,
        response_material_withheld=withheld,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message="Target transport failed." if error_type else None,
    )
