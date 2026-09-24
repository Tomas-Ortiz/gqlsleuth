"""Terminal, separately confirmed federation session; preparation is entirely local."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from time import perf_counter

from graphql import GraphQLError
from pydantic import JsonValue

from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.federation import (
    MAX_PHASE29_REQUESTS,
    FederationCandidate,
    FederationEvidence,
    FederationFinding,
    FederationOutcome,
    FederationPlan,
    FederationPolicy,
    FederationProbe,
    FederationSecurityResult,
    parse_entity_case,
)
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.graphql.federation import (
    FederationObservation,
    build_federation_plan,
    classify_federation_response,
)
from gqlsleuth.graphql.schema_parser import load_introspection_schema, parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest
from gqlsleuth.infrastructure.probe_evidence import (
    capture_probe_response,
    request_context_material,
    same_origin,
)
from gqlsleuth.rules.security_review import federation_surfaces, review_schema


def prepare_federation(
    safe: SafeExecutionScanResult,
    *,
    enabled: bool = False,
    entity_case: dict[str, JsonValue] | None = None,
    deny_sdl: bool = False,
) -> FederationSecurityResult:
    scan = safe.query_generation.operation_analysis.schema_scan
    if enabled is not True or scan.introspection.detection.discovery.mode is not ScanMode.ACTIVE:
        return FederationSecurityResult(
            limitations=("Federation Security requires explicit enablement and ACTIVE mode.",)
        )
    if type(deny_sdl) is not bool:
        raise HttpConfigurationError("SDL policy must be explicit Boolean state.")
    if entity_case is not None:
        try:
            entity_case = parse_entity_case(
                [json.dumps(entity_case, ensure_ascii=False, separators=(",", ":"))]
            )
        except (ValueError, TypeError, RecursionError):
            raise HttpConfigurationError("Requires one validated federation entity case.") from None
    review = safe.query_generation.security_review
    candidates = []
    limitations = []
    for source in review.candidates if review else ():
        if source.candidate_type is not SecurityCandidateType.FEDERATION_SURFACE:
            continue
        try:
            schemas = tuple(
                s.schema
                for s in scan.schemas
                if s.endpoint == source.endpoint and s.success and s.schema is not None
            )
            responses = tuple(
                s.full_response
                for s in scan.introspection.introspections
                if s.endpoint == source.endpoint and s.full_response is not None
            )
            references = tuple(
                e.evidence_id
                for e in safe.evidence
                if e.endpoint == source.endpoint and e.evidence_type is EvidenceType.SCHEMA_ARTIFACT
            )
            if (
                len(schemas) != 1
                or len(responses) != 1
                or not references
                or parse_introspection_response(responses[0].body) != schemas[0]
            ):
                raise SafeExecutionValidationError(
                    "Retained federation schema/provenance is unavailable or inconsistent."
                )
            schema = schemas[0]
            if (
                source
                not in review_schema(
                    source.endpoint, schema, source_evidence_ids=references
                ).candidates
            ):
                raise SafeExecutionValidationError(
                    "Retained Phase 16 federation source is inconsistent."
                )
            native = load_introspection_schema(responses[0].body)
            service, entities = federation_surfaces(schema, {t.name: t for t in schema.types})
            union = schema.type_named("_Entity")
            plans = []
            notes = []
            for probe, available in (
                (FederationProbe.SERVICE, service),
                (FederationProbe.ENTITY, entities and entity_case is not None),
            ):
                if available:
                    try:
                        plans.append(
                            build_federation_plan(schema, native, probe, entity_case, deny_sdl)
                        )
                    except (SafeExecutionValidationError, GraphQLError) as error:
                        notes.append(f"{probe.value}: {error}")
            candidates.append(
                FederationCandidate(
                    source.endpoint,
                    source,
                    tuple(sorted(union.possible_types)) if union else (),
                    service,
                    entities,
                    tuple(plans),
                    tuple(notes),
                )
            )
        except (SafeExecutionValidationError, SchemaParsingError, GraphQLError):
            limitations.append(
                "A retained federation endpoint has inconsistent schema/provenance; "
                "it is not selectable."
            )
    return FederationSecurityResult(candidates=tuple(candidates), limitations=tuple(limitations))


class FederationSecuritySession:
    """Rebuild canonical selected plans before every send; no caller artifact is executed."""

    def __init__(
        self,
        safe: SafeExecutionScanResult,
        *,
        enabled: bool = False,
        entity_case: dict[str, JsonValue] | None = None,
        deny_sdl: bool = False,
        http_settings: HttpClientSettings | None = None,
    ) -> None:
        self._safe, self._enabled = safe, enabled
        self._case, self._deny = deepcopy(entity_case), deny_sdl
        self._settings = http_settings or HttpClientSettings()
        self._settings_snapshot = self._settings.model_dump_json()
        self._endpoint: str | None = None
        self._selected: tuple[FederationProbe, ...] = ()
        self._preview = self._prepare()
        self._result = self._preview
        self._finished = False
        self._attempts = 0

    def _prepare(self) -> FederationSecurityResult:
        return replace(
            prepare_federation(
                self._safe, enabled=self._enabled, entity_case=self._case, deny_sdl=self._deny
            ),
            selected_endpoint=self._endpoint,
            selected_probes=self._selected,
        )

    @property
    def preview(self) -> FederationSecurityResult:
        return deepcopy(self._preview)

    def select(
        self, endpoint: str, probes: tuple[FederationProbe, ...]
    ) -> FederationSecurityResult:
        candidate = next((c for c in self._preview.candidates if c.endpoint == endpoint), None)
        available = {p.probe for p in candidate.plans} if candidate else set()
        if (
            self._finished
            or candidate is None
            or len(probes) > MAX_PHASE29_REQUESTS
            or len(set(probes)) != len(probes)
            or any(type(p) is not FederationProbe or p not in available for p in probes)
        ):
            raise HttpConfigurationError(
                "Select one retained endpoint and only its listed federation probes."
            )
        self._endpoint = endpoint
        self._selected = tuple(p for p in FederationProbe if p in probes)
        self._preview = self._prepare()
        return self.preview

    def execute(
        self, *, preview: FederationSecurityResult, confirmed: bool = False
    ) -> FederationSecurityResult:
        if self._finished:
            return deepcopy(self._result)
        self._finished = True
        self._result = replace(self._preview, confirmed=confirmed is True)
        if confirmed is not True or not self._selected:
            return deepcopy(self._result)
        attempts: list[FederationEvidence] = []
        findings = []
        limitations = list(self._preview.limitations)
        for probe in self._selected:
            try:
                fresh = self._prepare()
                valid = (
                    type(preview) is FederationSecurityResult
                    and preview == fresh
                    and self._preview == fresh
                    and type(preview.confirmed) is bool
                    and all(type(p) is FederationProbe for p in preview.selected_probes)
                    and exact_variables([p.variables for c in preview.candidates for p in c.plans])
                    == exact_variables([p.variables for c in fresh.candidates for p in c.plans])
                    and self._settings.model_dump_json() == self._settings_snapshot
                    and self._attempts == len(attempts)
                    and self._attempts < MAX_PHASE29_REQUESTS
                )
            except (HttpConfigurationError, ValueError, TypeError, RecursionError):
                valid = False
                fresh = FederationSecurityResult()
            candidate = next((c for c in fresh.candidates if c.endpoint == self._endpoint), None)
            plan = (
                next((p for p in candidate.plans if p.probe is probe), None) if candidate else None
            )
            if not valid or plan is None or candidate is None:
                limitations.append(
                    "Retained schema, context or approved federation plan changed; "
                    "remaining requests were not sent."
                )
                break
            self._attempts += 1
            evidence = self._request(candidate, plan)
            attempts.append(evidence)
            if evidence.evaluation is PolicyStatus.VIOLATED:
                service = probe is FederationProbe.SERVICE
                findings.append(
                    FederationFinding(
                        "FEDERATION_SDL_POLICY_VIOLATION"
                        if service
                        else "FEDERATION_ENTITY_AUTHORIZATION_FAILURE",
                        "Federation service metadata exposure"
                        if service
                        else "Federation entity authorization weakness",
                        candidate.endpoint,
                        evidence.evidence_id,
                        candidate.source.source_evidence_ids,
                        (
                            "Non-empty service SDL"
                            if service
                            else "The exact operator-supplied entity representation"
                        )
                        + " was returned despite the operator-supplied DENY policy.",
                    )
                )
        self._result = replace(
            self._result,
            attempts=tuple(attempts),
            findings=tuple(findings),
            limitations=tuple(limitations),
        )
        return deepcopy(self._result)

    def _request(self, candidate: FederationCandidate, plan: FederationPlan) -> FederationEvidence:
        timestamp, started = datetime.now(UTC), perf_counter()
        response = None
        error_type = None
        payload: dict[str, JsonValue] = {"query": plan.query}
        if plan.variables:
            payload["variables"] = deepcopy(plan.variables)
        try:
            with HttpClient(self._settings) as client:
                response = client.send(
                    HttpRequest(method="POST", url=candidate.endpoint, json_body=payload)
                )
        except HttpError as error:
            error_type = type(error).__name__
            observation = FederationObservation(FederationOutcome.NETWORK_FAILURE)
        else:
            observation = classify_federation_response(response.status_code, response.body, plan)
            if not same_origin(candidate.endpoint, response.final_url):
                observation = FederationObservation(FederationOutcome.INDETERMINATE)
        outcome = observation.outcome
        evaluation = None
        if plan.expected is FederationPolicy.DENY:
            evaluation = (
                PolicyStatus.VIOLATED
                if outcome in (FederationOutcome.SDL_RETURNED, FederationOutcome.ENTITY_RETURNED)
                else PolicyStatus.SATISFIED
                if outcome is FederationOutcome.EXPLICIT_DENIAL
                else PolicyStatus.UNRESOLVED
            )
        headers, body, withheld = capture_probe_response(
            response, request_context_material(self._settings)
        )
        scan = self._safe.query_generation.operation_analysis.schema_scan
        discovery = scan.introspection.detection.discovery
        return FederationEvidence(
            target=discovery.target,
            endpoint=candidate.endpoint,
            timestamp=timestamp,
            source="gqlsleuth.application.federation",
            summary=f"Federation {plan.probe.value}: {outcome.value}.",
            probe=plan.probe,
            expected=plan.expected,
            source_candidate=candidate.source,
            source_evidence_ids=candidate.source.source_evidence_ids,
            query=plan.query,
            variables=deepcopy(plan.variables),
            request_method="POST",
            outcome=outcome,
            evaluation=evaluation,
            sdl_returned=outcome is FederationOutcome.SDL_RETURNED,
            sdl_bytes=observation.sdl_bytes,
            sdl_sha256=observation.sdl_sha256,
            identity_matched=outcome is FederationOutcome.ENTITY_RETURNED,
            response_material_withheld=withheld,
            response_status_code=response.status_code if response else None,
            response_headers=headers,
            response_body=body,
            duration_seconds=response.duration_seconds if response else perf_counter() - started,
            error_type=error_type,
            error_message="Federation transport failed." if error_type else None,
        )
