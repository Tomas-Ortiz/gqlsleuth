"""Coordinate Phase 3 discovery and deterministic GraphQL detection."""

from dataclasses import dataclass

from gqlsleuth.application.endpoint_discovery import (
    EndpointDiscoveryResult,
    EndpointProbeResult,
    discover_endpoints,
)
from gqlsleuth.application.scan_configuration import map_scan_inputs
from gqlsleuth.domain.exceptions import HttpError
from gqlsleuth.domain.models import ConfidenceLevel, Evidence, EvidenceType, ScanMode
from gqlsleuth.graphql.detection import (
    GraphQLResponseAnalysis,
    GraphQLSignal,
    analyze_graphql_response,
    no_response_analysis,
    select_final_analysis,
)
from gqlsleuth.infrastructure.http import HttpClient, HttpRequest, HttpResponse

CONFIRMATION_SOURCE = "gqlsleuth.application.graphql_detection"
MINIMAL_TYPENAME_QUERY = "query { __typename }"


@dataclass(frozen=True)
class CandidateDetectionResult:
    """GraphQL analysis and optional fallback probe outcome for one candidate."""

    candidate_url: str
    get_signals: tuple[GraphQLSignal, ...]
    post_probe_required: bool
    post_response: HttpResponse | None
    post_signals: tuple[GraphQLSignal, ...]
    post_error_type: str | None
    post_error_message: str | None
    confidence: ConfidenceLevel
    reason: str


@dataclass(frozen=True)
class GraphQLDetectionResult:
    """Complete Phase 3 discovery and Phase 4 confirmation result."""

    discovery: EndpointDiscoveryResult
    detections: tuple[CandidateDetectionResult, ...]
    confirmation_evidence: tuple[Evidence, ...]

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """Return Phase 3 and Phase 4 evidence in production order."""
        return self.discovery.evidence + self.confirmation_evidence


def run_graphql_detection(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
) -> GraphQLDetectionResult:
    """Run discovery and GraphQL detection through one shared HTTP client."""
    target, settings = map_scan_inputs(target_url, mode=mode)
    with HttpClient() as client:
        discovery = discover_endpoints(target, mode=settings.mode, client=client)
        return detect_graphql(discovery, client=client)


def detect_graphql(
    discovery: EndpointDiscoveryResult,
    *,
    client: HttpClient,
) -> GraphQLDetectionResult:
    """Analyze discovery responses and probe only inconclusive candidates."""
    detections: list[CandidateDetectionResult] = []
    evidence: list[Evidence] = []

    for probe in discovery.probes:
        get_analysis = _analyze_get(probe)
        if get_analysis.confidence in {
            ConfidenceLevel.CONFIRMED,
            ConfidenceLevel.PROBABLE,
        }:
            detection = _without_post(probe, get_analysis)
        else:
            detection = _with_post(probe, get_analysis, client)

        detections.append(detection)
        evidence.append(_confirmation_evidence(discovery, detection))

    return GraphQLDetectionResult(
        discovery=discovery,
        detections=tuple(detections),
        confirmation_evidence=tuple(evidence),
    )


def _analyze_get(probe: EndpointProbeResult) -> GraphQLResponseAnalysis:
    if probe.response is None:
        return no_response_analysis("No GET response was available for analysis.")
    return analyze_graphql_response(probe.response.body, probe.response.headers)


def _without_post(
    probe: EndpointProbeResult,
    analysis: GraphQLResponseAnalysis,
) -> CandidateDetectionResult:
    return CandidateDetectionResult(
        candidate_url=probe.candidate_url,
        get_signals=analysis.signals,
        post_probe_required=False,
        post_response=None,
        post_signals=(),
        post_error_type=None,
        post_error_message=None,
        confidence=analysis.confidence,
        reason=analysis.reason,
    )


def _with_post(
    probe: EndpointProbeResult,
    get_analysis: GraphQLResponseAnalysis,
    client: HttpClient,
) -> CandidateDetectionResult:
    try:
        response = client.send(
            HttpRequest(
                method="POST",
                url=probe.candidate_url,
                json_body={"query": MINIMAL_TYPENAME_QUERY},
            )
        )
    except HttpError as error:
        error_type = type(error).__name__
        return CandidateDetectionResult(
            candidate_url=probe.candidate_url,
            get_signals=get_analysis.signals,
            post_probe_required=True,
            post_response=None,
            post_signals=(),
            post_error_type=error_type,
            post_error_message=str(error),
            confidence=get_analysis.confidence,
            reason=f"{get_analysis.reason} POST probe failed with {error_type}.",
        )

    post_analysis = analyze_graphql_response(response.body, response.headers)
    final_analysis = select_final_analysis(get_analysis, post_analysis)
    return CandidateDetectionResult(
        candidate_url=probe.candidate_url,
        get_signals=get_analysis.signals,
        post_probe_required=True,
        post_response=response,
        post_signals=post_analysis.signals,
        post_error_type=None,
        post_error_message=None,
        confidence=final_analysis.confidence,
        reason=final_analysis.reason,
    )


def _confirmation_evidence(
    discovery: EndpointDiscoveryResult,
    detection: CandidateDetectionResult,
) -> Evidence:
    notes = [f"GET signals: {_signal_names(detection.get_signals)}"]
    notes.append(f"POST probe required: {'yes' if detection.post_probe_required else 'no'}")
    if detection.post_probe_required:
        notes.append(f"POST signals: {_signal_names(detection.post_signals)}")
    if detection.post_error_type is not None:
        notes.append(f"POST failure: {detection.post_error_type}")

    return Evidence(
        evidence_type=EvidenceType.GRAPHQL_CONFIRMATION,
        target=discovery.target,
        endpoint=detection.candidate_url,
        summary=f"{detection.confidence.value.upper()} — {detection.reason}",
        source=CONFIRMATION_SOURCE,
        confidence=detection.confidence,
        notes=tuple(notes),
    )


def _signal_names(signals: tuple[GraphQLSignal, ...]) -> str:
    return ", ".join(signal.value for signal in signals) or "none"
