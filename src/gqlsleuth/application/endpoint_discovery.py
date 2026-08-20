"""Coordinate safe HTTP probing of generated endpoint candidates."""

from dataclasses import dataclass

from gqlsleuth.application.scan_configuration import map_scan_inputs
from gqlsleuth.discovery.endpoint_candidates import generate_endpoint_candidates
from gqlsleuth.domain.exceptions import HttpError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode, Target
from gqlsleuth.infrastructure.http import HttpClient, HttpRequest, HttpResponse

DISCOVERY_SOURCE = "gqlsleuth.application.endpoint_discovery"


@dataclass(frozen=True)
class EndpointProbeResult:
    """Transport outcome for one endpoint candidate."""

    candidate_url: str
    response: HttpResponse | None = None
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class EndpointDiscoveryResult:
    """Ordered probe outcomes and their directly observed evidence."""

    target: Target
    mode: ScanMode
    probes: tuple[EndpointProbeResult, ...]
    evidence: tuple[Evidence, ...]


def run_endpoint_discovery(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
) -> EndpointDiscoveryResult:
    """Validate CLI inputs and run endpoint discovery with the shared HTTP client."""
    target, settings = map_scan_inputs(target_url, mode=mode)
    with HttpClient() as client:
        return discover_endpoints(target, mode=settings.mode, client=client)


def discover_endpoints(
    target: Target,
    *,
    mode: ScanMode,
    client: HttpClient,
) -> EndpointDiscoveryResult:
    """Probe each generated candidate with GET and retain per-candidate failures."""
    probes: list[EndpointProbeResult] = []
    evidence: list[Evidence] = []

    for candidate_url in generate_endpoint_candidates(target):
        try:
            response = client.send(HttpRequest(method="GET", url=candidate_url))
        except HttpError as error:
            error_type = type(error).__name__
            probes.append(
                EndpointProbeResult(
                    candidate_url=candidate_url,
                    error_type=error_type,
                    error_message=str(error),
                )
            )
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
                    target=target,
                    endpoint=candidate_url,
                    summary=f"GET probe failed with {error_type}: {error}",
                    source=DISCOVERY_SOURCE,
                )
            )
            continue

        probes.append(EndpointProbeResult(candidate_url=candidate_url, response=response))
        evidence.append(
            Evidence(
                evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
                target=target,
                endpoint=candidate_url,
                summary=f"GET probe returned HTTP {response.status_code} at {response.final_url}.",
                source=DISCOVERY_SOURCE,
            )
        )

    return EndpointDiscoveryResult(
        target=target,
        mode=mode,
        probes=tuple(probes),
        evidence=tuple(evidence),
    )
