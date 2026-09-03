"""Coordinate safe HTTP probing of generated endpoint candidates."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from gqlsleuth.application.scan_configuration import map_scan_inputs
from gqlsleuth.discovery.endpoint_candidates import generate_endpoint_candidates
from gqlsleuth.domain.exceptions import HttpError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode, Target
from gqlsleuth.infrastructure.http import HttpClient, HttpRequest, HttpResponse

DISCOVERY_SOURCE = "gqlsleuth.application.endpoint_discovery"
DISCOVERY_TIMEOUT_SECONDS = 5.0
DISCOVERY_MAX_WORKERS = 4


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
    """Probe the preferred candidate first, then the remainder concurrently."""
    candidates = generate_endpoint_candidates(target)
    preferred = probe_endpoint_candidates(
        target,
        mode=mode,
        client=client,
        candidate_urls=candidates[:1],
    )
    remaining = probe_endpoint_candidates(
        target,
        mode=mode,
        client=client,
        candidate_urls=candidates[1:],
    )
    return combine_discovery_results(preferred, remaining)


def probe_endpoint_candidates(
    target: Target,
    *,
    mode: ScanMode,
    client: HttpClient,
    candidate_urls: tuple[str, ...],
) -> EndpointDiscoveryResult:
    """Probe an ordered candidate subset with at most four synchronous workers."""
    if len(candidate_urls) <= 1:
        probes = tuple(_probe_candidate(candidate_url, client) for candidate_url in candidate_urls)
    else:
        worker_count = min(DISCOVERY_MAX_WORKERS, len(candidate_urls))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(_probe_candidate, candidate_url, client)
                for candidate_url in candidate_urls
            ]
            probes = tuple(future.result() for future in futures)

    return EndpointDiscoveryResult(
        target=target,
        mode=mode,
        probes=probes,
        evidence=tuple(_probe_evidence(target, probe) for probe in probes),
    )


def combine_discovery_results(
    preferred: EndpointDiscoveryResult,
    remaining: EndpointDiscoveryResult,
) -> EndpointDiscoveryResult:
    """Combine compatible discovery subsets in their stable candidate order."""
    return EndpointDiscoveryResult(
        target=preferred.target,
        mode=preferred.mode,
        probes=preferred.probes + remaining.probes,
        evidence=preferred.evidence + remaining.evidence,
    )


def _probe_candidate(candidate_url: str, client: HttpClient) -> EndpointProbeResult:
    try:
        response = client.send(
            HttpRequest(
                method="GET",
                url=candidate_url,
                timeout_seconds=DISCOVERY_TIMEOUT_SECONDS,
            )
        )
    except HttpError as error:
        return EndpointProbeResult(
            candidate_url=candidate_url,
            error_type=type(error).__name__,
            error_message=str(error),
        )
    return EndpointProbeResult(candidate_url=candidate_url, response=response)


def _probe_evidence(target: Target, probe: EndpointProbeResult) -> Evidence:
    if probe.response is None:
        error_type = probe.error_type or "HttpError"
        summary = f"GET probe failed with {error_type}: {probe.error_message or 'Unknown error.'}"
    else:
        summary = (
            f"GET probe returned HTTP {probe.response.status_code} at {probe.response.final_url}."
        )
    return Evidence(
        evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
        target=target,
        endpoint=probe.candidate_url,
        summary=summary,
        source=DISCOVERY_SOURCE,
    )
