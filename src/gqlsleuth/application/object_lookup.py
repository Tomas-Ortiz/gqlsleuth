"""Select retained object-lookup artifacts locally for explicit and adjacent-ID probes."""

from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.discovery.endpoint_candidates import normalize_discovery_url
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.security_review import GraphQLSecurityReviewCandidate, SecurityCandidateType


def retained_object_lookup(
    scan: SafeExecutionScanResult, operation: str
) -> tuple[QueryGenerationResult, GraphQLSecurityReviewCandidate]:
    """Prefer the exact target endpoint; do not guess between multiple retained artifacts."""
    artifacts = tuple(
        item
        for item in scan.query_generation.queries
        if item.operation_name == operation and item.success
    )
    schema_scan = scan.query_generation.operation_analysis.schema_scan
    discovery = schema_scan.introspection.detection.discovery
    explicit_url = normalize_discovery_url(discovery.target.original_url)
    exact = tuple(item for item in artifacts if item.endpoint == explicit_url)
    if exact:
        artifacts = exact
    if len(artifacts) != 1:
        raise SafeExecutionValidationError(
            "Requires one unambiguous retained Query artifact/endpoint."
        )
    artifact = artifacts[0]
    review = scan.query_generation.security_review
    source = next(
        (
            item
            for item in (review.candidates if review else ())
            if item.endpoint == artifact.endpoint
            and item.subject == f"query {operation}"
            and item.candidate_type is SecurityCandidateType.OBJECT_LOOKUP_REVIEW
        ),
        None,
    )
    if source is None:
        raise SafeExecutionValidationError("No retained OBJECT_LOOKUP_REVIEW structural source.")
    return artifact, source
