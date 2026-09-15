"""Attach local structural review to retained schema/Phase 7 results, without new evidence."""

from gqlsleuth.application.operation_analysis import OperationAnalysisScanResult
from gqlsleuth.domain.models import EvidenceType
from gqlsleuth.domain.security_review import (
    GraphQLSecurityReviewCandidate,
    GraphQLSecurityReviewResult,
    SecurityReviewLimitation,
)
from gqlsleuth.rules.security_review import order_candidates, review_schema


def review_analyzed_schemas(analysis: OperationAnalysisScanResult) -> GraphQLSecurityReviewResult:
    schemas = analysis.schema_scan
    operations = {item.endpoint: item.operations for item in analysis.endpoints if item.success}
    candidates: list[GraphQLSecurityReviewCandidate] = []
    limitations: list[SecurityReviewLimitation] = []
    analyzed = []
    for item in sorted(schemas.schemas, key=lambda item: item.endpoint):
        if not item.success or item.schema is None:
            continue
        ids = tuple(
            evidence.evidence_id
            for evidence in schemas.schema_evidence
            if evidence.endpoint == item.endpoint
            and evidence.evidence_type is EvidenceType.SCHEMA_ARTIFACT
        )
        result = review_schema(
            item.endpoint, item.schema, operations.get(item.endpoint, ()), source_evidence_ids=ids
        )
        candidates.extend(result.candidates)
        limitations.extend(result.limitations)
        analyzed.append(item.endpoint)
        if item.endpoint not in operations:
            limitations.append(
                SecurityReviewLimitation(
                    item.endpoint,
                    "Phase 7 analysis unavailable; interest-dependent deprecated "
                    "operation review could not be performed. Structural review remains available.",
                )
            )
    missing = sorted(
        (
            {item.endpoint for item in schemas.introspection.introspections}
            | {item.endpoint for item in schemas.schemas}
        )
        - set(analyzed)
    )
    for endpoint in missing:
        if endpoint not in analyzed:
            limitations.append(
                SecurityReviewLimitation(
                    endpoint,
                    "Parsed schema unavailable; schema-derived security surface was not assessed. "
                    "See introspection/schema results. This is not an absence-of-risk conclusion.",
                )
            )
    if not analyzed and not missing:
        limitations.append(
            SecurityReviewLimitation(
                schemas.introspection.detection.discovery.target.original_url,
                "No parsed schema was retained; structural security review was not performed.",
            )
        )
    return GraphQLSecurityReviewResult(
        order_candidates(tuple(candidates)), tuple(limitations), tuple(analyzed)
    )
