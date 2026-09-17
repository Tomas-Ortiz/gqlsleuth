"""Human labels and bounded facts shared by deterministic security review views."""

from gqlsleuth.domain.security_review import GraphQLSecurityReviewCandidate, SecurityCandidateType
from gqlsleuth.presentation.capabilities import capability_wording


def candidate_label(kind: SecurityCandidateType) -> str:
    if kind is SecurityCandidateType.FLEXIBLE_SCALAR_INPUT_REVIEW:
        return "Flexible Scalar Input"
    return kind.value.replace("_", " ").title()


def candidate_summary(candidate: GraphQLSecurityReviewCandidate) -> str:
    """Short table labels; full deterministic reasons remain in details and reports."""
    return {
        SecurityCandidateType.FILE_UPLOAD_SURFACE: "Upload scalar/input observed",
        SecurityCandidateType.FEDERATION_SURFACE: "Coherent federation structures",
        SecurityCandidateType.SUBSCRIPTION_SURFACE: candidate.deterministic_reason,
        SecurityCandidateType.OBJECT_LOOKUP_REVIEW: "Direct object lookup by identifier",
        SecurityCandidateType.LIST_BOUNDING_REVIEW: "Collection without obvious size bound",
        SecurityCandidateType.RECURSIVE_GRAPH_REVIEW: "Query-reachable cycle with a list edge",
        SecurityCandidateType.FLEXIBLE_SCALAR_INPUT_REVIEW: "Broad custom scalar input",
        SecurityCandidateType.COMPLEX_INPUT_REVIEW: "Recursive/deep required input structure",
        SecurityCandidateType.DEPRECATED_SECURITY_RELEVANT_OPERATION: (
            "Deprecated with review interest"
        ),
    }[candidate.candidate_type]


def candidate_facts(candidate: GraphQLSecurityReviewCandidate) -> tuple[str, ...]:
    """Canonical JSON retains every fact; human displays bound long paths/name lists."""
    facts = tuple(
        capability_wording(text if len(text) <= 400 else text[:397] + "...")
        for text in candidate.supporting_facts[:8]
    )
    if len(candidate.supporting_facts) > 8:
        facts += ("Additional supporting facts are retained in JSON.",)
    return facts
