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
        SecurityCandidateType.LIST_BOUNDING_REVIEW: (
            "Collection without a schema-visible result limit"
        ),
        SecurityCandidateType.RECURSIVE_GRAPH_REVIEW: (
            "Query can follow object relationships in a loop, including a list"
        ),
        SecurityCandidateType.FLEXIBLE_SCALAR_INPUT_REVIEW: "Broad custom scalar input",
        SecurityCandidateType.COMPLEX_INPUT_REVIEW: "Recursive/deep required input structure",
        SecurityCandidateType.DEPRECATED_SECURITY_RELEVANT_OPERATION: (
            "Deprecated with review interest"
        ),
    }[candidate.candidate_type]


def review_wording(text: str) -> str:
    """Clarify known schema-review prose in human views only; retain all qualifications."""
    text = capability_wording(text)
    for original, readable in (
        ("Obvious bounding input:", "Input to limit the number of results:"),
        (
            "no obvious result-size bounding input was observed in the schema",
            "no schema input was found that clearly limits how many results it can return",
        ),
        ("A bounding input's presence", "The presence of a result-limit input"),
        (
            "A Query-reachable output cycle contains a list-valued composite relationship.",
            "A Query can follow object relationships back to an earlier type. "
            "At least one relationship returns a list of objects.",
        ),
    ):
        text = text.replace(original, readable)
    return text


def candidate_facts(candidate: GraphQLSecurityReviewCandidate) -> tuple[str, ...]:
    """Canonical JSON retains every fact; human displays bound long paths/name lists."""
    facts = tuple(
        text if len(text) <= 400 else text[:397] + "..."
        for text in map(review_wording, candidate.supporting_facts[:8])
    )
    if len(candidate.supporting_facts) > 8:
        facts += ("Additional supporting facts are retained in JSON.",)
    return facts
