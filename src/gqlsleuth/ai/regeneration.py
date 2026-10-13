"""Static corrections for model-content failures, never transport retry policy."""

_STRUCTURE = (
    "Use exactly the supplied structured schema, field types and complete JSON. "
    "Use only exact supplied references, eligible control references and distinct capability pairs."
)
_CORRECTIONS = dict.fromkeys(
    (
        "invalid_json",
        "invalid_schema",
        "invalid_response",
        "unknown_operation_reference",
        "invalid_security_references",
        "missing_summary_references",
        "duplicate_operation_reference",
        "insufficient_distinct_capabilities",
        "unsupported_control_reference",
    ),
    _STRUCTURE,
)
_CORRECTIONS.update(
    {
        "execution_summary_mismatch": (
            "Copy the canonical execution summary exactly. Attempts, successes, errors and skips "
            "are distinct; do not recount or paraphrase these facts."
        ),
        "unsupported_security_assurance": (
            "Do not infer overall security, safety or absence of vulnerabilities from zero "
            "Findings, successful execution or limited controls. State only bounded observations."
        ),
        "false_absence_claim": (
            "Do not deny supplied Findings, review facts or observations. "
            "Zero deterministic Findings "
            "does not mean zero review/security facts. Preserve their distinct categories."
        ),
        "unsupported_outcome_inference": (
            "Generic SUCCESS, GRAPHQL_ERROR, HTTP_ERROR, INDETERMINATE or network outcomes do not "
            "establish a security cause, correct behavior or control enforcement. "
            "State the outcome separately from the manual-review task."
        ),
        "unsupported_control_claim": (
            "Do not assert authentication, authorization, rate limiting, input validation, depth "
            "protection or other enforcement without an eligible explicit supplied control or "
            "satisfied-policy fact and its reference. Execution SUCCESS, GRAPHQL_ERROR, "
            "HTTP_ERROR, skips, review priority and schema structure do not prove target controls. "
            "Scanner safety skips describe the scanner, not the target."
        ),
        "unsupported_review_conclusion": (
            "Review candidates and review interest warrant manual review, not vulnerability, "
            "high-risk, exploitability or absent-runtime-control conclusions. Do not escalate them."
        ),
        "incomplete_security_summary": (
            "Write a naturally complete summary of 2-4 concise sentences, "
            "normally 180-350 characters "
            "total, well below the 800-character ceiling. End with punctuation, not an ellipsis. "
            "Use one supplied observation and one limitation; avoid repeating disclaimers."
        ),
    }
)


def corrective_instruction(code: str, attempt: int) -> str | None:
    """Unknown/local/provider errors are non-retryable; never interpolate arbitrary error text."""
    correction = _CORRECTIONS.get(code)
    if correction is None:
        return None
    return (
        f"Regeneration attempt {attempt}. The previous response failed deterministic validation. "
        + correction
        + " Regenerate the COMPLETE structured interpretation using the same supplied facts. "
        "Do not critique the previous response or provide reasoning."
    )
