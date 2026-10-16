"""Static corrections for model-content failures, never transport retry policy."""

_STRUCTURE = (
    "Use exactly the supplied structured schema, field types and complete JSON. "
    "Use only exact supplied references and distinct references within each global theme."
)
_CORRECTIONS = dict.fromkeys(
    (
        "invalid_json",
        "invalid_schema",
        "invalid_response",
        "unknown_operation_reference",
        "invalid_security_references",
        "missing_summary_references",
    ),
    _STRUCTURE,
)
_CORRECTIONS.update(
    {
        "incomplete_operation_interpretation_set": (
            "Provide exactly one interpretation for every supplied operation reference. "
            "Do not omit, duplicate, or invent operations."
        ),
        "insufficient_insight_references": (
            "Each global insight needs two or three distinct supplied references. "
            "Use an empty insights array when no useful relationship is supported."
        ),
        "output_token_limit_reached": (
            "The previous response reached the output generation limit. Regenerate the complete "
            "response more concisely. Preserve exactly one interpretation per supplied operation "
            "and finish all required fields well before their hard ceilings."
        ),
    }
)


def corrective_instruction(code: str | tuple[str, ...], attempt: int) -> str | None:
    """Unknown/local/provider errors are non-retryable; never interpolate arbitrary error text."""
    codes = (code,) if isinstance(code, str) else tuple(dict.fromkeys(code))
    if not codes or any(item not in _CORRECTIONS for item in codes):
        return None
    correction = "\n".join(dict.fromkeys(_CORRECTIONS[item] for item in codes))
    return (
        f"Regeneration attempt {attempt}. The previous response failed deterministic validation. "
        + correction
        + " Regenerate the COMPLETE structured interpretation using the same supplied facts. "
        "Do not critique the previous response or provide reasoning."
    )
