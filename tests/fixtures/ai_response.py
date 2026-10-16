"""Complete V2 replies for offline tests, using every supplied operation."""


def security_answer_fields(context):
    return {
        "summary_interpretation": {
            "text": "The supplied deterministic facts require scoped manual review.",
            "references": reference_items(
                []
                if context.security_facts or not context.operations
                else [context.operations[0].operation],
                [context.security_facts[0].security_fact_ref] if context.security_facts else [],
            ),
        },
        "operation_interpretations": [
            {
                "operation": operation.operation,
                "interpretation": "Review the apparent role against the intended business policy.",
                "manual_follow_up": (
                    "Manually inspect access requirements with authorized test identities."
                ),
            }
            for operation in context.operations
        ],
        "review_insights": [],
        "limitations": [],
    }


def set_operations(payload, entries):
    """Replace selected operation prose while retaining coverage of unrelated operations."""
    refs = {entry["operation"] for entry in entries}
    for entry in entries:
        entry.setdefault("manual_follow_up", "Manually inspect the intended access policy.")
    payload["operation_interpretations"] = entries + [
        entry for entry in payload["operation_interpretations"] if entry["operation"] not in refs
    ]


def reference_items(operations=(), security_facts=()):
    """Build typed generated references; never change context references."""
    return [
        *({"kind": "operation", "ref": ref} for ref in operations),
        *({"kind": "security_fact", "ref": ref} for ref in security_facts),
    ]
