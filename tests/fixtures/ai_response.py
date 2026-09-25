"""Small valid Phase 31 additions for deterministic mocked model replies."""


def security_answer_fields(context):
    return {
        "security_summary": {
            "text": "The supplied deterministic facts require scoped manual review.",
            "security_facts": [context.security_facts[0].security_fact_ref]
            if context.security_facts
            else [],
        },
        "security_fact_reviews": [],
        "control_observations": [],
        "cross_capability_insights": [],
    }
