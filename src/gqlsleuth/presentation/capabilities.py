"""Translate legacy developer stage labels only at human presentation boundaries."""

import re

_CAPABILITIES = {
    "Phase 20/21": "object authorization / authorization policy validation",
    "Phase 20": "object authorization",
    "Phase 21": "authorization policy validation",
    "Phase 22": "sequential object discovery",
    "Phase 18": "Query-depth validation",
    "Phase 17": "Query-shape validation",
    "Phase 7": "operation analysis",
}
_STAGE_LABEL = re.compile(r"\bPhase (?:20/21|20|21|22|18|17|7)\b")


def capability_wording(text: str) -> str:
    """Leave retained reasons/evidence unchanged while using functional names in human views."""
    return _STAGE_LABEL.sub(lambda match: _CAPABILITIES[match[0]], text)
