"""One console-only priority palette, including safe span styling of AI prose."""

import re

from rich.text import Text

from gqlsleuth.domain.analysis import InterestPriority

PRIORITY_STYLES = {
    InterestPriority.CRITICAL_INTEREST: "bold magenta",
    InterestPriority.HIGH_INTEREST: "bold red",
    InterestPriority.MEDIUM_INTEREST: "bold yellow",
    InterestPriority.LOW_INTEREST: "green",
    InterestPriority.INFORMATIONAL: "bright_blue",
}
_PRIORITIES_BY_WORD = {priority.value.split("_")[0]: priority for priority in PRIORITY_STYLES}
_PRIORITY_TERMS = re.compile(
    r"\b(critical|high|medium|low|informational)(?:\s+interest\b)?\b", re.I
)


def priority_label(priority: InterestPriority, *, compact: bool = False) -> Text:
    label = priority.value.split("_")[0] if compact else priority.value.replace("_", " ")
    return Text(label.upper(), style=PRIORITY_STYLES[priority])


def style_priority_terms(prose: str) -> Text:
    """Uppercase only standalone priority terms; model text is never Rich markup."""
    result = Text()
    end = 0
    for match in _PRIORITY_TERMS.finditer(prose):
        result.append(prose[end : match.start()])
        result.append(
            match.group().upper(), style=PRIORITY_STYLES[_PRIORITIES_BY_WORD[match[1].lower()]]
        )
        end = match.end()
    result.append(prose[end:])
    return result
