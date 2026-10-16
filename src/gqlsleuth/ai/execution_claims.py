"""Narrow lexical execution assertions checked against the existing AI projection.

This is not a natural-language fact checker. Scope is an explicit operation name/ref,
an entry's operation references, or ordinary Query/Mutation totals. Specialized probe
facts remain separate; a schema candidate never supplies an ordinary execution outcome.
"""

import re
from collections.abc import Iterator

from gqlsleuth.ai.models import AIContext, AIInterpretation, AIOperation, AIValidationError
from gqlsleuth.ai.prose_entries import prose_entries

_ASSERTION = re.compile(
    r"\b(?P<graphql_error>graphql[_ ]errors?)\b"
    r"|\b(?P<http_error>http[_ ]error)\b"
    r"|\b(?P<network_failure>network[_ ]failure)\b"
    r"|\b(?P<invalid_response>invalid[_ ]response)\b"
    r"|\b(?P<safety>skipped_safety|blocked_safety)\b"
    r"|\b(?P<limit>skipped_limit)\b"
    r"|\b(?P<not_selected>not_selected)\b"
    r"|\b(?P<declined>declined)\b"
    r"|\b(?P<not_run>not_run|unexecuted)\b"
    r"|\b(?P<success>success(?:ful(?:ly)?)?|succeeded)\b"
    r"|\b(?P<attempted>attempted|executed|ran|run|sent)\b"
    r"|\b(?P<failure>failed|failure|errored)\b"
    r"|\b(?P<skipped>skipped)\b"
    r"|\b(?P<blocked>blocked|denied|rejected)\b"
    r"|\b(?P<returned>returned)\b",
    re.IGNORECASE,
)
_KIND = re.compile(r"\b(query|queries|mutation|mutations)\b", re.IGNORECASE)
_NON_EXECUTION = re.compile(
    r"\b(?:schema|introspection|parsing|retrieval|generation|discovery)\b", re.IGNORECASE
)
_NON_ASSERTION = re.compile(
    r"\b(?:if|whether|should|must|cannot|can't)\b"
    r"|\b(?:does not|do not)\s+(?:establish|prove|mean|indicate|imply|show)\b"
    r"|\bno overall security assurance can be inferred\b"
    r"|^\s*(?:manually\s+)?(?:review|verify|check|assess|inspect)\b",
    re.IGNORECASE,
)
_NUMBERS = dict(
    enumerate(
        [
            "zero",
            "one",
            "two",
            "three",
            "four",
            "five",
            "six",
            "seven",
            "eight",
            "nine",
            "ten",
            "eleven",
            "twelve",
            "thirteen",
            "fourteen",
            "fifteen",
            "sixteen",
            "seventeen",
            "eighteen",
            "nineteen",
            "twenty",
        ]
    )
)
_NUMBER = re.compile(r"\b(?:\d+|" + "|".join(_NUMBERS.values()) + r")\b", re.IGNORECASE)
_ERRORS = {"graphql_error", "http_error", "invalid_response", "network_failure"}


def _entries(
    interpretation: AIInterpretation,
    context: AIContext,
) -> Iterator[tuple[str, tuple[str, ...]]]:
    def ordinary_refs(refs: tuple[str, ...]) -> tuple[str, ...]:
        # Schema-only review references can identify an ordinary operation, but never
        # supply an outcome themselves. Specialized probe outcomes are separate facts.
        return tuple(
            o.operation
            for o in context.operations
            if any(
                f.security_fact_ref in refs
                and f.category == "review_candidate"
                and f.name == o.name
                and f.kind == o.kind.value
                for f in context.security_facts
            )
        )

    for index, (text, refs, facts) in enumerate(prose_entries(interpretation)):
        # Summary references identify themes, not an implicit execution subject.
        # Preserve the summary's aggregate/named-operation scope from AI-013.
        yield text, () if index == 0 else refs or ordinary_refs(facts)


def _operation_supports(operation: AIOperation, state: str) -> bool:
    status = operation.execution_status
    decision = operation.mutation_decision or operation.mutation_safety
    match state:
        case "attempted":
            return operation.attempted
        case "not_run":
            return not operation.attempted
        case "safety":
            return not operation.attempted and (
                status == "skipped_safety" or decision == "blocked_safety"
            )
        case "limit":
            return not operation.attempted and (
                status == "skipped_limit" or decision == "skipped_limit"
            )
        case "not_selected" | "declined":
            return not operation.attempted and decision == state
        case "skipped":
            return not operation.attempted and (
                status in {"skipped_safety", "skipped_limit"}
                or decision in {"blocked_safety", "skipped_limit", "not_selected", "declined"}
            )
        case "blocked":
            # A transport failure or a scanner skip is never a target rejection.
            # This says nothing about the cause; AI-012 still governs control claims.
            return operation.attempted and operation.http_status in {401, 403}
        case "failure":
            return operation.attempted and status in _ERRORS
        case "returned":
            return operation.attempted and status in {
                "success",
                "graphql_error",
                "http_error",
                "invalid_response",
            }
        case _:
            return operation.attempted and status == state


def _count(context: AIContext, kind: str, state: str) -> int | None:
    counts = context.counts
    if state == "attempted":
        return counts.get(f"{kind}_requests")
    if state == "not_run":
        total, attempts = counts.get(f"{kind}_count"), counts.get(f"{kind}_requests")
        return total - attempts if total is not None and attempts is not None else None
    if state == "failure":
        return sum(counts.get(f"{kind}_{status}", 0) for status in _ERRORS)
    if state == "returned":
        return sum(
            counts.get(f"{kind}_{status}", 0)
            for status in _ERRORS - {"network_failure"} | {"success"}
        )
    if kind == "query" and state in {"skipped", "safety", "limit"}:
        return sum(
            counts.get(f"query_skipped_{suffix}", 0)
            for suffix in ("safety", "limit")
            if state == "skipped" or suffix == state
        )
    if state in {"success", *_ERRORS}:
        return counts.get(f"{kind}_{state}")
    # No aggregate target-denial/Mutation safety counter exists in this projection.
    # Use operation facts only when the relevant population was not truncated.
    operations = tuple(o for o in context.operations if o.kind.value == kind)
    if len(operations) == counts.get(f"{kind}_count"):
        return sum(_operation_supports(o, state) for o in operations)
    return None


def _explicit_operations(clause: str, context: AIContext) -> tuple[AIOperation, ...]:
    kinds = tuple(_KIND.finditer(clause))
    kind = None
    if kinds:
        kind = "query" if kinds[-1][0].casefold() in {"query", "queries"} else "mutation"
    return tuple(
        operation
        for operation in context.operations
        if (kind is None or operation.kind.value == kind)
        and (
            re.search(r"(?<![\w/])" + re.escape(operation.operation) + r"(?![\w/])", clause)
            or re.search(r"(?<![\w/])" + re.escape(operation.name) + r"(?![\w/])", clause)
        )
    )


def validate_execution_claims(interpretation: AIInterpretation, context: AIContext) -> None:
    """Reject supported assertion forms on contradiction or missing execution truth.

    Counts come from the complete canonical totals, never the truncated operation list.
    Operation references supply local scope only; they cannot lend a successful outcome
    to another named operation or to aggregate claims. No rejected text is retained.
    """
    by_ref = {o.operation: o for o in context.operations}
    for text, refs in _entries(interpretation, context):
        scope: tuple[AIOperation, ...] = tuple(by_ref[ref] for ref in refs)
        kind: str | None = None
        # Carry scope across a short entry, allowing coordinated counts and "It ...".
        # Negation does not carry across conjunctions or sentences.
        for clause in re.split(r"[.!?;:,\n]|\b(?:but|however|yet|and)\b", text):
            assertions = tuple(_ASSERTION.finditer(clause))
            if not assertions:
                explicit = _explicit_operations(clause, context)
                if explicit:
                    scope, kind = explicit, None
                continue
            explicit = _explicit_operations(clause, context)
            kinds = tuple(_KIND.finditer(clause))
            # Exact entry references disambiguate duplicate names across endpoints/roots.
            if explicit and refs and not kinds:
                scoped = tuple(o for o in explicit if o.operation in refs)
                if scoped:
                    explicit = scoped
            if explicit:
                scope, kind = explicit, None
            elif kinds and (not scope or kinds[-1][0].casefold() in {"queries", "mutations"}):
                kind = "query" if kinds[-1][0].casefold() in {"query", "queries"} else "mutation"
                scope = ()
            if not scope and not kind:
                if re.search(
                    r"`[^`]+`|\b(?:operation|operations)\b", clause, re.I
                ) and not _NON_ASSERTION.search(clause):
                    raise AIValidationError("facts", "unsupported_execution_claim")
                continue
            if _NON_EXECUTION.search(clause) and not explicit and not kinds:
                continue
            for assertion in assertions:
                prefix = clause[: assertion.start()]
                if _NON_ASSERTION.search(prefix):
                    continue
                state = assertion.lastgroup
                assert state is not None
                lower = clause.casefold()
                # A general denial of inference is not a claim that this operation ran.
                if re.match(
                    r"\s*(?:success(?:ful execution)?|graphql_error|http_error)\s+"
                    r"(?:does not|do not)\s+(?:establish|prove|mean|indicate|imply|suggest)",
                    lower,
                ):
                    continue
                if state == "blocked" and re.search(r"\b(?:gqlsleuth|scanner|safety)\b", lower):
                    state = "safety"
                if state == "skipped" and "safety" in lower:
                    state = "safety"
                # "returned a GraphQL error" is governed by that exact outcome;
                # "returned a result/data" needs SUCCESS, not a transport failure.
                if state == "returned" and any(a.lastgroup in _ERRORS for a in assertions):
                    continue
                if state == "returned" and re.search(r"\b(?:result|data|object)\b", lower):
                    state = "success"
                negated = bool(
                    re.search(
                        r"\b(?:not|never|neither)\b|n't\b|\bno\s+(?:ordinary\s+)?"
                        r"(?:queries|query|mutations?|operations?|requests?)\b",
                        prefix,
                        re.I,
                    )
                )
                if scope:
                    supported = all(_operation_supports(o, state) != negated for o in scope)
                else:
                    assert kind is not None
                    count = _count(context, kind, state)
                    numbers = tuple(_NUMBER.finditer(prefix))
                    if not numbers:
                        # Active voice: "executed two mutations". HTTP codes are not counts.
                        numbers = tuple(
                            m
                            for m in _NUMBER.finditer(clause[assertion.end() :])
                            if _KIND.match(clause[assertion.end() + m.end() :].lstrip())
                        )
                    expected = None
                    if numbers:
                        value = numbers[-1][0].casefold()
                        expected = (
                            int(value)
                            if value.isdigit()
                            else next(n for n, word in _NUMBERS.items() if word == value)
                        )
                    if re.search(r"\ball\b", prefix, re.I) and expected is None:
                        expected = context.counts.get(f"{kind}_count")
                    supported = count is not None and (
                        count == 0
                        if negated
                        else count == expected
                        if expected is not None
                        else count > 0
                    )
                if not supported:
                    raise AIValidationError("facts", "unsupported_execution_claim")
