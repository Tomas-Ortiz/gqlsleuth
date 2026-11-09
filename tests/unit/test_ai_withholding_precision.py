"""Paired grounding regressions and content-free verbose field diagnostics."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import (
    AIAnalysisStatus,
    AISecurityFact,
    AIWithheldField,
)
from gqlsleuth.ai.prompt import build_response_schema, build_system_prompt, validate_interpretation
from gqlsleuth.ai.quality import WITHHELD_PROSE, enforce_interpretation_grounding
from gqlsleuth.ai.sections import withholding_diagnostic_rows
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.presentation.limits import MAX_HUMAN_INVENTORY_ITEMS
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def prepared(phase_ten_scan):
    scan, _ = phase_ten_scan(
        """
        type Query { country(code: String!): Country continents: [Continent!]! }
        type Country { code: ID phone: String }
        type Continent { code: ID countries: [Country] }
        type Mutation { createUser: User createAlbum(input: AlbumInput!): Album }
        input AlbumInput { userId: ID! title: String }
        type User { id: ID } type Album { id: ID }
        """,
        mode=ScanMode.SAFE,
    )
    return scan, build_ai_context(scan)


def response(context, text, *, name="createUser", field="manual_follow_up"):
    payload = security_answer_fields(context)
    item = next(
        i for i in payload["operation_interpretations"] if i["operation"].endswith("/" + name)
    )
    item[field] = text
    return payload


def enforce(context, payload):
    original = validate_interpretation(json.dumps(payload), context)
    return original, enforce_interpretation_grounding(original, context)


@pytest.mark.parametrize(
    "name,text,code",
    [
        (
            "country",
            "This lookup allows unauthorized object access.",
            "unsupported_review_conclusion",
        ),
        ("country", "This lookup accesses unauthorized objects.", "unsupported_review_conclusion"),
        ("country", "This lookup accessed unauthorized objects.", "unsupported_review_conclusion"),
        (
            "countries",
            "The countries Query has no result-size controls.",
            "unsupported_control_claim",
        ),
        (
            "countries",
            "The countries Query has no runtime result-size controls.",
            "unsupported_control_claim",
        ),
    ],
)
@pytest.mark.parametrize("field", ["interpretation", "manual_follow_up"])
def test_equivalent_unsupported_lookup_and_collection_claims(
    phase_ten_scan, name, text, code, field
):
    scan, _ = phase_ten_scan(
        "type Query { countries: [Country] country(id: ID!): Country } type Country { id: ID }",
        mode=ScanMode.SAFE,
    )
    context = build_ai_context(scan)
    assert any(f.name == name and f.category == "review_candidate" for f in context.security_facts)
    before, context_before = deepcopy(scan), serialize_context(context)
    original, (filtered, codes, decisions) = enforce(
        context, response(context, text, name=name, field=field)
    )
    assert codes == (code,) and len(decisions) == 1
    decision = decisions[0]
    assert decision.section == "operation_interpretations" and decision.field == field
    assert decision.rule_codes == (code,)
    entry = filtered.operation_interpretations[decision.index]
    assert getattr(entry, field) == WITHHELD_PROSE
    assert filtered == original.model_copy(
        update={
            "operation_interpretations": tuple(
                item.model_copy(update={field: WITHHELD_PROSE}) if i == decision.index else item
                for i, item in enumerate(original.operation_interpretations)
            )
        }
    )
    assert text not in filtered.model_dump_json() and text not in str(decisions)
    assert scan == before and serialize_context(context) == context_before


@pytest.mark.parametrize("verb", ["Review", "Verify", "Check", "Assess", "Inspect", "Ensure"])
@pytest.mark.parametrize(
    "tail", ["input validation to prevent injection.", "authorization is enforced."]
)
def test_standalone_control_recommendations(prepared, verb, tail):
    _, context = prepared
    original, (filtered, codes, decisions) = enforce(context, response(context, f"{verb} {tail}"))
    assert filtered == original and codes == decisions == ()


@pytest.mark.parametrize(
    "text,code",
    [
        ("Authorization is enforced.", "unsupported_control_claim"),
        ("Authorization is missing.", "unsupported_control_claim"),
        ("Input validation prevents injection.", "unsupported_control_claim"),
        ("The endpoint has no authorization controls.", "unsupported_control_claim"),
        ("Ownership validation is effective.", "unsupported_control_claim"),
        ("This mutation allows unauthorized data creation.", "unsupported_review_conclusion"),
        ("This mutation allows unauthorized data modification.", "unsupported_review_conclusion"),
        ("This lookup is a confirmed IDOR vulnerability.", "unsupported_review_conclusion"),
        ("This lookup is a BOLA vulnerability.", "unsupported_review_conclusion"),
        ("This lookup is a confirmed IDOR/BOLA vulnerability.", "unsupported_review_conclusion"),
        ("This operation has an access-control failure.", "unsupported_review_conclusion"),
        ("The mutation executed successfully.", "unsupported_execution_claim"),
        ("The business logic succeeded.", "unsupported_review_conclusion"),
        (
            "Review whether authorization is enforced, "
            "and note that createUser lacks authorization.",
            "unsupported_control_claim",
        ),
        (
            "Verify whether authorization is enforced, and createUser is vulnerable.",
            "unsupported_review_conclusion",
        ),
        (
            "Ensure authorization is enforced, and authorization is missing.",
            "unsupported_control_claim",
        ),
        (
            "Review whether authorization is enforced, "
            "and the operation allows unauthorized access.",
            "unsupported_review_conclusion",
        ),
        (
            "Review input validation because authorization is missing.",
            "unsupported_control_claim",
        ),
    ],
)
@pytest.mark.parametrize("field", ["interpretation", "manual_follow_up"])
def test_unsupported_assertions_and_continuations(prepared, text, code, field):
    scan, context = prepared
    before, context_before = deepcopy(scan), serialize_context(context)
    original, (filtered, codes, decisions) = enforce(context, response(context, text, field=field))
    assert code in codes and len(decisions) == 1
    decision = decisions[0]
    assert decision.section == "operation_interpretations" and decision.field == field
    assert code in decision.rule_codes
    entry = filtered.operation_interpretations[decision.index]
    assert entry.operation.endswith("/createUser") and getattr(entry, field) == WITHHELD_PROSE
    sibling = "manual_follow_up" if field == "interpretation" else "interpretation"
    assert getattr(entry, sibling) == getattr(
        original.operation_interpretations[decision.index], sibling
    )
    assert scan == before and serialize_context(context) == context_before


@pytest.mark.parametrize(
    "name,text,accepted",
    [
        ("country", "The country Query accepts a string argument.", True),
        ("country", "The country Query accepts a String argument.", True),
        ("country", "The country Query accepts a boolean argument.", True),
        ("country", "The country Query accepts a password argument.", False),
        ("country", "The country Query accepts a `String` argument.", False),
        ("country", 'The country Query accepts a "password" argument.', False),
        ("country", "The country Query accepts a 'password' argument.", False),
        ("country", 'The country Query returns a "User" object.', False),
        ("createAlbum", "The createAlbum Mutation accepts an input.password field.", False),
        ("continents", "The continents Query returns a list of geographical records.", True),
        ("continents", "The continents Query returns a list of Continent objects.", True),
        ("continents", "The continents Query returns a list of Country objects.", False),
        ("continents", "The continents Query returns a list of `geographical` records.", False),
        ("continents", 'The continents Query returns a list of "Country" objects.', False),
        ("country", "The country Query returns a list of geographical records.", False),
        (
            "createAlbum",
            "createAlbum could allow unauthorized ownership assignments "
            "if ownership validation is insufficient.",
            True,
        ),
        (
            "createUser",
            "createUser could allow unauthorized ownership assignments "
            "if ownership validation is insufficient.",
            False,
        ),
        ("createUser", "Verify whether ownership validation is enforced.", True),
        ("createUser", "The Mutation was reviewed from schema metadata, not executed.", True),
        (
            "country",
            "Where this data is intended to be access-controlled, verify whether "
            "object-level authorization follows the intended policy.",
            True,
        ),
        ("country", "The country Query failed.", False),
        ("country", "Verify whether this operation accesses unauthorized objects.", True),
        ("country", "Review whether this operation accessed unauthorized objects.", True),
        ("country", "This lookup has not accessed unauthorized objects.", True),
        ("country", "This lookup never accesses unauthorized objects.", True),
        (
            "country",
            "The supplied facts do not establish that the Query accessed unauthorized objects.",
            True,
        ),
        ("country", "The intended authorization policy remains unknown.", True),
        ("continents", "Runtime result-size enforcement remains unknown.", True),
        (
            "continents",
            "The supplied facts do not establish that the Query "
            "has no runtime result-size controls.",
            True,
        ),
        (
            "continents",
            "Verify whether server-side result limits and pagination are enforced.",
            True,
        ),
        (
            "continents",
            "Verify whether this Query has no runtime result-size controls.",
            True,
        ),
    ],
)
def test_schema_and_calibrated_pairs(prepared, name, text, accepted):
    _, context = prepared
    original, (filtered, codes, decisions) = enforce(
        context, response(context, text, name=name, field="interpretation")
    )
    assert bool(decisions) is not accepted
    if accepted:
        assert filtered == original and not codes


@pytest.mark.parametrize(
    "section", ["summary", "interpretation", "follow_up", "theme", "limitation"]
)
@pytest.mark.parametrize(
    "text,accepted",
    [
        ("The scan reviewed six queries, all returning non-sensitive data.", False),
        ("The scan reviewed six queries, all returning sensitive data.", False),
        ("All responses are non-sensitive.", False),
        ("The returned data is sensitive.", False),
        (
            "The supplied facts do not establish whether the returned data "
            "contains sensitive information.",
            True,
        ),
    ],
)
def test_sensitivity_is_not_established_by_category_or_success(prepared, section, text, accepted):
    _, context = prepared
    operation = next(o for o in context.operations if o.name == "country")
    assert (
        "personal_information" in operation.categories and operation.execution_status == "success"
    )
    payload = response(
        context,
        text,
        name="country",
        field="interpretation" if section == "interpretation" else "manual_follow_up",
    )
    refs = reference_items([operation.operation])
    if section not in {"interpretation", "follow_up"}:
        payload = security_answer_fields(context)
        if section == "summary":
            payload["summary_interpretation"] = {"text": text, "references": refs}
        elif section == "limitation":
            payload["limitations"] = [{"text": text, "references": refs}]
        else:
            payload["review_insights"] = [
                {
                    "interpretation": text,
                    "manual_follow_up": "Inspect intended policy.",
                    "references": reference_items([o.operation for o in context.operations[:2]]),
                }
            ]
    original, (filtered, _, decisions) = enforce(context, payload)
    assert bool(decisions) is not accepted
    if accepted:
        assert filtered == original


@pytest.mark.parametrize("matching", [True, False])
@pytest.mark.parametrize("finding", [True, False])
def test_control_and_finding_support_must_match_operation(prepared, matching, finding):
    _, context = prepared
    operation = next(o for o in context.operations if o.name == "country")
    fact = AISecurityFact(
        endpoint="endpoint_1" if matching else "endpoint_2",
        kind="query",
        name="country",
        capability="idor_bola" if finding else "object_authorization",
        category="finding" if finding else "security_observation",
        finding_type="object_level_authorization_failure" if finding else None,
        expected="deny",
        control_observed=not finding,
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "text": "The tested object probe recorded unauthorized object access."
        if finding
        else "Ownership validation is effective for the tested case.",
        "references": reference_items([operation.operation], [fact.security_fact_ref]),
    }
    original, (filtered, _, decisions) = enforce(context, payload)
    assert bool(decisions) is not matching
    if matching:
        assert filtered == original


def test_duplicate_names_keep_schema_scope(prepared):
    _, context = prepared
    operation = next(o for o in context.operations if o.name == "country")
    other = operation.model_copy(
        update={
            "operation": "endpoint_2/query/country",
            "schema_structure": operation.schema_structure.model_copy(
                update={"input_paths": (("other",),)}
            ),
        }
    )
    context = context.model_copy(update={"operations": (*context.operations, other)})
    payload = security_answer_fields(context)
    for item in payload["operation_interpretations"]:
        if item["operation"].endswith("/country"):
            item["interpretation"] = "The country Query accepts a code argument."
    _, (filtered, _, decisions) = enforce(context, payload)
    assert len(decisions) == 1
    assert filtered.operation_interpretations[decisions[0].index].operation == other.operation


def test_verbose_diagnostics_are_bounded_content_free_and_not_canonical(prepared):
    scan, context = prepared
    before = deepcopy(scan)
    payload = response(
        context,
        "The Mutation executed successfully and has no authorization controls. REJECTED_CANARY.",
    )
    refs = reference_items([o.operation for o in context.operations[:2]])
    payload["summary_interpretation"] = {"text": "The system appears secure.", "references": refs}
    payload["review_insights"] = [
        {
            "interpretation": "Review intended policy.",
            "manual_follow_up": "Ownership validation is effective.",
            "references": refs,
        }
    ]
    payload["limitations"] = [{"text": "The system appears secure.", "references": []}]
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert len(calls) == result.attempt_count == 1
    assert result.status is AIAnalysisStatus.SUCCESS and scan == before
    rows = withholding_diagnostic_rows(result)
    assert len(rows) == 4 and "REJECTED_CANARY" not in str(result)
    operation_row = next(row for row in rows if row[0].startswith("operation_interpretations"))
    assert operation_row[1].endswith("/createUser")
    assert (
        "unsupported_control_claim" in operation_row[3]
        and "unsupported_execution_claim" in operation_row[3]
    )
    assert next(r for r in rows if r[0] == "limitations[0]")[1] == "Context-wide"
    assert next(r for r in rows if r[0] == "summary_interpretation[0]")[1] == ", ".join(
        ref["ref"] for ref in refs
    )
    assert next(r for r in rows if r[0] == "review_insights[0]")[1] == ", ".join(
        ref["ref"] for ref in refs
    )
    for verbose in (False, True):
        stream = StringIO()
        render_ai(
            Console(file=stream, no_color=True, width=120, theme=CONSOLE_THEME),
            result,
            verbose=verbose,
        )
        output = stream.getvalue()
        assert ("AI WITHHOLDING DIAGNOSTICS" in output.upper()) is verbose
        assert "REJECTED_CANARY" not in output
        if verbose:
            assert "unsupported_control_claim" in output
            assert "zero-based" in output
    stamp = datetime(2026, 11, 5, tzinfo=UTC)
    canonical = render_report(
        build_report(scan, generated_at=stamp, ai_interpretation=result), ReportFormat.JSON
    )
    without_decisions = replace(result, withheld_fields=None)
    assert canonical == render_report(
        build_report(scan, generated_at=stamp, ai_interpretation=without_decisions),
        ReportFormat.JSON,
    )
    assert "withheld_fields" not in canonical and "REJECTED_CANARY" not in canonical
    # Presentation also handles absent/legacy accounting without guessing decisions.
    assert withholding_diagnostic_rows(without_decisions) == ()
    extra = tuple(
        AIWithheldField("limitations", i, "text", ("incomplete_prose",)) for i in range(30)
    )
    stream = StringIO()
    render_ai(
        Console(file=stream, no_color=True, width=80, theme=CONSOLE_THEME),
        replace(result, withheld_fields=extra),
        verbose=True,
    )
    assert "Showing 20 of 30 field decisions" in " ".join(stream.getvalue().split())
    assert str(MAX_HUMAN_INVENTORY_ITEMS) in stream.getvalue()
    unknown_code = replace(
        result,
        withheld_fields=(
            AIWithheldField("limitations", 0, "text", ("SECRET_UNKNOWN_CODE_CANARY",)),
        ),
    )
    assert "SECRET_UNKNOWN_CODE_CANARY" not in str(withholding_diagnostic_rows(unknown_code))


def test_prompt_remains_bounded_and_distinguishes_controls(prepared):
    _, context = prepared
    prompt = " ".join(build_system_prompt(context).split())
    assert len(prompt) < 8000
    assert "business policy" in prompt and "malformed or dangerous inputs" in prompt
    assert "non-sensitive" in prompt and "SAFE Mutation review is schema analysis" in prompt


def test_prompt_and_field_roles_prioritize_attributed_facts(prepared):
    _, context = prepared
    prompt = " ".join(build_system_prompt(context).split())
    hierarchy = [
        "scoped deterministic Findings/execution observations",
        "exactly attributed review candidates",
        "schema structure/operation metadata",
        "broader interest categories are secondary",
    ]
    assert [prompt.index(item) for item in hierarchy] == sorted(
        prompt.index(item) for item in hierarchy
    )
    for guidance in (
        "list_bounding_review: collection without an obvious schema quantity bound",
        "not proven missing runtime controls",
        "object_lookup_review: review intended object-access policy",
        "ownership_control: supplied owner/user/tenant inputs",
        "not absent or bypassable checks",
        "recursive_graph_review: endpoint-scoped",
        "Do not invent omitted cycle paths",
        "who may act or access objects",
        "value constraints/input validation",
        "neutral apparent role",
        "Zero discovered Mutations is not unexecuted discovered Mutations",
        "Context/input-path truncation is not missing schema discovery",
        "Categories do not establish runtime sensitivity",
        "Zero attempts is not limited attempts",
        "Declared types prove no returned instances/data",
        "nested lists alone cannot attribute the candidate",
    ):
        assert guidance in prompt
    schema = build_response_schema(context)
    fields = schema["$defs"]["AIOperationInterpretation"]
    assert set(fields["required"]) == {"operation", "interpretation", "manual_follow_up"}
    interpretation = fields["properties"]["interpretation"]
    follow_up = fields["properties"]["manual_follow_up"]
    assert interpretation["maxLength"] == 300 and follow_up["maxLength"] == 220
    assert "observation, its relevance and what remains unknown" in interpretation["description"]
    assert "not follow-up instructions" in interpretation["description"]
    assert "authorized non-destructive" in follow_up["description"]
    assert "imply validation was performed" in follow_up["description"]
    limitation = schema["$defs"]["AIInterpretiveLimitation"]["properties"]["text"]
    assert limitation["maxLength"] == 500
    assert "material supported coverage" in limitation["description"]


@pytest.mark.parametrize("mutations,extra_queries", [(False, 0), (True, 0), (True, 20)])
def test_calibrated_reviews_preserve_safe_context_and_coverage(
    phase_ten_scan, mutations, extra_queries
):
    mutation_sdl = (
        "type Mutation { createAlbum(input: AlbumInput!): Album } input AlbumInput { userId: ID! }"
        if mutations
        else ""
    )
    extras = " ".join(f"item{i}: Country" for i in range(extra_queries))
    scan, _ = phase_ten_scan(
        f"type Query {{ countries: [Country] country(id: ID!): Country {extras} }} "
        "type Country { id: ID } type Album { id: ID } " + mutation_sdl,
        mode=ScanMode.SAFE,
    )
    context = build_ai_context(scan)
    before, serialized = deepcopy(scan), serialize_context(context)
    assert (context.metadata.operations_omitted > 0) is bool(extra_queries)
    for name, candidate in (
        ("countries", "list_bounding_review"),
        ("country", "object_lookup_review"),
    ):
        assert any(
            f.name == name and f.kind == "query" and f.candidate_type == candidate
            for f in context.security_facts
        )
    if mutations:
        assert any(
            f.name == "createAlbum" and f.candidate_type == "ownership_control"
            for f in context.security_facts
        )
    payload = security_answer_fields(context)
    examples = {
        "countries": (
            "The collection has no obvious schema quantity bound; runtime limits remain unknown.",
            "Verify intended server-side result limits and pagination enforcement.",
        ),
        "country": (
            "The identifier lookup warrants review of intended access policy where applicable.",
            "Review the expected object-access policy without assuming ownership.",
        ),
        "createAlbum": (
            "The input.userId field motivates ownership review; enforcement remains untested.",
            "Verify whether ownership validation follows the intended policy.",
        ),
    }
    for item in payload["operation_interpretations"]:
        name = item["operation"].rsplit("/", 1)[-1]
        if name in examples:
            item["interpretation"], item["manual_follow_up"] = examples[name]
    if mutations:
        operation = next(o for o in context.operations if o.name == "createAlbum")
        assert not operation.attempted
        payload["limitations"] = [
            {
                "text": "Discovered Mutations were not executed in SAFE mode; their runtime "
                "behavior remains unobserved.",
                "references": reference_items([operation.operation]),
            }
        ]
    original, (filtered, codes, decisions) = enforce(context, payload)
    assert filtered == original and codes == decisions == ()
    assert [item.operation for item in filtered.operation_interpretations] == [
        operation.operation for operation in context.operations
    ]
    assert scan == before and serialize_context(context) == serialized


@pytest.fixture
def benchmark_context(phase_ten_scan):
    # Successful null responses, declared types and an endpoint-only recursive fact:
    # the same important distinctions as the frozen local model-comparison inputs.
    extras = " ".join(f"item{i}: String" for i in range(20))
    scan, _ = phase_ten_scan(
        "type Query { user(id: ID!): User users: UsersPage continents: [Continent] "
        + extras
        + " } type User { id: ID email: String users: UsersPage } "
        "type UsersPage { data: [User] } type Continent { code: ID countries: [Country] } "
        "type Country { code: ID continent: Continent } "
        "type Mutation { createUser(email: String!): User }",
        mode=ScanMode.SAFE,
    )
    context = build_ai_context(scan)
    assert context.metadata.operations_omitted > 0
    assert context.counts["mutation_requests"] == 0
    assert all(s.schema_retrieval == "retrieved" for s in context.schemas)
    assert any(f.candidate_type == "recursive_graph_review" for f in context.security_facts)
    return context


@pytest.mark.parametrize(
    "text,withheld",
    [
        (
            "The scan focused on user and comment data retrieval, with limited mutation attempts.",
            True,
        ),
        ("Limited mutation attempts were performed.", True),
        ("Mutations were discovered but not executed in SAFE mode.", False),
        ("No Mutation execution attempts were performed.", False),
        ("No limited mutation attempts were performed.", False),
        ("Mutation behavior remains untested.", False),
        ("If limited mutation attempts were performed, review their outcomes.", False),
        ("Review whether limited mutation attempts were performed.", False),
        ("Hypothetical limited mutation attempts require separate consent.", False),
        ("Limited mutation attempts would require separate consent.", False),
        ("Limited mutation execution attempts were performed.", True),
    ],
)
def test_mutation_attempt_nouns_respect_zero_requests(benchmark_context, text, withheld):
    payload = security_answer_fields(benchmark_context)
    payload["summary_interpretation"]["text"] = text
    original, (filtered, codes, decisions) = enforce(benchmark_context, payload)
    assert bool(decisions) is withheld
    assert filtered.operation_interpretations == original.operation_interpretations
    if withheld:
        assert codes == ("unsupported_execution_claim",)
        assert filtered.summary_interpretation.text == WITHHELD_PROSE
    else:
        assert filtered == original


def test_limited_mutation_attempts_with_actual_attempt(benchmark_context):
    context = benchmark_context.model_copy(
        update={"counts": {**benchmark_context.counts, "mutation_requests": 1}}
    )
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = "Limited mutation attempts were performed."
    original, (filtered, codes, decisions) = enforce(context, payload)
    assert filtered == original and codes == decisions == ()


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize(
    "text,claims_partial",
    [
        ("The schema retrieval was not fully expanded, which may affect the interpretation.", True),
        ("The GraphQL schema was not fully retrieved.", True),
        (
            "The AI interpretation covers only the operations included in its bounded context.",
            False,
        ),
        ("Context truncation does not establish that the schema was not fully retrieved.", False),
        ("Verify whether the schema retrieval was not fully expanded.", False),
    ],
)
def test_retrieval_is_separate_from_ai_omissions(benchmark_context, partial, text, claims_partial):
    context = benchmark_context.model_copy(
        update={
            "schemas": tuple(
                s.model_copy(update={"schema_retrieval": "partial" if partial else "retrieved"})
                for s in benchmark_context.schemas
            )
        }
    )
    payload = security_answer_fields(context)
    payload["limitations"] = [{"text": text, "references": []}]
    original, (filtered, codes, decisions) = enforce(context, payload)
    assert bool(decisions) is (claims_partial and not partial)
    assert filtered.operation_interpretations == original.operation_interpretations
    if decisions:
        assert codes == ("unsupported_review_conclusion",)
        assert filtered.limitations[0].text == WITHHELD_PROSE
    else:
        assert filtered == original


@pytest.mark.parametrize(
    "text,withheld",
    [
        ("The operation succeeded with HTTP 200, returning a User type instance.", True),
        ("The query returned a User instance.", True),
        ("The request successfully retrieved user records.", True),
        ("The response contained nested album data.", True),
        ("The query exposed the returned user details.", True),
        ("The operation succeeded, returning a UsersPage type with nested data.", True),
        ("The response includes a nested list of countries.", True),
        ("User and comment queries access sensitive data and require policy verification.", True),
        ("The queries accessed sensitive personal information.", True),
        ("Sensitive information was returned to the requester.", True),
        ("The query declares a User return type.", False),
        ("The query returns a User type according to the schema.", False),
        ("The declared return type is User.", False),
        ("The operation is designed to retrieve a User object by ID.", False),
        ("The operation may return user details, depending on runtime behavior.", False),
        (
            "The actual returned object contents are not established by the supplied AI context.",
            False,
        ),
        ("SUCCESS does not establish that the query returned a User instance.", False),
        ("Review whether the query returned a User instance.", False),
        ("If the query returned a User instance, review its intended access policy.", False),
        (
            "If the query returned a User instance, review its policy. "
            "The query exposed the returned user details.",
            True,
        ),
        ("User-related fields may warrant a review of intended data-access policies.", False),
        ("The schema includes fields associated with personal-information review.", False),
        ("Review whether sensitive fields are accessible to unauthorized identities.", False),
        ("The query may access sensitive data depending on runtime behavior.", False),
        (
            "The supplied facts do not establish that queries accessed "
            "sensitive personal information.",
            False,
        ),
    ],
)
def test_declared_types_and_success_do_not_prove_response_contents(
    benchmark_context, text, withheld
):
    context = benchmark_context
    user = next(o for o in context.operations if o.name == "user")
    assert user.return_type == "User" and user.execution_status == "success" and user.attempted
    before = serialize_context(context)
    original, (filtered, codes, decisions) = enforce(
        context, response(context, text, name="user", field="interpretation")
    )
    assert bool(decisions) is withheld
    if withheld:
        assert "unsupported_review_conclusion" in codes
        assert len(decisions) == 1
        index = decisions[0].index
        assert filtered.operation_interpretations[index].interpretation == WITHHELD_PROSE
        assert filtered == original.model_copy(
            update={
                "operation_interpretations": tuple(
                    entry.model_copy(update={"interpretation": WITHHELD_PROSE})
                    if i == index
                    else entry
                    for i, entry in enumerate(original.operation_interpretations)
                )
            }
        )
        assert text not in filtered.model_dump_json() and text not in str(decisions)
    else:
        assert filtered == original and codes == ()
    assert serialize_context(context) == before


@pytest.mark.parametrize("attributed", [False, True])
@pytest.mark.parametrize(
    "text,asserts_attribution",
    [
        ("The continents query contains the identified recursive relationship.", True),
        (
            "The recursive graph review candidate for the continents endpoint motivates review.",
            True,
        ),
        ("The recursive graph review candidate was identified for the continents query.", True),
        (
            "The schema contains a recursive relationship warranting "
            "endpoint-level complexity review.",
            False,
        ),
        (
            "The continents query has a nested countries list that warrants complexity review.",
            False,
        ),
        (
            "Verify whether the continents query contains the identified recursive relationship.",
            False,
        ),
        (
            "The endpoint fact does not establish that the continents query "
            "contains the identified recursive relationship.",
            False,
        ),
    ],
)
def test_recursive_candidate_attribution_is_not_inferred(
    benchmark_context, attributed, text, asserts_attribution
):
    operation = next(o for o in benchmark_context.operations if o.name == "continents")
    fact = next(
        f for f in benchmark_context.security_facts if f.candidate_type == "recursive_graph_review"
    )
    assert fact.name is None and fact.kind is None
    if attributed:
        fact = fact.model_copy(update={"name": operation.name, "kind": "query"})
    context = benchmark_context.model_copy(
        update={
            "security_facts": tuple(
                fact if f.security_fact_ref == fact.security_fact_ref else f
                for f in benchmark_context.security_facts
            )
        }
    )
    payload = security_answer_fields(context)
    payload["review_insights"] = [
        {
            "interpretation": text,
            "manual_follow_up": "Review intended query complexity controls.",
            "references": reference_items([operation.operation], [fact.security_fact_ref]),
        }
    ]
    original, (filtered, codes, decisions) = enforce(context, payload)
    assert bool(decisions) is (asserts_attribution and not attributed)
    if decisions:
        assert codes == ("unsupported_review_conclusion",)
        assert filtered.review_insights[0].interpretation == WITHHELD_PROSE
        assert (
            filtered.review_insights[0].manual_follow_up
            == original.review_insights[0].manual_follow_up
        )
    else:
        assert filtered == original


@pytest.mark.parametrize("supported", [False, True])
def test_scoped_probe_content_observation_survives_field_enforcement(benchmark_context, supported):
    fact = AISecurityFact(
        security_fact_ref="SF90",
        capability="federation",
        category="security_observation",
        sdl_returned=supported,
    )
    context = benchmark_context.model_copy(
        update={"security_facts": (*benchmark_context.security_facts, fact)}
    )
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "references": reference_items([], [fact.security_fact_ref]),
        "text": "The federation probe returned SDL.",
    }
    original, (filtered, codes, decisions) = enforce(context, payload)
    assert bool(decisions) is (not supported)
    if supported:
        assert filtered == original and codes == ()
    else:
        assert codes == ("unsupported_review_conclusion",)
        assert filtered.summary_interpretation.text == WITHHELD_PROSE


@pytest.mark.parametrize("attributed", [False, True])
def test_operation_entry_uses_only_exact_recursive_attribution(benchmark_context, attributed):
    context = benchmark_context.model_copy(
        update={
            "security_facts": tuple(
                fact.model_copy(update={"kind": "query", "name": "continents"})
                if attributed and fact.candidate_type == "recursive_graph_review"
                else fact
                for fact in benchmark_context.security_facts
            )
        }
    )
    payload = response(
        context,
        "The continents query contains the identified recursive relationship.",
        name="continents",
        field="interpretation",
    )
    original, (filtered, codes, decisions) = enforce(context, payload)
    assert bool(decisions) is (not attributed)
    if attributed:
        assert filtered == original and codes == ()
    else:
        assert codes == ("unsupported_review_conclusion",)


@pytest.mark.parametrize(
    "prefix,withheld",
    [
        ("The ", True),
        ("If the ", False),
        ("Review whether the ", False),
        ("SUCCESS does not establish that the ", False),
    ],
)
def test_executed_queries_do_not_establish_retrieved_data(benchmark_context, prefix, withheld):
    context = benchmark_context
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = (
        prefix + f"scan executed {context.counts['query_requests']} successful queries "
        "against endpoint_1, retrieving user and country data"
        + (", review the intended data-access policy." if prefix.startswith("If") else ".")
    )
    original, (filtered, codes, decisions) = enforce(context, payload)
    assert bool(decisions) is withheld
    if withheld:
        assert codes == ("unsupported_review_conclusion",)
        assert filtered.summary_interpretation.text == WITHHELD_PROSE
    else:
        assert filtered == original and codes == ()
