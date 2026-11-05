"""Phase 2D: explicit schema/execution contradictions, not general language verification."""

import html
import json
from copy import deepcopy
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import MAX_AI_ATTEMPTS, AIAnalysisStatus, AISecurityFact, AIValidationError
from gqlsleuth.ai.prompt import build_system_prompt, validate_interpretation
from gqlsleuth.ai.quality import WITHHELD_PROSE, enforce_interpretation_grounding
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def factual(phase_ten_scan):
    scan, _ = phase_ten_scan("""
        type Query {
            countries: [Country!]! country(code: ID!): Country
            continents: [Continent!]! continent(code: ID!): Continent
            languages: [Language!]! language(code: ID!): Language
            users: [User] albums: [Album] comments: [Comment]
        }
        type Country { id: ID } type Continent { id: ID countries: [Country] }
        type Language { id: ID } type User { id: ID }
        type Album { id: ID } type Comment { id: ID }
        input AlbumInput { userId: ID! }
        type Mutation { createAlbum(input: AlbumInput!): Album updateUser(id: ID!): User }
    """)
    return scan, build_ai_context(scan)


def payload_for(context, text, *, section="operation", name="languages"):
    payload = security_answer_fields(context)
    operation = next(o.operation for o in context.operations if o.name == name)
    refs = reference_items([operation])
    if section == "summary":
        payload["summary_interpretation"] = {"text": text, "references": refs}
    elif section in {"operation", "follow_up"}:
        item = next(i for i in payload["operation_interpretations"] if i["operation"] == operation)
        item["interpretation" if section == "operation" else "manual_follow_up"] = text
    elif section in {"theme", "theme_follow_up"}:
        other = next(o.operation for o in context.operations if o.operation != operation)
        payload["review_insights"] = [
            {
                "references": reference_items([operation, other]),
                "interpretation": text if section == "theme" else "Review the supplied roles.",
                "manual_follow_up": text
                if section == "theme_follow_up"
                else "Review relevant controls.",
            }
        ]
    else:
        payload["limitations"] = [{"text": text, "references": refs}]
    return payload


def enforce(context, payload):
    return enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )


@pytest.mark.parametrize(
    "section", ["summary", "operation", "follow_up", "theme", "theme_follow_up", "limitation"]
)
@pytest.mark.parametrize(
    "text,code",
    [
        ("The languages Query returns a list of Country objects.", "unsupported_review_conclusion"),
        (
            "The scan did not execute these Queries to confirm the behavior.",
            "unsupported_execution_claim",
        ),
        (
            "The absence of query depth controls may lead to excessive data retrieval.",
            "unsupported_control_claim",
        ),
    ],
)
def test_contradictions_across_shared_prose_boundary(factual, section, text, code):
    _, context = factual
    payload = payload_for(context, text, section=section)
    filtered, warnings, withheld = enforce(context, payload)
    assert code in warnings and len(withheld) == 1
    assert text not in filtered.model_dump_json()
    assert WITHHELD_PROSE in filtered.model_dump_json()
    if section == "operation":
        original = next(
            i for i in payload["operation_interpretations"] if i["operation"].endswith("/languages")
        )
        retained = next(
            i for i in filtered.operation_interpretations if i.operation.endswith("/languages")
        )
        assert retained.manual_follow_up == original["manual_follow_up"]


@pytest.mark.parametrize(
    "text,valid",
    [
        ("The languages Query returns a list of Language objects.", True),
        ("The continents Query returns a list of countries.", False),
        ("Operation languages retrieves a collection of Country.", False),
        ("The root Query languages returns [Country!]!.", False),
        ("The root Query languages returns [Language!]!.", True),
        ("The language Query returns a Language object.", True),
        ("The language Query returns a Country object.", False),
        ("The languages Query returns a Language object.", False),
        ("The country Query returns a list of Country objects.", False),
        ("The languages Query returns a list of Secret objects.", False),
        (
            "The continent Query returns a Continent object "
            "that exposes a nested countries collection.",
            True,
        ),
        ("Continent.countries returns a list of Country objects.", True),
        ("The nested countries field returns a list of Country objects.", True),
        ("The countries, continents and languages Queries return collections.", True),
        ("All six Queries return lists.", False),
    ],
)
def test_root_types_and_named_collective_subjects(factual, text, valid):
    _, context = factual
    filtered, warnings, withheld = enforce(context, payload_for(context, text, section="theme"))
    assert bool(withheld) is not valid
    if valid:
        assert warnings == () and text in filtered.model_dump_json()


@pytest.mark.parametrize(
    "name", ["countries", "continents", "languages", "country", "continent", "language"]
)
def test_candidate_assertion_uses_its_actual_source(factual, name):
    _, context = factual
    text = f"A Result Size Limit Review was identified for {name}."
    _, warnings, withheld = enforce(context, payload_for(context, text, section="theme", name=name))
    assert bool(withheld) == (name in {"country", "continent", "language"})
    if withheld:
        assert "unsupported_review_conclusion" in warnings


@pytest.mark.parametrize("truncated", [False, True])
def test_invented_inputs_and_candidate_absence_respect_truncation(factual, truncated):
    _, context = factual
    context = context.model_copy(
        update={
            "metadata": context.metadata.model_copy(
                update={"security_facts_omitted": int(truncated)}
            ),
            "operations": tuple(
                o.model_copy(
                    update={
                        "schema_structure": o.schema_structure.model_copy(
                            update={"inputs_truncated": truncated}
                        )
                    }
                )
                for o in context.operations
            ),
        }
    )
    for text in (
        "The country Query accepts a password argument.",
        "A Result Size Limit Review was identified for country.",
    ):
        _, _, withheld = enforce(
            context, payload_for(context, text, section="theme", name="country")
        )
        assert bool(withheld) is not truncated


@pytest.mark.parametrize(
    "name,text",
    [
        ("users", "The users Query was not executed."),
        ("users", "The scan did not execute users."),
        ("users", "The users, albums and comments Queries were not executed."),
        ("createAlbum", "The createAlbum Mutation executed successfully."),
        (
            "users",
            "The users Query succeeded, demonstrating that unauthorized users "
            "can retrieve private data.",
        ),
        (
            "countries",
            "The countries Query has no server-side result-size limits and can exhaust resources.",
        ),
    ],
)
def test_false_execution_claims_in_limitations(factual, name, text):
    _, context = factual
    _, warnings, withheld = enforce(
        context, payload_for(context, text, section="limitation", name=name)
    )
    assert warnings and len(withheld) == 1


@pytest.mark.parametrize(
    "name,text",
    [
        ("users", "The users Query completed without a classified execution error."),
        ("users", "Query-depth enforcement was not specifically assessed."),
        (
            "users",
            "Although normal Queries completed without classified errors, dedicated query-depth "
            "and complexity testing was not established by the supplied evidence.",
        ),
        (
            "createAlbum",
            "The createAlbum Mutation accepts an input.userId field. "
            "If ownership validation is insufficient, createAlbum could allow "
            "unauthorized owner assignments.",
        ),
        (
            "updateUser",
            "If object-level authorization is missing, updateUser could permit "
            "changes outside the caller's scope.",
        ),
        (
            "countries",
            "Without server-side list limits, large responses may increase resource consumption.",
        ),
        (
            "continent",
            "Insufficient query-complexity controls could make deeply nested selections expensive.",
        ),
        (
            "country",
            "If this API restricts access to reference data, "
            "verify that the intended access policy is enforced.",
        ),
        (
            "language",
            "The language Query returns an individual Language object. "
            "No specific runtime security weakness was established.",
        ),
    ],
)
def test_calibrated_analysis_remains_useful(factual, name, text):
    _, context = factual
    payload = payload_for(context, text, name=name)
    filtered, warnings, withheld = enforce(context, payload)
    assert warnings == withheld == ()
    assert filtered.model_dump(mode="json") == payload


def test_dedicated_probe_fact_is_separate_from_ordinary_success(factual):
    _, context = factual
    fact = AISecurityFact(
        capability="query_depth",
        category="security_observation",
        endpoint="endpoint_1",
        kind="query",
        name="users",
        outcome="accepted",
        probe_depth=5,
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    _, warnings, withheld = enforce(
        context, payload_for(context, "Query-depth validation was not performed.", name="users")
    )
    assert "unsupported_execution_claim" in warnings and len(withheld) == 1
    _, warnings, withheld = enforce(
        context,
        payload_for(context, "Overall query-depth enforcement remains unproven.", name="users"),
    )
    assert warnings == withheld == ()


@pytest.mark.parametrize(
    "status,text,valid",
    [
        ("graphql_error", "The users Query returned a GraphQL error.", True),
        ("graphql_error", "The users Query completed without a classified execution error.", False),
        ("network_failure", "The users Query was attempted but returned NETWORK_FAILURE.", True),
        ("network_failure", "The server executed the users Query.", False),
    ],
)
def test_execution_categories_remain_distinct(factual, status, text, valid):
    _, context = factual
    context = context.model_copy(
        update={
            "operations": tuple(
                o.model_copy(
                    update={
                        "execution_status": status,
                        "http_status": 200 if status == "graphql_error" else None,
                    }
                )
                if o.name == "users"
                else o
                for o in context.operations
            )
        }
    )
    _, _, withheld = enforce(context, payload_for(context, text, name="users"))
    assert bool(withheld) is not valid


def test_mocked_application_preserves_reports_and_one_inference(factual, monkeypatch):
    scan, context = factual
    before = deepcopy(scan)
    text = "The languages Query returns a list of Country objects."
    payload = payload_for(context, text, section="limitation")
    requests = []

    def reply(request):
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        requests.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    monkeypatch.setattr(HttpClient, "send", lambda *a, **kw: pytest.fail("Target request"))
    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(reply))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(requests) == 1
    assert result.validation_failures == ()
    assert len(result.withheld_fields) == 1
    assert requests[0]["messages"][1]["content"] == serialize_context(context)
    assert requests[0]["options"]["num_predict"] == 2048
    for width in (45, 120):
        stream = StringIO()
        render_ai(
            Console(file=stream, width=width, no_color=True, theme=CONSOLE_THEME),
            result,
            verbose=True,
        )
        assert "returns a list of Country" not in stream.getvalue()
    for format in ReportFormat:
        rendered = render_report(build_report(scan, ai_interpretation=result), format)
        assert text not in rendered
        marker = (
            WITHHELD_PROSE
            if format is ReportFormat.JSON
            else "Withheld — unsupported by supplied facts"
        )
        assert marker in html.unescape(rendered).replace("\\.", ".")
        if format is ReportFormat.JSON:
            assert json.loads(rendered)["report_schema_version"] == result.ai_contract_version == 2
            assert "schema_structure" not in rendered
    assert scan == before and scan.evidence == before.evidence


def test_prompt_guidance_preserves_hard_reference_and_coverage_gates(factual):
    _, context = factual
    prompt = build_system_prompt(context)
    assert "operations[].operation" in prompt and "security_facts[].security_fact_ref" in prompt
    assert "If security_facts is empty" in prompt
    assert "EVERY supplied operations[] item" in prompt
    assert "identifier lookup alone does not establish user ownership" in prompt
    assert MAX_AI_ATTEMPTS == 10
    bad = security_answer_fields(context)
    bad["summary_interpretation"]["references"] = reference_items([], ["SF999"])
    with pytest.raises(AIValidationError) as failure:
        validate_interpretation(json.dumps(bad), context)
    assert failure.value.code == "invalid_security_references"
    bad = security_answer_fields(context)
    bad["operation_interpretations"].pop()
    with pytest.raises(AIValidationError) as failure:
        validate_interpretation(json.dumps(bad), context)
    assert failure.value.code == "incomplete_operation_interpretation_set"


@pytest.mark.parametrize("return_type,valid", [("Language", True), ("Country", False)])
def test_fact_only_reference_preserves_exact_root_subject(factual, return_type, valid):
    _, context = factual
    fact = next(
        f
        for f in context.security_facts
        if f.name == "languages" and f.candidate_type == "list_bounding_review"
    )
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "text": f"This Query returns a list of {return_type} objects.",
        "references": reference_items([], [fact.security_fact_ref]),
    }
    _, warnings, withheld = enforce(context, payload)
    assert bool(withheld) is not valid
    if valid:
        assert warnings == ()
