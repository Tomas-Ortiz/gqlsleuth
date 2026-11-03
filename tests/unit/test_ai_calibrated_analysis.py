"""Offline Phase 2C: exact schema subjects, conditional analysis and incomplete fields."""

import html
import json
from copy import deepcopy
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import MAX_CONTEXT_BYTES, AIAnalysisStatus
from gqlsleuth.ai.prompt import build_response_schema, validate_interpretation
from gqlsleuth.ai.quality import INCOMPLETE_PROSE, WITHHELD_PROSE, enforce_interpretation_grounding
from gqlsleuth.ai.sections import quality_summary_lines
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def calibrated(phase_ten_scan):
    scan, _ = phase_ten_scan("""
        type Query {
            countries: [Country!]! country(code: ID!): Country
            continents: [Continent!]! continent(code: ID!): Continent
            languages: [Language!]! language(code: ID!): Language
        }
        type Country { id: ID }
        type Continent { id: ID countries: [Country] }
        type Language { id: ID }
        input AlbumInput { userId: ID! title: String }
        input UserInput { name: String }
        type Mutation {
            createAlbum(input: AlbumInput!): Country
            updateAlbum(input: AlbumInput!): Country
            createUser(input: UserInput): Country
            updateUser(input: UserInput): Country deleteUser(id: ID!): Country
        }
    """)
    return scan, build_ai_context(scan)


def response(context, name, text, field="interpretation"):
    payload = security_answer_fields(context)
    item = next(
        i for i in payload["operation_interpretations"] if i["operation"].endswith("/" + name)
    )
    item[field] = text
    return payload


def enforce(context, payload):
    return enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )


def test_context_preserves_operation_structure_and_exact_review_subjects(calibrated):
    scan, context = calibrated
    assert context == build_ai_context(scan)
    assert len(context.operations) == 11
    assert (
        context.metadata.serialized_bytes
        == len(serialize_context(context).encode())
        <= MAX_CONTEXT_BYTES
    )
    operations = {o.name: o for o in context.operations}
    lists = {f.name for f in context.security_facts if f.candidate_type == "list_bounding_review"}
    assert lists == {"countries", "continents", "languages"}
    for plural, singular in (
        ("countries", "country"),
        ("continents", "continent"),
        ("languages", "language"),
    ):
        assert operations[plural].schema_structure.returns_list is True
        assert operations[singular].schema_structure.returns_list is False
        assert operations[plural].return_type == operations[singular].return_type
    assert operations["continent"].schema_structure.nested_list_fields == ("countries",)
    assert ("input", "userId") in operations["createAlbum"].schema_structure.input_paths
    assert ("input", "userId") not in operations["updateUser"].schema_structure.input_paths
    assert not any(o.attempted for o in context.operations if o.kind == "mutation")


@pytest.mark.parametrize(
    "name,text",
    [
        (
            "createAlbum",
            "If ownership checks are absent, createAlbum may allow unauthorized owner assignment.",
        ),
        (
            "createAlbum",
            "If ownership assignments are not validated server-side, createAlbum may allow "
            "a caller to associate albums with an unauthorized user.",
        ),
        (
            "updateUser",
            "If field-level restrictions are missing, updateUser could permit "
            "unauthorized attribute changes.",
        ),
        (
            "updateUser",
            "Insufficient object-level authorization could expose records "
            "outside the caller's scope.",
        ),
        (
            "deleteUser",
            "If target authorization is insufficient, deleteUser may allow unauthorized deletion.",
        ),
        (
            "createUser",
            "If authorization is absent, createUser could permit "
            "account creation without authorization.",
        ),
        (
            "countries",
            "Without server-side list limits, large result sets may increase resource consumption.",
        ),
        (
            "countries",
            "If server-side result-size controls are insufficient, "
            "large countries responses could increase resource usage.",
        ),
        ("continents", "Weak query-complexity controls could allow expensive nested selections."),
        (
            "continent",
            "Review nested query complexity for the supplied countries collection field.",
        ),
        (
            "language",
            "The language Query exposes an individual Language lookup. "
            "The recorded Query completed without a classified execution error.",
        ),
        (
            "country",
            "The country Query exposes an individual Country lookup. "
            "Review access restrictions where applicable; "
            "public reference data need not require authentication.",
        ),
    ],
)
def test_relevant_conditional_hypotheses_remain_unchanged(calibrated, name, text):
    _, context = calibrated
    payload = response(context, name, text)
    filtered, warnings, withheld = enforce(context, payload)
    assert warnings == withheld == ()
    assert filtered.model_dump(mode="json") == payload


@pytest.mark.parametrize(
    "name,text",
    [
        (
            "createAlbum",
            "createAlbum does not validate ownership and allows unauthorized user assignments.",
        ),
        (
            "updateUser",
            "updateUser lacks object-level authorization "
            "and allows users to modify arbitrary accounts.",
        ),
        ("updateUser", "The mutation executed successfully."),
        (
            "countries",
            "The successful execution demonstrates that unauthorized callers "
            "can access private user information.",
        ),
        ("countries", "The Query successfully retrieves user data."),
        (
            "country",
            "The country Query has the same unbounded root list risk identified for countries.",
        ),
        ("continent", "The continent Query has an unbounded root list."),
        (
            "language",
            "Validate whether list-bounding controls are enforced for the language Query.",
        ),
        (
            "createAlbum",
            "If authorization is absent, this may be relevant. The mutation lacks authorization.",
        ),
        (
            "createAlbum",
            "If authorization is absent, the mutation may allow unauthorized edits "
            "and actually lacks ownership validation.",
        ),
        (
            "createAlbum",
            "If authorization is absent, edits may be unauthorized "
            "and input validation is not implemented.",
        ),
    ],
)
def test_factual_errors_and_cross_operation_leakage_still_withheld(calibrated, name, text):
    _, context = calibrated
    filtered, warnings, withheld = enforce(context, response(context, name, text))
    assert warnings and len(withheld) == 1
    assert text not in filtered.model_dump_json()
    assert WITHHELD_PROSE in filtered.model_dump_json()


@pytest.mark.parametrize("name", ["countries", "continents", "languages"])
def test_result_size_followup_uses_its_own_candidate(calibrated, name):
    _, context = calibrated
    _, warnings, withheld = enforce(
        context,
        response(
            context, name, "Review result-size limits and pagination defaults.", "manual_follow_up"
        ),
    )
    assert warnings == withheld == ()


@pytest.mark.parametrize("name", ["country", "continent", "language"])
def test_explicit_reference_cannot_borrow_other_operations_candidate(calibrated, name):
    _, context = calibrated
    payload = security_answer_fields(context)
    fact = next(
        f
        for f in context.security_facts
        if f.name == "countries" and f.candidate_type == "list_bounding_review"
    )
    operation = next(o for o in context.operations if o.name == name)
    payload["summary_interpretation"] = {
        "text": "A result-size candidate was identified for this operation.",
        "references": reference_items([operation.operation], [fact.security_fact_ref]),
    }
    _, warnings, withheld = enforce(context, payload)
    assert "unsupported_review_conclusion" in warnings and len(withheld) == 1


def test_shared_ownership_theme_uses_both_structures(calibrated):
    _, context = calibrated
    payload = security_answer_fields(context)
    refs = [o.operation for o in context.operations if o.name in {"createAlbum", "updateAlbum"}]
    payload["review_insights"] = [
        {
            "references": reference_items(refs),
            "interpretation": "Both mutations accept an input.userId field. "
            "If ownership checks are absent, they may allow unauthorized ownership changes.",
            "manual_follow_up": "Review owner assignment permissions on both paths.",
        }
    ]
    filtered, warnings, withheld = enforce(context, payload)
    assert warnings == withheld == ()
    assert filtered.model_dump(mode="json") == payload


@pytest.mark.parametrize(
    "unsupported_theme",
    [
        "If ownership checks are absent, both operations may allow unauthorized ownership changes.",
        "If authorization is absent, all 19 mutations may allow unauthorized modifications.",
    ],
)
def test_theme_cannot_invent_shared_inputs_or_extend_to_omitted_operations(
    calibrated, unsupported_theme
):
    _, context = calibrated
    context = context.model_copy(
        update={
            "metadata": context.metadata.model_copy(
                update={
                    "operations_total": 25,
                    "operations_omitted": 14,
                    "context_truncated": True,
                }
            )
        }
    )
    payload = security_answer_fields(context)
    refs = [o.operation for o in context.operations if o.name in {"createAlbum", "updateUser"}]
    payload["review_insights"] = [
        {
            "references": reference_items(refs),
            "interpretation": unsupported_theme,
            "manual_follow_up": "Review each operation's actual declared input fields.",
        }
    ]
    filtered, warnings, withheld = enforce(context, payload)
    assert "unsupported_review_conclusion" in warnings and len(withheld) == 1
    assert filtered.review_insights[0].interpretation == WITHHELD_PROSE
    assert (
        filtered.review_insights[0].manual_follow_up
        == payload["review_insights"][0]["manual_follow_up"]
    )


@pytest.mark.parametrize(
    "fragment",
    [
        "Both operations fall under user management and personal information, warrant",
        "Review the supplied structure " + "x" * (350 - len("Review the supplied structure ")),
        "Review the supplied structure...",
    ],
)
def test_incomplete_model_fields_are_not_rendered_as_complete(calibrated, monkeypatch, fragment):
    scan, context = calibrated
    before = deepcopy(scan)
    payload = security_answer_fields(context)
    payload["review_insights"] = [
        {
            "references": reference_items([o.operation for o in context.operations[:2]]),
            "interpretation": fragment,
            "manual_follow_up": "Review the separate declared input paths.",
        }
    ]
    original = validate_interpretation(json.dumps(payload), context)
    assert original.review_insights[0].interpretation == fragment  # parser never clips
    calls = []

    def reply(request):
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        calls.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "done_reason": "stop",
                "eval_count": 1549,
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    monkeypatch.setattr(
        HttpClient, "send", lambda *a, **kw: pytest.fail("Unexpected target request")
    )
    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(reply))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(calls) == 1
    assert calls[0]["messages"][1]["content"] == serialize_context(context)
    assert result.quality_warnings == ("incomplete_prose",)
    assert len(result.withheld_fields) == 1
    assert result.interpretation.operation_interpretations == original.operation_interpretations
    assert (
        result.interpretation.review_insights[0].manual_follow_up
        == original.review_insights[0].manual_follow_up
    )
    assert result.interpretation.review_insights[0].interpretation == INCOMPLETE_PROSE
    assert "1 text fields withheld" in " ".join(quality_summary_lines(result))
    for width in (45, 120):
        stream = StringIO()
        render_ai(
            Console(file=stream, width=width, no_color=True, theme=CONSOLE_THEME),
            result,
            verbose=True,
        )
        assert fragment not in stream.getvalue()
        assert "incomplete text" in " ".join(stream.getvalue().split())
    report = build_report(scan, ai_interpretation=result)
    for format in ReportFormat:
        rendered = render_report(report, format)
        assert fragment not in html.unescape(rendered)
        assert INCOMPLETE_PROSE in html.unescape(rendered).replace("\\.", ".")
        if format is ReportFormat.JSON:
            canonical = json.loads(rendered)
            assert canonical["report_schema_version"] == 2
            assert "schema_structure" not in rendered
        else:
            assert rendered.rfind("Safety Notice") > rendered.rfind("AI-Assisted Interpretation")
    assert result.ai_contract_version == 2
    assert scan == before and scan.evidence == before.evidence
    assert (
        build_response_schema(context)["$defs"]["AIReviewInsight"]["properties"]["interpretation"][
            "maxLength"
        ]
        == 350
    )


def test_input_projection_bounds_cycles_and_excludes_values(phase_ten_scan):
    scan, _ = phase_ten_scan("""
        input Cycle { next: Cycle userId: ID private: String = "SECRET_CANARY" }
        type Query { item(input: Cycle): Item }
        type Item { id: ID }
    """)
    context = build_ai_context(scan)
    structure = context.operations[0].schema_structure
    assert structure.inputs_truncated
    assert len(structure.input_paths) <= 8
    assert max(map(len, structure.input_paths)) <= 3
    assert "SECRET_CANARY" not in serialize_context(context)
    assert context.metadata.serialized_bytes <= MAX_CONTEXT_BYTES


@pytest.mark.parametrize(
    "name,text,accepted",
    [
        (
            "createAlbum",
            "Ownership validation remains unverified. "
            "This operation may allow unauthorized ownership changes.",
            True,
        ),
        (
            "updateUser",
            "Ownership validation remains unverified. "
            "This operation may allow unauthorized ownership changes.",
            False,
        ),
        ("createAlbum", "The createAlbum mutation accepts an input.userId field.", True),
        ("updateUser", "The updateUser mutation accepts a userId input.", False),
        ("country", "The country Query returns a list of Country objects.", False),
        ("countries", "The countries Query returns a list of Country objects.", True),
        (
            "continent",
            "No root list-size issue was identified; review the supplied nested countries field.",
            True,
        ),
        (
            "countries",
            "The tested Query completed without a classified execution error. "
            "If access controls are insufficient, it could expose records beyond permitted scope.",
            True,
        ),
    ],
)
def test_complete_claim_and_surrounding_qualification(calibrated, name, text, accepted):
    _, context = calibrated
    filtered, warnings, withheld = enforce(context, response(context, name, text))
    assert bool(withheld) is not accepted
    assert (text in filtered.model_dump_json()) is accepted
    if accepted:
        assert warnings == ()


def test_wide_and_deep_schema_metadata_remains_bounded(phase_ten_scan):
    fields = " ".join(f"field{i}: String" for i in range(40))
    scan, _ = phase_ten_scan(f"""
        input Wide {{ {fields} }}
        input A {{ child: B }} input B {{ child: C }} input C {{ child: D }}
        input D {{ secret: String = "DEFAULT_VALUE_CANARY" }}
        type Query {{ wide(input: Wide): Item deep(input: A): Item }}
        type Item {{ id: ID a: [String] b: [String] c: [String] d: [String] e: [String] }}
    """)
    context = build_ai_context(scan)
    for operation in context.operations:
        structure = operation.schema_structure
        assert structure.inputs_truncated and structure.nested_lists_truncated
        assert len(structure.input_paths) <= 8
        assert max(map(len, structure.input_paths)) <= 3
        assert len(structure.nested_list_fields) == 4
    assert "DEFAULT_VALUE_CANARY" not in serialize_context(context)
    assert context.metadata.serialized_bytes <= MAX_CONTEXT_BYTES


def test_collection_wrapper_candidate_is_not_a_literal_root_list(phase_ten_scan):
    scan, _ = phase_ten_scan(
        "type Query { items: ItemsPage } type ItemsPage { data: [Item] } type Item { id: ID }"
    )
    context = build_ai_context(scan)
    assert context.operations[0].schema_structure.returns_list is False
    assert any(f.candidate_type == "list_bounding_review" for f in context.security_facts)
    _, warnings, withheld = enforce(
        context, response(context, "items", "Review result-size limits for the data collection.")
    )
    assert warnings == withheld == ()
    _, warnings, withheld = enforce(
        context, response(context, "items", "The root operation returns a list.")
    )
    assert warnings == ("unsupported_review_conclusion",) and len(withheld) == 1


def test_duplicate_operation_names_on_different_endpoints_keep_structure(phase_ten_scan):
    from dataclasses import replace

    first, _ = phase_ten_scan("type Query { record: [Item] } type Item { id: ID }")
    second, _ = phase_ten_scan("type Query { record: Item } type Item { id: ID }")
    analysis = first.query_generation.operation_analysis
    other = second.query_generation.operation_analysis
    endpoint = "https://second.example/graphql"
    other_analysis = replace(
        other.endpoints[0],
        endpoint=endpoint,
        operations=tuple(replace(o, endpoint=endpoint) for o in other.endpoints[0].operations),
    )
    combined = replace(
        first,
        query_generation=replace(
            first.query_generation,
            operation_analysis=replace(
                analysis,
                endpoints=(*analysis.endpoints, other_analysis),
                schema_scan=replace(
                    analysis.schema_scan,
                    schemas=(
                        *analysis.schema_scan.schemas,
                        replace(other.schema_scan.schemas[0], endpoint=endpoint),
                    ),
                ),
            ),
        ),
    )
    context = build_ai_context(combined)
    by_ref = {o.operation: o for o in context.operations}
    assert by_ref["endpoint_1/query/record"].schema_structure.returns_list is True
    assert by_ref["endpoint_2/query/record"].schema_structure.returns_list is False
    payload = security_answer_fields(context)
    for item in payload["operation_interpretations"]:
        if item["operation"] == "endpoint_2/query/record":
            item["manual_follow_up"] = "Review result-size controls for this root list."
    _, warnings, withheld = enforce(context, payload)
    assert warnings == ("unsupported_review_conclusion",)
    assert len(withheld) == 1
