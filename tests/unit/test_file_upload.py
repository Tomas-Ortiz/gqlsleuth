"""Bounded file preparation, canonical multipart plans, policy gates and privacy."""

import base64
import hashlib
import json
from dataclasses import replace
from io import StringIO
from pathlib import Path

import httpx
import pytest
from graphql import parse, validate
from rich.console import Console

from fixtures.phase28_target import PNG, SDL, multipart_parts, response_for
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import file_upload as application
from gqlsleuth.application.abuse_controls import prepare_abuse_controls
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.mutation_preparation import retained_mutation
from gqlsleuth.domain.exceptions import HttpConfigurationError, SafeExecutionValidationError
from gqlsleuth.domain.file_upload import (
    MAX_PHASE28_FILE_BYTES,
    UPLOAD_VARIANTS,
    UploadOutcome,
    UploadProbe,
    parse_upload_case,
)
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.graphql.file_upload import build_upload_document, classify_upload_response
from gqlsleuth.graphql.query_generation import generate_mutation
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.infrastructure.upload_file import (
    BENIGN_UPLOAD_CONTENT,
    read_upload_file,
    upload_variant,
)
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.file_upload import render_file_upload
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

CASE = parse_upload_case(["uploadAvatar:input.file"])
SECRET = "PHASE28_AUTH_CANARY"


@pytest.fixture
def file(tmp_path):
    path = tmp_path / "PHASE28_PRIVATE_PARENT" / "avatar.png"
    path.parent.mkdir()
    path.write_bytes(PNG)
    return path


@pytest.fixture
def safe(phase_ten_scan):
    return phase_ten_scan(SDL)[0]


@pytest.fixture
def wire(monkeypatch):
    requests = []
    settings = []
    behavior = {"scenario": "accept", "failure": None, "override": {}, "redirect": None}

    def handler(request):
        requests.append(request)
        index = sum(str(req.url).endswith("graphql") for req in requests)
        if behavior["failure"] == index:
            raise httpx.ConnectError("PHASE28_AUTH_CANARY", request=request)
        if behavior["redirect"] and str(request.url).endswith("graphql"):
            return httpx.Response(
                307, headers={"location": behavior["redirect"], "set-cookie": "learned=NO"}
            )
        if behavior["redirect"] and "other.example" in str(request.url):
            assert "authorization" not in request.headers and "cookie" not in request.headers
            assert "x-api-key" not in request.headers
        else:
            assert request.headers["authorization"] == "Bearer " + SECRET
            assert request.headers["cookie"] == "session=PHASE28_COOKIE_CANARY"
        status, body = behavior["override"].get(
            index,
            response_for(
                request.method,
                request.headers["content-type"],
                request.content,
                behavior["scenario"],
            ),
        )
        return httpx.Response(status, json=body)

    def factory(config):
        settings.append(config)
        # A configured proxy has its own HTTPX mount, so remove it only inside this mock adapter.
        return HttpClient(
            config.model_copy(update={"proxy": None}), transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(application, "HttpClient", factory)
    return requests, behavior, settings


def session(safe, file, **kwargs):
    return application.FileUploadSecuritySession(
        safe,
        case=CASE,
        file_path=file,
        enabled=True,
        http_settings=HttpClientSettings(
            custom_headers=(
                ("Authorization", "Bearer " + SECRET),
                ("Cookie", "session=PHASE28_COOKIE_CANARY"),
                ("X-API-Key", "PHASE28_KEY_CANARY"),
                ("Content-Type", "text/incorrect"),
            ),
            proxy="http://fake:PHASE28_PROXY_CANARY@proxy.example:8888",
            timeout_seconds=2,
            verify_tls=False,
        ),
        **kwargs,
    )


@pytest.mark.parametrize("text", ["u:f", "u:i.f", "u:a.b.c.d"])
def test_case_valid(text):
    case = parse_upload_case([text])
    assert case.operation + ":" + ".".join(case.path) == text


@pytest.mark.parametrize(
    "values",
    [
        [],
        ["u:f", "v:f"],
        [" u:f"],
        ["u: f"],
        ["u:f "],
        ["u:f[0]"],
        ["u:*"],
        ["u:a..b"],
        ["u:a.b.c.d.e"],
        ["1u:f"],
        ["u-f:x"],
        ["u:f=path"],
        ["u:f:extra"],
    ],
)
def test_case_invalid(values):
    with pytest.raises(HttpConfigurationError):
        parse_upload_case(values)


@pytest.mark.parametrize(
    "mime", ["", "text", "image/png\r\nX: y", "text/plain; charset=utf-8", " image/png"]
)
def test_bad_mime(file, mime):
    with pytest.raises(HttpConfigurationError):
        read_upload_file(file, mime)


def test_file_bounds_basename_hash_and_bounded_read(file, monkeypatch):
    metadata, data = read_upload_file(file)
    assert data == PNG and metadata.sha256 == hashlib.sha256(PNG).hexdigest()
    assert metadata.filename == "avatar.png" and metadata.content_type == "image/png"
    assert str(file.parent) not in repr(metadata)
    file.write_bytes(b"x" * MAX_PHASE28_FILE_BYTES)
    assert read_upload_file(file)[0].size == MAX_PHASE28_FILE_BYTES
    file.write_bytes(b"x" * (MAX_PHASE28_FILE_BYTES + 2))
    original = Path.open
    amounts = []

    class Reader:
        def __enter__(self):
            self.stream = original(file, "rb")
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, amount):
            amounts.append(amount)
            return self.stream.read(amount)

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: Reader())
    with pytest.raises(HttpConfigurationError):
        read_upload_file(file)
    assert amounts == [MAX_PHASE28_FILE_BYTES + 1]


@pytest.mark.parametrize("kind", ["missing", "directory", "empty", "unreadable"])
def test_unusable_file_local_error(file, kind, monkeypatch):
    if kind == "missing":
        file.unlink()
    elif kind == "directory":
        file = file.parent
    elif kind == "empty":
        file.write_bytes(b"")
    else:

        def denied(*args, **kwargs):
            raise PermissionError("PHASE28_PRIVATE_PARENT")

        monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(HttpConfigurationError) as error:
        read_upload_file(file)
    assert "PHASE28_PRIVATE_PARENT" not in str(error.value)


@pytest.mark.parametrize(
    "field,argument,path,eligible",
    [
        ("file: Upload!", "input: AvatarInput!", "input.file", True),
        ("file: Upload", "input: AvatarInput", "input.file", True),
        ("file: Upload!", "file: Upload!", "file", True),
        ("file: Upload!", "file: Upload", "file", True),
        ("file: String!", "input: AvatarInput!", "input.file", False),
        ("file: File!", "input: AvatarInput!", "input.file", False),
        ("file: [Upload!]!", "input: AvatarInput!", "input.file", False),
        ("file: Upload!", "input: [AvatarInput!]!", "input.file", False),
        ("file: Upload!, other: Upload!", "input: AvatarInput!", "input.file", False),
        ("file: Upload!, other: Upload", "input: AvatarInput!", "input.file", True),
        ("file: Upload!", "input: AvatarInput!", "input.missing", False),
    ],
)
def test_schema_shapes_and_required_placeholders(
    phase_ten_scan, file, field, argument, path, eligible
):
    sdl = (
        f"scalar Upload scalar File input AvatarInput {{ {field}, email: String!, unused: Int }} "
        f"type Query {{ ok: Boolean }} type Mutation {{ uploadAvatar({argument}): Boolean }}"
    )
    safe = phase_ten_scan(sdl)[0]
    result = application.prepare_file_upload(
        safe, case=parse_upload_case(["uploadAvatar:" + path]), file_path=file, enabled=True
    )
    assert (result.plan is not None) is eligible, result.limitations
    if result.plan:
        assert result.plan.multipart_map == {"0": ["variables." + path]}
        assert result.plan.source_evidence_ids
        assert "unused" not in json.dumps(result.plan.variables)
        if path == "input.file":
            assert result.plan.variables == {"input": {"file": None, "email": "test@example.com"}}


def test_nested_optional_path_and_actual_variable_name(phase_ten_scan, file):
    sdl = """scalar Upload input A { document: B, id: ID! }
    input B { file: Upload!, flag: Boolean!, unused: String }
    type Query { ok: Boolean } type Mutation { uploadAvatar(input: A!): Boolean }"""
    safe = phase_ten_scan(sdl)[0]
    schema, native, operation, _ = retained_mutation(safe, "uploadAvatar")
    artifact = generate_mutation(schema, operation)
    artifact = replace(
        artifact,
        query_text=artifact.query_text.replace("$input", "$actual"),
        variables={"actual": artifact.variables["input"]},
    )
    query, variables, path = build_upload_document(
        schema, native, artifact, parse_upload_case(["uploadAvatar:input.document.file"])
    )
    assert not validate(native, parse(query))
    assert path == "variables.actual.document.file"
    assert variables == {"actual": {"id": "1", "document": {"file": None, "flag": False}}}


@pytest.mark.parametrize("kind", ["query", "subscription", "destructive", "missing-signal"])
def test_invalid_roots_safety_and_provenance(phase_ten_scan, file, kind):
    sdl = SDL.replace("uploadAvatar", "deleteAvatar") if kind == "destructive" else SDL
    safe = phase_ten_scan(sdl)[0]
    if kind in {"query", "subscription"}:
        name = "health" if kind == "query" else "watchUpload"
    else:
        name = "deleteAvatar" if kind == "destructive" else "uploadAvatar"
    if kind == "missing-signal":
        safe = replace(safe, query_generation=replace(safe.query_generation, security_review=None))
    result = application.prepare_file_upload(
        safe, case=parse_upload_case([name + ":input.file"]), file_path=file, enabled=True
    )
    assert result.plan is None and result.limitations


@pytest.mark.parametrize("replacement", ["mutation Named", "query", "subscription", "mutation"])
def test_bad_documents_rejected(safe, replacement):
    schema, native, op, _ = retained_mutation(safe, "uploadAvatar")
    artifact = generate_mutation(schema, op)
    query = artifact.query_text.replace("mutation", replacement, 1)
    if replacement == "mutation":
        query = query.replace("uploadAvatar(", "alias: uploadAvatar(")
    with pytest.raises(SafeExecutionValidationError):
        build_upload_document(schema, native, replace(artifact, query_text=query), CASE)


@pytest.mark.parametrize(
    "scenario,probes,count,findings,baseline",
    [
        ("accept", (), 1, 0, "baseline_confirmed"),
        ("baseline-reject", UPLOAD_VARIANTS, 1, 0, "baseline_unusable"),
        ("null", UPLOAD_VARIANTS, 1, 0, "baseline_unusable"),
        ("accept", UPLOAD_VARIANTS, 4, 3, "baseline_confirmed"),
        ("reject", UPLOAD_VARIANTS, 4, 0, "baseline_confirmed"),
        ("ambiguous", UPLOAD_VARIANTS, 4, 0, "baseline_confirmed"),
    ],
)
def test_sequential_baseline_gates_policy_and_exact_multipart(
    safe, file, wire, scenario, probes, count, findings, baseline
):
    wire[1]["scenario"] = scenario
    workflow = session(safe, file)
    preview = workflow.select_variants(tuple(reversed(probes)))
    assert not wire[0]
    result = workflow.execute(preview=preview, confirmed=True)
    assert result.attempted_request_count == len(wire[0]) == count, result.limitations
    assert result.baseline_status.value == baseline and len(result.findings) == findings
    assert result.selected_variants == probes
    for request, attempt in zip(wire[0], result.attempts, strict=True):
        parts = multipart_parts(request.headers["content-type"], request.content)
        assert parts["operations"] == attempt.operations == preview.plan.operations
        assert parts["map"] == attempt.multipart_map == {"0": ["variables.input.file"]}
        assert hashlib.sha256(parts["bytes"]).hexdigest() == attempt.file.sha256
        assert len(parts["bytes"]) == attempt.file.size
        if attempt.probe is UploadProbe.CONTENT_MISMATCH:
            assert (
                parts["bytes"] == BENIGN_UPLOAD_CONTENT
                and parts["filename"] == "avatar.png"
                and parts["mime"] == "image/png"
            )
        else:
            assert parts["bytes"] == PNG
        if attempt.probe is UploadProbe.MIME_MISMATCH:
            assert parts["mime"] == "text/plain" and parts["filename"] == "avatar.png"
        if attempt.probe is UploadProbe.EXTENSION_MISMATCH:
            assert parts["filename"] == "avatar.txt" and parts["mime"] == "image/png"
    for finding in result.findings:
        assert finding.baseline_evidence_id == result.attempts[0].evidence_id
        assert finding.variant_evidence_id in {a.evidence_id for a in result.attempts[1:]}
        assert finding.expected.value == "deny" and finding.provenance.value == "operator_supplied"
    assert all(
        setting.timeout_seconds == 2 and not setting.verify_tls and setting.proxy
        for setting in wire[2]
    )
    assert workflow.execute(preview=preview, confirmed=True) == result and len(wire[0]) == count


@pytest.mark.parametrize("confirmed", [False, None, "yes", 1])
def test_strict_consent_is_terminal(safe, file, wire, confirmed):
    workflow = session(safe, file)
    result = workflow.execute(preview=workflow.preview, confirmed=confirmed)
    assert not result.attempts and not wire[0]
    assert workflow.execute(preview=workflow.preview, confirmed=True) == result


@pytest.mark.parametrize("failure", [1, 2, 3, 4])
def test_transport_consumes_attempt_without_retry_later_variants_continue(
    safe, file, wire, failure
):
    wire[1]["failure"] = failure
    workflow = session(safe, file)
    result = workflow.execute(preview=workflow.select_variants(UPLOAD_VARIANTS), confirmed=True)
    assert len(wire[0]) == (1 if failure == 1 else 4)
    assert result.attempts[failure - 1].outcome is UploadOutcome.NETWORK_FAILURE
    assert len(result.findings) == (0 if failure == 1 else 2)
    assert SECRET not in repr(result)


@pytest.mark.parametrize(
    "change",
    ["bytes", "size", "missing", "variables", "map", "filename", "mime", "query", "plan-count"],
)
def test_changed_file_or_forged_preview_sends_nothing(safe, file, wire, change):
    workflow = session(safe, file)
    preview = workflow.preview
    if change == "bytes":
        file.write_bytes(b"a" * len(PNG))
    elif change == "size":
        file.write_bytes(b"x")
    elif change == "missing":
        file.unlink()
    elif change == "variables":
        preview.plan.variables["input"]["email"] = "forged"
    elif change == "map":
        preview.plan.multipart_map["1"] = ["variables.input.email"]
    elif change in {"filename", "mime"}:
        preview = replace(
            preview,
            plan=replace(
                preview.plan,
                baseline=replace(
                    preview.plan.baseline,
                    **{("content_type" if change == "mime" else change): "forged"},
                ),
            ),
        )
    elif change == "query":
        preview = replace(preview, plan=replace(preview.plan, query="mutation { other }"))
    else:
        preview = replace(preview, selected_variants=(*UPLOAD_VARIANTS, UploadProbe.BASELINE))
    result = workflow.execute(preview=preview, confirmed=True)
    assert not wire[0] and not result.attempts and result.limitations


def test_file_changed_after_baseline_stops_remaining(safe, file, wire, monkeypatch):
    workflow = session(safe, file)
    original = workflow._request

    def request(*args):
        evidence = original(*args)
        file.write_bytes(b"changed")
        return evidence

    monkeypatch.setattr(workflow, "_request", request)
    result = workflow.execute(preview=workflow.select_variants(UPLOAD_VARIANTS), confirmed=True)
    assert len(wire[0]) == 1 and not result.findings and result.limitations


def test_multipart_response_limit_remains_enforced(safe, file, wire):
    settings = session(safe, file)._settings.model_copy(update={"max_response_body_bytes": 1})
    workflow = application.FileUploadSecuritySession(
        safe, case=CASE, file_path=file, enabled=True, http_settings=settings
    )
    result = workflow.execute(preview=workflow.select_variants(UPLOAD_VARIANTS), confirmed=True)
    assert len(wire[0]) == 1 and result.baseline_status.value == "baseline_unusable"
    assert result.attempts[0].error_type == "ResponseTooLargeError"


def test_source_provenance_and_settings_rechecked_before_each_send(safe, file, wire, monkeypatch):
    workflow = session(safe, file)
    original = workflow._request

    def request(*args):
        evidence = original(*args)
        workflow._settings = workflow._settings.model_copy(update={"timeout_seconds": 99})
        return evidence

    monkeypatch.setattr(workflow, "_request", request)
    result = workflow.execute(preview=workflow.select_variants(UPLOAD_VARIANTS), confirmed=True)
    assert len(wire[0]) == 1 and result.limitations and not result.findings


@pytest.mark.parametrize("extra", ["extra-root", "fragment", "definition"])
def test_extra_graphql_structure_rejected(safe, extra):
    schema, native, op, _ = retained_mutation(safe, "uploadAvatar")
    artifact = generate_mutation(schema, op)
    text = artifact.query_text
    if extra == "extra-root":
        text = text.rsplit("}", 1)[0] + " other: uploadAvatar(input: $input) { id } }"
    elif extra == "fragment":
        text = text.replace("id", "... F") + " fragment F on UploadResult { id }"
    else:
        text += " query { health }"
    with pytest.raises(SafeExecutionValidationError):
        build_upload_document(schema, native, replace(artifact, query_text=text), CASE)


def test_multipart_request_cannot_mix_json_or_nonpost():
    from gqlsleuth.infrastructure.http import HttpRequest, SingleFileMultipart

    multipart = SingleFileMultipart({"operations": "{}", "map": "{}"}, "a.png", "image/png", PNG)
    for method, body in (("GET", None), ("POST", {})):
        with pytest.raises(ValueError):
            HttpRequest(
                method=method, url="https://example.com", multipart=multipart, json_body=body
            )
    request = HttpRequest(method="POST", url="https://example.com", multipart=multipart)
    assert "multipart" not in request.model_dump() and repr(PNG) not in repr(request)


@pytest.mark.parametrize("origin", ["example.com", "other.example"])
def test_redirect_protection(safe, file, wire, origin):
    wire[1]["redirect"] = f"https://{origin}/next"
    workflow = session(safe, file)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert len(wire[0]) == 2
    assert result.attempts[0].outcome.value == (
        "upload_accepted" if origin == "example.com" else "indeterminate"
    )


@pytest.mark.parametrize(
    "name,mime,expected_name,expected_mime",
    [
        ("a.txt", "text/plain", "a.bin", "application/octet-stream"),
        ("a.b.png", "image/png", "a_b.txt", "text/plain"),
    ],
)
def test_safe_alternates(file, name, mime, expected_name, expected_mime):
    baseline, data = read_upload_file(file, mime)
    baseline = replace(baseline, filename=name)
    changed, same = upload_variant(baseline, data, UploadProbe.EXTENSION_MISMATCH)
    assert changed.filename == expected_name and same == data and changed.content_type == mime
    changed, same = upload_variant(baseline, data, UploadProbe.MIME_MISMATCH)
    assert changed.content_type == expected_mime and changed.filename == name and same == data
    assert BENIGN_UPLOAD_CONTENT == b"GQLSleuth benign file-upload validation payload.\n"


def test_reports_ai_provenance_privacy_and_no_cross_capability_handoff(safe, file, wire):
    workflow = session(safe, file)
    result = workflow.execute(preview=workflow.select_variants(UPLOAD_VARIANTS), confirmed=True)
    active = execute_selected_mutations(
        prepare_active_mutations(safe), selected_indices=(), confirmed=False
    )
    combined = replace(active, file_upload_security=result)
    assert combined.evidence == (*active.evidence, *result.evidence)
    assert build_ai_context(combined).operations == build_ai_context(active).operations
    assert prepare_abuse_controls(combined, enabled=True) == prepare_abuse_controls(
        active, enabled=True
    )
    report = build_report(combined)
    assert human_sections(report)[-1].title == "Safety Notice"
    outputs = [repr(result), repr(build_ai_context(combined))]
    for width in (48, 100):
        stream = StringIO()
        render_file_upload(
            Console(file=stream, width=width, theme=CONSOLE_THEME), result, preview=True
        )
        outputs.append(stream.getvalue())
    for format in ReportFormat:
        text = render_report(report, format)
        outputs.append(text)
        if format is ReportFormat.JSON:
            value = json.loads(text)["file_upload_security"]
            assert value["attempted_request_count"] == 4 and len(value["findings"]) == 3
            assert value["attempts"][0]["operations"] == result.plan.operations
        else:
            assert text.count("Safety Notice") == 1 and "File Upload Findings" in text
    assert all(
        canary not in text
        for text in outputs
        for canary in (
            SECRET,
            "PHASE28_COOKIE_CANARY",
            "PHASE28_KEY_CANARY",
            "PHASE28_PROXY_CANARY",
            "PHASE28_PRIVATE_PARENT",
            base64.b64encode(PNG).decode(),
            BENIGN_UPLOAD_CONTENT.decode().strip(),
        )
    )
    assert len(wire[0]) == 4
    assert "file_upload_security" not in json.loads(
        render_report(build_report(active), ReportFormat.JSON)
    )


@pytest.mark.parametrize(
    "echo",
    [SECRET, "PHASE28_COOKIE_CANARY", "PHASE28_KEY_CANARY", "PHASE28_PROXY_CANARY", "file", "path"],
)
def test_echo_capture_boundary(safe, file, wire, echo):
    value = (
        base64.b64encode(PNG).decode() if echo == "file" else str(file) if echo == "path" else echo
    )
    wire[1]["override"][1] = (200, {"data": {"uploadAvatar": {"echo": value}}})
    workflow = session(safe, file)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.attempts[0].response_material_withheld
    assert value not in repr(result)


def test_prior_uploaded_content_is_withheld_if_echoed_by_later_variant(safe, file, wire):
    wire[1]["override"][2] = (
        200,
        {"data": {"uploadAvatar": {"echo": base64.b64encode(PNG).decode()}}},
    )
    wire[1]["override"][3] = (
        200,
        {"data": {"uploadAvatar": {"echo": BENIGN_UPLOAD_CONTENT.decode()}}},
    )
    workflow = session(safe, file)
    result = workflow.execute(preview=workflow.select_variants(UPLOAD_VARIANTS), confirmed=True)
    assert len(wire[0]) == 4
    assert all(attempt.response_material_withheld for attempt in result.attempts[1:3])


@pytest.mark.parametrize("mode,enabled", [(ScanMode.SAFE, True), (ScanMode.ACTIVE, False)])
def test_disabled_and_safe_gate(phase_ten_scan, file, wire, mode, enabled):
    safe = phase_ten_scan(SDL, mode)[0]
    workflow = application.FileUploadSecuritySession(
        safe, case=CASE, file_path=file, enabled=enabled
    )
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.plan is None and not result.attempts and not wire[0]


@pytest.mark.parametrize(
    "status,body,outcome",
    [
        (200, {"data": {"uploadAvatar": True}}, "upload_accepted"),
        (200, {"data": {"uploadAvatar": {}}}, "upload_accepted"),
        (200, {"data": {"uploadAvatar": "id"}}, "upload_accepted"),
        (200, {"data": {"uploadAvatar": False}}, "upload_accepted"),
        (200, {"data": {"uploadAvatar": None}}, "indeterminate"),
        (200, {"data": {"other": True}}, "indeterminate"),
        (200, {"errors": [{"message": "invalid input"}]}, "indeterminate"),
        (200, {"errors": [{"message": "unsupported file type"}]}, "indeterminate"),
        (
            200,
            {"errors": [{"message": "unsupported file type", "path": ["uploadAvatar"]}]},
            "explicit_file_rejection",
        ),
        (
            200,
            {"errors": [{"message": "file type not allowed", "path": ["other"]}]},
            "indeterminate",
        ),
        (415, {"error": "type"}, "explicit_file_rejection"),
        (413, {}, "explicit_file_rejection"),
        (400, {}, "indeterminate"),
        (404, {}, "indeterminate"),
        (500, {}, "indeterminate"),
        (200, [], "indeterminate"),
        (200, {"data": {"uploadAvatar": True}, "errors": "bad"}, "indeterminate"),
    ],
)
def test_response_classifier(status, body, outcome):
    assert classify_upload_response(status, json.dumps(body).encode(), CASE).value == outcome


@pytest.mark.parametrize(
    "code",
    [
        "INVALID_FILE_TYPE",
        "fileTypeNotAllowed",
        "UNSUPPORTED_FILE_TYPE",
        "UNSUPPORTED_MEDIA_TYPE",
        "INVALID_UPLOAD",
        "FILE_EXTENSION_NOT_ALLOWED",
    ],
)
def test_exact_rejection_codes_and_ambiguity(code):
    error = {"message": "file", "extensions": {"code": code}}
    assert (
        classify_upload_response(200, json.dumps({"errors": [error]}).encode(), CASE)
        is UploadOutcome.EXPLICIT_FILE_REJECTION
    )
    error["path"] = ["other"]
    assert (
        classify_upload_response(200, json.dumps({"errors": [error]}).encode(), CASE)
        is UploadOutcome.INDETERMINATE
    )
    error["path"] = ["uploadAvatar"]
    assert (
        classify_upload_response(
            200, json.dumps({"data": {"uploadAvatar": True}, "errors": [error]}).encode(), CASE
        )
        is UploadOutcome.INDETERMINATE
    )
    error["extensions"]["code"] += "_NOT"
    assert (
        classify_upload_response(200, json.dumps({"errors": [error]}).encode(), CASE)
        is UploadOutcome.INDETERMINATE
    )
    assert classify_upload_response(200, b"not JSON", CASE) is UploadOutcome.INDETERMINATE
