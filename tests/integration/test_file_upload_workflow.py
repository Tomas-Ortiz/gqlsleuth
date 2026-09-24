"""Offline CLI upload workflow, separate consent and additive reports."""

import json

import httpx
import pytest
from typer.testing import CliRunner

from fixtures.phase28_target import PNG, multipart_parts, response_for
from gqlsleuth import cli
from gqlsleuth.infrastructure.http import HttpClient

TARGET = "https://example.com/graphql"
CASE = ["--upload-case", "uploadAvatar:input.file"]


@pytest.fixture
def local_file(tmp_path):
    path = tmp_path / "PHASE28_PARENT_CANARY" / "avatar.png"
    path.parent.mkdir()
    path.write_bytes(PNG)
    return path


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def factory(**kwargs):
        def handler(request):
            requests.append(request)
            assert request.headers["authorization"] == "Bearer PHASE28_CLI_CANARY"
            status, body = response_for(
                request.method, request.headers.get("content-type", ""), request.content
            )
            return httpx.Response(status, json=body)

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", factory)
    monkeypatch.setattr(cli, "_run_multiplicity_stage", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_run_depth_stage", lambda *args, **kwargs: None)
    return requests


@pytest.mark.parametrize(
    "options",
    [
        ["--file-upload-review"],
        ["--mode", "active", "--file-upload-review"],
        ["--mode", "active", "--file-upload-review", *CASE],
        ["--mode", "active", *CASE],
        ["--mode", "active", "--file-upload-review", *CASE, "--upload-case", "other:file"],
        ["--mode", "active", "--file-upload-review", *CASE, "--auth-context", "one"],
        [
            "--mode",
            "active",
            "--file-upload-review",
            *CASE,
            "--auth-context",
            "one",
            "--auth-context",
            "two",
        ],
    ],
)
def test_invalid_combinations_fail_before_network(monkeypatch, options):
    monkeypatch.setattr(
        HttpClient, "send", lambda *args: pytest.fail("Invalid configuration sent HTTP")
    )
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *options])
    assert result.exit_code == 2 and "Traceback" not in result.output


@pytest.mark.parametrize("kind", ["missing", "oversized", "empty", "double", "mime"])
def test_file_configuration_failures_are_local(monkeypatch, local_file, kind):
    options = ["--mode", "active", "--file-upload-review", *CASE, "--upload-file", str(local_file)]
    if kind == "missing":
        local_file.unlink()
    elif kind == "oversized":
        local_file.write_bytes(b"a" * (1024 * 1024 + 1))
    elif kind == "empty":
        local_file.write_bytes(b"")
    elif kind == "double":
        options += ["--upload-file", str(local_file)]
    else:
        options += ["--upload-content-type", "image/png\r\nX: PHASE28_SECRET"]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid file sent HTTP"))
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *options])
    assert result.exit_code == 2
    assert "PHASE28_PARENT_CANARY" not in result.output and "PHASE28_SECRET" not in result.output


@pytest.mark.parametrize(
    "interactive,inputs,count,findings,confirmations",
    [
        (False, "", 0, 0, 0),
        (True, "\n\nn\n", 0, 0, 1),
        (True, "\n\n\n", 0, 0, 1),
        (True, "\n\ny\n", 1, 0, 1),
        (True, "\n1\ny\n", 2, 1, 1),
        (True, "\n3,1\ny\n", 3, 2, 1),
        (True, "\n3,2,1,1\ny\n", 4, 3, 1),
        (True, "\nall\n*\n1-3\n4\n1,2,3\ny\n", 4, 3, 1),
    ],
)
def test_selection_confirmation_reports(
    controlled,
    monkeypatch,
    local_file,
    tmp_path,
    interactive,
    inputs,
    count,
    findings,
    confirmations,
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            "--mode",
            "active",
            "--file-upload-review",
            *CASE,
            "--upload-file",
            str(local_file),
            "-H",
            "Authorization: Bearer PHASE28_CLI_CANARY",
            "-f",
            "json,markdown,html",
            "-o",
            str(tmp_path / "reports"),
        ],
        input=inputs,
    )
    assert result.exit_code == 0, (result.exception, result.output)
    uploads = [r for r in controlled if r.headers.get("content-type", "").startswith("multipart/")]
    assert len(uploads) == count
    assert result.output.count("Execute file upload security validation?") == confirmations
    assert (
        "PHASE28_PARENT_CANARY" not in result.output and "PHASE28_CLI_CANARY" not in result.output
    )
    report = json.loads(next((tmp_path / "reports").glob("*.json")).read_text(encoding="utf-8"))
    value = report["file_upload_security"]
    assert value["attempted_request_count"] == count and len(value["findings"]) == findings
    assert sum(e["evidence_type"] == "file_upload_probe" for e in report["evidence"]) == count
    if count:
        assert (
            multipart_parts(uploads[0].headers["content-type"], uploads[0].content)["bytes"] == PNG
        )
    for path in (tmp_path / "reports").iterdir():
        text = path.read_text(encoding="utf-8")
        assert "PHASE28_PARENT_CANARY" not in text and "PHASE28_CLI_CANARY" not in text
        if path.suffix != ".json":
            assert text.count("Safety Notice") == 1 and "File Upload Security" in text


def test_disabled_and_noninteractive_keep_normal_requests_identical(
    controlled, monkeypatch, local_file
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    options = ["scan", TARGET, "--mode", "active", "-H", "Authorization: Bearer PHASE28_CLI_CANARY"]
    off = CliRunner().invoke(cli.app, options)
    assert off.exit_code == 0, off.output
    original = [(r.method, str(r.url), r.content, dict(r.headers)) for r in controlled]
    controlled.clear()
    on = CliRunner().invoke(
        cli.app, [*options, "--file-upload-review", *CASE, "--upload-file", str(local_file)]
    )
    assert on.exit_code == 0, on.output
    assert original == [(r.method, str(r.url), r.content, dict(r.headers)) for r in controlled]


def test_uploads_do_not_add_ai_calls(controlled, monkeypatch, local_file):
    from gqlsleuth.ai.context import build_ai_context

    calls = []
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.setattr(
        cli, "interpret_completed_scan", lambda result: calls.append(build_ai_context(result))
    )
    monkeypatch.setattr(cli, "render_ai", lambda *args, **kwargs: None)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            "--mode",
            "active",
            "--file-upload-review",
            *CASE,
            "--upload-file",
            str(local_file),
            "--ai",
            "-H",
            "Authorization: Bearer PHASE28_CLI_CANARY",
        ],
        input="\n1,2,3\ny\n",
    )
    assert result.exit_code == 0, (result.exception, result.output)
    assert len(calls) == 1 and "file_upload_security" not in repr(calls[0])


def test_help_lists_upload_options():
    result = CliRunner().invoke(cli.app, ["scan", "--help"])
    assert result.exit_code == 0
    for option in (
        "--file-upload-review",
        "--upload-case",
        "--upload-file",
        "--upload-content-type",
    ):
        assert option in result.output
