"""Exact request-sequence invariance, pre-network policy errors and human report boundaries."""

import ast
import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from fixtures.phase20_target import response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.infrastructure.http import HttpClient

TARGET = "https://example.com/graphql"
TWO = [
    "--auth-context",
    "clienteA=X-Test-Context: clienteA",
    "--auth-context",
    "clienteA=Authorization: PHASE21_A_SECRET",
    "--auth-context",
    "clienteB=X-Test-Context: clienteB",
    "--auth-context",
    "clienteB=Cookie: PHASE21_B_SECRET",
]


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def transport(**kwargs):
        def handler(request):
            requests.append(
                (
                    request.method,
                    str(request.url),
                    tuple(request.headers.multi_items()),
                    request.content,
                )
            )
            payload = json.loads(request.content) if request.method == "POST" else None
            status, document = response_for(request.method, request.headers, payload)
            return httpx.Response(status, json=document)

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    return requests


SCENARIOS = [
    (
        [],
        ["order:id=100", "order:id=456", "order:id=mismatch"],
        ["1", "2", "3"],
        ["violated", "satisfied", "unresolved"],
        3,
        0,
    ),
    (["--auth-context", "foo"], ["order:id=100"], ["1:foo"], ["violated"], 1, 0),
    (
        TWO,
        ["clienteA:order:id=123", "clienteB:order:id=456"],
        ["1:clienteB", "2:clienteA"],
        ["violated", "satisfied"],
        4,
        0,
    ),
    (
        [*TWO, "--auth-context", "public"],
        ["clienteA:order:id=123"],
        ["1:clienteB", "1:public"],
        ["violated", "violated"],
        3,
        0,
    ),
    (TWO, ["clienteA:order:id=999"], ["1:clienteB"], ["unresolved"], 1, 0),
    (
        [*TWO, "--auth-context", "public", "--nested-auth-review"],
        ["clienteA:order:id=123"],
        ["1:public"],
        ["violated"],
        3,
        3,
    ),
]


@pytest.mark.parametrize("options,cases,policies,statuses,phase20,phase19", SCENARIOS)
def test_exact_request_invariance_and_reports(
    controlled, tmp_path, options, cases, policies, statuses, phase20, phase19
):
    common = [
        "scan",
        TARGET,
        *options,
        "--object-auth-review",
        *[value for case in cases for value in ("--object-auth-case", case)],
        "-f",
        "json,markdown,html",
    ]
    before = CliRunner().invoke(cli.app, [*common, "-o", str(tmp_path / "off")])
    assert before.exit_code == 0, before.exception
    original = list(controlled)
    controlled.clear()
    after = CliRunner().invoke(
        cli.app,
        [
            *common,
            "--auth-policy-review",
            *[value for policy in policies for value in ("--expect-deny", policy)],
            "-v",
            "-o",
            str(tmp_path / "on"),
        ],
    )
    assert after.exit_code == 0, after.exception
    assert controlled == original
    baseline = json.loads(next((tmp_path / "off").glob("*.json")).read_text(encoding="utf-8"))
    report = json.loads(next((tmp_path / "on").glob("*.json")).read_text(encoding="utf-8"))
    assert "authorization_policy_validation" not in baseline
    policy = report["authorization_policy_validation"]
    assert [item["status"] for item in policy["evaluations"]] == statuses
    assert len(policy["violations"]) == statuses.count("violated")
    review = report["object_authorization_review"]
    assert review["attempted_request_count"] == phase20
    assert [item["outcome"] for item in review["executions"]] == [
        item["outcome"] for item in baseline["object_authorization_review"]["executions"]
    ]
    nested = report.get("nested_authorization_review")
    assert (sum(item["attempted"] for item in nested["executions"]) if nested else 0) == phase19
    evidence_ids = {
        item["evidence"]["evidence_id"] for item in review["executions"] if item["evidence"]
    }
    assert all(set(item["source_evidence_ids"]) <= evidence_ids for item in policy["evaluations"])
    policy_json = json.dumps(policy)
    for excluded in (
        "response_body",
        "response_headers",
        "variables",
        "PHASE21_A_SECRET",
        "PHASE21_B_SECRET",
        "HttpClientSettings",
        "CWE",
        "CVSS",
        "BOLA",
        "IDOR",
    ):
        assert excluded not in policy_json
    for extension in ("md", "html"):
        human = next((tmp_path / "on").glob(f"*.{extension}")).read_text(encoding="utf-8")
        assert human.count("Safety Notice") == 1
        assert (
            human.index("Controlled Object Authorization Validation")
            < human.index("Authorization Policy Validation")
            < human.index("Safety Notice")
        )
        for secret in ("PHASE21_A_SECRET", "PHASE21_B_SECRET", "PHASE20_BUSINESS_VALUE"):
            assert secret not in human
    assert "Authorization Policy Validation" in after.output
    assert "Authorization Policy Validation" not in before.output
    assert "PHASE21_A_SECRET" not in after.output and "PHASE21_B_SECRET" not in after.output
    if phase19:
        assert (
            after.output.index("Nested Authorization Review")
            < after.output.index("Controlled Object Authorization Validation")
            < after.output.index("Authorization Policy Validation")
        )


@pytest.mark.parametrize(
    "extra",
    [
        ["--auth-policy-review"],
        ["--expect-deny", "1"],
        ["--object-auth-review", "--object-auth-case", "order:id=100", "--auth-policy-review"],
        [
            "--object-auth-review",
            "--object-auth-case",
            "order:id=100",
            "--auth-policy-review",
            "--expect-deny",
            "2",
        ],
        [
            "--object-auth-review",
            "--object-auth-case",
            "order:id=100",
            "--auth-policy-review",
            "--expect-deny",
            "1:SECRET",
        ],
        [
            *TWO,
            "--object-auth-review",
            "--object-auth-case",
            "clienteA:order:id=123",
            "--auth-policy-review",
            "--expect-deny",
            "1:clienteA",
        ],
        [
            *TWO,
            "--object-auth-review",
            "--object-auth-case",
            "clienteA:order:id=123",
            "--auth-policy-review",
            "--expect-deny",
            "1:clienteB",
            "--expect-deny",
            "01:clienteB",
        ],
    ],
)
def test_invalid_policy_fails_before_scanning(monkeypatch, extra):
    monkeypatch.setattr(
        HttpClient, "send", lambda *args: pytest.fail("Invalid policy performed network I/O")
    )
    run = CliRunner().invoke(cli.app, ["scan", TARGET, *extra])
    assert run.exit_code == 2
    assert "SECRET" not in run.output
    assert not isinstance(run.exception, AssertionError)


def test_ai_context_and_one_call_unchanged(controlled, monkeypatch):
    contexts = []

    def interpret(result):
        contexts.append(build_ai_context(result))
        return None

    monkeypatch.setattr(cli, "interpret_completed_scan", interpret)
    monkeypatch.setattr(cli, "render_ai", lambda *args, **kwargs: None)
    args = ["scan", TARGET, "--object-auth-review", "--object-auth-case", "order:id=100", "--ai"]
    assert CliRunner().invoke(cli.app, args).exit_code == 0
    assert (
        CliRunner().invoke(cli.app, [*args, "--auth-policy-review", "--expect-deny", "1"]).exit_code
        == 0
    )
    assert len(contexts) == 2 and contexts[0].operations == contexts[1].operations
    assert not any(f.capability == "authorization_policy" for f in contexts[0].security_facts)
    assert any(f.capability == "authorization_policy" for f in contexts[1].security_facts)


def test_evaluator_import_boundary():
    import gqlsleuth.application.authorization_policy as module

    tree = ast.parse(Path(module.__file__).read_text())
    imported = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    imported += [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert all(
        name in {"json", "uuid"} or name.startswith("gqlsleuth.domain.") for name in imported
    )
