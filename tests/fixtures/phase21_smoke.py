"""Reuse the Phase 20 loopback server: uv run python tests/fixtures/phase21_smoke.py."""

import json
from http.server import HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from phase20_target import Handler
from typer.testing import CliRunner

from gqlsleuth.cli import app


def main():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    target = f"http://127.0.0.1:{server.server_port}/graphql"
    Thread(target=server.serve_forever, daemon=True).start()
    named = [
        "--auth-context",
        "clienteA=X-Test-Context: clienteA",
        "--auth-context",
        "clienteB=X-Test-Context: clienteB",
    ]
    scenarios = [
        (
            "anonymous",
            [],
            ["order:id=100", "order:id=456", "order:id=mismatch"],
            ["1", "2", "3"],
            ["violated", "satisfied", "unresolved"],
            3,
            0,
        ),
        ("bare", ["--auth-context", "foo"], ["order:id=100"], ["1:foo"], ["violated"], 1, 0),
        (
            "two contexts",
            named,
            ["clienteA:order:id=123", "clienteB:order:id=456"],
            ["1:clienteB", "2:clienteA"],
            ["violated", "satisfied"],
            4,
            0,
        ),
        (
            "three contexts",
            [*named, "--auth-context", "public"],
            ["clienteA:order:id=123"],
            ["1:clienteB", "1:public"],
            ["violated", "violated"],
            3,
            0,
        ),
        (
            "owner short circuit",
            named,
            ["clienteA:order:id=999"],
            ["1:clienteB"],
            ["unresolved"],
            1,
            0,
        ),
        (
            "combined",
            [*named, "--auth-context", "public", "--nested-auth-review"],
            ["clienteA:order:id=123"],
            ["1:public"],
            ["violated"],
            3,
            3,
        ),
    ]
    try:
        for label, options, cases, policies, expected, object_count, nested_count in scenarios:
            base = [
                "scan",
                target,
                *options,
                "--object-auth-review",
                *[part for case in cases for part in ("--object-auth-case", case)],
            ]
            Handler.requests.clear()
            off = CliRunner().invoke(app, base)
            assert off.exit_code == 0, (off.exception, off.output)
            original = list(Handler.requests)
            Handler.requests.clear()
            with TemporaryDirectory(prefix="gqlsleuth-phase21-") as directory:
                on = CliRunner().invoke(
                    app,
                    [
                        *base,
                        "--auth-policy-review",
                        *[part for policy in policies for part in ("--expect-deny", policy)],
                        "-f",
                        "json,markdown,html",
                        "-o",
                        directory,
                    ],
                )
                assert on.exit_code == 0, (on.exception, on.output)
                assert Handler.requests == original, "Phase 21 changed target requests"
                report = json.loads(
                    next(Path(directory).glob("*.json")).read_text(encoding="utf-8")
                )
                assert [
                    item["status"]
                    for item in report["authorization_policy_validation"]["evaluations"]
                ] == expected
                assert (
                    report["object_authorization_review"]["attempted_request_count"] == object_count
                )
                nested = report.get("nested_authorization_review")
                assert (
                    sum(item["attempted"] for item in nested["executions"]) if nested else 0
                ) == nested_count
                for extension in ("md", "html"):
                    human = next(Path(directory).glob(f"*.{extension}")).read_text(encoding="utf-8")
                    assert (
                        human.index("Controlled Object Authorization Validation")
                        < human.index("Authorization Policy Validation")
                        < human.index("Safety Notice")
                    )
                    assert human.count("Safety Notice") == 1
                print(
                    f"PASS {label}: identical {len(original)} requests; "
                    f"Phase 19={nested_count}, Phase 20={object_count}, Phase 21=0; {expected}"
                )
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
