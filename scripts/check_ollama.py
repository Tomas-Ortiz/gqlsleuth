"""Manual acceptance: mocked SAFE scan -> bounded local qwen3:8b interpretation.

Run explicitly with `uv run python scripts/check_ollama.py`; never run in normal CI.
Requires an already running Ollama and installed model. No model downloads or public targets.
"""

import json
import sys
from copy import deepcopy
from unittest.mock import patch

import httpx
from graphql import build_schema, introspection_from_schema

from gqlsleuth.ai.models import (
    MAX_AI_ATTEMPTS,
    MAX_AI_SUMMARY_CHARACTERS,
    AIAnalysisStatus,
    AIContext,
    AIInterpretation,
    AIValidationError,
)
from gqlsleuth.ai.prompt import validate_interpretation
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.safe_execution import SafeExecutionScanResult, run_safe_execution_scan
from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY
from gqlsleuth.infrastructure.ollama import OLLAMA_ENDPOINT, OllamaClient

SDL = """
scalar Upload
type Query { lookup(id: ID!): Item login: String items: [Item] }
type Mutation { updateUser(id: ID!, input: Input!): Item upload(file: Upload!): Item }
input Input { ownerId: ID role: String }
type Item { id: ID children: [Item] }
type Subscription { notificationCreated(objectId: ID!): Item }
"""


def fixture_scan() -> SafeExecutionScanResult:
    """Exercise the real SAFE pipeline with every target transport mocked."""
    schema = introspection_from_schema(build_schema(SDL))

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "127.0.0.1" and request.url.port == 9
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": {"__schema": {}}})
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": schema})
        assert query.strip().startswith("query")
        return httpx.Response(200, json={"data": None})

    with patch(
        "httpx._client.HTTPTransport", side_effect=lambda **kw: httpx.MockTransport(respond)
    ):
        return run_safe_execution_scan("http://127.0.0.1:9/graphql")


class LocalInferenceTransport(httpx.HTTPTransport):
    calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert str(request.url) == OLLAMA_ENDPOINT + "/api/chat" and request.method == "POST"
        self.calls += 1
        assert self.calls <= MAX_AI_ATTEMPTS, "AI attempt limit exceeded"
        return super().handle_request(request)


def local_only(event: str, args: tuple[object, ...]) -> None:
    """Fail closed if the manual smoke accidentally attempts any non-Ollama networking."""
    if event == "socket.connect" and args[1] == ("127.0.0.1", 11434):
        return
    if event == "socket.getaddrinfo" and args[:2] == ("127.0.0.1", 11434):
        return
    if event in {
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.sendto",
        "socket.bind",
    }:
        raise RuntimeError("Acceptance smoke permits only local Ollama networking")


def validate_fixture_reply(text: str, context: AIContext) -> AIInterpretation:
    """Expose only typed synthetic-fixture prose for manual triage; never bypass validation."""
    try:
        return validate_interpretation(text, context)
    except AIValidationError as error:
        if error.stage not in {"json", "schema"}:
            # The real validator already passed the strict typed contract. This helper runs
            # only on the fixed synthetic fixture, never on target scans or in the normal CLI.
            typed = AIInterpretation.model_validate_json(text, strict=True)
            print("Rejected fixture prose (NOT an accepted interpretation):")
            print(json.dumps(typed.model_dump(mode="json"), indent=2, ensure_ascii=True))
            print(f"Rejected summary length: {len(typed.security_summary.text)}")
        raise


def main() -> None:
    sys.addaudithook(local_only)
    scan = fixture_scan()
    before = deepcopy(scan)
    transport = LocalInferenceTransport()
    # Normal acceptance retains only safe rejection codes, never rejected model prose.
    result = interpret_completed_scan(scan, client=OllamaClient(transport=transport))
    assert scan == before and scan.evidence == before.evidence
    print(
        "Deterministic scan/Evidence unchanged; target requests mocked; five-attempt guard active."
    )
    print(f"Ollama acceptance: {result.status.value}; inference requests: {transport.calls}")
    print(f"Validation failures: {result.validation_failures}")
    assert transport.calls == result.attempt_count
    if result.status is not AIAnalysisStatus.SUCCESS:
        print(f"Controlled diagnostic: {result.error_code}")
        raise SystemExit(1)
    assert 1 <= transport.calls <= MAX_AI_ATTEMPTS and result.interpretation is not None
    print("Typed interpretation and supplied references validated; no raw output retained.")
    summary = result.interpretation.security_summary.text
    print(
        f"Summary: {len(summary)} characters; structural ceiling: {MAX_AI_SUMMARY_CHARACTERS}; "
        "completion/assurance/absence/grounding checks passed; deterministic scan unchanged."
    )
    # This explicitly invoked fixture uses no target data; permit complete prose inspection.
    print(json.dumps(result.interpretation.model_dump(mode="json"), indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
