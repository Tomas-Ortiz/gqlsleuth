"""Manual acceptance: mocked SAFE scan -> bounded local qwen3:8b interpretation.

Run explicitly with `uv run python scripts/check_ollama.py`; never run in normal CI.
Requires an already running Ollama and installed model. No model downloads or public targets.
"""

import json
import sys
from copy import deepcopy
from dataclasses import asdict
from unittest.mock import patch

import httpx
from graphql import build_schema, introspection_from_schema

from gqlsleuth.ai.models import (
    AI_NOTICE,
    MAX_AI_ATTEMPTS,
    MAX_AI_SUMMARY_CHARACTERS,
    AIAnalysisStatus,
    AIContext,
    AIInterpretation,
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
    """Validate the complete contract without printing or retaining rejected prose."""
    return validate_interpretation(text, context)


def main() -> None:
    sys.addaudithook(local_only)
    scan = fixture_scan()
    before = deepcopy(scan)
    transport = LocalInferenceTransport()
    # Normal acceptance retains only safe rejection codes, never rejected model prose.
    result = interpret_completed_scan(scan, client=OllamaClient(transport=transport))
    assert scan == before and scan.evidence == before.evidence
    print(
        "Deterministic scan/Evidence unchanged; target requests mocked; ten-attempt guard active."
    )
    print(f"Ollama acceptance: {result.status.value}; inference requests: {transport.calls}")
    print(f"Validation failures: {result.validation_failures}")
    print(f"Advisory quality warnings: {result.quality_warnings}")
    print(json.dumps([asdict(attempt) for attempt in result.attempts], indent=2))
    assert transport.calls == result.attempt_count
    if result.status is not AIAnalysisStatus.SUCCESS:
        print(f"Controlled diagnostic: {result.error_code}")
        raise SystemExit(1)
    assert 1 <= transport.calls <= MAX_AI_ATTEMPTS and result.interpretation is not None
    supplied = {operation.operation for operation in result.references.operations}
    returned = [item.operation for item in result.interpretation.operation_interpretations]
    assert set(returned) == supplied and len(returned) == len(supplied)
    print(
        f"Operation coverage: {len(returned)}/{len(supplied)}; omitted from context: "
        f"{result.context_metadata.operations_omitted}"
    )
    print("Typed interpretation and supplied references validated; no raw output retained.")
    summary = result.interpretation.summary_interpretation.text
    print(
        f"Summary: {len(summary)} characters; structural ceiling: {MAX_AI_SUMMARY_CHARACTERS}; "
        "hard structural checks passed; prose quality flags are advisory; "
        "deterministic scan unchanged."
    )
    print(AI_NOTICE)
    # This explicitly invoked fixture uses no target data; permit complete prose inspection.
    print(json.dumps(result.interpretation.model_dump(mode="json"), indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
