"""Manual acceptance: mocked SAFE scan -> one real local qwen3:8b interpretation.

Run explicitly with `uv run python scripts/check_ollama.py`; never run in normal CI.
Requires an already running Ollama and installed model. No model downloads or public targets.
"""

import json
import sys
from unittest.mock import patch

import httpx
from graphql import build_schema, introspection_from_schema

from gqlsleuth.ai.models import AIAnalysisStatus
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
        assert self.calls == 1, "Only one inference is allowed"
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


def main() -> None:
    sys.addaudithook(local_only)
    scan = fixture_scan()
    transport = LocalInferenceTransport()
    result = interpret_completed_scan(scan, client=OllamaClient(transport=transport))
    print(f"Ollama acceptance: {result.status.value}; inference requests: {transport.calls}")
    if result.status is not AIAnalysisStatus.SUCCESS:
        print(f"Controlled diagnostic: {result.error_code}")
        raise SystemExit(1)
    assert transport.calls == 1 and result.interpretation is not None
    print("Typed interpretation and supplied references validated; no raw output retained.")


if __name__ == "__main__":
    main()
