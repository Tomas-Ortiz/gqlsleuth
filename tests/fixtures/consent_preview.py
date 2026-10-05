"""Observe real CLI consent boundaries and compare previews with mock-bound requests."""

import json
from dataclasses import dataclass, field
from io import StringIO

from rich.console import Console

from fixtures.cli_output import plain_cli_output
from gqlsleuth import cli
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.console import CONSOLE_THEME


@dataclass
class PromptSnapshot:
    text: str
    output: str
    request_count: int
    answer: object = None


@dataclass
class ConsentTrace:
    stream: StringIO = field(default_factory=StringIO)
    selections: list = field(default_factory=list)
    confirmations: list = field(default_factory=list)
    requests: list = field(default_factory=list)

    @property
    def output(self):
        return plain_cli_output(self.stream.getvalue())

    def confirmation(self, hint):
        matches = [item for item in self.confirmations if hint in item.text]
        assert len(matches) == 1
        confirmation = matches[0]
        assert confirmation.answer is True
        assert "GQLSleuth Assessment" not in confirmation.output
        return confirmation

    def sent_after(self, confirmation):
        index = self.confirmations.index(confirmation)
        end = (
            self.confirmations[index + 1].request_count
            if index + 1 < len(self.confirmations)
            else len(self.requests)
        )
        return self.requests[confirmation.request_count : end]

    def selection_before(self, hint, confirmation):
        matches = [item for item in self.selections if hint in item.text]
        assert len(matches) == 1
        selection = matches[0]
        # No request can run between selection and its independent confirmation.
        assert selection.request_count == confirmation.request_count
        assert confirmation.output.startswith(selection.output)
        assert len(confirmation.output) > len(selection.output)
        return selection

    def assert_private(self, *secrets):
        for secret in secrets:
            assert secret not in self.output
            assert all(secret not in item.output for item in self.confirmations)


def watch_consent(monkeypatch):
    trace = ConsentTrace()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=trace.stream, width=160, force_terminal=True, theme=CONSOLE_THEME),
    )
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)

    def wrap(original, snapshots):
        def interact(text, *args, **kwargs):
            snapshot = PromptSnapshot(text, trace.output, len(trace.requests))
            snapshots.append(snapshot)
            snapshot.answer = original(text, *args, **kwargs)
            return snapshot.answer

        return interact

    monkeypatch.setattr(cli.typer, "prompt", wrap(cli.typer.prompt, trace.selections))
    monkeypatch.setattr(cli.typer, "confirm", wrap(cli.typer.confirm, trace.confirmations))
    original_send = HttpClient.send

    def send(client, request):
        if trace.confirmations:
            assert trace.confirmations[-1].answer is True, "Request sent before consent"
        trace.requests.append(request)
        return original_send(client, request)

    monkeypatch.setattr(HttpClient, "send", send)
    return trace


def assert_request_preview(output, payload):
    """Compare complete documents and decoded variables, ignoring only Rich line padding."""
    plain = "\n".join(line.rstrip() for line in output.splitlines())
    assert payload["query"].strip() in plain
    values = []
    for index, char in enumerate(plain):
        if char != "{":
            continue
        try:
            value, _ = json.JSONDecoder().raw_decode(plain[index:])
        except ValueError:
            continue
        values.append(value)
    assert payload.get("variables", {}) in values
