"""Offline terminal selection, one-confirmation, and non-interactive Active Mode tests."""

import json

import httpx
import pytest
from typer.testing import CliRunner

import gqlsleuth.cli as cli
from gqlsleuth.application.active_execution import execute_selected_mutations
from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient


@pytest.fixture
def active_cli(phase_ten_scan, monkeypatch):
    requests = []
    results = []

    def fake_scan(target_url, *, mode=ScanMode.SAFE, http_settings=None):
        return phase_ten_scan(mode=mode)[0]

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"data": None})

    def execute(preview, *, selected_indices=(), confirmed=False, http_settings=None):
        with HttpClient(http_settings, transport=httpx.MockTransport(handler)) as client:
            result = execute_selected_mutations(
                preview, selected_indices=selected_indices, confirmed=confirmed, client=client
            )
        results.append(result)
        return result

    monkeypatch.setattr(cli, "run_safe_execution_scan", fake_scan)
    monkeypatch.setattr(cli, "execute_selected_mutations", execute)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    return requests, results


def _invoke(input="", mode="active"):
    return CliRunner().invoke(cli.app, ["scan", "https://example.com", "--mode", mode], input=input)


def test_safe_never_enters_mutation_stage_or_prompts(active_cli, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("SAFE entered Mutation UI")

    monkeypatch.setattr(cli, "prepare_active_mutations", unexpected)
    monkeypatch.setattr(cli.typer, "prompt", unexpected)
    monkeypatch.setattr(cli.typer, "confirm", unexpected)
    result = _invoke(mode="safe")
    assert result.exit_code == 0
    assert "Active Mutation candidates" not in result.stdout
    assert active_cli == ([], [])


def test_empty_selection_displays_previews_and_executes_none(active_cli):
    result = _invoke("\n")
    assert result.exit_code == 0
    output = " ".join(result.stdout.split())
    assert "ACTIVE mode" in output
    assert "Active Mutation candidates" in output
    assert "BLOCKED SAFETY deleteUser" in output
    assert "Destructive action token(s): delete" in output
    assert "mutation ($id: ID!)" in output
    assert 'Variables: {"id": "1"}' in output
    assert "Execute these" not in output
    assert "0 executed" in output
    assert active_cli[0] == []
    assert active_cli[1][0].selected_indices == ()
    preview_output = result.stdout.split("Active Mutation candidates:")[1].split(
        "Select Mutations"
    )[0]
    assert preview_output.count("Endpoint: https://example.com/graphql") == 1


def test_selected_batch_is_rendered_then_confirmed_exactly_once(active_cli, phase_ten_scan):
    from gqlsleuth.application.active_execution import prepare_active_mutations

    safe, _ = phase_ten_scan()
    preview = prepare_active_mutations(safe)
    indices = [i for i, item in enumerate(preview.candidates, 1) if item.selectable][:2]
    selection = ",".join(str(i) for i in reversed(indices))
    result = _invoke(selection + "\ny\n")
    assert result.exit_code == 0
    assert result.stdout.count("Execute these 2 selected Mutations?") == 1
    assert result.stdout.count("Select Mutations to execute") == 1
    selected_output = result.stdout.split("Selected Mutations:")[1].split("Execute these")[0]
    assert "WARNING: These operations may modify application state." in selected_output
    assert selected_output.count("Endpoint: https://example.com/graphql") == 1
    for index in indices:
        artifact = preview.candidates[index - 1].generated_mutation
        assert artifact.operation_name in selected_output
        assert artifact.query_text in selected_output
    assert len(active_cli[0]) == 2
    assert active_cli[1][0].confirmed
    assert all("operationName" not in payload for payload in active_cli[0])


@pytest.mark.parametrize("answer", ["n\n", "\n"])
def test_declined_or_default_confirmation_executes_zero(active_cli, answer):
    # updateProfile is first in retained priority order in this fixture.
    result = _invoke("1\n" + answer)
    assert result.exit_code == 0
    assert result.stdout.count("Execute these 1 selected Mutations?") == 1
    assert "[y/N]" in result.stdout
    assert active_cli[0] == []
    assert not active_cli[1][0].confirmed
    assert any(item.decision is MutationDecision.DECLINED for item in active_cli[1][0].executions)
    assert active_cli[1][0].execution_evidence == ()


def test_noninteractive_stdin_never_prompts_or_consumes_piped_confirmation(active_cli, monkeypatch):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)

    def unexpected(*args, **kwargs):
        raise AssertionError("Non-interactive input was read")

    monkeypatch.setattr(cli.typer, "prompt", unexpected)
    monkeypatch.setattr(cli.typer, "confirm", unexpected)
    result = _invoke("1\ny\n")
    assert result.exit_code == 0
    assert "Interactive selection and confirmation are required" in " ".join(result.stdout.split())
    assert active_cli[0] == []
    assert active_cli[1][0].selected_indices == ()


def test_invalid_blocked_wildcard_range_and_duplicate_selection_handling(
    active_cli, phase_ten_scan
):
    from gqlsleuth.application.active_execution import prepare_active_mutations

    safe, _ = phase_ten_scan()
    preview = prepare_active_mutations(safe)
    blocked = next(i for i, item in enumerate(preview.candidates, 1) if not item.selectable)
    result = _invoke(f"all\n*\n1-3\n999\n0\n-1\n{blocked}\n1,1\nn\n")
    assert result.exit_code == 0
    output = " ".join(result.stdout.split())
    assert "individual comma-separated indices only" in output
    assert "Unknown Mutation index" in output
    assert "Blocked or failed Mutation candidates cannot be selected" in output
    assert result.stdout.count("Execute these 1 selected Mutations?") == 1
    assert active_cli[0] == []


def test_more_than_five_selection_is_rejected_then_reprompted(
    active_cli, phase_ten_scan, monkeypatch
):
    sdl = (
        "type Query { health: String } type Mutation { "
        + " ".join(f"action{i}: String" for i in range(6))
        + " }"
    )
    monkeypatch.setattr(
        cli, "run_safe_execution_scan", lambda *args, **kwargs: phase_ten_scan(sdl)[0]
    )
    result = _invoke("1,2,3,4,5,6\n\n")
    assert result.exit_code == 0
    assert "Select at most 5 Mutations." in result.stdout
    assert result.stdout.count("Select Mutations to execute") == 2
    assert "Execute these" not in result.stdout
    assert active_cli[0] == []


def test_no_mutation_schema_finishes_without_input(active_cli, phase_ten_scan, monkeypatch):
    monkeypatch.setattr(
        cli,
        "run_safe_execution_scan",
        lambda *args, **kwargs: phase_ten_scan("type Query { health: String }")[0],
    )
    result = _invoke()
    assert result.exit_code == 0
    assert "No Mutation candidates." in result.stdout
    assert "Select Mutations" not in result.stdout
    assert active_cli[0] == []


def test_failed_generation_index_is_rejected_without_confirmation(
    active_cli, phase_ten_scan, monkeypatch
):
    sdl = """
        input Cycle { children: [Cycle!]! }
        type Query { health: String }
        type Mutation { broken(input: Cycle!): String createPaste: String }
    """
    monkeypatch.setattr(
        cli, "run_safe_execution_scan", lambda *args, **kwargs: phase_ten_scan(sdl)[0]
    )
    result = _invoke("1\n\n")
    assert result.exit_code == 0
    assert "GENERATION FAILED broken" in result.stdout
    assert "Blocked or failed Mutation candidates cannot be selected" in result.stdout
    assert "Execute these" not in result.stdout
    assert active_cli[0] == []
    assert active_cli[1][0].execution_evidence == ()


@pytest.mark.parametrize("stage", ["prompt", "confirm"])
def test_interrupted_selection_or_confirmation_fails_closed(active_cli, monkeypatch, stage):
    def interrupted(*args, **kwargs):
        raise cli.typer.Abort()

    monkeypatch.setattr(cli.typer, stage, interrupted)
    result = _invoke("1\n")
    assert result.exit_code == 0
    assert "cancelled" in result.stdout
    assert active_cli[0] == []
    assert not active_cli[1][0].confirmed
    assert active_cli[1][0].execution_evidence == ()


@pytest.mark.parametrize("flag", ["--authorized", "--yes", "--force"])
def test_execution_bypass_flags_are_not_available(active_cli, flag):
    result = CliRunner().invoke(cli.app, ["scan", "https://example.com", "--mode", "active", flag])
    assert result.exit_code == 2
    assert active_cli == ([], [])
