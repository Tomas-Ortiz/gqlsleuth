"""Generic names/header syntax and pre-scan rejection boundaries."""

import pytest
from typer.testing import CliRunner

import gqlsleuth.cli as cli
from gqlsleuth.application.scan_configuration import map_auth_context_inputs
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import ScanMode

SECRET = "PHASE15_CONTEXT_A_SECRET"


def test_names_are_opaque_ordered_and_repeated_names_accumulate_headers():
    contexts = map_auth_context_inputs(
        [
            "tenant-b=Authorization: Bearer " + SECRET,
            "Public",
            "tenant-b=X-Tenant-ID: 123",
            "Public",
            "public=Cookie: session=fake",
            "tenant-b=X-Custom: one:two=three",
            "tenant-b=X-Custom: again",
        ]
    )
    assert [item.name for item in contexts] == ["tenant-b", "Public", "public"]
    assert contexts[0].headers == (
        ("Authorization", "Bearer " + SECRET),
        ("X-Tenant-ID", "123"),
        ("X-Custom", "one:two=three"),
        ("X-Custom", "again"),
    )
    assert contexts[1].headers == ()
    assert contexts[2].headers == (("Cookie", "session=fake"),)
    assert SECRET not in repr(contexts)


@pytest.mark.parametrize(
    "entries",
    [
        [],
        ["one"],
        ["one", "one"],
        ["a", "b", "c", "d"],
        ["", "b"],
        ["=X-Key: " + SECRET, "b"],
        ["bad label", "b"],
        ["../bad", "b"],
        ["a" * 65, "b"],
        ["á", "b"],
        ["-bad", "b"],
        ["a\nb", "b"],
        ["a=", "b"],
        ["a=" + SECRET, "b"],
        ["a=: " + SECRET, "b"],
        ["a=X-Key: " + SECRET + "\r\nInjected: yes", "b"],
        ["a=Host: " + SECRET, "b"],
    ],
)
def test_invalid_syntax_count_and_names_never_echo_input(entries):
    with pytest.raises(HttpConfigurationError) as error:
        map_auth_context_inputs(entries)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize(
    "extra",
    [
        {"headers": ["Authorization: " + SECRET]},
        {"mode": ScanMode.ACTIVE},
        {"ai": True},
    ],
)
def test_incompatible_options_are_rejected(extra):
    with pytest.raises(HttpConfigurationError):
        map_auth_context_inputs(["north", "south"], **extra)


@pytest.mark.parametrize(
    "options",
    [
        ["--auth-context", "a"],
        ["--auth-context", "a", "--auth-context", "b", "-H", "Authorization: " + SECRET],
        ["--auth-context", "a", "--auth-context", "b", "--mode", "active"],
        ["--auth-context", "a", "--auth-context", "b", "--ai"],
        ["--auth-context", "a=" + SECRET, "--auth-context", "b"],
    ],
)
def test_invalid_cli_exits_before_scanning_or_ai(monkeypatch, options):
    def unexpected(*args, **kwargs):
        pytest.fail("Invalid configuration initiated work")

    monkeypatch.setattr(cli, "run_safe_execution_scan", unexpected)
    monkeypatch.setattr(cli, "run_differential_scan", unexpected)
    monkeypatch.setattr(cli, "interpret_completed_scan", unexpected)
    result = CliRunner().invoke(cli.app, ["scan", "https://example.com", *options])
    assert result.exit_code == 2
    assert SECRET not in result.output and "Traceback" not in result.output


def test_scan_help_exposes_context_syntax():
    result = CliRunner().invoke(cli.app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--auth-context" in result.output
    assert "SAFE" in result.output and "privilege order" in " ".join(result.output.split())
