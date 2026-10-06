"""Semantic status styling is console-only and preserves every displayed status token."""

from io import StringIO

import pytest
from rich.console import Console
from rich.style import Style
from rich.text import Text

from fixtures.cli_output import plain_cli_output
from gqlsleuth.presentation.console import _status
from gqlsleuth.presentation.statuses import status_text, style_status_terms


@pytest.mark.parametrize(
    "value,color",
    [
        ("SUCCESS", "green"),
        ("ACCEPTED", "green"),
        ("OBSERVED", "green"),
        ("CONTROL", "green"),
        ("GRAPHQL_ERROR", "yellow"),
        ("REVIEW", "yellow"),
        ("UNRESOLVED", "yellow"),
        ("FAILED", "red"),
        ("NETWORK_FAILURE", "red"),
        ("HTTP_ERROR", "red"),
        ("INVALID_RESPONSE", "red"),
        ("GENERATION_FAILED", "red"),
        ("BLOCKED_SAFETY", "magenta"),
        ("SKIPPED_SAFETY", "magenta"),
    ],
)
def test_status_labels_and_compound_cells_share_palette(value, color):
    label = status_text(value)
    cell = style_status_terms("Result: " + value + "; 1")
    assert label.plain == value and cell.plain == "Result: " + value + "; 1"
    assert Style.parse(label.style).color.name == color
    assert Style.parse(cell.spans[0].style).color.name == color
    assert _status(value.lower()).style == label.style


@pytest.mark.parametrize(
    "value", ["NOT_RUN", "NOT_SELECTED", "NOT_ATTEMPTED", "DECLINED", "SKIPPED_LIMIT"]
)
def test_unexecuted_states_are_dim_and_neutral(value):
    style = Style.parse(status_text(value).style)
    assert style.dim and style.color is None


def test_labels_preserve_case_spaces_and_unknown_values_without_markup():
    assert status_text("graphql_error").plain == "graphql_error"
    assert status_text("BLOCKED SAFETY").style == status_text("BLOCKED_SAFETY").style
    value = "[red]REVIEW[/red]; SUCCESSOR; NOT_SELECTED_EXTRA; success; UNKNOWN"
    text = style_status_terms(value)
    assert text.plain == value and len(text.spans) == 1
    assert text.plain[text.spans[0].start : text.spans[0].end] == "REVIEW"
    assert not status_text("UNKNOWN").style


@pytest.mark.parametrize("mode", ["color", "no_color", "plain", "non_tty"])
def test_rich_color_controls_preserve_identical_normalized_text(monkeypatch, mode):
    monkeypatch.delenv("NO_COLOR", raising=False)
    if mode == "no_color":
        monkeypatch.setenv("NO_COLOR", "1")
    stream = StringIO()
    options = (
        {"color_system": None}
        if mode == "plain"
        else ({"color_system": "standard"} if mode in {"color", "no_color"} else {})
    )
    console = Console(
        file=stream, force_terminal=mode != "non_tty", legacy_windows=False, **options
    )
    text = "SUCCESS; GRAPHQL_ERROR; FAILED; NOT_RUN; BLOCKED_SAFETY"
    console.print(style_status_terms(text))
    rendered = stream.getvalue()
    assert plain_cli_output(rendered).strip() == text
    if mode in {"plain", "non_tty"}:
        assert "\x1b[" not in rendered
    elif mode == "no_color":
        assert console.no_color
        assert all(
            Style.parse(span.style).color is None
            if isinstance(span.style, str)
            else span.style.color is None
            for span in Text.from_ansi(rendered).spans
        )
    else:
        assert any(span.style.color for span in Text.from_ansi(rendered).spans)
