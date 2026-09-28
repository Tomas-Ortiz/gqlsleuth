"""Plain text for semantic CLI assertions; rendering tests keep their original output."""

from rich.text import Text


def plain_cli_output(output: str, *, normalize_whitespace: bool = False) -> str:
    text = Text.from_ansi(output).plain
    return " ".join(text.split()) if normalize_whitespace else text
