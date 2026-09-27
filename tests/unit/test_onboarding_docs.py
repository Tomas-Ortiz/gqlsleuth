"""Small checks for public onboarding claims; not a general Markdown lint framework."""

import re
from pathlib import Path


def test_onboarding_and_privacy_contract():
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert readme.index("## Installation") < readme.index("## Quick Start")
    assert readme.index("## Quick Start") < readme.index("## Capability reference")
    for fact in ("SAFE is the default", "Python >=3.13", "qwen3:8b", "127.0.0.1:11434"):
        assert fact in readme
    assert "AI is optional" in readme
    assert "completed scan exits 0" in readme
    assert not re.search(r"\bPhase\s+\d+", readme)
    assert not re.search(r"pip install gqlsleuth(?:\s|$)", readme)
    for relative in ("SECURITY.md", "CHANGELOG.md", "docs/RELEASING.md", "examples/README.md"):
        assert f"]({relative})" in readme
        assert (root / relative).is_file()
    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
    assert "Do not introduce a generic redaction subsystem" in agents
    assert "Sensitive headers must be redacted" not in agents
    assert "silently sanitize canonical Evidence" in agents
