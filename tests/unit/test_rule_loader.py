"""Tests for package-safe Phase 7 YAML rule loading and validation."""

from pathlib import Path

import pytest

from gqlsleuth.domain.analysis import OperationCategory, RuleSurface
from gqlsleuth.domain.exceptions import RuleConfigurationError
from gqlsleuth.rules.loader import load_bundled_rules, load_rules


def test_bundled_rules_load_with_expected_thresholds() -> None:
    rules = load_bundled_rules()

    assert rules.thresholds.model_dump() == {"critical": 8, "high": 5, "medium": 3, "low": 1}
    assert rules.rules[0].category is OperationCategory.AUTHENTICATION
    assert rules.rules[0].surfaces == (RuleSurface.PRIMARY, RuleSurface.INPUT)
    assert len(rules.rules) >= 10


def test_explicit_local_rule_file_is_supported(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(
        """
thresholds: {critical: 8, high: 5, medium: 3, low: 1}
rules:
  - id: test_rule
    category: debugging
    keywords: [debug]
    surfaces: [primary, input]
    weight: 3
    reason: Debug terminology.
""".strip(),
        encoding="utf-8",
    )

    rules = load_rules(path)

    assert rules.rules[0].id == "test_rule"


@pytest.mark.parametrize(
    "contents",
    (
        "rules: [",
        "thresholds: {critical: 3, high: 5, medium: 2, low: 1}\nrules: []",
        "thresholds: {critical: 8, high: 5, medium: 3, low: 1}\nunknown: true",
    ),
)
def test_invalid_yaml_or_rule_configuration_fails_clearly(
    tmp_path: Path,
    contents: str,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(RuleConfigurationError, match="Invalid"):
        load_rules(path)


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text(
        """
thresholds: {critical: 8, high: 5, medium: 3, low: 1}
rules:
  - id: duplicate
    category: search
    keywords: [search]
    surfaces: [primary]
    weight: 1
    reason: Search.
  - id: duplicate
    category: reporting
    keywords: [report]
    surfaces: [primary]
    weight: 2
    reason: Report.
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(RuleConfigurationError, match="rule IDs must be unique"):
        load_rules(path)


def test_bundled_rule_loading_is_independent_of_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    rules = load_bundled_rules()

    assert rules.rules
