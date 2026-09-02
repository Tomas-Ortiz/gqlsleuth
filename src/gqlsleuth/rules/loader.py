"""Load and validate Phase 7 YAML rules from package resources or a local path."""

from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError

from gqlsleuth.domain.analysis import RuleSet
from gqlsleuth.domain.exceptions import RuleConfigurationError

RULES_PACKAGE = "gqlsleuth.rules"
DEFAULT_RULES_RESOURCE = "default_rules.yaml"


def load_bundled_rules() -> RuleSet:
    """Load the bundled rule set without depending on the working directory."""
    try:
        text = files(RULES_PACKAGE).joinpath(DEFAULT_RULES_RESOURCE).read_text(encoding="utf-8")
    except (OSError, TypeError) as error:
        raise RuleConfigurationError(f"Could not read bundled operation rules: {error}") from None
    return _parse_rules(text, source="bundled operation rules")


def load_rules(path: str | Path) -> RuleSet:
    """Load a rule set from an explicitly supplied local YAML file."""
    rule_path = Path(path)
    try:
        text = rule_path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuleConfigurationError(
            f"Could not read operation rules from {rule_path}: {error}"
        ) from None
    return _parse_rules(text, source=str(rule_path))


def _parse_rules(text: str, *, source: str) -> RuleSet:
    try:
        raw_rules = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise RuleConfigurationError(f"Invalid YAML in {source}: {error}") from None
    if raw_rules is None:
        raise RuleConfigurationError(f"Invalid operation rules in {source}: document is empty")
    try:
        return RuleSet.model_validate(raw_rules)
    except ValidationError as error:
        raise RuleConfigurationError(f"Invalid operation rules in {source}: {error}") from None
