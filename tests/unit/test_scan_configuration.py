"""Tests for the minimal CLI-to-application configuration mapping."""

import pytest

from gqlsleuth.application.scan_configuration import map_scan_inputs
from gqlsleuth.domain.models import ScanMode


@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
def test_scan_configuration_maps_target_and_mode(mode: ScanMode) -> None:
    target, settings = map_scan_inputs(
        "https://Example.COM/graphql?operation=test",
        mode=mode,
    )

    assert target.host == "Example.COM"
    assert target.path == "/graphql"
    assert target.query == "operation=test"
    assert settings.mode is mode
