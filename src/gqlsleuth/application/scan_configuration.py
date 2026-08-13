"""Map scan command inputs to the minimal Phase 1 application settings."""

from dataclasses import dataclass

from gqlsleuth.domain.models import ScanMode, Target


@dataclass(frozen=True)
class ApplicationSettings:
    """Settings accepted directly by the Phase 1 CLI."""

    mode: ScanMode = ScanMode.SAFE


def map_scan_inputs(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
) -> tuple[Target, ApplicationSettings]:
    """Validate a target and map the selected mode to application settings."""
    return Target.parse(target_url), ApplicationSettings(mode=mode)
