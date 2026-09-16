"""Map CLI inputs to scan mode and immutable target HTTP settings."""

from dataclasses import dataclass
from math import isfinite

from pydantic import ValidationError

from gqlsleuth.domain.differential import NamedAuthContext, validate_context_names
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.infrastructure.http import (
    DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    HttpClientSettings,
    validate_target_header,
)


def map_target_http_inputs(
    *,
    headers: list[str] | None = None,
    timeout: str | None = None,
    verify_tls: bool = True,
    proxy: str | None = None,
) -> HttpClientSettings:
    """Map CLI-only inputs once; errors identify arguments without echoing their values."""
    parsed_headers = []
    for index, entry in enumerate(headers or (), start=1):
        try:
            if "\r" in entry or "\n" in entry:
                raise ValueError("CR/LF characters are not allowed.")
            name, separator, value = entry.partition(":")
            if not separator:
                raise ValueError("Expected NAME: VALUE.")
            parsed_headers.append(validate_target_header(name.strip(" \t"), value))
        except ValueError as error:
            raise HttpConfigurationError(f"Header argument {index}: {error}") from None
    seconds = DEFAULT_TIMEOUT_SECONDS
    discovery_seconds = DEFAULT_DISCOVERY_TIMEOUT_SECONDS
    if timeout is not None:
        try:
            seconds = float(timeout)
            if not isfinite(seconds) or seconds <= 0:
                raise ValueError
        except ValueError:
            raise HttpConfigurationError(
                "--timeout must be a finite positive number of seconds."
            ) from None
        discovery_seconds = seconds
    try:
        return HttpClientSettings(
            custom_headers=tuple(parsed_headers),
            verify_tls=verify_tls,
            proxy=proxy,
            timeout_seconds=seconds,
            discovery_timeout_seconds=discovery_seconds,
        )
    except ValidationError:
        raise HttpConfigurationError(
            "--proxy must be a valid HTTP(S) proxy URL with a host and optional port."
        ) from None


def map_auth_context_inputs(
    entries: list[str],
    *,
    headers: list[str] | None = None,
    mode: ScanMode = ScanMode.SAFE,
    ai: bool = False,
    object_review: bool = False,
) -> tuple[NamedAuthContext, ...]:
    """Accumulate first-seen labels, reusing Phase 14 header syntax and validation."""
    if headers:
        raise HttpConfigurationError("--auth-context cannot be combined with --header / -H.")
    if mode is not ScanMode.SAFE:
        raise HttpConfigurationError("--auth-context supports SAFE mode only.")
    if ai:
        raise HttpConfigurationError(
            "Differential AI interpretation is not implemented; omit --ai."
        )
    grouped: dict[str, list[str]] = {}
    for entry in entries:
        name, separator, header = entry.partition("=")
        validate_context_names((name,), check_count=False)
        grouped.setdefault(name, [])
        if separator:
            grouped[name].append(header)
    single_bare = object_review is True and len(grouped) == 1 and not next(iter(grouped.values()))
    validate_context_names(tuple(grouped), check_count=not single_bare)
    return tuple(
        NamedAuthContext(name, map_target_http_inputs(headers=values).custom_headers)
        for name, values in grouped.items()
    )


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
