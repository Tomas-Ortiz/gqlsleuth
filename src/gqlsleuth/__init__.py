"""GQLSleuth package metadata."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("gqlsleuth")
except PackageNotFoundError:
    # Source-only imports are usable, but must not pretend to be an installed release.
    __version__ = "0+unknown"
