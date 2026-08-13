"""Project-specific exceptions available during Phase 1."""


class GQLSleuthError(Exception):
    """Base class for expected GQLSleuth failures."""


class TargetError(GQLSleuthError):
    """Base class for invalid target input."""


class InvalidUrlError(TargetError):
    """Raised when a target is not a structurally valid URL."""


class UnsupportedSchemeError(TargetError):
    """Raised when a target uses a scheme other than HTTP or HTTPS."""
