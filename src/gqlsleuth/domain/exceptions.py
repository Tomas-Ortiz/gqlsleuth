"""Project-specific exceptions available through Phase 2."""


class GQLSleuthError(Exception):
    """Base class for expected GQLSleuth failures."""


class TargetError(GQLSleuthError):
    """Base class for invalid target input."""


class InvalidUrlError(TargetError):
    """Raised when a target is not a structurally valid URL."""


class UnsupportedSchemeError(TargetError):
    """Raised when a target uses a scheme other than HTTP or HTTPS."""


class HttpError(GQLSleuthError):
    """Base class for normalized HTTP-layer failures."""


class HttpTimeoutError(HttpError):
    """Raised when an HTTP operation exceeds its configured timeout."""


class HttpProxyError(HttpError):
    """Raised when HTTPX reports a proxy-specific failure."""


class HttpRedirectError(HttpError):
    """Raised when HTTP redirect handling cannot complete."""


class ResponseTooLargeError(HttpError):
    """Raised when a streamed response exceeds the configured body limit."""


class HttpTransportError(HttpError):
    """Raised for other HTTPX request or transport failures."""
