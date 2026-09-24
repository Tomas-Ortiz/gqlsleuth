"""Central synchronous HTTPX adapter with conservative transport limits."""

import re
from dataclasses import dataclass, field
from time import perf_counter
from types import TracebackType
from typing import Self
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from gqlsleuth import __version__
from gqlsleuth.domain.exceptions import (
    HttpProxyError,
    HttpRedirectError,
    HttpTimeoutError,
    HttpTransportError,
    ResponseTooLargeError,
)

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_DISCOVERY_TIMEOUT_SECONDS = 8.0
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024
DEFAULT_USER_AGENT = f"GQLSleuth/{__version__}"
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_TRANSPORT_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    }
)


def validate_target_header(name: str, value: str) -> tuple[str, str]:
    """Validate without including potentially secret input in errors."""
    if not _HEADER_NAME.fullmatch(name):
        raise ValueError("Invalid HTTP header name.")
    if name.lower() in _TRANSPORT_HEADERS:
        raise ValueError("Transport-controlled headers cannot be supplied with --header.")
    if any((ord(char) < 32 and char != "\t") or ord(char) >= 127 for char in value):
        raise ValueError("Header values must be ASCII text without control characters.")
    return name, value.strip(" \t")


def _validate_proxy(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
        url = httpx.URL(value)
        valid = (
            not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
            and "\\" not in value
            and parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and bool(url.host)
            and (parsed.port is None or parsed.port > 0)
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )
    except (ValueError, httpx.InvalidURL):
        valid = False
    if not valid:
        raise ValueError("Proxy must be a valid HTTP(S) proxy URL with a host and optional port.")
    return value


class HttpClientSettings(BaseModel):
    """Conservative settings for the reusable synchronous HTTP client."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    timeout_seconds: float = Field(default=DEFAULT_TIMEOUT_SECONDS, gt=0, allow_inf_nan=False)
    discovery_timeout_seconds: float = Field(
        default=DEFAULT_DISCOVERY_TIMEOUT_SECONDS, gt=0, allow_inf_nan=False
    )
    custom_headers: tuple[tuple[str, str], ...] = Field(default=(), repr=False)
    verify_tls: bool = True
    follow_redirects: bool = True
    max_redirects: int = Field(default=DEFAULT_MAX_REDIRECTS, ge=0)
    max_response_body_bytes: int = Field(
        default=DEFAULT_MAX_RESPONSE_BODY_BYTES,
        gt=0,
    )
    proxy: str | None = Field(default=None, repr=False)

    @field_validator("custom_headers")
    @classmethod
    def validate_headers(cls, values: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        return tuple(validate_target_header(name, value) for name, value in values)

    @field_validator("proxy")
    @classmethod
    def validate_proxy(cls, value: str | None) -> str | None:
        return _validate_proxy(value)


@dataclass(repr=False)
class _RedirectHeaderScope:
    """Per-send state, isolated from concurrent discovery requests and other origins."""

    origin: tuple[str, str, int | None]
    names: frozenset[str]
    cookies: tuple[tuple[str, str], ...]
    crossed_origin: bool = False


def _restrict_redirect_headers(request: httpx.Request) -> None:
    scope = request.extensions.get("gqlsleuth_header_scope")
    if not isinstance(scope, _RedirectHeaderScope):
        return
    origin = (request.url.scheme, request.url.host, request.url.port)
    if origin != scope.origin:
        scope.crossed_origin = True
    if scope.crossed_origin:
        for name in scope.names | {"authorization", "cookie", "proxy-authorization"}:
            request.headers.pop(name, None)
    elif scope.cookies and tuple(request.headers.get_list("cookie")) != tuple(
        value for _, value in scope.cookies
    ):
        # HTTPX removes an explicit Cookie header on redirects, even on the same origin.
        request.headers.pop("cookie", None)
        request.headers = httpx.Headers([*request.headers.multi_items(), *scope.cookies])


@dataclass(frozen=True)
class SingleFileMultipart:
    """Runtime-only one-file body. HTTPX owns multipart framing and boundary selection."""

    fields: dict[str, str]
    filename: str
    content_type: str
    content: bytes = field(repr=False)


class HttpRequest(BaseModel):
    """GQLSleuth-owned input for a single HTTP request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: JsonValue | None = None
    multipart: SingleFileMultipart | None = Field(default=None, repr=False, exclude=True)
    timeout_seconds: float | None = Field(default=None, gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def one_body(self) -> Self:
        if self.multipart is not None and (self.json_body is not None or self.method != "POST"):
            raise ValueError("Multipart requires POST and no JSON body.")
        return self


class HttpResponse(BaseModel):
    """Useful transport information preserved from an HTTP response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    duration_seconds: float = Field(ge=0)
    redirect_count: int = Field(ge=0)


class HttpClient:
    """Reusable synchronous target HTTP client shared by application workflows."""

    def __init__(
        self,
        settings: HttpClientSettings | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings or HttpClientSettings()
        self._client = httpx.Client(
            timeout=self.settings.timeout_seconds,
            verify=self.settings.verify_tls,
            follow_redirects=self.settings.follow_redirects,
            max_redirects=self.settings.max_redirects,
            proxy=self.settings.proxy,
            trust_env=False,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            transport=transport,
            event_hooks={"request": [_restrict_redirect_headers]},
        )

    def send(self, request: HttpRequest) -> HttpResponse:
        """Send one request and stream its body up to the configured size limit."""
        started_at = perf_counter()
        timeout = request.timeout_seconds or self.settings.timeout_seconds
        headers = self._request_headers(request)
        url = httpx.URL(request.url)
        scope = (
            _RedirectHeaderScope(
                (url.scheme, url.host, url.port),
                frozenset(name.lower() for name, _ in headers),
                tuple((name, value) for name, value in headers if name.lower() == "cookie"),
            )
            if headers
            else None
        )
        try:
            with self._client.stream(
                request.method,
                request.url,
                headers=headers,
                json=request.json_body,
                data=request.multipart.fields if request.multipart else None,
                files={
                    "0": (
                        request.multipart.filename,
                        request.multipart.content,
                        request.multipart.content_type,
                    )
                }
                if request.multipart
                else None,
                timeout=timeout,
                extensions={"gqlsleuth_header_scope": scope},
            ) as response:
                body = self._read_limited_body(response)
                return HttpResponse(
                    request_url=request.url,
                    final_url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=body,
                    duration_seconds=perf_counter() - started_at,
                    redirect_count=len(response.history),
                )
        except ResponseTooLargeError:
            raise
        except httpx.TimeoutException as error:
            raise HttpTimeoutError("HTTP request timed out.") from error
        except httpx.ProxyError as error:
            raise HttpProxyError("HTTP proxy request failed.") from error
        except httpx.TooManyRedirects as error:
            raise HttpRedirectError("HTTP request exceeded the redirect limit.") from error
        except httpx.RequestError as error:
            raise HttpTransportError("HTTP transport request failed.") from error

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()

    def _request_headers(self, request: HttpRequest) -> list[tuple[str, str]]:
        """Keep repeated custom fields; scanner fields and body framing take precedence."""
        owned = {name.lower() for name in request.headers}
        if request.json_body is not None or request.multipart is not None:
            owned.add("content-type")
        headers = [
            (name, value)
            for name, value in self.settings.custom_headers
            if name.lower() not in owned
        ]
        headers.extend(
            (name, value)
            for name, value in request.headers.items()
            if (request.json_body is None and request.multipart is None)
            or name.lower() != "content-type"
        )
        # HTTPX supplies JSON/multipart Content-Type and computes Content-Length itself.
        return headers

    def __enter__(self) -> Self:
        self._client.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._client.__exit__(exc_type, exc_value, traceback)

    def _read_limited_body(self, response: httpx.Response) -> bytes:
        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > self.settings.max_response_body_bytes:
                raise ResponseTooLargeError(
                    "HTTP response body exceeded the configured "
                    f"{self.settings.max_response_body_bytes}-byte limit."
                )
            body.extend(chunk)
        return bytes(body)
