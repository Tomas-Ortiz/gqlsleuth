"""Central synchronous HTTPX adapter with conservative transport limits."""

from time import perf_counter
from types import TracebackType
from typing import Self

import httpx
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from gqlsleuth import __version__
from gqlsleuth.domain.exceptions import (
    HttpProxyError,
    HttpRedirectError,
    HttpTimeoutError,
    HttpTransportError,
    ResponseTooLargeError,
)

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024
DEFAULT_USER_AGENT = f"GQLSleuth/{__version__}"


class HttpClientSettings(BaseModel):
    """Conservative settings for the reusable synchronous HTTP client."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_seconds: float = Field(default=DEFAULT_TIMEOUT_SECONDS, gt=0, allow_inf_nan=False)
    verify_tls: bool = True
    follow_redirects: bool = True
    max_redirects: int = Field(default=DEFAULT_MAX_REDIRECTS, ge=0)
    max_response_body_bytes: int = Field(
        default=DEFAULT_MAX_RESPONSE_BODY_BYTES,
        gt=0,
    )
    proxy: str | None = None


class HttpRequest(BaseModel):
    """GQLSleuth-owned input for a single HTTP request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: JsonValue | None = None
    timeout_seconds: float | None = Field(default=None, gt=0, allow_inf_nan=False)


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
    """Reusable synchronous HTTP client shared by future application workflows."""

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
        )

    def send(self, request: HttpRequest) -> HttpResponse:
        """Send one request and stream its body up to the configured size limit."""
        started_at = perf_counter()
        timeout = request.timeout_seconds or self.settings.timeout_seconds
        try:
            with self._client.stream(
                request.method,
                request.url,
                headers=request.headers,
                json=request.json_body,
                timeout=timeout,
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
