"""Explicit credential capture boundary for controlled probes; no body rewriting/redaction."""

import json
from urllib.parse import unquote, urlsplit

from gqlsleuth.infrastructure.http import HttpClientSettings, HttpResponse


def same_origin(left: str, right: str) -> bool:
    def origin(url: str) -> tuple[str, str | None, int | None]:
        parsed = urlsplit(url)
        return (
            parsed.scheme,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )

    return origin(left) == origin(right)


def request_context_material(settings: HttpClientSettings) -> tuple[str, ...]:
    """Transient values only; callers must not store this tuple in public results."""
    values = [value for _, value in settings.custom_headers if value]
    for name, value in settings.custom_headers:
        if name.lower() == "cookie":
            values.extend(
                part.partition("=")[2].strip() for part in value.split(";") if "=" in part
            )
        elif name.lower() == "authorization":
            parts = value.split(None, 1)
            if len(parts) == 2:
                values.append(parts[1])
    if settings.proxy:
        proxy = urlsplit(settings.proxy)
        values.extend(
            (settings.proxy, unquote(proxy.username or ""), unquote(proxy.password or ""))
        )
    return tuple(value for value in values if value)


def contains_request_material(text: str, material: tuple[str, ...]) -> bool:
    return any(
        value in text or json.dumps(value, ensure_ascii=True)[1:-1] in text for value in material
    )


def capture_probe_response(
    response: HttpResponse | None,
    material: tuple[str, ...],
    *,
    additional_headers: tuple[str, ...] = (),
) -> tuple[dict[str, str] | None, bytes | None, bool]:
    """Keep original bounded bytes or withhold them entirely if request secrets were echoed."""
    if response is None:
        return None, None, False
    allowed = {
        "content-type",
        "content-length",
        "date",
        "server",
        "retry-after",
        *additional_headers,
    }
    headers = {
        name: value
        for name, value in response.headers.items()
        if name.lower() in allowed and not contains_request_material(value, material)
    }
    withheld = contains_request_material(response.body.decode("utf-8", errors="replace"), material)
    return headers, None if withheld else response.body, withheld
