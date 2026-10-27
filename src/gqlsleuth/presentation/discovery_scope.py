"""Human discovery disclosure derived solely from retained candidate evidence."""

from urllib.parse import urlsplit

from gqlsleuth.discovery.endpoint_candidates import normalize_discovery_url
from gqlsleuth.domain.exceptions import InvalidUrlError
from gqlsleuth.domain.models import Evidence, EvidenceType, Target
from gqlsleuth.presentation.limits import MAX_HUMAN_DETAIL_ITEMS, showing_notice


def _origin(url: str) -> tuple[str, str | None, int]:
    parsed = urlsplit(url)
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname, port


def discovery_scope_notes(target: Target, evidence: tuple[Evidence, ...]) -> tuple[str, ...]:
    """Describe actual expansion, not the full list of potentially generated candidates.

    Candidate URLs establish where discovery started requests, not where redirects ended.
    Normalization matches discovery, including default ports and trailing path slashes.
    """
    try:
        supplied = normalize_discovery_url(target.original_url)
    except InvalidUrlError:
        # Human renderers still display/escape unparseable supplied text; do not infer scope.
        return ()
    candidates = []
    for item in evidence:
        if item.evidence_type is not EvidenceType.ENDPOINT_CANDIDATE or not item.endpoint:
            continue
        try:
            candidate = normalize_discovery_url(item.endpoint)
        except InvalidUrlError:
            continue  # Keep the original evidence visible, without assigning it an origin.
        if candidate != supplied and _origin(candidate) == _origin(supplied):
            candidates.append(item.endpoint)
    additional = tuple(dict.fromkeys(candidates))
    if not additional:
        return ()
    notice = (
        "The supplied target was the origin root. Discovery checked common GraphQL paths "
        "on the same origin; the root itself was not probed."
        if not target.path.rstrip("/")
        else f"Discovery expanded beyond the supplied path {target.path} to additional "
        "GraphQL candidates on the same origin."
    )
    paths = []
    for url in additional[:MAX_HUMAN_DETAIL_ITEMS]:
        parsed = urlsplit(url)
        paths.append((parsed.path or "/") + ("?" + parsed.query if parsed.query else ""))
    scope = "Additional same-origin paths checked: " + ", ".join(paths) + "."
    if len(additional) > MAX_HUMAN_DETAIL_ITEMS:
        scope += " " + showing_notice(
            MAX_HUMAN_DETAIL_ITEMS, len(additional), "additional discovery candidates"
        )
    return (
        notice,
        scope,
        "Same origin means the supplied scheme, host and effective port. This describes "
        "candidate URLs; same-origin redirects are followed automatically. Redirects may lead "
        "to another origin only after explicit consent to destination and credential forwarding.",
    )
