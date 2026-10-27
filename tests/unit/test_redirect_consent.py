"""Offline pre-transport consent, request-context forwarding and worker coordination."""

from threading import Barrier, current_thread, main_thread

import httpx
import pytest

from gqlsleuth.application.endpoint_discovery import probe_endpoint_candidates
from gqlsleuth.domain.exceptions import HttpRedirectDeniedError, HttpRedirectError
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest
from gqlsleuth.infrastructure.redirect_consent import HttpOrigin, RedirectConsent

SOURCE = "https://example.com/graphql"
DESTINATION = "https://api.example.com/graphql"
HEADERS = (
    ("Authorization", "Bearer AUTH_REDIRECT_CANARY"),
    ("X-API-Key", "KEY_REDIRECT_CANARY"),
    ("Cookie", "session=COOKIE_REDIRECT_CANARY"),
    ("X-Tenant", "TENANT_REDIRECT_CANARY"),
)
BODY = {
    "query": "mutation ($input: String!) { create(input: $input) }",
    "variables": {"input": "x"},
}


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("approve", [True, False, None])
def test_gate_precedes_transport_and_preserves_httpx_semantics(code, approve):
    seen, notices = [], []

    def confirm(notice):
        assert len(seen) == 1
        assert current_thread() is main_thread()
        notices.append(notice)
        return approve

    def handler(request):
        seen.append(request)
        if request.url.host == "example.com":
            return httpx.Response(code, headers={"Location": DESTINATION})
        return httpx.Response(200, json={"data": None})

    consent = RedirectConsent(confirm if approve is not None else None)
    settings = HttpClientSettings(custom_headers=HEADERS, redirect_consent=consent)
    with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
        request = HttpRequest(method="POST", url=SOURCE, json_body=BODY)
        if approve:
            response = client.send(request)
            assert response.redirect_count == 1
            assert response.final_url == DESTINATION
        else:
            with pytest.raises(HttpRedirectDeniedError, match="blocked locally"):
                client.send(request)
    assert len(seen) == (2 if approve else 1)
    assert len(notices) == (0 if approve is None else 1)
    if approve:
        for name, value in HEADERS:
            assert seen[1].headers[name] == value
        assert seen[1].method == ("POST" if code in (307, 308) else "GET")
        assert seen[1].content == (seen[0].content if code in (307, 308) else b"")
        assert seen[1].headers["host"] == "api.example.com"
        assert ("content-length" in seen[1].headers) is (code in (307, 308))
        assert seen[1].extensions["timeout"] == seen[0].extensions["timeout"]
    assert "REDIRECT_CANARY" not in repr(notices)
    assert "redirect_consent" not in settings.model_dump_json()


@pytest.mark.parametrize(
    "destination,asks",
    [
        ("https://EXAMPLE.com:443/next", False),
        ("https://example.com/next", False),
        ("https://api.example.com/next", True),
        ("https://example.com:8443/next", True),
        ("https://example.com:0/next", True),
        ("http://example.com/next", True),
        ("https://unrelated.example/next", True),
    ],
)
def test_exact_origin_scope_and_return_to_original(destination, asks):
    notices, seen = [], []

    def handler(request):
        seen.append(request)
        if request.url.path == "/graphql":
            return httpx.Response(307, headers={"Location": destination})
        if request.url.path == "/next":
            return httpx.Response(307, headers={"Location": "https://example.com/final"})
        return httpx.Response(200)

    settings = HttpClientSettings(
        custom_headers=HEADERS,
        redirect_consent=RedirectConsent(lambda notice: notices.append(notice) or True),
    )
    with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
        client.send(HttpRequest(method="POST", url=SOURCE, json_body=BODY))
    assert len(notices) == int(asks)
    assert len(seen) == 3
    assert all(request.headers["authorization"] == HEADERS[0][1] for request in seen)


def test_upgrade_and_distinct_hops_need_separate_approval_then_cache():
    seen, notices = [], []
    urls = ["http://example.com/start", SOURCE, DESTINATION, "https://api.example.com:8443/end"]

    def handler(request):
        seen.append(str(request.url))
        index = urls.index(str(request.url))
        if index < len(urls) - 1:
            return httpx.Response(307, headers={"Location": urls[index + 1]})
        return httpx.Response(200)

    consent = RedirectConsent(lambda notice: notices.append(notice) or True)
    with HttpClient(
        HttpClientSettings(redirect_consent=consent), transport=httpx.MockTransport(handler)
    ) as client:
        for _ in range(2):
            client.send(HttpRequest(method="GET", url=urls[0]))
    assert len(notices) == 3
    assert seen == urls * 2
    assert notices[0].source.scheme == "http" and notices[0].destination.scheme == "https"


@pytest.mark.parametrize("approve", [True, False])
def test_decisions_shared_across_clients_but_reset_between_scans(approve):
    notices, seen = [], []

    def handler(request):
        seen.append(request)
        if request.url.host == "example.com":
            return httpx.Response(307, headers={"Location": DESTINATION})
        return httpx.Response(200)

    for _ in range(2):
        consent = RedirectConsent(lambda n: notices.append(n) or approve)
        for secret in ("CONTEXT_A_CANARY", "CONTEXT_B_CANARY"):
            with HttpClient(
                HttpClientSettings(custom_headers=(("X-Key", secret),), redirect_consent=consent),
                transport=httpx.MockTransport(handler),
            ) as client:
                if approve:
                    client.send(HttpRequest(method="GET", url=SOURCE))
                    assert seen[-1].headers["x-key"] == secret
                else:
                    with pytest.raises(HttpRedirectDeniedError):
                        client.send(HttpRequest(method="GET", url=SOURCE))
    assert len(notices) == 2
    assert len(seen) == (8 if approve else 4)


@pytest.mark.parametrize("approve", [True, False])
@pytest.mark.parametrize(
    "destination,cookie,eligible",
    [
        (DESTINATION, "session=LEARNED_CANARY; Domain=example.com; Path=/", True),
        ("https://example.com:8443/graphql", "session=LEARNED_CANARY; Path=/", True),
        ("http://example.com/graphql", "session=LEARNED_CANARY; Path=/", True),
        ("http://example.com/graphql", "session=LEARNED_CANARY; Path=/; Secure", False),
        (DESTINATION, "session=LEARNED_CANARY; Domain=example.com; Path=/private", False),
        ("https://unrelated.example/graphql", "session=LEARNED_CANARY; Path=/", False),
    ],
)
def test_learned_cookies_without_configured_headers_require_consent(
    approve, destination, cookie, eligible
):
    seen, notices = [], []

    def handler(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(307, headers={"Location": destination, "Set-Cookie": cookie})
        return httpx.Response(200)

    with HttpClient(
        HttpClientSettings(
            redirect_consent=RedirectConsent(lambda n: notices.append(n) or approve)
        ),
        transport=httpx.MockTransport(handler),
    ) as client:
        if approve:
            client.send(HttpRequest(method="GET", url=SOURCE))
        else:
            with pytest.raises(HttpRedirectDeniedError):
                client.send(HttpRequest(method="GET", url=SOURCE))
    assert len(seen) == (2 if approve else 1)
    assert len(notices) == 1
    assert notices[0].has_cookies is eligible
    if approve:
        assert ("LEARNED_CANARY" in seen[-1].headers.get("cookie", "")) is eligible


def test_explicit_cookie_wins_over_jar_without_duplicates_and_jar_is_not_shared():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.host == "example.com":
            return httpx.Response(
                307,
                headers={"Location": DESTINATION, "Set-Cookie": "x=JAR_CANARY; Domain=example.com"},
            )
        return httpx.Response(200)

    consent = RedirectConsent(lambda _: True)
    for headers in (HEADERS, ()):
        with HttpClient(
            HttpClientSettings(custom_headers=headers, redirect_consent=consent),
            transport=httpx.MockTransport(handler),
        ) as client:
            client.send(HttpRequest(method="GET", url=SOURCE if headers else DESTINATION))
    assert seen[1].headers.get_list("cookie") == [HEADERS[2][1]]
    assert "cookie" not in seen[2].headers


@pytest.mark.parametrize("answer", [True, False, "cancel"])
@pytest.mark.parametrize("unique_origins", [False, True])
def test_concurrent_discovery_single_main_thread_prompts_no_deadlock(answer, unique_origins):
    barrier = Barrier(4, timeout=5)
    seen, notices = [], []
    urls = tuple(f"https://example.com/path{i}" for i in range(4))

    def handler(request):
        seen.append(str(request.url))
        if request.url.host == "example.com":
            barrier.wait()
            host = request.url.path[1:] if unique_origins else "api"
            return httpx.Response(307, headers={"Location": f"https://{host}.example.com/graphql"})
        return httpx.Response(200)

    def confirm(notice):
        assert current_thread() is main_thread()
        assert str(notice.destination) + "/graphql" not in seen
        notices.append(notice)
        if answer == "cancel":
            raise KeyboardInterrupt
        return answer

    consent = RedirectConsent(confirm)
    with HttpClient(
        HttpClientSettings(redirect_consent=consent), transport=httpx.MockTransport(handler)
    ) as client:

        def probe():
            return probe_endpoint_candidates(
                Target.parse(SOURCE), mode=ScanMode.SAFE, client=client, candidate_urls=urls
            )

        if answer == "cancel":
            with pytest.raises(KeyboardInterrupt):
                probe()
            with pytest.raises(KeyboardInterrupt):
                client.send(HttpRequest(method="GET", url=SOURCE))
        else:
            results = probe()
            assert tuple(item.candidate_url for item in results.probes) == urls
            assert all((item.response is not None) is answer for item in results.probes)
            if not answer:
                assert all(item.error_type == "HttpRedirectDeniedError" for item in results.probes)
    assert len(seen) == (8 if answer is True else 4)
    assert len(notices) == (4 if unique_origins and answer != "cancel" else 1)


def test_approved_redirects_still_enforce_existing_limit():
    seen = []
    consent = RedirectConsent(lambda _: True)

    def handler(request):
        seen.append(request)
        return httpx.Response(307, headers={"Location": DESTINATION})

    with (
        HttpClient(
            HttpClientSettings(redirect_consent=consent), transport=httpx.MockTransport(handler)
        ) as client,
        pytest.raises(HttpRedirectError, match="redirect limit"),
    ):
        client.send(HttpRequest(method="GET", url=SOURCE))
    assert len(seen) == 6


def test_origin_normalization_excludes_private_url_material():
    origin = HttpOrigin.from_url(
        httpx.URL("https://user:SECRET@EXAMPLE.com:443/path?token=PRIVATE")
    )
    assert str(origin) == "https://example.com"
    assert HttpOrigin.from_url(httpx.URL("https://[::1]")) == HttpOrigin.from_url(
        httpx.URL("https://[0:0:0:0:0:0:0:1]:443")
    )


def test_denied_later_hop_is_not_authorized_by_prior_approval():
    seen, notices = [], []

    def handler(request):
        seen.append(str(request.url))
        destination = DESTINATION if request.url.host == "example.com" else "https://third.example/"
        return httpx.Response(308, headers={"Location": destination})

    def confirm(notice):
        notices.append(notice)
        return notice.destination.host == "api.example.com"

    with (
        HttpClient(
            HttpClientSettings(custom_headers=HEADERS, redirect_consent=RedirectConsent(confirm)),
            transport=httpx.MockTransport(handler),
        ) as client,
        pytest.raises(HttpRedirectDeniedError),
    ):
        client.send(HttpRequest(method="POST", url=SOURCE, json_body=BODY))
    assert seen == [SOURCE, DESTINATION]
    assert len(notices) == 2
    assert notices[1].source == notices[0].destination


def test_no_follow_does_not_ask_or_forward_and_same_origin_cookies_still_work():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/graphql":
            return httpx.Response(
                302, headers={"Location": "/next", "Set-Cookie": "session=SAME_ORIGIN; Path=/"}
            )
        return httpx.Response(200)

    def unexpected(_):
        pytest.fail("Same-origin redirects must not prompt")

    for follow in (False, True):
        with HttpClient(
            HttpClientSettings(
                follow_redirects=follow, redirect_consent=RedirectConsent(unexpected)
            ),
            transport=httpx.MockTransport(handler),
        ) as client:
            response = client.send(HttpRequest(method="GET", url=SOURCE))
            assert response.redirect_count == int(follow)
    assert len(seen) == 3
    assert seen[-1].headers["cookie"] == "session=SAME_ORIGIN"
