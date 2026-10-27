"""Per-scan redirect decisions; discovery workers wait, only the main thread asks."""

from collections.abc import Callable
from concurrent.futures import Future
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import ip_address
from threading import Condition, current_thread, main_thread

import httpx

from gqlsleuth.domain.exceptions import HttpRedirectDeniedError


@dataclass(frozen=True)
class HttpOrigin:
    scheme: str
    host: str
    port: int | None

    @classmethod
    def from_url(cls, url: httpx.URL) -> "HttpOrigin":
        host = url.raw_host.decode("ascii").lower()
        with suppress(ValueError):
            host = str(ip_address(host))
        port = url.port if url.port is not None else {"http": 80, "https": 443}.get(url.scheme)
        return cls(url.scheme.lower(), host, port)

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = "" if self.port == {"http": 80, "https": 443}.get(self.scheme) else f":{self.port}"
        return f"{self.scheme}://{host}{port}"


@dataclass(frozen=True)
class RedirectNotice:
    """Only safe origin/boolean metadata, never header values, paths or request bodies."""

    source: HttpOrigin
    destination: HttpOrigin
    has_configured_headers: bool
    has_cookies: bool


class RedirectConsent:
    """Runtime-only decisions, discarded after the logical scan.

    Pending notices are bounded by the existing discovery worker count (four).
    No additional executor or polling is used. Call wait_for on the main thread
    instead of Future.result when those workers may need interactive consent.
    A missing confirmation callback means unattended/default-deny operation.
    """

    def __init__(self, confirm: Callable[[RedirectNotice], bool] | None = None) -> None:
        self._confirm = confirm
        self._condition = Condition()
        self._decisions: dict[HttpOrigin, bool] = {}
        self._pending: dict[HttpOrigin, RedirectNotice] = {}
        self._cancelled = False

    def check_cancelled(self) -> None:
        with self._condition:
            if self._cancelled:
                raise KeyboardInterrupt

    def cancel(self) -> None:
        """Release all waiting workers before executor shutdown, without sending."""
        with self._condition:
            self._cancelled = True
            self._pending.clear()
            self._condition.notify_all()

    def authorize(self, notice: RedirectNotice) -> None:
        destination = notice.destination
        with self._condition:
            self.check_cancelled()
            if destination not in self._decisions:
                if self._confirm is None:
                    self._decisions[destination] = False
                elif current_thread() is not main_thread():
                    self._pending.setdefault(destination, notice)
                    self._condition.notify_all()
                    self._condition.wait_for(
                        lambda: self._cancelled or destination in self._decisions
                    )
                    self.check_cancelled()
            decided = destination in self._decisions
        if not decided:
            self._decide(notice)
        with self._condition:
            self.check_cancelled()
            if not self._decisions[destination]:
                raise HttpRedirectDeniedError(
                    "Cross-origin redirect blocked locally: destination not approved. "
                    "No redirected request was sent to that origin."
                )

    def _decide(self, notice: RedirectNotice) -> None:
        assert current_thread() is main_thread()
        completed = False
        try:
            allowed = self._confirm is not None and self._confirm(notice) is True
            with self._condition:
                self.check_cancelled()
                self._decisions[notice.destination] = allowed
                self._pending.pop(notice.destination, None)
                self._condition.notify_all()
            completed = True
        finally:
            if not completed:
                self.cancel()

    def wait_for[T](self, future: Future[T]) -> T:
        """Wait for an ordered discovery result while servicing any worker's notice."""
        assert current_thread() is main_thread()

        def wake(_: Future[T]) -> None:
            with self._condition:
                self._condition.notify_all()

        future.add_done_callback(wake)
        while True:
            with self._condition:
                self._condition.wait_for(
                    lambda: self._cancelled or future.done() or bool(self._pending)
                )
                self.check_cancelled()
                if future.done():
                    return future.result()
                notice = next(iter(self._pending.values()))
            self._decide(notice)
