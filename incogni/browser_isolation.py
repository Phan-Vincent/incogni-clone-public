"""Fresh-context browser execution boundary for broker operations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import urlparse

from incogni.adapters.guarded import safety_flags
from incogni.adapters.service import GuardrailPause


class BrowserLike(Protocol):
    def new_context(self, **kwargs: Any) -> Any: ...

    def close(self) -> None: ...


class FreshContextBrowser:
    """Runs one bounded operation in a new browser and context every time."""

    def __init__(self, launcher: Callable[[], BrowserLike]):
        self.launcher = launcher

    def run(
        self,
        target_url: str,
        *,
        allowed_hosts: set[str],
        operation: Callable[[Any], Any],
    ) -> Any:
        normalized_hosts = {
            item.rstrip(".").lower().encode("idna").decode("ascii")
            for item in allowed_hosts
        }

        def request_host(url: str) -> str:
            host = (urlparse(url).hostname or "").rstrip(".").lower()
            try:
                return host.encode("idna").decode("ascii")
            except UnicodeError:
                return ""

        host = request_host(target_url)
        if not host or host not in normalized_hosts:
            raise GuardrailPause("unexpected_target_host")
        browser = self.launcher()
        context = browser.new_context(
            accept_downloads=False,
            java_script_enabled=True,
            service_workers="block",
        )
        blocked_network = False

        def enforce_request(route: Any, request: Any) -> None:
            nonlocal blocked_network
            if request_host(request.url) not in normalized_hosts:
                blocked_network = True
                route.abort("blockedbyclient")
                return
            route.continue_()

        def enforce_websocket(websocket: Any) -> None:
            nonlocal blocked_network
            if request_host(websocket.url) not in normalized_hosts:
                blocked_network = True
                websocket.close(code=1008, reason="host not allowed")
                return
            websocket.connect_to_server()

        try:
            context.route("**/*", enforce_request)
            if hasattr(context, "route_web_socket"):
                context.route_web_socket("**/*", enforce_websocket)
            page = context.new_page()
            try:
                page.goto(target_url, wait_until="domcontentloaded")
            except Exception as exc:
                if blocked_network:
                    raise GuardrailPause("unexpected_network_host") from exc
                raise
            if blocked_network:
                raise GuardrailPause("unexpected_network_host")
            final_host = request_host(page.url)
            if final_host not in normalized_hosts:
                raise GuardrailPause("unexpected_redirect")
            flags = safety_flags(page.content())
            if flags:
                raise GuardrailPause(flags[0])
            try:
                result = operation(page)
            except Exception as exc:
                if blocked_network:
                    raise GuardrailPause("unexpected_network_host") from exc
                raise
            if blocked_network:
                raise GuardrailPause("unexpected_network_host")
            return result
        finally:
            context.close()
            browser.close()


class _ManagedBrowser:
    def __init__(self, browser: Any, playwright: Any):
        self._browser = browser
        self._playwright = playwright

    def new_context(self, **kwargs: Any) -> Any:
        return self._browser.new_context(**kwargs)

    def close(self) -> None:
        try:
            self._browser.close()
        finally:
            self._playwright.stop()


class PlaywrightLauncher:
    """Lazy production launcher. Browser binaries are installed by the operator."""

    def __init__(self, *, headless: bool = True):
        self.headless = headless

    def __call__(self) -> Any:
        from playwright.sync_api import sync_playwright

        playwright = sync_playwright().start()
        try:
            browser = playwright.chromium.launch(headless=self.headless)
        except Exception:
            playwright.stop()
            raise
        return _ManagedBrowser(browser, playwright)
