import unittest

from incogni.adapters.service import GuardrailPause
from incogni.browser_isolation import FreshContextBrowser


class FakePage:
    def __init__(self, final_url, html):
        self.url = final_url
        self.html = html

    def goto(self, target, wait_until):
        self.target = target
        self.wait_until = wait_until

    def content(self):
        return self.html


class FakeContext:
    def __init__(self, page):
        self.page = page
        self.closed = False
        self.request_handler = None
        self.websocket_handler = None

    def route(self, _pattern, handler):
        self.request_handler = handler

    def route_web_socket(self, _pattern, handler):
        self.websocket_handler = handler

    def new_page(self):
        return self.page

    def close(self):
        self.closed = True


class FakeRequest:
    def __init__(self, url):
        self.url = url


class FakeRoute:
    def __init__(self):
        self.aborted = False
        self.continued = False

    def abort(self, _reason):
        self.aborted = True

    def continue_(self):
        self.continued = True


class FakeBrowser:
    def __init__(self, page):
        self.context = FakeContext(page)
        self.closed = False
        self.options = None

    def new_context(self, **kwargs):
        self.options = kwargs
        return self.context

    def close(self):
        self.closed = True


class BrowserIsolationTest(unittest.TestCase):
    def test_fresh_context_closes_after_success_and_failure(self):
        browsers = []

        def launch():
            browser = FakeBrowser(FakePage("https://broker.invalid/form", "<form></form>"))
            browsers.append(browser)
            return browser

        runner = FreshContextBrowser(launch)
        self.assertEqual(
            runner.run(
                "https://broker.invalid/start",
                allowed_hosts={"broker.invalid"},
                operation=lambda _page: "done",
            ),
            "done",
        )
        self.assertTrue(browsers[0].context.closed)
        self.assertTrue(browsers[0].closed)
        self.assertFalse(browsers[0].options["accept_downloads"])
        self.assertEqual(browsers[0].options["service_workers"], "block")

        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            runner.run(
                "https://broker.invalid/start",
                allowed_hosts={"broker.invalid"},
                operation=lambda _page: (_ for _ in ()).throw(
                    RuntimeError("synthetic")
                ),
            )
        self.assertIsNot(browsers[0], browsers[1])
        self.assertTrue(browsers[1].context.closed)
        self.assertTrue(browsers[1].closed)

    def test_unexpected_subrequest_pauses_before_pii_can_leave(self):
        browser = FakeBrowser(FakePage("https://broker.invalid/form", "<form></form>"))

        def attempt_exfiltration(_page):
            route = FakeRoute()
            browser.context.request_handler(
                route, FakeRequest("https://tracker.invalid/leak?pii=synthetic")
            )
            self.assertTrue(route.aborted)
            return "must not escape"

        with self.assertRaisesRegex(GuardrailPause, "unexpected_network_host"):
            FreshContextBrowser(lambda: browser).run(
                "https://broker.invalid/start",
                allowed_hosts={"broker.invalid"},
                operation=attempt_exfiltration,
            )
        self.assertTrue(browser.context.closed)
        self.assertTrue(browser.closed)

    def test_allowed_subrequest_continues(self):
        browser = FakeBrowser(FakePage("https://broker.invalid/form", "<form></form>"))

        def request_asset(_page):
            route = FakeRoute()
            browser.context.request_handler(
                route, FakeRequest("https://broker.invalid/static/form.js")
            )
            self.assertTrue(route.continued)
            return "done"

        self.assertEqual(
            FreshContextBrowser(lambda: browser).run(
                "https://broker.invalid/start",
                allowed_hosts={"broker.invalid"},
                operation=request_asset,
            ),
            "done",
        )

    def test_redirect_captcha_and_unlisted_host_pause(self):
        with self.assertRaisesRegex(GuardrailPause, "unexpected_target_host"):
            FreshContextBrowser(lambda: None).run(
                "https://evil.invalid",
                allowed_hosts={"broker.invalid"},
                operation=lambda page: page,
            )

        for page, reason in (
            (FakePage("https://evil.invalid", "<form></form>"), "unexpected_redirect"),
            (
                FakePage("https://broker.invalid", '<div class="g-recaptcha"></div>'),
                "captcha",
            ),
        ):
            browser = FakeBrowser(page)
            with self.assertRaisesRegex(GuardrailPause, reason):
                FreshContextBrowser(lambda browser=browser: browser).run(
                    "https://broker.invalid",
                    allowed_hosts={"broker.invalid"},
                    operation=lambda value: value,
                )
            self.assertTrue(browser.context.closed)
            self.assertTrue(browser.closed)


if __name__ == "__main__":
    unittest.main()
