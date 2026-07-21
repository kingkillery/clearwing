"""Tests for browser tools module (unit tests, no real browser)."""

from clearwing.agent.tools.recon.browser_tools import (
    _browser_state,
    browser_close,
    browser_list_tabs,
    get_browser_tools,
)


class TestGetBrowserTools:
    def test_returns_list(self):
        tools = get_browser_tools()
        assert isinstance(tools, list)
        assert len(tools) == 11

    def test_tool_names(self):
        tools = get_browser_tools()
        names = [t.name for t in tools]
        expected = [
            "browser_navigate",
            "browser_get_content",
            "browser_get_html",
            "browser_fill",
            "browser_click",
            "browser_get_cookies",
            "browser_set_cookie",
            "browser_execute_js",
            "browser_screenshot",
            "browser_list_tabs",
            "browser_close",
        ]
        assert names == expected


class TestBrowserState:
    def test_initial_state(self):
        assert _browser_state["browser"] is None
        assert _browser_state["context"] is None
        assert isinstance(_browser_state["tabs"], dict)
        assert _browser_state["active_tab"] is None


class TestBrowserListTabs:
    def test_empty_tabs(self):
        result = browser_list_tabs.invoke({})
        assert result == []


class TestBrowserClose:
    def test_close_nonexistent_tab(self):
        result = browser_close.invoke({"tab_name": "nonexistent"})
        assert result["closed"] == "nonexistent"
        assert result["remaining_tabs"] == []

    def test_close_all_when_empty(self):
        result = browser_close.invoke({})
        assert result["closed"] == "all"
        assert result["remaining_tabs"] == []


class TestEnsureBrowserCleanup:
    """A failed browser launch must not leak the Playwright driver.

    sync_playwright().start() spawns a driver whose internal event loop
    keeps running in the calling thread. If chromium.launch() then fails
    and pw.stop() is never called, that loop poisons the thread: every
    later AgentTool.invoke() returns an unawaited coroutine instead of
    running the tool.
    """

    def test_launch_failure_stops_driver_and_resets_state(self, monkeypatch):
        import asyncio

        import clearwing.agent.tools.recon.browser_tools as bt

        stop_calls = []

        class FakeChromium:
            def launch(self, headless=True):
                raise RuntimeError("Executable doesn't exist (fake)")

        class FakePlaywright:
            def __init__(self):
                self.chromium = FakeChromium()

            def stop(self):
                stop_calls.append(True)

        class FakeSyncPlaywright:
            def start(self):
                return FakePlaywright()

        monkeypatch.setattr(bt, "_browser_state", {
            "browser": None, "context": None, "tabs": {}, "active_tab": None,
        })
        # Patch the sync_playwright factory imported inside _ensure_browser
        import playwright.sync_api as sync_api

        monkeypatch.setattr(sync_api, "sync_playwright", lambda: FakeSyncPlaywright())

        try:
            bt._ensure_browser()
            raise AssertionError("expected launch failure")
        except RuntimeError:
            pass

        assert stop_calls == [True], "pw.stop() was not called on launch failure"
        assert bt._browser_state["_pw"] is None
        assert bt._browser_state["browser"] is None
        assert bt._browser_state["context"] is None
        assert bt._browser_state["tabs"] == {}

        # The calling thread must not have a leftover running loop
        try:
            asyncio.get_running_loop()
            leaked = True
        except RuntimeError:
            leaked = False
        assert not leaked, "failed browser launch leaked a running event loop"

    def test_launch_failure_reraises(self, monkeypatch):
        import clearwing.agent.tools.recon.browser_tools as bt

        class FakeChromium:
            def launch(self, headless=True):
                raise ValueError("boom")

        class FakePlaywright:
            def __init__(self):
                self.chromium = FakeChromium()

            def stop(self):
                pass

        class FakeSyncPlaywright:
            def start(self):
                return FakePlaywright()

        monkeypatch.setattr(bt, "_browser_state", {
            "browser": None, "context": None, "tabs": {}, "active_tab": None,
        })
        import playwright.sync_api as sync_api

        monkeypatch.setattr(sync_api, "sync_playwright", lambda: FakeSyncPlaywright())

        import pytest

        with pytest.raises(ValueError, match="boom"):
            bt._ensure_browser()
