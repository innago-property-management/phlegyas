"""
Tests for SlackApprovalService (phlegyas/slack.py).

Tests cover:
- is_available() with various env var combinations
- _build_approval_blocks() structure, truncation, and emoji mapping
- notify_pending() fire-and-forget behavior (never raises)
- request_approval() timeout, Slack API error, and unexpected exception paths
- start_background() idempotency and event loop capture
- close() resets _started flag

Mocking strategy
----------------
slack_sdk is an *optional* dependency that is NOT installed in the dev venv.
When the package is absent the module-level try/except sets
``_SLACK_SDK_AVAILABLE = False`` and none of the SDK names are bound in the
``phlegyas.slack`` namespace.

We therefore:
1. Create lightweight fakes for the three SDK symbols the module uses.
2. Inject them into ``phlegyas.slack`` via ``monkeypatch.setattr`` before
   constructing any ``SlackApprovalService`` instance.
3. Patch ``_SLACK_SDK_AVAILABLE`` to ``True`` so ``__init__`` doesn't raise.
"""

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fake SDK types (module-level so they can be reused across fixtures)
# ---------------------------------------------------------------------------


class FakeSlackApiError(Exception):
    """Minimal stand-in for slack_sdk.errors.SlackApiError."""

    def __init__(self, message: str = "slack_error", error: str = "generic_error"):
        super().__init__(message)
        self.response = {"error": error, "ok": False}


class FakeWebClient:
    """Minimal stand-in for slack_sdk.WebClient — delegates to a MagicMock."""

    def __init__(self, token: str | None = None, **kwargs):
        self._mock = MagicMock()
        self.token = token

    def __getattr__(self, item):
        return getattr(self._mock, item)


class FakeSocketModeClient:
    """Minimal stand-in for slack_sdk.socket_mode.SocketModeClient."""

    def __init__(self, app_token: str | None = None, web_client=None, **kwargs):
        self.app_token = app_token
        self.web_client = web_client
        self.socket_mode_request_listeners: list = []
        self._mock = MagicMock()

    def connect(self):
        pass

    def close(self):
        pass

    def send_socket_mode_response(self, response):
        pass


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _inject_sdk_fakes(monkeypatch, web_client_instance=None, socket_client_instance=None):
    """
    Patch phlegyas.slack so it behaves as if slack_sdk is installed.

    Optionally pass pre-constructed client mocks so tests can inspect calls.
    """
    import phlegyas.slack as slack_module

    # Make the module believe slack_sdk is available
    monkeypatch.setattr(slack_module, "_SLACK_SDK_AVAILABLE", True)

    # Inject SlackApiError under the name the module references
    monkeypatch.setattr(slack_module, "SlackApiError", FakeSlackApiError, raising=False)

    # Inject constructors; if caller supplies pre-built instances wrap them
    if web_client_instance is not None:
        monkeypatch.setattr(
            slack_module,
            "WebClient",
            lambda token=None, **kw: web_client_instance,
            raising=False,
        )
    else:
        monkeypatch.setattr(slack_module, "WebClient", FakeWebClient, raising=False)

    if socket_client_instance is not None:
        monkeypatch.setattr(
            slack_module,
            "SocketModeClient",
            lambda app_token=None, web_client=None, **kw: socket_client_instance,
            raising=False,
        )
    else:
        monkeypatch.setattr(slack_module, "SocketModeClient", FakeSocketModeClient, raising=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_slack_env(monkeypatch):
    """Set both Slack tokens and approval channel in the environment."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test-bot-token")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test-app-token")
    monkeypatch.setenv("SLACK_APPROVAL_CHANNEL", "test-approvals")


@pytest.fixture
def web_client_mock():
    """Return a MagicMock that stands in for an instantiated WebClient."""
    m = MagicMock()
    return m


@pytest.fixture
def socket_client_mock():
    """Return a MagicMock that stands in for an instantiated SocketModeClient."""
    m = MagicMock()
    m.socket_mode_request_listeners = []
    m.close = MagicMock()
    m.connect = MagicMock()
    return m


@pytest.fixture
def service(mock_slack_env, monkeypatch, web_client_mock, socket_client_mock):
    """
    Construct a SlackApprovalService with fully mocked SDK clients.

    The fixture injects fake SDK names into phlegyas.slack and hands back
    a service whose web_client and socket_client are MagicMocks.
    """
    _inject_sdk_fakes(monkeypatch, web_client_mock, socket_client_mock)

    from phlegyas.slack import SlackApprovalService

    svc = SlackApprovalService(timeout_seconds=300)
    # Ensure the attributes point at the mocks we created
    svc.web_client = web_client_mock
    svc.socket_client = socket_client_mock
    return svc


# ---------------------------------------------------------------------------
# TestSlackAvailability
# ---------------------------------------------------------------------------


class TestSlackAvailability:
    """Tests for the is_available() classmethod."""

    def test_is_available_false_without_tokens(self, monkeypatch):
        """is_available() must return False when neither token is set."""
        monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
        monkeypatch.delenv("SLACK_APP_TOKEN", raising=False)
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "_SLACK_SDK_AVAILABLE", True)

        from phlegyas.slack import SlackApprovalService

        assert SlackApprovalService.is_available() is False

    def test_is_available_true_with_both_tokens(self, monkeypatch):
        """is_available() must return True when both tokens are present."""
        monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-real")
        monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-real")
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "_SLACK_SDK_AVAILABLE", True)

        from phlegyas.slack import SlackApprovalService

        assert SlackApprovalService.is_available() is True

    def test_is_available_false_with_only_bot_token(self, monkeypatch):
        """is_available() must return False when only SLACK_BOT_TOKEN is set."""
        monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-only")
        monkeypatch.delenv("SLACK_APP_TOKEN", raising=False)
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "_SLACK_SDK_AVAILABLE", True)

        from phlegyas.slack import SlackApprovalService

        assert SlackApprovalService.is_available() is False

    def test_is_available_false_with_only_app_token(self, monkeypatch):
        """is_available() must return False when only SLACK_APP_TOKEN is set."""
        monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
        monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-only")
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "_SLACK_SDK_AVAILABLE", True)

        from phlegyas.slack import SlackApprovalService

        assert SlackApprovalService.is_available() is False

    def test_is_available_false_when_sdk_missing(self, monkeypatch):
        """is_available() must return False when slack_sdk is not installed."""
        monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-real")
        monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-real")
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "_SLACK_SDK_AVAILABLE", False)

        from phlegyas.slack import SlackApprovalService

        assert SlackApprovalService.is_available() is False


# ---------------------------------------------------------------------------
# TestSlackMessageBuilding
# ---------------------------------------------------------------------------


class TestSlackMessageBuilding:
    """Tests for _build_approval_blocks() — no Slack API calls needed."""

    def test_builds_blocks_with_correct_tool_name(self, service):
        """The header block must contain the tool name."""
        blocks = service._build_approval_blocks(
            tool_name="Bash",
            input_data={"command": "ls -la"},
            reasoning="Listing files",
            category="benign",
        )
        header = blocks[0]
        assert header["type"] == "header"
        assert "Bash" in header["text"]["text"]

    def test_truncates_long_input_at_500_chars(self, service):
        """Input strings longer than 500 chars must be truncated with '...'."""
        large_input = {"data": "x" * 1000}
        blocks = service._build_approval_blocks(
            tool_name="Write",
            input_data=large_input,
            reasoning="Writing large content",
            category="moderate_risk",
        )
        # Find the section block containing the input code fence
        input_block = next(
            b
            for b in blocks
            if b.get("type") == "section" and "Input" in b.get("text", {}).get("text", "")
        )
        # Strip the mrkdwn wrapper to get at the raw input_str
        raw = input_block["text"]["text"]
        # The raw JSON is inside ```...```
        start = raw.index("```") + 3
        end = raw.rindex("```")
        inner = raw[start:end]
        assert len(inner) <= 500
        assert inner.endswith("...")

    def test_risk_emoji_benign(self, service):
        """Category 'benign' maps to the checkmark emoji."""
        blocks = service._build_approval_blocks(
            tool_name="Read",
            input_data={"path": "/tmp/file.txt"},
            reasoning="Reading a file",
            category="benign",
        )
        assert "✅" in blocks[0]["text"]["text"]

    def test_risk_emoji_moderate_risk(self, service):
        """Category 'moderate_risk' maps to the warning emoji."""
        blocks = service._build_approval_blocks(
            tool_name="Edit",
            input_data={"file": "config.json"},
            reasoning="Editing config",
            category="moderate_risk",
        )
        assert "⚠️" in blocks[0]["text"]["text"]

    def test_risk_emoji_high_risk(self, service):
        """Category 'high_risk' maps to the siren emoji."""
        blocks = service._build_approval_blocks(
            tool_name="Bash",
            input_data={"command": "curl -X DELETE https://api.example.com"},
            reasoning="DELETE to external API",
            category="high_risk",
        )
        assert "🚨" in blocks[0]["text"]["text"]

    def test_risk_emoji_critical(self, service):
        """Category 'critical' maps to the red circle emoji."""
        blocks = service._build_approval_blocks(
            tool_name="Bash",
            input_data={"command": "drop database prod"},
            reasoning="Destructive DB operation",
            category="critical",
        )
        assert "🔴" in blocks[0]["text"]["text"]

    def test_default_category_is_unknown_emoji(self, service):
        """An unrecognised category falls back to the question-mark emoji."""
        blocks = service._build_approval_blocks(
            tool_name="Bash",
            input_data={"command": "whoami"},
            reasoning="Some operation",
            category="totally_unknown_category",
        )
        assert "❓" in blocks[0]["text"]["text"]

    def test_includes_timeout_in_context_block(self, service):
        """The trailing context block must mention the auto-deny timeout in minutes."""
        service.timeout_seconds = 600  # 10 minutes
        blocks = service._build_approval_blocks(
            tool_name="Bash",
            input_data={"command": "ls"},
            reasoning="Info command",
            category="benign",
        )
        context_block = blocks[-1]
        assert context_block["type"] == "context"
        context_text = context_block["elements"][0]["text"]
        assert "10" in context_text  # 600 // 60 == 10

    def test_includes_approval_actions_block(self, service):
        """The blocks must contain an actions block with the expected button action IDs."""
        blocks = service._build_approval_blocks(
            tool_name="Bash",
            input_data={"command": "echo hi"},
            reasoning="Echo",
            category="benign",
        )
        action_blocks = [b for b in blocks if b.get("block_id") == "approval_actions"]
        assert len(action_blocks) == 1
        action_ids = {a["action_id"] for a in action_blocks[0]["elements"]}
        assert "approve_permission" in action_ids
        assert "deny_permission" in action_ids

    def test_reasoning_appears_in_block(self, service):
        """The reasoning text must appear in one of the section blocks."""
        reasoning = "This is the unique reasoning text for the test."
        blocks = service._build_approval_blocks(
            tool_name="Read",
            input_data={"path": "/tmp"},
            reasoning=reasoning,
            category="benign",
        )
        all_text = " ".join(
            b.get("text", {}).get("text", "") for b in blocks if b.get("type") == "section"
        )
        assert reasoning in all_text


# ---------------------------------------------------------------------------
# TestSlackNotifyPending
# ---------------------------------------------------------------------------


class TestSlackNotifyPending:
    """Tests for notify_pending() — fire-and-forget, never raises."""

    @pytest.mark.asyncio
    async def test_notify_pending_posts_message_with_request_id(self, service):
        """notify_pending() should call chat_postMessage including the request_id."""
        request_id = "req-abc-123"
        await service.notify_pending(
            tool_name="Bash",
            input_data={"command": "ls"},
            reasoning="Safe listing",
            category="benign",
            request_id=request_id,
        )

        service.web_client.chat_postMessage.assert_called_once()
        call_kwargs = service.web_client.chat_postMessage.call_args[1]
        assert request_id in call_kwargs.get("text", "")

    @pytest.mark.asyncio
    async def test_notify_pending_strips_action_buttons(self, service):
        """notify_pending() must remove the 'approval_actions' block from the message."""
        await service.notify_pending(
            tool_name="Edit",
            input_data={"file": "README.md"},
            reasoning="Editing docs",
            category="moderate_risk",
            request_id="req-no-buttons",
        )

        call_kwargs = service.web_client.chat_postMessage.call_args[1]
        blocks: list[dict[str, Any]] = call_kwargs.get("blocks", [])
        block_ids = [b.get("block_id") for b in blocks]
        assert "approval_actions" not in block_ids

    @pytest.mark.asyncio
    async def test_notify_pending_appends_context_block_with_request_id(self, service):
        """notify_pending() must append a context block containing the request_id."""
        request_id = "req-ctx-789"
        await service.notify_pending(
            tool_name="Bash",
            input_data={"command": "git status"},
            reasoning="Checking git",
            category="benign",
            request_id=request_id,
        )

        call_kwargs = service.web_client.chat_postMessage.call_args[1]
        blocks: list[dict[str, Any]] = call_kwargs.get("blocks", [])
        last_block = blocks[-1]
        assert last_block["type"] == "context"
        ctx_text = last_block["elements"][0]["text"]
        assert request_id in ctx_text

    @pytest.mark.asyncio
    async def test_notify_pending_does_not_raise_on_slack_api_error(self, service, monkeypatch):
        """notify_pending() must swallow SlackApiError and never raise."""
        # Patch the module-level SlackApiError to our fake so except clause matches
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "SlackApiError", FakeSlackApiError, raising=False)
        service.web_client.chat_postMessage.side_effect = FakeSlackApiError(
            "channel_not_found", "channel_not_found"
        )

        # Must complete without raising
        await service.notify_pending(
            tool_name="Bash",
            input_data={"command": "rm -rf /tmp/test"},
            reasoning="Cleanup",
            category="high_risk",
            request_id="req-error-test",
        )

    @pytest.mark.asyncio
    async def test_notify_pending_does_not_raise_on_unexpected_exception(self, service):
        """notify_pending() must swallow arbitrary exceptions and never raise."""
        service.web_client.chat_postMessage.side_effect = RuntimeError("network unavailable")

        await service.notify_pending(
            tool_name="Bash",
            input_data={"command": "ls"},
            reasoning="Listing",
            category="benign",
            request_id="req-runtime-error",
        )


# ---------------------------------------------------------------------------
# TestSlackDecisionHandling
# ---------------------------------------------------------------------------


class TestSlackDecisionHandling:
    """Tests for request_approval() error and timeout paths."""

    @pytest.mark.asyncio
    async def test_returns_deny_on_timeout(self, service):
        """request_approval() must return 'deny' when the future never resolves."""
        service.web_client.chat_postMessage.return_value = {"ts": "1234567890.000100"}
        service.web_client.conversations_history.return_value = {
            "messages": [
                {
                    "blocks": [
                        {"type": "header", "text": {"type": "plain_text", "text": "Test"}},
                        {
                            "type": "actions",
                            "block_id": "approval_actions",
                            "elements": [],
                        },
                    ]
                }
            ]
        }
        service.web_client.chat_update.return_value = {"ok": True}

        decision = await service.request_approval(
            tool_name="Bash",
            input_data={"command": "curl https://api.prod.com"},
            reasoning="External network call",
            category="high_risk",
            timeout_seconds=0.01,  # Extremely short — expires immediately
        )

        assert decision == "deny"

    @pytest.mark.asyncio
    async def test_returns_deny_on_slack_api_error(self, service, monkeypatch):
        """request_approval() must return 'deny' when chat_postMessage raises SlackApiError."""
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "SlackApiError", FakeSlackApiError, raising=False)
        service.web_client.chat_postMessage.side_effect = FakeSlackApiError(
            "channel_not_found", "channel_not_found"
        )

        decision = await service.request_approval(
            tool_name="Bash",
            input_data={"command": "ls"},
            reasoning="Safe command",
            category="benign",
        )

        assert decision == "deny"

    @pytest.mark.asyncio
    async def test_returns_deny_on_unexpected_exception(self, service):
        """request_approval() must return 'deny' when an unexpected exception occurs."""
        service.web_client.chat_postMessage.side_effect = ConnectionError("Slack is unreachable")

        decision = await service.request_approval(
            tool_name="Edit",
            input_data={"file": "main.py"},
            reasoning="Code edit",
            category="moderate_risk",
        )

        assert decision == "deny"

    @pytest.mark.asyncio
    async def test_cleans_up_pending_approvals_after_timeout(self, service):
        """pending_approvals dict must be empty after a timed-out request."""
        service.web_client.chat_postMessage.return_value = {"ts": "9999.0001"}
        service.web_client.conversations_history.return_value = {"messages": [{"blocks": []}]}
        service.web_client.chat_update.return_value = {"ok": True}

        await service.request_approval(
            tool_name="Bash",
            input_data={"command": "ls"},
            reasoning="Safe",
            category="benign",
            timeout_seconds=0.01,
        )

        assert len(service.pending_approvals) == 0

    @pytest.mark.asyncio
    async def test_cleans_up_pending_approvals_after_api_error(self, service, monkeypatch):
        """pending_approvals must remain empty when chat_postMessage fails."""
        import phlegyas.slack as slack_module

        monkeypatch.setattr(slack_module, "SlackApiError", FakeSlackApiError, raising=False)
        service.web_client.chat_postMessage.side_effect = FakeSlackApiError()

        await service.request_approval(
            tool_name="Bash",
            input_data={"command": "ls"},
            reasoning="Safe",
            category="benign",
        )

        assert len(service.pending_approvals) == 0


# ---------------------------------------------------------------------------
# TestSlackStartBackground
# ---------------------------------------------------------------------------


class TestSlackStartBackground:
    """Tests for start_background() lifecycle method."""

    def test_start_background_is_idempotent(self, service):
        """Calling start_background() twice must only spawn one thread."""
        spawned: list = []
        fake_loop = MagicMock(spec=asyncio.AbstractEventLoop)

        def counting_thread(**kwargs):
            t = MagicMock()
            t.start = MagicMock()
            spawned.append(t)
            return t

        with (
            patch("threading.Thread", side_effect=counting_thread),
            patch("asyncio.get_event_loop", return_value=fake_loop),
        ):
            service.start_background()
            service.start_background()  # Second call — no-op

        assert len(spawned) == 1
        spawned[0].start.assert_called_once()

    def test_start_background_sets_started_flag(self, service):
        """start_background() must set _started to True."""
        assert service._started is False
        fake_loop = MagicMock(spec=asyncio.AbstractEventLoop)

        with (
            patch("threading.Thread", return_value=MagicMock()),
            patch("asyncio.get_event_loop", return_value=fake_loop),
        ):
            service.start_background()

        assert service._started is True

    def test_start_background_captures_event_loop(self, service):
        """start_background() must assign an asyncio event loop to self._loop."""
        assert service._loop is None
        fake_loop = MagicMock(spec=asyncio.AbstractEventLoop)

        with (
            patch("threading.Thread", return_value=MagicMock()),
            patch("asyncio.get_event_loop", return_value=fake_loop),
        ):
            service.start_background()

        assert service._loop is not None

    def test_start_background_spawns_daemon_thread(self, service):
        """The background thread must be a daemon named 'phlegyas-slack-socket'."""
        captured: dict = {}
        fake_loop = MagicMock(spec=asyncio.AbstractEventLoop)

        def fake_thread(**kwargs):
            captured.update(kwargs)
            t = MagicMock()
            t.start = MagicMock()
            return t

        with (
            patch("threading.Thread", side_effect=fake_thread),
            patch("asyncio.get_event_loop", return_value=fake_loop),
        ):
            service.start_background()

        assert captured.get("daemon") is True
        assert captured.get("name") == "phlegyas-slack-socket"


# ---------------------------------------------------------------------------
# TestSlackClose
# ---------------------------------------------------------------------------


class TestSlackClose:
    """Tests for close() lifecycle method."""

    def test_close_resets_started_flag(self, service):
        """close() must set _started back to False."""
        fake_loop = MagicMock(spec=asyncio.AbstractEventLoop)
        with (
            patch("threading.Thread", return_value=MagicMock()),
            patch("asyncio.get_event_loop", return_value=fake_loop),
        ):
            service.start_background()

        assert service._started is True
        service.close()
        assert service._started is False

    def test_close_calls_socket_client_close(self, service):
        """close() must call socket_client.close()."""
        service.close()
        service.socket_client.close.assert_called_once()

    def test_close_does_not_raise_on_socket_error(self, service):
        """close() must swallow exceptions raised by socket_client.close()."""
        service.socket_client.close.side_effect = RuntimeError("already closed")
        # Must not propagate the exception
        service.close()

    def test_close_denies_pending_approvals(self, service):
        """close() must resolve any pending futures with 'deny'."""
        loop = asyncio.new_event_loop()
        service._loop = loop

        future: asyncio.Future[str] = loop.create_future()
        with service._lock:
            service.pending_approvals["ts-pending"] = future

        service.close()

        # Execute all scheduled callbacks
        loop.run_until_complete(asyncio.sleep(0))

        assert future.done()
        assert future.result() == "deny"
        loop.close()

    def test_close_skips_already_done_futures(self, service):
        """close() must not raise when a pending future is already resolved."""
        loop = asyncio.new_event_loop()
        service._loop = loop

        future: asyncio.Future[str] = loop.create_future()
        future.set_result("allow")  # Already done

        with service._lock:
            service.pending_approvals["ts-done"] = future

        # Should complete without InvalidStateError
        service.close()

        # Drain any scheduled callbacks before closing so Python 3.14 does not
        # report unclosed-socket ResourceWarnings during garbage collection.
        loop.run_until_complete(asyncio.sleep(0))
        loop.close()
