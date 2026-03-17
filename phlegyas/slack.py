"""
SlackApprovalService — production-grade Slack escalation for phlegyas.

Extracted and hardened from examples/slack_integration.py.

Setup:
    1. Create a Slack App at https://api.slack.com/apps
    2. Enable Socket Mode (for interactive buttons)
    3. Add Bot Token Scopes: chat:write, users:read
    4. Install app to workspace
    5. Set environment variables:
       - SLACK_BOT_TOKEN=xoxb-your-bot-token
       - SLACK_APP_TOKEN=xapp-your-app-token (for Socket Mode)
       - SLACK_APPROVAL_CHANNEL=approvals (channel name, without #)

Usage:
    if SlackApprovalService.is_available():
        slack = SlackApprovalService()
        slack.start_background()

        decision = await slack.request_approval(
            tool_name="Bash",
            input_data={"command": "curl -X DELETE https://api.prod.com/users/123"},
            reasoning="DELETE to production API without context",
        )

        if decision == "allow":
            ...  # approved
        else:
            ...  # denied or timed out

        slack.close()
"""

import asyncio
import json
import logging
import os
import threading
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# Soft imports — slack_sdk is optional
try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.request import SocketModeRequest
    from slack_sdk.socket_mode.response import SocketModeResponse

    _SLACK_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SLACK_SDK_AVAILABLE = False


class SlackApprovalService:
    """
    Handles permission approval escalation via Slack with interactive buttons.

    Thread-safety notes:
    - ``pending_approvals`` is guarded by ``_lock`` for all mutations.
    - ``_handle_interaction`` runs in the Slack SDK's thread; it resolves
      asyncio Futures via ``loop.call_soon_threadsafe`` to avoid race conditions.
    - ``start_background`` is idempotent; repeated calls are safe.
    """

    @classmethod
    def is_available(cls) -> bool:
        """
        Return True if both Slack tokens are present in the environment.

        Callers should check this before constructing an instance.
        """
        return bool(
            _SLACK_SDK_AVAILABLE and os.getenv("SLACK_BOT_TOKEN") and os.getenv("SLACK_APP_TOKEN")
        )

    def __init__(
        self,
        bot_token: str | None = None,
        app_token: str | None = None,
        approval_channel: str | None = None,
        timeout_seconds: int = 300,
    ):
        """
        Initialize the Slack approval service.

        Args:
            bot_token: Slack Bot Token (xoxb-...). Defaults to SLACK_BOT_TOKEN env var.
            app_token: Slack App Token (xapp-...) for Socket Mode. Defaults to SLACK_APP_TOKEN.
            approval_channel: Channel name (without #). Defaults to SLACK_APPROVAL_CHANNEL
                              or "approvals".
            timeout_seconds: Default seconds to wait before auto-denying (default: 300).

        Note:
            Callers should check ``SlackApprovalService.is_available()`` before
            constructing. ``__init__`` will assert that tokens are present but will
            not raise a user-friendly error — that is the responsibility of
            ``is_available()``.
        """
        if not _SLACK_SDK_AVAILABLE:
            raise RuntimeError(
                "slack-sdk is not installed. Install phlegyas with: pip install phlegyas[slack]"
            )

        self.bot_token = bot_token or os.getenv("SLACK_BOT_TOKEN")
        self.app_token = app_token or os.getenv("SLACK_APP_TOKEN")
        self.approval_channel = approval_channel or os.getenv("SLACK_APPROVAL_CHANNEL", "approvals")
        self.timeout_seconds = timeout_seconds

        assert self.bot_token, (
            "SLACK_BOT_TOKEN is required. Check is_available() before constructing."
        )
        assert self.app_token, (
            "SLACK_APP_TOKEN is required. Check is_available() before constructing."
        )

        # Slack SDK clients
        self.web_client: WebClient = WebClient(token=self.bot_token)
        self.socket_client: SocketModeClient = SocketModeClient(
            app_token=self.app_token, web_client=self.web_client
        )

        # {message_ts: asyncio.Future[str]} — guarded by _lock
        self.pending_approvals: dict[str, asyncio.Future] = {}
        self._lock = threading.Lock()

        # Asyncio event loop captured in start_background()
        self._loop: asyncio.AbstractEventLoop | None = None

        # Idempotency guard for start_background()
        self._started = False
        self._start_lock = threading.Lock()

        # Register Socket Mode handler
        self.socket_client.socket_mode_request_listeners.append(self._handle_interaction)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_background(self) -> None:
        """
        Spawn a daemon thread running the Socket Mode client.

        Idempotent — calling more than once is safe.
        Captures the current asyncio event loop so that ``_handle_interaction``
        can resolve Futures from its own thread.
        """
        with self._start_lock:
            if self._started:
                return

            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()

            thread = threading.Thread(
                target=self._run_socket_client,
                name="phlegyas-slack-socket",
                daemon=True,
            )
            thread.start()
            self._started = True
            logger.info("Slack Socket Mode client started in background thread.")

    def _run_socket_client(self) -> None:
        """Entry point for the Socket Mode daemon thread."""
        try:
            self.socket_client.connect()
        except Exception:
            logger.exception("Slack Socket Mode client encountered an error.")

    def close(self) -> None:
        """
        Gracefully tear down the Socket Mode connection.

        Any pending approvals are denied before shutdown.
        """
        logger.info("Closing Slack Socket Mode client...")

        # Deny any approvals still waiting
        with self._lock:
            pending = dict(self.pending_approvals)

        for _ts, future in pending.items():
            if self._loop is not None and not future.done():
                self._loop.call_soon_threadsafe(
                    lambda f=future: f.set_result("deny") if not f.done() else None
                )

        try:
            self.socket_client.close()
        except Exception:
            logger.exception("Error while closing Slack Socket Mode client.")

        self._started = False

    # ------------------------------------------------------------------
    # Approval request
    # ------------------------------------------------------------------

    async def request_approval(
        self,
        tool_name: str,
        input_data: dict[str, Any],
        reasoning: str,
        category: str = "high_risk",
        timeout_seconds: int | None = None,
    ) -> str:
        """
        Send an interactive approval request to Slack and await a human decision.

        Args:
            tool_name: Tool requesting permission (e.g. "Bash", "Edit").
            input_data: Tool parameters.
            reasoning: AI reasoning for escalation.
            category: Risk category ("benign", "moderate_risk", "high_risk", "critical").
            timeout_seconds: Override default timeout. Falls back to self.timeout_seconds.

        Returns:
            "allow" if the human approved, "deny" if denied or timed out.
        """
        timeout = timeout_seconds if timeout_seconds is not None else self.timeout_seconds
        message_ts: str | None = None

        try:
            blocks = self._build_approval_blocks(tool_name, input_data, reasoning, category)

            response = self.web_client.chat_postMessage(
                channel=self.approval_channel,
                blocks=blocks,
                text="Permission Request",
            )
            message_ts = response["ts"]
            logger.info("Sent approval request to Slack: ts=%s", message_ts)

            loop = asyncio.get_event_loop()
            approval_future: asyncio.Future[str] = loop.create_future()

            with self._lock:
                self.pending_approvals[message_ts] = approval_future

            try:
                decision = await asyncio.wait_for(approval_future, timeout=timeout)
                logger.info("Approval decision received: %s (ts=%s)", decision, message_ts)
                self._update_message_with_decision(message_ts, decision)
                return decision

            except TimeoutError:
                logger.warning("Approval request timed out after %ss (ts=%s)", timeout, message_ts)
                self._update_message_with_decision(message_ts, "timeout")
                return "deny"

            finally:
                with self._lock:
                    self.pending_approvals.pop(message_ts, None)

        except SlackApiError as exc:
            logger.error("Slack API error during request_approval: %s", exc.response.get("error"))
            return "deny"

        except Exception:
            logger.exception("Unexpected error during request_approval")
            return "deny"

    # ------------------------------------------------------------------
    # Notify (fire-and-forget)
    # ------------------------------------------------------------------

    async def notify_pending(
        self,
        tool_name: str,
        input_data: dict[str, Any],
        reasoning: str,
        category: str,
        request_id: str,
    ) -> None:
        """
        Post a Slack notification about a pending approval without awaiting a response.

        The message includes the request_id in a context block so operators can
        correlate it with the phlegyas ``submit_approval`` tool.

        This method never raises — all errors are swallowed and logged.

        Args:
            tool_name: Tool requesting permission.
            input_data: Tool parameters.
            reasoning: AI reasoning for escalation.
            category: Risk category.
            request_id: Opaque identifier for the pending approval record.
        """
        try:
            blocks = self._build_approval_blocks(tool_name, input_data, reasoning, category)

            # Replace the action buttons block with a read-only context block
            blocks = [b for b in blocks if b.get("block_id") != "approval_actions"]

            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Request ID:* `{request_id}`  |  "
                                "Use `submit_approval` to approve or deny."
                            ),
                        }
                    ],
                }
            )

            self.web_client.chat_postMessage(
                channel=self.approval_channel,
                blocks=blocks,
                text=f"Pending approval notification — request_id: {request_id}",
            )
            logger.info("Sent pending-approval notification to Slack (request_id=%s)", request_id)

        except Exception:
            logger.exception(
                "Failed to send pending-approval notification (request_id=%s)", request_id
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_approval_blocks(
        self,
        tool_name: str,
        input_data: dict[str, Any],
        reasoning: str,
        category: str,
    ) -> list[dict[str, Any]]:
        """Build a Slack Block Kit message with Approve/Deny buttons."""

        risk_emoji = {
            "benign": "✅",
            "moderate_risk": "⚠️",
            "high_risk": "🚨",
            "critical": "🔴",
        }.get(category, "❓")

        input_str = json.dumps(input_data, indent=2)
        if len(input_str) > 500:
            input_str = input_str[:497] + "..."

        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{risk_emoji} Permission Request: {tool_name}",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{tool_name}`"},
                    {"type": "mrkdwn", "text": f"*Risk Category:*\n`{category}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Reasoning:*\n{reasoning}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Input:*\n```{input_str}```"},
            },
            {"type": "divider"},
            {
                "type": "actions",
                "block_id": "approval_actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve"},
                        "style": "primary",
                        "value": "allow",
                        "action_id": "approve_permission",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Deny"},
                        "style": "danger",
                        "value": "deny",
                        "action_id": "deny_permission",
                    },
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"⏱️ Auto-denies in {self.timeout_seconds // 60} minutes | {timestamp}"
                        ),
                    }
                ],
            },
        ]

    def _handle_interaction(self, client: "SocketModeClient", req: "SocketModeRequest") -> None:
        """
        Handle Slack interactive button clicks.

        Runs in the Slack SDK's thread. Resolves asyncio Futures via
        ``call_soon_threadsafe`` to avoid cross-thread Future mutation.
        """
        # Acknowledge immediately
        response = SocketModeResponse(envelope_id=req.envelope_id)
        client.send_socket_mode_response(response)

        if req.type != "interactive":
            return
        if req.payload.get("type") != "block_actions":
            return

        payload = req.payload
        message_ts: str = payload["message"]["ts"]
        actions: list[dict] = payload.get("actions", [])

        if not actions:
            return

        action = actions[0]
        if action.get("action_id") not in ("approve_permission", "deny_permission"):
            return

        decision: str = action["value"]  # "allow" or "deny"
        user_id: str = payload["user"]["id"]

        try:
            user_info = self.web_client.users_info(user=user_id)
            user_name: str = user_info["user"]["real_name"]
        except Exception:
            user_name = user_id

        logger.info(
            "User %s (%s) decided: %s for message ts=%s",
            user_name,
            user_id,
            decision,
            message_ts,
        )

        with self._lock:
            future = self.pending_approvals.get(message_ts)

        if future is not None and self._loop is not None and not future.done():
            self._loop.call_soon_threadsafe(
                lambda f=future, d=decision: f.set_result(d) if not f.done() else None
            )

    def _update_message_with_decision(self, message_ts: str, decision: str) -> None:
        """Update the Slack message to show the final decision (approve/deny/timeout)."""

        decision_text = {
            "allow": "✅ *APPROVED*",
            "deny": "❌ *DENIED*",
            "timeout": "⏱️ *TIMED OUT* (auto-denied)",
        }.get(decision, "❓ *UNKNOWN*")

        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            history = self.web_client.conversations_history(
                channel=self.approval_channel,
                latest=message_ts,
                limit=1,
                inclusive=True,
            )

            if not history["messages"]:
                return

            original_blocks: list[dict] = history["messages"][0]["blocks"]

            # Strip the action buttons
            updated_blocks = [b for b in original_blocks if b.get("block_id") != "approval_actions"]

            # Insert decision banner just after the header
            updated_blocks.insert(
                1,
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"{decision_text} at {timestamp}"},
                },
            )

            self.web_client.chat_update(
                channel=self.approval_channel,
                ts=message_ts,
                blocks=updated_blocks,
            )

        except Exception:
            logger.exception(
                "Failed to update message ts=%s with decision %s", message_ts, decision
            )
