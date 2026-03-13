"""
Slack Integration Example for Claude Permission Approver

This example shows how to escalate high-risk permission requests to humans via Slack.
When the AI evaluator returns "ask_user", this module sends an interactive approval request
to a Slack channel with Approve/Deny buttons.

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
    from examples.slack_integration import SlackApprovalService

    slack = SlackApprovalService()

    # Send approval request
    decision = await slack.request_approval(
        tool_name="Bash",
        input_data={"command": "curl -X DELETE https://api.prod.com/users/123"},
        reasoning="DELETE to production API without context",
        timeout_seconds=300  # 5 minutes
    )

    if decision == "allow":
        # User approved
    else:
        # User denied or timed out
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse

logger = logging.getLogger(__name__)


class SlackApprovalService:
    """Handles permission approval escalation via Slack with interactive buttons."""

    def __init__(
        self,
        bot_token: str | None = None,
        app_token: str | None = None,
        approval_channel: str | None = None,
        timeout_seconds: int = 300,  # 5 minutes default
    ):
        """
        Initialize Slack approval service.

        Args:
            bot_token: Slack Bot Token (xoxb-...). Defaults to SLACK_BOT_TOKEN env var.
            app_token: Slack App Token (xapp-...) for Socket Mode. Defaults to SLACK_APP_TOKEN env var.
            approval_channel: Channel name (without #) for approval requests. Defaults to SLACK_APPROVAL_CHANNEL.
            timeout_seconds: Seconds to wait before auto-denying (default: 300 = 5 minutes)
        """
        self.bot_token = bot_token or os.getenv("SLACK_BOT_TOKEN")
        self.app_token = app_token or os.getenv("SLACK_APP_TOKEN")
        self.approval_channel = approval_channel or os.getenv("SLACK_APPROVAL_CHANNEL", "approvals")
        self.timeout_seconds = timeout_seconds

        if not self.bot_token:
            raise ValueError("SLACK_BOT_TOKEN environment variable not set")
        if not self.app_token:
            raise ValueError("SLACK_APP_TOKEN environment variable not set")

        # Initialize clients
        self.web_client = WebClient(token=self.bot_token)
        self.socket_client = SocketModeClient(app_token=self.app_token, web_client=self.web_client)

        # Track pending approvals {message_ts: Future}
        self.pending_approvals: dict[str, asyncio.Future] = {}

        # Register Socket Mode handler
        self.socket_client.socket_mode_request_listeners.append(self._handle_interaction)

    async def request_approval(
        self,
        tool_name: str,
        input_data: dict[str, Any],
        reasoning: str,
        category: str = "high_risk",
        timeout_seconds: int | None = None,
    ) -> str:
        """
        Request human approval via Slack with interactive buttons.

        Args:
            tool_name: The tool requesting permission (e.g., "Bash", "Edit")
            input_data: The parameters for the tool
            reasoning: AI's reasoning for escalation
            category: Risk category (e.g., "high_risk", "critical")
            timeout_seconds: Override default timeout (default: 300 seconds)

        Returns:
            "allow" if approved, "deny" if denied or timed out
        """
        timeout = timeout_seconds or self.timeout_seconds
        message_ts = None

        try:
            # Build approval message
            blocks = self._build_approval_blocks(tool_name, input_data, reasoning, category)

            # Send message to Slack
            response = self.web_client.chat_postMessage(
                channel=self.approval_channel, blocks=blocks, text="Permission Request"
            )

            message_ts = response["ts"]
            logger.info(f"Sent approval request to Slack: {message_ts}")

            # Create future for this approval
            approval_future = asyncio.Future()
            self.pending_approvals[message_ts] = approval_future

            # Wait for approval or timeout
            try:
                decision = await asyncio.wait_for(approval_future, timeout=timeout)
                logger.info(f"Approval decision: {decision}")

                # Update message to show decision
                self._update_message_with_decision(message_ts, decision)

                return decision

            except TimeoutError:
                logger.warning(f"Approval request timed out after {timeout}s")

                # Update message to show timeout
                self._update_message_with_decision(message_ts, "timeout")

                return "deny"

            finally:
                # Clean up pending approval
                if message_ts in self.pending_approvals:
                    del self.pending_approvals[message_ts]

        except SlackApiError as e:
            logger.error(f"Slack API error: {e.response['error']}")
            return "deny"

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return "deny"

    def _build_approval_blocks(
        self, tool_name: str, input_data: dict[str, Any], reasoning: str, category: str
    ) -> list[dict[str, Any]]:
        """Build Slack Block Kit message with approval buttons."""

        # Risk emoji
        risk_emoji = {
            "benign": "✅",
            "moderate_risk": "⚠️",
            "high_risk": "🚨",
            "critical": "🔴",
        }.get(category, "❓")

        # Format input data (truncate if too long)
        input_str = json.dumps(input_data, indent=2)
        if len(input_str) > 500:
            input_str = input_str[:497] + "..."

        # Timestamp
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

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
                        "text": f"⏱️ Auto-denies in {self.timeout_seconds // 60} minutes | {timestamp}",
                    }
                ],
            },
        ]

    def _handle_interaction(self, client: SocketModeClient, req: SocketModeRequest):
        """Handle Slack interactive button clicks."""

        # Acknowledge the request immediately
        response = SocketModeResponse(envelope_id=req.envelope_id)
        client.send_socket_mode_response(response)

        # Process the action
        if req.type == "interactive" and req.payload.get("type") == "block_actions":
            payload = req.payload
            message_ts = payload["message"]["ts"]
            action = payload["actions"][0]

            if action["action_id"] in ["approve_permission", "deny_permission"]:
                decision = action["value"]  # "allow" or "deny"
                user_id = payload["user"]["id"]

                # Get user name
                try:
                    user_info = self.web_client.users_info(user=user_id)
                    user_name = user_info["user"]["real_name"]
                except Exception:
                    user_name = user_id

                logger.info(
                    f"User {user_name} ({user_id}) made decision: {decision} for message {message_ts}"
                )

                # Resolve the pending approval future
                if message_ts in self.pending_approvals:
                    future = self.pending_approvals[message_ts]
                    if not future.done():
                        future.set_result(decision)

    def _update_message_with_decision(self, message_ts: str, decision: str):
        """Update Slack message to show final decision."""

        decision_text = {
            "allow": "✅ *APPROVED*",
            "deny": "❌ *DENIED*",
            "timeout": "⏱️ *TIMED OUT* (auto-denied)",
        }.get(decision, "❓ *UNKNOWN*")

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            # Get original message
            response = self.web_client.conversations_history(
                channel=self.approval_channel, latest=message_ts, limit=1, inclusive=True
            )

            if response["messages"]:
                original_blocks = response["messages"][0]["blocks"]

                # Remove action buttons
                updated_blocks = [
                    block
                    for block in original_blocks
                    if block.get("block_id") != "approval_actions"
                ]

                # Add decision banner
                updated_blocks.insert(
                    1,
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"{decision_text} at {timestamp}"},
                    },
                )

                # Update message
                self.web_client.chat_update(
                    channel=self.approval_channel, ts=message_ts, blocks=updated_blocks
                )

        except Exception as e:
            logger.error(f"Failed to update message: {e}")

    def start(self):
        """Start Socket Mode client (blocking call)."""
        logger.info("Starting Slack Socket Mode client...")
        self.socket_client.connect()

    def stop(self):
        """Stop Socket Mode client."""
        logger.info("Stopping Slack Socket Mode client...")
        self.socket_client.close()


# Example usage and integration with approver.py
async def example_integration():
    """Example showing how to integrate Slack approval into approver.py."""

    from phlegyas.tier3_ai import AIEvaluator

    # Initialize services
    ai_evaluator = AIEvaluator()
    slack_service = SlackApprovalService()

    # Start Slack Socket Mode client in background
    import threading

    slack_thread = threading.Thread(target=slack_service.start, daemon=True)
    slack_thread.start()

    # Example permission request
    tool_name = "Bash"
    input_data = {"command": "curl -X DELETE https://api.production.com/users/123"}

    # Get AI evaluation
    decision, evaluation = await ai_evaluator.evaluate(tool_name, input_data)

    if decision == "ask_user":
        # Escalate to Slack
        print("🔔 AI says 'ask_user' - escalating to Slack...")

        slack_decision = await slack_service.request_approval(
            tool_name=tool_name,
            input_data=input_data,
            reasoning=evaluation.reasoning,
            category=evaluation.category,
        )

        if slack_decision == "allow":
            print("✅ Human approved via Slack")
        else:
            print("❌ Human denied via Slack (or timed out)")

    else:
        print(f"AI made final decision: {decision}")


if __name__ == "__main__":
    # Run example
    asyncio.run(example_integration())
