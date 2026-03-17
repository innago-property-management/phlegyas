"""
Slack Integration Example for Claude Permission Approver

This example shows how to escalate high-risk permission requests to humans via Slack.
When the AI evaluator returns "ask_user", phlegyas sends an interactive approval request
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

For full Slack App setup instructions, see examples/SLACK_SETUP.md.

Usage:
    from phlegyas.slack import SlackApprovalService

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
        ...
    else:
        # User denied or timed out
        ...
"""

import asyncio
import logging

from phlegyas.slack import SlackApprovalService
from phlegyas.tier3_ai import AIEvaluator

logger = logging.getLogger(__name__)


async def example_integration():
    """Example showing Slack escalation when Tier 3 returns ask_user."""

    # Check Slack credentials are available before initialising
    if not SlackApprovalService.is_available():
        print("Slack env vars not set (SLACK_BOT_TOKEN, SLACK_APP_TOKEN, SLACK_APPROVAL_CHANNEL).")
        print("Set them and re-run, or see examples/SLACK_SETUP.md.")
        return

    # Create services
    ai_evaluator = AIEvaluator()
    slack_service = SlackApprovalService()

    # Start Socket Mode listener in background (non-blocking)
    await slack_service.start_background()
    print("Slack listener started.")

    # Example permission request
    tool_name = "Bash"
    input_data = {"command": "curl -X DELETE https://api.production.com/users/123"}

    # Get AI evaluation
    decision, evaluation = await ai_evaluator.evaluate(tool_name, input_data)

    if decision == "ask_user":
        print("AI returned ask_user — escalating to Slack...")

        slack_decision = await slack_service.request_approval(
            tool_name=tool_name,
            input_data=input_data,
            reasoning=evaluation.reasoning,
            category=evaluation.category,
        )

        if slack_decision == "allow":
            print("Human approved via Slack.")
        else:
            print("Human denied via Slack (or timed out — auto-denied).")
    else:
        print(f"AI made final decision: {decision}")


if __name__ == "__main__":
    asyncio.run(example_integration())
