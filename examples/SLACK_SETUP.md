# Slack Integration Setup Guide

This guide walks through setting up Slack integration for human escalation of high-risk permission requests.

## Overview

When the AI evaluator returns `"ask_user"` (confidence < 80% or critical operations), the permission request is escalated to a Slack channel where humans can approve/deny via interactive buttons on their phone.

**Benefits:**
- 🏖️ Work remotely while Claude operates autonomously
- 📱 Approve/deny from mobile phone via Slack
- ⏱️ Auto-deny after 5 minutes (configurable timeout)
- 📊 Full audit trail of human decisions

## Prerequisites

- Slack workspace (free tier works fine)
- Admin permissions to create Slack apps
- Python 3.11+ with `slack-sdk` installed

## Step 1: Create Slack App

1. Go to https://api.slack.com/apps
2. Click **"Create New App"**
3. Choose **"From scratch"**
4. Name: `Claude Permission Approver`
5. Select your workspace
6. Click **"Create App"**

## Step 2: Enable Socket Mode

Socket Mode allows your local Python script to receive interactive button clicks without needing a public webhook URL.

1. In your app settings, go to **Settings → Socket Mode**
2. Toggle **"Enable Socket Mode"** → ON
3. Click **"Generate an app-level token"**
   - Token Name: `socket-mode-token`
   - Scope: `connections:write`
4. Click **"Generate"**
5. **Copy the token** (starts with `xapp-...`) → Save to `.env` as `SLACK_APP_TOKEN`

## Step 3: Add Bot Token Scopes

1. Go to **Features → OAuth & Permissions**
2. Scroll to **"Scopes" → "Bot Token Scopes"**
3. Click **"Add an OAuth Scope"** and add:
   - `chat:write` - Post messages to channels
   - `users:read` - Read user names for audit trail
4. Scroll to top and click **"Install to Workspace"**
5. Click **"Allow"**
6. **Copy the Bot User OAuth Token** (starts with `xoxb-...`) → Save to `.env` as `SLACK_BOT_TOKEN`

## Step 4: Create Approval Channel

1. In Slack, create a new channel: `#approvals` (or any name you prefer)
2. Invite the bot to the channel:
   - Type `/invite @Claude Permission Approver` in the channel
   - Or: Right-click channel → Integrations → Add apps → Select your bot

## Step 5: Enable Interactivity

1. Go to **Features → Interactivity & Shortcuts**
2. Toggle **"Interactivity"** → ON
3. **Request URL**: Not needed (using Socket Mode)
4. Click **"Save Changes"**

## Step 6: Configure Environment Variables

Add to your `.env` file:

```bash
# Slack Integration (Optional)
SLACK_BOT_TOKEN=xoxb-your-bot-token-here
SLACK_APP_TOKEN=xapp-your-app-token-here
SLACK_APPROVAL_CHANNEL=approvals
SLACK_TIMEOUT_SECONDS=300  # 5 minutes
```

## Step 7: Install Dependencies

```bash
# Install with Slack support
pip install -e ".[slack]"

# Or install slack-sdk directly
pip install slack-sdk>=3.31.0
```

## Step 8: Integrate with Approver

Update `phlegyas/approver_mcp.py` to use Slack for `ask_user` decisions:

```python
from examples.slack_integration import SlackApprovalService
import threading

# Initialize Slack service (only if configured)
slack_service = None
if os.getenv("SLACK_BOT_TOKEN"):
    try:
        slack_service = SlackApprovalService()
        # Start Socket Mode in background thread
        slack_thread = threading.Thread(target=slack_service.start, daemon=True)
        slack_thread.start()
        logger.info("Slack integration enabled")
    except Exception as e:
        logger.warning(f"Slack integration disabled: {e}")

@mcp.tool()
async def permissions__approve(toolName: str, input: dict[str, Any]) -> dict[str, Any]:
    # ... Tier 1 and Tier 2 logic ...

    # Tier 3: AI evaluation
    decision, evaluation = await ai_evaluator.evaluate(toolName, input)

    if decision == "ask_user":
        # Escalate to Slack if configured
        if slack_service:
            logger.info("Escalating to Slack for human approval")
            slack_decision = await slack_service.request_approval(
                tool_name=toolName,
                input_data=input,
                reasoning=evaluation.reasoning,
                category=evaluation.category,
            )

            if slack_decision == "allow":
                message = f"Human approved via Slack: {evaluation.reasoning}"
                logger.info(f"APPROVED (Human via Slack): {message}")
                write_audit_log(toolName, input, "allow", "tier3_human_approve", message)
                return {"behavior": "allow", "message": message}
            else:
                message = f"Human denied via Slack: {evaluation.reasoning}"
                logger.warning(f"DENIED (Human via Slack): {message}")
                write_audit_log(toolName, input, "deny", "tier3_human_deny", message)
                return {"behavior": "deny", "message": message}
        else:
            # Fallback: deny if Slack not configured
            message = f"Denied: Requires human approval. {evaluation.reasoning}"
            logger.warning(f"DENIED (Tier 3 - needs human, Slack not configured): {message}")
            write_audit_log(toolName, input, "deny", "tier3_needs_human", message)
            return {"behavior": "deny", "message": message}

    # ... rest of Tier 3 logic ...
```

## Step 9: Test the Integration

1. Run the approver with Slack integration:
```bash
cd /path/to/phlegyas
source .venv/bin/activate
python phlegyas/approver_mcp.py
```

2. Trigger a high-risk operation via Claude Code:
```bash
claude --permission-prompt-tool mcp__phlegyas__permissions__approve \
  -p "Delete all files in /tmp/test"
```

3. Check your Slack `#approvals` channel - you should see:
   - 🚨 Permission request with details
   - ✅ Approve and ❌ Deny buttons
   - ⏱️ Auto-deny countdown

4. Click a button to approve/deny

## Slack Message Example

```
🚨 Permission Request: Bash
━━━━━━━━━━━━━━━━━━━━━━━━━━

Tool:                    Risk Category:
`Bash`                   `high_risk`

Reasoning:
DELETE operation on unknown directory requires human approval

Input:
```
{
  "command": "rm -rf /tmp/test"
}
```

━━━━━━━━━━━━━━━━━━━━━━━━━━
[ ✅ Approve ]  [ ❌ Deny ]

⏱️ Auto-denies in 5 minutes | 2025-11-08 14:23:45 UTC
```

## Troubleshooting

### "SLACK_BOT_TOKEN environment variable not set"
- Check `.env` file exists and is loaded
- Verify token starts with `xoxb-`

### "SLACK_APP_TOKEN environment variable not set"
- Check `.env` file has app token
- Verify token starts with `xapp-`

### Bot not posting to channel
- Invite bot to channel: `/invite @Claude Permission Approver`
- Check bot has `chat:write` scope

### Buttons not responding
- Verify Socket Mode is enabled
- Check `SLACK_APP_TOKEN` is correct
- Ensure `slack_service.start()` is called in background thread

### Messages timeout without response
- Check Socket Mode client is running (`slack_thread.is_alive()`)
- Verify network connectivity
- Check Slack app status at https://api.slack.com/apps

## Security Considerations

1. **Token Security**: Never commit `.env` file with tokens to git
2. **Channel Access**: Limit `#approvals` channel to authorized personnel only
3. **Audit Trail**: All Slack approvals logged to `audit.jsonl` with user ID
4. **Timeout**: Use conservative timeouts (5 minutes) to prevent stale approvals
5. **Testing**: Test Slack integration in non-production environment first

## Cost

- **Slack**: Free tier supports up to 10,000 messages/month
- **Typical usage**: 5-10 approval requests per day = ~200/month (well under limit)

## Next Steps

- Set up multiple approval channels for different risk levels
- Add approval workflow with multiple approvers required
- Integrate with PagerDuty for critical operations
- Add approval history dashboard

## Support

For issues or questions:
- GitHub: https://github.com/innago-property-management/phlegyas/issues
- Documentation: See `examples/slack_integration.py` for implementation details
