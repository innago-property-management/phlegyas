# Cygnus Spawn-Time Contract for Blocking Approval Hook

When Cygnus spawns a worker agent that should use phlegyas in blocking mode,
it must inject environment variables and a settings override.

## Required Environment Variables

```bash
export PHLEGYAS_APPROVAL_MODE=blocking
export CYGNUS_SUPERVISOR_ID=<supervisor_session_id>
export CYGNUS_WORKFLOW_ID=<workflow_uuid>
export CYGNUS_AGENT_ID=<worker_agent_id>
export CYGNUS_TASK_ID=<task_id>
```

## Optional Environment Variables

```bash
# Supervisor API for fast HTTP notification (default: http://localhost:4000)
export CYGNUS_API_URL=http://localhost:4000

# Override default timeouts (seconds)
export PHLEGYAS_SUPERVISOR_TIMEOUT_SECONDS=60   # default
export PHLEGYAS_HUMAN_TIMEOUT_SECONDS=120       # default
export PHLEGYAS_POLL_INTERVAL_SECONDS=2          # default
```

## Settings Override

Write `.claude/settings.local.json` to the worker's cwd with a 300-second
hook timeout (the global default is 5 seconds, too short for blocking):

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "/path/to/phlegyas/.venv/bin/python3 ~/.claude/hooks/phlegyas-guardrail.py",
        "timeout": 300000
      }]
    }]
  }
}
```

## Behavior Summary

| Condition | Hook Behavior |
|-----------|---------------|
| `PHLEGYAS_APPROVAL_MODE` unset or `advisory` | Advisory mode — Tier 3 passes through |
| `PHLEGYAS_APPROVAL_MODE=blocking` + supervisor env set | Blocks on Tier 3, notifies supervisor via HTTP, polls for resolution |
| `PHLEGYAS_APPROVAL_MODE=blocking` + no supervisor env | Blocks on Tier 3, skips supervisor phase, goes directly to human escalation |
| Tier 1 dangerous | Always exit 1 (deny) regardless of mode |
| Tier 2 safe | Always exit 0 (approve) regardless of mode |

## Delegation Chain

```
Worker tool call → phlegyas hook
  ├── Tier 1 dangerous → exit 1 (instant deny)
  ├── Tier 2 safe → exit 0 (instant approve)
  └── Tier 3 ambiguous (blocking mode):
      ├── Write pending approval to ~/.claude/pending-approvals/
      ├── POST to CYGNUS_API_URL/api/approvals/notify
      ├── Poll file for supervisor decision (60s default)
      │   ├── Supervisor approves → exit 0
      │   ├── Supervisor denies → exit 2
      │   └── Timeout → escalate to human
      └── Notify human via Slack + macOS notification
          ├── Poll file for human decision (120s default)
          │   ├── Human approves → exit 0
          │   └── Human denies → exit 2
          └── All-timeout → exit 2 (deny, fail closed)
```

## Supervisor Response

The supervisor calls `supervisor_approve` MCP tool with the `request_id`:

```python
await mcp__phlegyas__supervisor_approve(
    request_id="<from notification>",
    decision="approve",  # or "deny" or "escalate_to_human"
    supervisor_id="<CYGNUS_SUPERVISOR_ID>",
    workflow_id="<CYGNUS_WORKFLOW_ID>",
    reasoning="Operation aligns with workflow objectives"
)
```

This resolves the file in `~/.claude/pending-approvals/`, which the polling
hook detects and unblocks.
