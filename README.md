# Phlegyas

<div align="center">
  <img src="docs/images/phlegyas-hero.jpg" alt="Phlegyas ferrying Dante and Virgil across the Styx -- 19th century stained glass, Museo Poldi Pezzoli, Milan" width="400">
  <br>
  <em>Phlegyas ferrying Dante and Virgil across the Styx</em>
  <br>
  <sub>19th century stained glass, Museo Poldi Pezzoli, Milan. Photo: <a href="https://commons.wikimedia.org/wiki/File:Milano_-_Vetrata_ottocentesca_del_Museo_Poldi_Pezzoli_-_Caronte_-_Foto_Giovanni_Dall%27Orto_-_14-sept-2003.jpg">Giovanni Dall'Orto</a> (Attribution license)</sub>
</div>

[![CI](https://github.com/innago-property-management/phlegyas/actions/workflows/ci.yml/badge.svg)](https://github.com/innago-property-management/phlegyas/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/phlegyas.svg)](https://pypi.org/project/phlegyas/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Automated approval system for AI agents** -- a 3.5-level permission gate that lets agents use tools safely while keeping humans in control.

> *Named for the ferryman of the Styx in Dante's Inferno -- the gatekeeper who decides who crosses.*

## Why

AI agents need to run tools -- read files, execute commands, make API calls. But unrestricted tool access is dangerous, and requiring human approval for every action makes agents useless.

Phlegyas solves this with a layered permission model:

- **95% of operations auto-approve in <1ms** -- safe, known patterns need zero human input
- **Dangerous operations are blocked instantly** -- `rm -rf`, `DROP TABLE`, force-push to main
- **New scripts earn trust progressively** -- first use needs approval, then the content hash is stored so identical future calls auto-approve
- **Grey areas get AI evaluation** -- an LLM judge assesses ambiguous requests against project context
- **Truly risky operations reach a human** -- via Slack, macOS notification, or file queue
- **Every decision is audited** -- full JSONL ledger of what was approved, denied, and why

Phlegyas works as a Claude Code [pre-tool-use hook](https://docs.anthropic.com/en/docs/claude-code/hooks) (fast, local guardrail) or as an MCP server (full feature set including AI evaluation and Slack escalation).

## The 3.5-Level Model

| Level | Name | What happens | Speed | Cost |
|-------|------|-------------|-------|------|
| **1** | Dangerous patterns | Instant deny via regex -- destructive ops, production targets, credential exposure | <1ms | $0 |
| **1.5** | Hash-based trust (TOFU) | First call to a new script needs approval; SHA-256 hash stored so future identical calls auto-approve | <1ms | $0 |
| **2** | Safe patterns | Instant allow via regex -- read-only tools, test runners, linters, builds | <1ms | $0 |
| **3** | AI evaluation | Claude (Haiku by default) judges ambiguous cases against project context and confidence thresholds | 200-500ms | ~$0.001 |
| **3+** | Human escalation | When AI confidence is low, the decision is parked for a human via Slack, macOS notification, or file queue | async | $0 |

The levels are evaluated in order: dangerous check first (nothing can bypass it), then trust store, then safe patterns, then AI, then human. This means a trusted script that suddenly contains `rm -rf /` will still be blocked by Level 1.

### Hash-Based Trust: The Clever Bit

Most approval systems are all-or-nothing: either a tool is on the allow-list, or it isn't. Phlegyas adds a middle ground inspired by SSH's "Trust On First Use" (TOFU) model:

1. An agent tries to run `scripts/deploy-staging.sh` for the first time
2. Phlegyas doesn't recognize it -- falls through to AI evaluation or human approval
3. The human approves it (or the AI does, with high confidence)
4. Phlegyas computes a SHA-256 hash of the script's contents and stores it
5. Next time the agent runs the same script, the hash matches -- instant auto-approve
6. If someone modifies the script, the hash changes -- back to evaluation

This makes agents genuinely useful with custom tooling. The first call to any new script or tool needs a one-time approval, but after that it's trusted as long as the content hasn't changed. You get the safety of explicit approval with the speed of an allow-list.

```bash
# Trust a script (one-time)
phlegyas-trust /path/to/script.sh --note "Staging deploy script"

# Or let the approval flow handle it automatically -- approve once, trusted forever
# (until the script changes)

# Management commands
phlegyas-trust --list                       # See all trusted scripts
phlegyas-trust --verify                     # Check all hashes still match
phlegyas-trust --revoke /path/to/script.sh  # Remove trust
```

## Quick Start

### Install

```bash
pip install phlegyas
```

> Install with Slack support: `pip install phlegyas[slack]`

### Option A: Pre-Tool-Use Hook (Recommended)

The simplest setup -- a Claude Code hook that evaluates every tool call through Levels 1 and 2:

1. Create `~/.claude/hooks/phlegyas-guardrail.py`:

```python
#!/usr/bin/env python3
import json, sys

def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, OSError):
        return

    tool_name = data.get("tool_name", "")
    input_data = data.get("input", {})
    if not tool_name:
        return

    try:
        from phlegyas.tier1_dangerous import DangerousPatternDetector
        from phlegyas.tier2_safe import SafeOperationDetector, SafePatternStore
    except ImportError:
        return

    dangerous_detector = DangerousPatternDetector()
    is_dangerous, reason = dangerous_detector.is_dangerous(tool_name, input_data)
    if is_dangerous:
        json.dump({"error": f"Blocked by phlegyas: {reason}"}, sys.stdout)
        sys.exit(1)

    safe_detector = SafeOperationDetector(user_store=SafePatternStore())
    is_safe, _ = safe_detector.is_safe(tool_name, input_data)
    if is_safe:
        return  # Pass through

    # Ambiguous: pass through (Level 3 AI not invoked for speed)

if __name__ == "__main__":
    main()
```

2. Wire into `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{
          "type": "command",
          "command": "python3 ~/.claude/hooks/phlegyas-guardrail.py",
          "timeout": 5000
        }]
      }
    ]
  }
}
```

### Option B: MCP Server (Full Feature Set)

For AI evaluation (Level 3), hash-based trust (Level 1.5), and Slack escalation:

1. Set your API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

2. Add to `~/.claude/mcp-servers.json`:

```json
{
  "mcpServers": {
    "phlegyas": {
      "command": "python",
      "args": ["-m", "phlegyas"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-your-key-here",
        "PROJECT_NAME": "Your Project Name",
        "PROJECT_TYPE": "Python web service",
        "CURRENT_TASK": "Building auth module"
      }
    }
  }
}
```

3. Run Claude Code with the permission tool:

```bash
claude --permission-prompt-tool mcp__phlegyas__permissions__approve \
  -p "Refactor the authentication service"
```

### Hook vs MCP Server

| Feature | Hook (PreToolUse) | MCP Server |
|---------|-------------------|------------|
| Level 1 (dangerous) + Level 2 (safe) | Yes | Yes |
| Level 1.5 (hash-based trust) | No | Yes |
| Level 3 (AI evaluation) | No | Yes |
| Slack escalation | No | Yes |
| Latency | <10ms | <1ms (Level 1/2), 200-500ms (Level 3) |
| Best for | Supervised agents, fast guardrail | Print mode (`-p`), full autonomy |

## What Gets Blocked, What Gets Through

### Level 1: Always Blocked

- **Destructive:** `rm -rf`, `DROP TABLE`, `DELETE FROM`, `TRUNCATE`, `format C:`
- **Production:** `production`, `prod-db`, `--env=prod`
- **Git:** `git push --force`, `git reset --hard`, `git push origin main`
- **Credentials:** `password=`, `API_KEY`, `AWS_SECRET`

### Level 2: Always Approved

**Read-only tools:** `Read`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, Firecrawl tools, JetBrains tools

**Safe bash commands:**
- Git: `status`, `log`, `diff`, `checkout -b feature/*`
- Tests: `npm test`, `dotnet test`, `pytest`, `cargo test`
- Linting: `eslint`, `dotnet format`, `black`, `prettier`
- Builds: `npm build`, `dotnet build`, `cargo build`
- Info: `ls`, `cat`, `grep`, `ps`, `env`
- Install: `npm install`, `pip install`, `dotnet restore`

**Safe file operations:** writes to `/tmp/`, `docs/research/`, `tests/`, `scripts/`; edits to project files (excluding `.env`, `secrets`, `credentials`)

### Level 3: AI Evaluates

Everything else goes to Claude AI (Haiku by default), which evaluates:
- Is the operation aligned with the current task?
- Is the risk minimal or well-contained?
- Is the operation reversible?

The AI returns `approve` (confidence >= 80%), `deny`, or `ask_user` (confidence too low -- escalate to human).

## Audit Ledger

Every decision is logged to `audit.jsonl`:

```json
{
  "timestamp": "2025-11-08T10:15:23.456Z",
  "tool_name": "Bash",
  "input": {"command": "git status"},
  "decision": "allow",
  "tier": "tier2_safe",
  "reason": "safe git operation",
  "confidence": null
}
```

Query with the `get_approval_stats` MCP tool or directly:

```bash
cat audit.jsonl | jq '.'
```

In a typical 8-hour coding session, expect ~250 requests: 95% auto-approved (Level 2), 2% blocked (Level 1), 4% AI-evaluated (Level 3). Total cost: ~$0.01.

## MCP Tools

The server exposes seven tools:

| Tool | Purpose |
|------|---------|
| `permissions__approve` | Main permission gate -- returns `allow`/`deny` for Claude Code's `--permission-prompt-tool` flag |
| `validate_operation` | Pre-flight check for Task agents -- returns `approved`/`denied`/`pending` with request IDs |
| `poll_approval` | Agent-oriented polling -- check resolution status of a pending `request_id` |
| `submit_approval` | Human decision submission for pending approvals (approve or deny by `request_id`) |
| `supervisor_approve` | Supervisor agent delegation -- approve/deny/escalate within workflow policy constraints |
| `get_pending_approvals` | List pending approvals awaiting human decision (filterable by `workflow_id`/`agent_id`) |
| `get_approval_stats` | Audit log statistics (totals, by-tier, by-tool breakdowns) |

## Slack Integration

When Level 3 returns `ask_user` and Slack is configured, phlegyas escalates the decision to a human via interactive Slack messages with Approve/Deny buttons.

```bash
pip install phlegyas[slack]
```

```bash
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token
SLACK_APPROVAL_CHANNEL=approvals
```

Auto-denies after 300 seconds (configurable via `SLACK_APPROVAL_TIMEOUT_SECONDS`). See `examples/SLACK_SETUP.md` for full setup guide.

## Architecture

```
Claude Code Tool Call
        |
        v
Level 1: Dangerous? --> YES --> DENY (instant)
        |
        v NO
Level 1.5: Trusted script? --> YES (hash matches) --> ALLOW (instant)
        |
        v NO
Level 2: Safe pattern? --> YES --> ALLOW (instant)
        |
        v NO
Level 3: AI evaluation
        |
        +--> approve (>= 80% confidence) --> ALLOW
        |
        +--> deny --> DENY
        |
        +--> ask_user --> Slack / macOS notification / file queue --> Human decides
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | **Required** | Your Anthropic API key (only needed for Level 3) |
| `CLAUDE_MODEL` | `claude-haiku-4-5-20251001` | Model for AI evaluation |
| `APPROVAL_CONFIDENCE_THRESHOLD` | `0.8` | Min confidence for auto-approval (0.0-1.0) |
| `DENIAL_CONFIDENCE_THRESHOLD` | `0.2` | Max confidence for auto-denial (0.0-1.0) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `ENABLE_AUDIT_LOG` | `true` | Enable audit logging |
| `AUDIT_LOG_FILE` | `audit.jsonl` | Audit log file path |
| `PROJECT_NAME` | `Unknown` | Your project name (improves AI context) |
| `PROJECT_TYPE` | `Software project` | Project type (e.g., "C# microservices") |
| `CURRENT_TASK` | `Development work` | Current task description |
| `CACHE_TTL_SECONDS` | `3600` | TTL for Level 3 decision cache |
| `ENABLE_APPROVAL_CACHE` | `true` | Enable caching of Level 3 decisions |
| `PENDING_TTL_SECONDS` | `1800` | TTL for pending human approvals |

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

575 tests covering all levels, prompt injection hardening, supervisor delegation, Slack integration, and end-to-end flows.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and known considerations around LLM-as-judge prompt injection.

## License

[MIT](LICENSE)

## Part of the Agent Infrastructure Trio

| Tool | Purpose |
|------|---------|
| [**AgentGit**](https://github.com/innago-property-management/stand-sure-ai) | Identity -- bot commits and pushes via GitHub App |
| **Phlegyas** (this repo) | Authorization -- permission gate for tool use |
| **Ratatoskr** *(coming soon)* | Capability -- agent tooling and coordination |
