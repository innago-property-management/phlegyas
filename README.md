# Claude Permission Approver

AI-powered permission approval system for Claude Code using three-tier intelligent evaluation.

## Overview

When running Claude Code with long-running tasks or multi-agent workflows, you need a way to approve operations autonomously while maintaining security. This MCP server provides intelligent permission approval that:

- **Blocks dangerous operations** instantly (Tier 1)
- **Auto-approves safe operations** instantly (Tier 2)
- **Trusts human-approved scripts** via content hashing (Tier 2.5)
- **Uses Claude AI** to evaluate ambiguous cases (Tier 3)
- **Escalates to humans** for high-risk operations (optional Slack integration)

## Why Use This?

### Problem

Claude Code's Task agents spawn separate processes that don't inherit parent session permissions. This causes:
- Permission prompts blocking autonomous execution
- Manual approval required for every web fetch, file write, etc.
- Inability to work remotely (away from MacBook)

### Solution

This permission-prompt-tool MCP server acts as a centralized approval system that:
-  **Autonomous**: 95% of operations approved instantly without human input
-  **Intelligent**: Claude AI evaluates ambiguous cases with project context
-  **Secure**: Dangerous operations (rm -rf, DROP TABLE, production changes) always blocked
-  **Remote-friendly**: Optional Slack integration for phone-based approval
-  **Auditable**: Full JSONL audit log of all decisions

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/innago-property-management/claude-permission-approver.git
cd claude-permission-approver

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .
```

### 2. Configuration

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings
nano .env
```

**Required:**
```bash
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

**Optional (with defaults):**
```bash
CLAUDE_MODEL=claude-haiku-4-5-20251001
APPROVAL_CONFIDENCE_THRESHOLD=0.8
LOG_LEVEL=INFO
ENABLE_AUDIT_LOG=true
```

### 3. MCP Server Configuration

Add to your `~/.claude/mcp-servers.json`:

```json
{
  "mcpServers": {
    "permission-approver": {
      "command": "python",
      "args": ["/path/to/claude-permission-approver/src/approver_mcp.py"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-your-key-here",
        "PROJECT_NAME": "Your Project Name",
        "PROJECT_TYPE": "C# microservices",
        "CURRENT_TASK": "Auth0 migration"
      }
    }
  }
}
```

### 4. Run Claude Code with Permission Tool

```bash
claude --permission-prompt-tool mcp__permission-approver__permissions__approve \
  -p "Refactor the authentication service to use Auth0"
```

## Three-Tier Evaluation System

### Tier 1: Dangerous Patterns (Always Block)

Instant denial for known-dangerous operations:

- **Destructive:** `rm -rf`, `DROP TABLE`, `DELETE FROM`, `TRUNCATE`, `format C:`
- **Production:** `production`, `prod-db`, `--env=prod`
- **Git:** `git push --force`, `git reset --hard`, `git push origin main`
- **Credentials:** `password=`, `API_KEY`, `AWS_SECRET`

**Response time:** <1ms
**Cost:** $0

### Tier 2: Safe Categories (Always Approve)

Instant approval for known-safe operations:

**Read-only tools:**
- `Read`, `Glob`, `Grep`, `WebFetch`, `WebSearch`
- All Firecrawl tools (`search`, `scrape`, `map`, `extract`)
- JetBrains tools (find, search, list)

**Safe bash commands:**
- Git: `status`, `log`, `diff`, `checkout -b feature/*`
- Tests: `npm test`, `dotnet test`, `pytest`, `cargo test`
- Linting: `eslint`, `dotnet format`, `black`, `prettier`
- Builds: `npm build`, `dotnet build`, `cargo build`
- Info: `ls`, `cat`, `grep`, `ps`, `env`
- Install: `npm install`, `pip install`, `dotnet restore`

**Safe file operations:**
- Writes to: `/tmp/`, `docs/research/`, `tests/`, `scripts/`
- Edits to: project files (excluding `.env`, `secrets`, `credentials`)

**Response time:** <1ms
**Cost:** $0

### Tier 2.5: Script Trust Store (TOFU)

Auto-approval for human-trusted scripts via content hashing:

- Human trusts a script once with `claude-trust /path/to/script.sh`
- SHA-256 hash of file contents stored in `~/.claude/trusted-scripts.json`
- On execution: hash verified → match = auto-approve, mismatch = Tier 3
- Tier 1 dangerous patterns still checked first (trust cannot bypass)
- Changes logged to `~/.claude/trusted-scripts.log`

```bash
# Trust a script
claude-trust /path/to/script.sh --note "Morning schedule"

# List, revoke, or verify
claude-trust --list
claude-trust --revoke /path/to/script.sh
claude-trust --verify
```

**Response time:** <1ms (file hash comparison)
**Cost:** $0

### Tier 3: AI Evaluation (Ambiguous Cases)

Claude AI evaluates based on project context:

**Evaluation criteria:**
- Is operation aligned with current task?
- Is risk minimal or well-contained?
- Is operation reversible?
- Is it clearly dangerous or unrelated?

**AI Decision:**
- `approve` - Safe and aligned (confidence >= 80%)
- `deny` - Dangerous or out of scope
- `ask_user` - Needs human judgment (confidence < 80%)

**Response time:** 200-500ms
**Cost:** ~$0.001 per evaluation (Haiku)

## Usage Examples

### Example 1: Research Task with WebFetch

```bash
# Task agent needs to fetch web content
Tool: WebFetch
Input: {"url": "https://anthropic.com/prompt-caching"}

# Result: APPROVED (Tier 2 - safe category)
# Reason: "Auto-approved: read-only tool: WebFetch"
```

### Example 2: Git Branch Creation

```bash
# Agent wants to create feature branch
Tool: Bash
Input: {"command": "git checkout -b feature/auth0-setup"}

# Result: APPROVED (Tier 2 - safe category)
# Reason: "Auto-approved: safe git operation"
```

### Example 3: Dangerous Operation

```bash
# Agent attempts dangerous command
Tool: Bash
Input: {"command": "rm -rf /tmp/cache"}

# Result: DENIED (Tier 1 - dangerous pattern)
# Reason: "Blocked: Destructive operation detected - rm\s+-rf"
```

### Example 4: Ambiguous Write Operation

```bash
# Agent wants to write to unusual location
Tool: Write
Input: {"file_path": "/etc/app/config.yaml", "content": "..."}

# Result: AI EVALUATION (Tier 3)
# Decision: "ask_user" (confidence: 0.65)
# Reason: "Write to system directory requires explicit approval"
# Final: DENIED (pending human approval)
```

## MCP Tools

The server exposes five tools:

| Tool | Purpose |
|------|---------|
| `permissions__approve` | Main permission gate — returns `allow`/`deny` for Claude Code's `--permission-prompt-tool` flag |
| `validate_operation` | Pre-flight check for Task agents — returns `approved`/`denied`/`pending` with request IDs |
| `submit_approval` | Human decision submission for pending approvals (approve or deny by `request_id`) |
| `get_pending_approvals` | List pending approvals awaiting human decision (filterable by `workflow_id`/`agent_id`) |
| `get_approval_stats` | Audit log statistics (totals, by-tier, by-tool breakdowns) |

## Audit Logging

All decisions are logged to `audit.jsonl` in JSONL format:

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

**View statistics:**

Use the `get_approval_stats` MCP tool, or query the audit log directly:

```bash
cat audit.jsonl | jq '.'
```

Output:
```json
{
  "total": 247,
  "approved": 235,
  "denied": 12,
  "by_tier": {
    "tier1_dangerous": 3,
    "tier2_safe": 230,
    "tier3_ai_approve": 5,
    "tier3_ai_deny": 7,
    "tier3_needs_human": 2
  },
  "by_tool": {
    "Bash": 145,
    "Read": 62,
    "WebFetch": 28,
    "Write": 12
  }
}
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | **Required** | Your Anthropic API key |
| `CLAUDE_MODEL` | `claude-haiku-4-5-20251001` | Model for AI evaluation (haiku/sonnet) |
| `APPROVAL_CONFIDENCE_THRESHOLD` | `0.8` | Min confidence for auto-approval (0.0-1.0) |
| `DENIAL_CONFIDENCE_THRESHOLD` | `0.2` | Max confidence for auto-denial (0.0-1.0) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `ENABLE_AUDIT_LOG` | `true` | Enable audit logging |
| `AUDIT_LOG_FILE` | `audit.jsonl` | Audit log file path |
| `PROJECT_NAME` | `Unknown` | Your project name (improves AI context) |
| `PROJECT_TYPE` | `Software project` | Project type (e.g., "C# microservices") |
| `CURRENT_TASK` | `Development work` | Current task description |
| `CACHE_TTL_SECONDS` | `3600` | TTL for Tier 3 decision cache (seconds) |
| `ENABLE_APPROVAL_CACHE` | `true` | Enable caching of Tier 3 decisions |
| `PENDING_TTL_SECONDS` | `1800` | TTL for pending human approvals (seconds) |

### Model Selection

**Haiku (Recommended):**
- Cost: ~$0.001 per evaluation
- Speed: 200-400ms
- Use for: Most operations

**Sonnet (Advanced):**
- Cost: ~$0.015 per evaluation
- Speed: 500-1000ms
- Use for: Complex operations requiring deeper reasoning

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run specific tier tests
pytest tests/test_tier1_dangerous.py -v
pytest tests/test_tier2_safe.py -v
pytest tests/test_tier3_ai.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

**Test suite: 233 tests (100% passing)**
- Tier 1: 32 tests (dangerous patterns)
- Tier 2: 79 tests (safe operations)
- Tier 2.5: 27 tests (script trust store)
- Tier 3: 33 tests (AI evaluation)
- Validate Operation: 23 tests (Task agent workflow)
- Integration: 18 tests (end-to-end)

## Performance & Cost

### Typical 8-Hour Coding Session

| Tier | Requests | % of Total | Avg Time | Total Cost |
|------|----------|------------|----------|------------|
| Tier 1 (Dangerous) | 5 | 2% | <1ms | $0 |
| Tier 2 (Safe) | 235 | 95% | <1ms | $0 |
| Tier 3 (AI) | 10 | 4% | 300ms | $0.01 |
| **Total** | **250** | **100%** | **~12ms avg** | **$0.01** |

**Key Metrics:**
- **95%+ auto-approved** - No human intervention needed
- **<20ms avg latency** - Minimal impact on agent speed
- **<$0.02/day** - Extremely cost-effective

## Slack Integration (Optional)

For high-risk operations requiring human approval, integrate with Slack:

See `examples/slack_integration.py` for implementation guide.

**Features:**
- Send approval requests to Slack channel
- Approve/Deny buttons in mobile app
- 5-minute timeout (auto-deny if no response)
- Full audit trail

## Architecture

```
Claude Code Permission Request
        |
        v
Is it dangerous? --> YES --> Deny immediately (Tier 1)
        |
        v NO
Is it safe? --> YES --> Approve immediately (Tier 2)
        |
        v NO
Is it a trusted script? --> YES (hash matches) --> Approve (Tier 2.5)
        |
        v NO / hash mismatch
Ask Claude AI to evaluate (Tier 3)
        |
        v
AI says "approve"? --> Approve with reasoning
        |
        v
AI says "deny"? --> Deny with reasoning
        |
        v
AI says "ask_user"? --> Park as pending (or deny if no escalation)
        |
        v
Human submit_approval --> Return decision
```

## Troubleshooting

### "ANTHROPIC_API_KEY environment variable not set"

**Solution:** Set your API key in `.env` file or environment:
```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### "AI evaluator unavailable, requires manual approval"

**Problem:** Anthropic API initialization failed
**Solution:** Check API key, network connection, and Anthropic service status

### All operations denied

**Problem:** MCP server not registered correctly
**Solution:** Verify `mcp-servers.json` configuration and server path

### Tier 2 not approving expected operations

**Problem:** Pattern not in safe category list
**Solution:** Review `src/tier2_safe.py` and add pattern, or file GitHub issue

## Security Best Practices

1. **Start conservative** - Begin with most operations requiring approval
2. **Review audit logs** - Regularly check `audit.jsonl` for unusual patterns
3. **Never auto-approve:**
   - Production deployments
   - Database schema changes
   - Credential operations
   - Main/master branch modifications
4. **Use project context** - Set `PROJECT_NAME` and `CURRENT_TASK` for better AI decisions
5. **Monitor costs** - Track Tier 3 usage via audit logs

## Contributing

Contributions welcome! Areas for improvement:

- Additional safe operation patterns
- Improved AI evaluation prompts
- Slack/Teams/Discord integrations
- Web UI for approval management
- Machine learning for pattern detection

## License

MIT License - See LICENSE file for details

## Credits

Created by Christopher J. Anderson for autonomous Claude Code multi-agent workflows.

Inspired by the `--permission-prompt-tool` documentation and real-world needs for remote approval while maintaining security.
