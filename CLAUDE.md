# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**claude-permission-approver** is a FastMCP server that provides AI-powered permission approval for Claude Code using a three-tier intelligent evaluation system. It enables autonomous multi-agent workflows by automatically approving safe operations while blocking dangerous ones.

**Core Architecture:** Three-tier evaluation pipeline
- **Tier 1 (Dangerous):** Instant denial using regex pattern matching for destructive operations
- **Tier 2 (Safe):** Instant approval for known-safe operations (read-only tools, tests, builds)
- **Tier 3 (AI):** Claude AI evaluation for ambiguous cases with confidence thresholds

## Task Agent Permission Validation

**For Task agents running autonomous workflows**, use the `validate_operation` tool before risky operations:

### When to Validate

Validate before executing:
- **Bash commands** that aren't obviously safe (anything beyond ls, git status, etc.)
- **Edit/Write operations** to files outside your working scope
- **Any operation** you're uncertain about

### How to Use

```python
# Before executing a potentially risky operation
validation = await mcp__claude_permission_approver__validate_operation(
    tool_name="Bash",
    input={"command": "npm install new-package", "description": "Install dependency"}
)

# Handle the response
if validation["status"] == "approved":
    # Proceed with operation
    result = bash("npm install new-package")
elif validation["status"] == "denied":
    # Skip operation and report in final output
    report(f"❌ SKIPPED: {validation['reason']}")
elif validation["status"] == "needs_human":
    # Mark for parent session approval
    report(f"🔐 NEEDS_APPROVAL [request_id: {validation['request_id']}]")
    report(f"   Operation: {tool_name} {input}")
    report(f"   Reason: {validation['reason']}")
    report(f"   Confidence: {validation['confidence']}")
```

### Response Format

```json
{
  "status": "approved" | "denied" | "needs_human",
  "tier": "tier1_dangerous | tier2_safe | tier2_5_trusted_script | tier3_ai_approve | tier3_ai_deny | tier3_needs_human",
  "reason": "Explanation of decision",
  "confidence": 0.85,  // Only for tier3
  "request_id": "uuid"  // Only for needs_human
}
```

### Graceful Handling

**Best practice:** Skip operations that need human approval and report them in your final output:

```
Task completed with 2 operations requiring approval:

🔐 NEEDS_APPROVAL [request_id: abc-123]
   Operation: Bash command "curl -X POST https://api.prod.com/deploy"
   Reason: Production API modification requires human approval
   Confidence: 0.65

🔐 NEEDS_APPROVAL [request_id: def-456]
   Operation: Edit file ".env.production"
   Reason: Production configuration change
   Confidence: 0.72
```

The parent session can review these and either:
1. Add operations to allow list and re-run
2. Execute operations manually
3. Decide the operations aren't needed

## Development Commands

### Environment Setup
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
aut
# Install in editable mode
pip install -e .

# Install with dev dependencies (includes pytest)
pip install -e ".[dev]"

# Install with Slack integration
pip install -e ".[slack]"
```

### Testing
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_tier1_dangerous.py -v

# Run specific test by name
pytest tests/test_tier2_safe.py::test_safe_git_commands -v

# Run with coverage
pytest --cov=src --cov-report=html

# Run only unit tests (skip integration)
pytest -m unit

# Run only integration tests
pytest -m integration
```

### Running the MCP Server

```bash
# Run directly with Python (official MCP SDK)
python src/approver_mcp.py

# Legacy FastMCP server (backup)
python src/approver.py
```

### Code Quality
```bash
# Format code with Black
black src/ tests/

# Lint with Ruff
ruff check src/ tests/

# Auto-fix issues
ruff check --fix src/ tests/
```

## Architecture Details

### Three-Tier Evaluation Pipeline

**Flow:** `permissions__approve()` → Tier 1 → Tier 2 → Tier 2.5 → Tier 3 → Decision

1. **Tier 1: DangerousPatternDetector** (src/tier1_dangerous.py:12)
   - Regex-based pattern matching for immediate denial
   - Checks: destructive ops, production patterns, credentials, dangerous git, network ops
   - Returns: `(is_dangerous: bool, reason: str | None)`

2. **Tier 2: SafeOperationDetector** (src/tier2_safe.py:12)
   - Regex-based pattern matching for immediate approval
   - Checks: read-only tools, safe bash commands (git/test/lint/build/info), safe directories
   - Returns: `(is_safe: bool, category: str | None)`

3. **Tier 2.5: ScriptTrustStore** (src/tier2_5_trust.py:54)
   - TOFU (Trust On First Use) with SHA-256 content hashing
   - Human trusts a script once via `claude-trust` CLI; auto-approves if hash matches
   - Hash mismatch or missing file → falls through to Tier 3
   - Persistent store at `~/.claude/trusted-scripts.json`
   - Returns: `(is_trusted: bool, category: str | None)`

4. **Tier 3: AIEvaluator** (src/tier3_ai.py:26)
   - Claude AI evaluation for ambiguous cases
   - Uses Haiku 4.5 (default) or Sonnet models
   - Returns: `(decision: str, evaluation: EvaluationResult)` where decision is "allow", "deny", or "ask_user"
   - Applies confidence thresholds to final decision

### Main Entry Point

**src/approver_mcp.py** - Official MCP SDK server with five tools:
- `permissions__approve` - Main permission gate (`allow`/`deny` for `--permission-prompt-tool`)
- `validate_operation` - Pre-flight check for Task agents (`approved`/`denied`/`pending`)
- `submit_approval` - Human decision submission for pending approvals
- `get_pending_approvals` - List pending approvals (filterable by workflow/agent ID)
- `get_approval_stats` - Audit log statistics

### Audit Logging

**Format:** JSONL (one JSON object per line) in `audit.jsonl`
- Fields: timestamp, tool_name, input, decision, tier, reason, confidence
- Read via: `get_approval_stats` MCP tool or `cat audit.jsonl | jq '.'`

## Configuration

### Environment Variables

**Required:**
- `ANTHROPIC_API_KEY` - Your Anthropic API key

**Optional (with defaults):**
- `CLAUDE_MODEL` (default: `claude-haiku-4-5-20251001`) - Model for AI evaluation
- `APPROVAL_CONFIDENCE_THRESHOLD` (default: `0.8`) - Min confidence for auto-approval
- `DENIAL_CONFIDENCE_THRESHOLD` (default: `0.2`) - Max confidence for auto-denial
- `LOG_LEVEL` (default: `INFO`) - Python logging level
- `ENABLE_AUDIT_LOG` (default: `true`) - Enable audit logging
- `AUDIT_LOG_FILE` (default: `audit.jsonl`) - Audit log file path
- `CACHE_TTL_SECONDS` (default: `3600`) - TTL for Tier 3 decision cache
- `ENABLE_APPROVAL_CACHE` (default: `true`) - Enable caching of Tier 3 decisions
- `PENDING_TTL_SECONDS` (default: `1800`) - TTL for pending human approvals

**Project Context (improves AI decisions):**
- `PROJECT_NAME` (default: `Unknown`) - Your project name
- `PROJECT_TYPE` (default: `Software project`) - Project type
- `CURRENT_TASK` (default: `Development work`) - Current task description

### Permission Configuration

**The MCP permission approver works ONLY in print mode (`-p` flag).** For interactive sessions and Task agents, use static allow/deny rules.

#### Option 1: Static Allow/Deny Rules (Recommended for Interactive Sessions)

Create `.claude/settings.local.json` in your project:

```json
{
  "permissions": {
    "allow": [
      "Read",
      "Glob",
      "Grep",
      "WebFetch",
      "WebSearch",
      "Edit",
      "Write",
      "Bash(git *)",
      "Bash(ls *)",
      "Bash(npm test*)",
      "Bash(pytest*)",
      "Bash(dotnet test*)"
    ],
    "deny": [
      "Bash(rm -rf*)",
      "Bash(git push --force*)",
      "Bash(DROP TABLE*)"
    ]
  }
}
```

See `.claude/settings.local.json` in this project for a complete Tier 2 allow list.

#### Option 2: CLI Flag for Print Mode (Non-Interactive)

The MCP permission approver works in print mode with explicit flag:

```bash
claude -p "Your task here" \
  --permission-prompt-tool mcp__claude-permission-approver__permissions__approve
```

**Note:** Task agents and interactive sessions do NOT use this flag.

## Script Trust Store (Tier 2.5)

Trust scripts for auto-approval using content hashing (TOFU model).

### CLI: `claude-trust`
```bash
# Trust a script (computes SHA-256, adds to store)
claude-trust /path/to/script.sh --note "Morning schedule"

# List all trusted scripts
claude-trust --list

# Revoke trust
claude-trust --revoke /path/to/script.sh

# Verify all hashes still match
claude-trust --verify
```

### How It Works
- Human trusts a script once → SHA-256 hash stored in `~/.claude/trusted-scripts.json`
- On execution, content hash is verified → match = auto-approve, mismatch = Tier 3 AI eval
- Tier 1 dangerous patterns still run first (trust store cannot bypass destructive op detection)
- Changes logged to `~/.claude/trusted-scripts.log` + best-effort Pieces OS checkpoint

### Adding Trusted Scripts
Edit `~/.claude/trusted-scripts.json` directly or use `claude-trust` CLI. The store is a simple JSON allowlist with 0600 file permissions.

## Testing Strategy

**276 tests, 100% passing.**

**Test Files:**
- `tests/test_tier1_dangerous.py` - Dangerous pattern detection (32 tests)
- `tests/test_tier2_safe.py` - Safe operation detection (79 tests)
- `tests/test_tier2_5_trust.py` - Script trust store (27 tests)
- `tests/test_tier3_ai.py` - AI evaluation logic (32 tests)
- `tests/test_c3_prompt_injection.py` - Prompt injection hardening (34 tests)
- `tests/test_validate_operation.py` - Task agent validation workflow (23 tests)
- `tests/test_approver.py` - Integration tests (18 tests)
- `tests/conftest.py` - Shared fixtures and test data

**Key Fixtures (conftest.py):**
- `mock_env_vars` - Sets up test environment variables
- `dangerous_bash_commands` - Collection of commands that should be denied
- `safe_*_commands` - Collections of safe commands (git, test, lint, build, info, install)
- `mock_anthropic_response` - Factory for mocking AI text responses (legacy)
- `mock_anthropic_tool_use_response` - Factory for mocking AI tool_use responses (current)

**Markers:**
- `@pytest.mark.unit` - Unit tests for individual components
- `@pytest.mark.integration` - Integration tests for multi-tier flow
- `@pytest.mark.asyncio` - Tests using async/await

## Adding New Patterns

### Adding Dangerous Patterns
Edit `src/tier1_dangerous.py`:
1. Add regex pattern to appropriate constant (e.g., `DESTRUCTIVE_PATTERNS`)
2. Add test case to `tests/test_tier1_dangerous.py`

### Adding Safe Patterns
Edit `src/tier2_safe.py`:
1. Add regex pattern to appropriate constant (e.g., `SAFE_GIT_PATTERNS`)
2. Add test case to `tests/test_tier2_safe.py`

### Modifying AI Evaluation
Edit `src/tier3_ai.py`:
1. Update `_build_evaluation_prompt()` for prompt changes (src/tier3_ai.py:103)
2. Update `_apply_thresholds()` for threshold logic changes (src/tier3_ai.py:199)

## Common Development Tasks

### Debugging Permission Decisions
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python src/approver_mcp.py

# Review audit log
cat audit.jsonl | jq '.'

# Filter by tier
cat audit.jsonl | jq 'select(.tier == "tier3_ai_approve")'
```

### Testing AI Evaluation Locally
```python
from src.tier3_ai import AIEvaluator

evaluator = AIEvaluator(
    model="claude-haiku-4-5-20251001",
    approval_threshold=0.8
)

decision, evaluation = await evaluator.evaluate(
    "Bash",
    {"command": "npm install lodash"}
)
print(f"Decision: {decision}")
print(f"Reasoning: {evaluation.reasoning}")
print(f"Confidence: {evaluation.confidence}")
```

### Running with Claude Code

**With Persistent Configuration (Recommended):**
```bash
# Just run normally - permission approver is auto-configured
claude -p "Your task here"
```

**With CLI Flag (Manual Override):**
```bash
# Use permission approver for all permission prompts
claude --permission-prompt-tool mcp__claude-permission-approver__permissions__approve \
  -p "Your task here"
```

## Troubleshooting

### Still Seeing Permission Prompts in Interactive Sessions?

**Problem:** You're getting permission prompts for safe operations like Read, Glob, or git status.

**Solution:** The MCP permission approver only works in print mode (`-p`). For interactive sessions and Task agents, use static allow rules in `.claude/settings.local.json`:

```json
{
  "permissions": {
    "allow": [
      "Read",
      "Glob",
      "Grep",
      "WebFetch",
      "Edit",
      "Write",
      "Bash(git *)",
      "Bash(ls *)"
    ]
  }
}
```

**Verify static rules are working:**
- Operations in the allow list should not prompt
- Check `.claude/settings.local.json` exists in your project
- Restart Claude Code session to pick up changes

### MCP Permission Approver Not Working?

**Problem:** Using `--permission-prompt-tool` but not seeing audit log entries.

**Solution:** The flag only works in print mode:

```bash
# ✅ Works - print mode
claude -p "List files" --permission-prompt-tool mcp__claude-permission-approver__permissions__approve

# ❌ Doesn't work - interactive mode (use static rules instead)
claude
```

**Verify it's working in print mode:**
```bash
# Check audit log after running a print mode command
tail /Volumes/Repos/claude-permission-approver/audit.jsonl

# Should see entries like:
# {"decision": "allow", "tier": "tier2_safe", "tool_name": "Bash", ...}
```

## Project Dependencies

**Core:**
- `mcp` - Official MCP SDK (used by `approver_mcp.py`)
- `fastmcp>=0.2.0` - FastMCP framework (used by legacy `approver.py`)
- `anthropic>=0.39.0` - Anthropic API client for AI evaluation
- `pydantic>=2.0.0` - Data validation and settings management
- `python-dotenv>=1.0.0` - Environment variable management

**Dev:**
- `pytest>=8.0.0` - Testing framework
- `pytest-asyncio>=0.23.0` - Async test support
- `pytest-mock>=3.14.0` - Mocking utilities

**Optional:**
- `slack-sdk>=3.31.0` - Slack integration for human escalation (not yet implemented)

## File Structure

```
src/
  approver_mcp.py          # Main MCP server (official SDK) with permissions__approve() tool
  approver.py              # Legacy FastMCP server
  tier1_dangerous.py       # Tier 1: Dangerous pattern detection (regex-based)
  tier2_safe.py            # Tier 2: Safe operation detection (regex-based)
  tier2_5_trust.py         # Tier 2.5: Script trust store (TOFU + content hashing)
  tier3_ai.py              # Tier 3: AI evaluation with Claude (Haiku/Sonnet)
  trust_cli.py             # CLI for managing trusted scripts (claude-trust)

tests/
  conftest.py                # Shared fixtures and test data
  test_tier1_dangerous.py    # Tier 1 tests
  test_tier2_safe.py         # Tier 2 tests
  test_tier2_5_trust.py      # Tier 2.5 tests
  test_tier3_ai.py           # Tier 3 tests
  test_validate_operation.py # Validate operation (Task agent) tests
  test_approver.py           # Integration tests

audit.jsonl              # Audit log (JSONL format, gitignored)
.env                     # Environment variables (gitignored)
.env.example             # Example environment configuration
```
