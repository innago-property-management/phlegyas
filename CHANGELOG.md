# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-16

### Added

- **Tier 1:** Dangerous pattern detection — instant denial via regex matching for destructive operations, production patterns, credential exposure, and dangerous git commands
- **Tier 2:** Safe operation auto-approval — instant approval for read-only tools, safe bash commands (git, test, lint, build, info), and safe directories
- **Tier 2 (User-configurable):** `SafePatternStore` loads custom safe patterns from `~/.claude/safe-patterns.json` — augments built-in defaults, never replaces them
- **Tier 2.5:** Script trust store (TOFU model) — trust scripts once via `phlegyas-trust` CLI, auto-approve on SHA-256 hash match
- **Tier 3:** AI evaluation via Claude (Haiku/Sonnet) for ambiguous cases with confidence thresholds
- **Prompt injection hardening:** System/user prompt separation, random delimiters, input truncation, confidence caps, structured tool_use output, Tier 1 post-hoc re-check
- MCP server with five tools: `permissions__approve`, `validate_operation`, `submit_approval`, `get_pending_approvals`, `get_approval_stats`
- JSONL audit logging with credential masking
- 299 tests (100% passing)

[0.1.0]: https://github.com/innago-property-management/phlegyas/releases/tag/0.1.0
