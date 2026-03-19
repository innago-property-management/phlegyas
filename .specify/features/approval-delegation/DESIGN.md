# DESIGN.md: Approval Delegation

**Version:** 1.0
**Date:** 2026-03-19
**Status:** Design — alternatives evaluated, approach selected

---

## Design Question 1: Slack Approval Flow Completion for validate_operation

### Current State

`validate_operation` returns `status: "pending"` with a `request_id` and TTL. The Slack
`notify_pending` path posts a fire-and-forget notification with the `request_id` in a context
block. The human is told to call `submit_approval`, but:

- The subordinate agent has no way to know when `submit_approval` is called.
- The agent cannot block waiting without implementing its own polling loop.
- There is no structured guidance in the phlegyas API for "how does an agent resume?"

### Alternatives Considered

#### Alternative A: Pure Polling (Extend `get_pending_approvals`)

Agents poll `get_pending_approvals(request_id=<id>)` on a timer. When the human calls
`submit_approval`, the pending record transitions from `status: "pending"` to `status: "approved"`
or `status: "denied"`. The next poll sees the resolved state.

**Problem:** The current `pending_approvals` dict removes the record when `submit_approval` is
called (line 915 of `approver_mcp.py`: `pending_approvals.pop(request_id)`). The agent would need
to poll before the record is removed, creating a race condition. More fundamentally, once a record
is gone, polling returns "not found" — which is indistinguishable from expiry or never-existing.

**Verdict:** Viable with one change: keep resolved records in the dict for a short TTL after
resolution (e.g., 300 seconds). Add `resolved_at` and `resolution` fields to `PendingApproval`.
This is a minimal, non-breaking change.

#### Alternative B: New `poll_approval` Tool

A dedicated `poll_approval(request_id)` MCP tool that returns the current status of a specific
request_id, including resolved decisions. Semantically cleaner than filtering `get_pending_approvals`
and gives agents a clear, single-purpose API.

**Verdict:** Preferred over Alternative A. The separation of concerns is cleaner. `get_pending_approvals`
remains a human-oriented list view; `poll_approval` is the agent-oriented "has my specific request
been decided?" check. Adding one MCP tool is a non-breaking additive change.

#### Alternative C: Blocking poll via asyncio.Event

When an agent calls `validate_operation` and gets `pending`, it can call a new
`await_approval(request_id, timeout_seconds)` tool that blocks (using asyncio.Event) until the
human submits a decision or the timeout expires. This mirrors how `permissions__approve` + Slack
works today.

**Problem:** MCP tool calls have an implicit timeout governed by the Claude Code session. A
blocking tool call for 1800 seconds (default TTL) would hang the agent's MCP connection. The MCP
SDK and Claude Code are not designed for long-blocking tool calls. This would also couple the
phlegyas server's asyncio event loop to the agent's session lifecycle in ways that are fragile.

**Verdict:** Rejected. Too much architectural coupling for uncertain benefit. Polling is sufficient.

### Selected Approach: Alternative B — `poll_approval` Tool

**New MCP tool: `poll_approval`**

```
Input:  { "request_id": "uuid" }
Output: {
    "found": true,
    "status": "pending" | "approved" | "denied" | "expired",
    "decision": "approve" | "deny" | null,
    "decided_by": "human:<id>" | "supervisor:<id>" | null,
    "decided_at": "<iso8601>" | null,
    "reason": "<string>",
    "ttl_remaining_seconds": 847
}
```

**Behavior change to `submit_approval`:** Instead of immediately removing the record from
`pending_approvals`, move it to a short-lived `resolved_approvals` dict with a 300-second TTL.
`poll_approval` checks both dicts.

**Agent resumption pattern:**

```python
result = await validate_operation(tool_name="Bash", input={...})
if result["status"] == "pending":
    request_id = result["request_id"]
    # Continue with other non-blocked work...
    # Periodically poll:
    while True:
        poll = await poll_approval(request_id=request_id)
        if poll["status"] != "pending":
            if poll["status"] == "approved":
                # Resume the blocked operation
            else:
                # Report skipped operation
            break
        await asyncio.sleep(30)  # Poll every 30s
```

**Why not push notification to agent?** MCP is a request-response protocol; phlegyas cannot
initiate a push to an agent. The agent must poll. File-queue (Design Question 2) provides an
out-of-band signal that agents can use as a faster polling alternative.

---

## Design Question 2: Non-Slack Notification Channels

### Current State

When Slack is not configured and Tier 3 returns `ask_user`:
- `permissions__approve`: silently denies, logs `tier3_needs_human`, returns `{"behavior": "deny"}`.
- `validate_operation`: creates a `PendingApproval` record but notifies nobody. The record sits in
  memory until it expires.

The human has no indication anything needs their attention unless they proactively check the audit
log or `get_pending_approvals`.

### Alternatives Considered

#### Alternative A: macOS osascript Notifications Only

Use `osascript -e 'display notification "..." with title "..."'` for a native macOS notification.
Simple, zero dependencies, requires no setup.

**Problem 1:** osascript notifications are ephemeral — they disappear from the notification center
if dismissed. The human could miss the notification entirely (screen locked, notification
dismissed, DND mode).
**Problem 2:** macOS-only. Linux users get nothing.
**Problem 3:** `permissions__approve` blocking behavior: the osascript notification fires but
the blocking call still times out and auto-denies before a human can react unless the TTL is
generously long. For `validate_operation`, the notification fires but the record expires.
**Verdict:** Good complement to other channels but insufficient alone.

#### Alternative B: File-Based Queue (~/.claude/pending-approvals/)

Write a JSON file per pending approval to `~/.claude/pending-approvals/<request_id>.json`. When
`submit_approval` is called, delete or update the file. The file persists through MCP server
restarts (unlike the in-memory dict). Other processes (Pharos, scripts, Cygnus supervisor) can
watch the directory with `fswatch` or poll it.

**Strengths:**
- Cross-platform (macOS, Linux)
- Survives MCP server restart (the in-memory dict does not)
- Can be polled by external processes without going through MCP
- Pharos Phase 3 integration can read this directory directly
- Human-readable: `ls ~/.claude/pending-approvals/` shows what's waiting
- Other Claude Code sessions can submit approvals via MCP without needing Slack

**Weaknesses:**
- Requires disk I/O on every pending creation and resolution
- File permissions: 0644 means other local users on the machine can read pending approval content
  (may contain partial command data). For a personal workstation this is acceptable; for multi-user
  servers it needs documentation.
- Does not actively notify the human — just persists the request.

**Verdict:** Strong choice for durability and inter-process communication. Should be combined with
an active notification channel.

#### Alternative C: `say` + Home-Notify (Hue Lights)

Use `say "Phlegyas needs approval. Check your terminal."` and `notify_human(message, "warning")`
via the home-notify MCP server (already in CLAUDE.md conventions).

**Problem:** `notify_human` is a separate MCP tool — phlegyas cannot call it directly (it is in a
different MCP server). `say` is macOS-only and requires the MCP server to have audio access.
**Verdict:** These are good mechanisms for the *user's session* to invoke, but phlegyas cannot
call them from within the approval flow. Document them as manual invocation patterns, not built-in
channels.

#### Alternative D: Configurable Notification Command (Shell Hook)

Allow users to configure `PHLEGYAS_NOTIFY_COMMAND="osascript -e '...'"` in their `.env`. When
a pending approval is created, phlegyas executes this command as a subprocess. This is the most
flexible approach.

**Strengths:**
- User-defined: works with any notification system (osascript, libnotify, ntfy, a custom script)
- No phlegyas-level dependencies
- macOS and Linux compatible
- Can integrate with Hue lights via `home-notify` CLI if one exists

**Weaknesses:**
- Security: arbitrary command execution from an env var. Must be carefully sandboxed.
  Specifically: only execute commands from a fixed whitelist or require the command to be
  a path to a pre-existing file (not a shell string with pipes/redirects).
- UX: requires setup; no-op by default.
- Testing: harder to test than built-in channels.

**Verdict:** Best long-term extensibility option, but needs careful security design. Defer the
general case; implement a specific macOS notification path in v0.3.0.

### Selected Approach: Layered Channels (B + osascript as built-in + D as future)

**Layer 1: File-Queue (primary, cross-platform)**

- When `status: pending` is created, write `~/.claude/pending-approvals/<request_id>.json`
- File format:
  ```json
  {
    "request_id": "uuid",
    "tool_name": "Bash",
    "input_summary": "npm install some-package",
    "reason": "AI reasoning text",
    "confidence": 0.65,
    "workflow_id": "optional",
    "agent_id": "optional",
    "created_at": "ISO8601",
    "expires_at": "ISO8601",
    "status": "pending"
  }
  ```
- `input_summary` is a truncated (100 char) sanitized string, not full input, to limit
  information exposure.
- File permissions: 0644 (readable by tools watching the directory).
- When `submit_approval` or TTL expiry resolves the request, update `status` in the file and
  remove it after 60 seconds (soft delete: lets external pollers see the resolution).

**Layer 2: macOS osascript notification (opt-in, default on when not in CI)**

- New env var: `PHLEGYAS_NOTIFY_MACOS` (default: `true` if `sys.platform == "darwin"`)
- When a pending approval is created, spawn `osascript -e 'display notification ...'`
  as a background subprocess (non-blocking, fire-and-forget).
- If subprocess fails (non-Mac, no access), silently ignore.

**Channel priority matrix:**

| Slack configured | macOS | File-queue behavior |
|-----------------|-------|---------------------|
| Yes | Yes | File-queue + osascript (Slack handles blocking approve, file-queue for validate) |
| Yes | No | File-queue only (Slack handles blocking approve) |
| No | Yes | File-queue + osascript |
| No | No | File-queue only; permissions__approve still auto-denies |

**Open question for implementation:** For `permissions__approve` with no Slack and no blocking
channel, should we park the request in the file-queue and block waiting for file-based resolution?
This would require a polling loop inside the MCP handler, which is architecturally unclean. The
conservative choice is to retain the auto-deny for `permissions__approve` when Slack is absent, and
focus the file-queue on `validate_operation` only. See PLAN.md for the phased decision.

---

## Design Question 3: Supervisor Agent Delegation

### Trust Model Analysis

A "supervisor" in the Cygnus context is a Claude Code session (typically running in a tmux pane)
that spawns worker agents via the Task tool. The supervisor has:

- Full context about the current workflow and task objectives
- Knowledge of which operations are intentional vs. unexpected
- The `workflow_id` and `agent_id` values passed to `validate_operation`
- Authority (by design) to make decisions on behalf of the workflow

A supervisor should be able to approve pending operations from workers it spawned, subject to
policy constraints.

### Alternatives Considered

#### Alternative A: Extend `submit_approval` with `approver_type`

Add an optional `approver_type: "supervisor" | "human"` field to `submit_approval`. When
`approver_type: "supervisor"` is provided, enforce delegation policy constraints before accepting
the approval.

**Strengths:**
- No new MCP tool; existing callers unaffected.
- Supervisor and human approvals flow through the same code path.
- `approver_id` already exists; supervisor sets it to its own agent ID.

**Weaknesses:**
- Policy enforcement in `submit_approval` becomes complex; the function currently does no
  policy validation.
- No way for the system to distinguish an agent incorrectly claiming to be "supervisor" from
  an actual supervisor (unless we add token-based authentication, which is out of scope).
- Delegation constraints (confidence floor, category ceiling) are checked too late — after the
  pending approval was created with whatever confidence the AI assigned.

**Verdict:** Acceptable but messy. Better as a starting point than as a long-term design.

#### Alternative B: New `supervisor_approve` Tool with Policy Enforcement

A new MCP tool specifically for supervisor-agent approval decisions:

```
Input: {
    "request_id": "uuid",
    "decision": "approve" | "deny" | "escalate_to_human",
    "supervisor_id": "string",    // agent's identifier
    "workflow_id": "string",      // must match pending approval's workflow_id
    "reasoning": "string"         // supervisor's justification
}
```

Policy constraints enforced server-side:
1. `workflow_id` on the pending approval must match the supervisor's `workflow_id`.
2. Pending approval `tier` must not be `tier1_dangerous` (hard block).
3. Pending approval `category` must be `benign`, `moderate_risk`, or `high_risk` (not `critical`).
4. Pending approval `confidence` must be >= 0.3 (supervisors cannot approve near-zero confidence).
5. `supervisor_id` must not match `agent_id` on the pending approval (recursion guard).
6. If the pending approval has `supervisor_id` in `agent_id`, reject (a supervisor cannot approve
   its own prior actions even from a different "layer").

**Strengths:**
- Clear semantic separation: humans use `submit_approval`, supervisors use `supervisor_approve`.
- Policy constraints enforced at the tool level, not scattered through `submit_approval`.
- Audit trail has distinct tier labels (`tier3_supervisor_approved`, `tier3_supervisor_denied`).
- Allows `escalate_to_human` as a third decision — supervisor can explicitly punt to a human
  without denying.

**Weaknesses:**
- Adds a new MCP tool; clients need to know about it.
- Trust boundary problem (same as Alternative A): phlegyas cannot cryptographically verify that
  the caller is actually a supervisor vs. a rogue agent claiming supervisor identity.

**Verdict:** Preferred. The semantic clarity and enforcement at tool boundaries justifies a
separate tool.

#### Alternative C: Static Authorization Config

A `~/.claude/supervisor-policy.json` file listing authorized supervisor agent IDs and their
permitted approval scopes (confidence floor, allowed categories, allowed workflow_id patterns).
`submit_approval` checks this config before accepting a non-human approval.

**Strengths:**
- Human-curated allowlist: reduces risk of a rogue agent claiming supervisor identity.
- Can be updated by the human without restarting phlegyas.

**Weaknesses:**
- Supervisor IDs in Cygnus are often generated dynamically; static config is brittle.
- Adds operational complexity: user must manage a config file before spawning agents.
- Still does not prevent a rogue agent from knowing a legitimate supervisor's ID and impersonating
  it (MCP has no caller identity mechanism).

**Verdict:** Useful as an opt-in hardening layer on top of Alternative B, not a replacement.

### Trust Boundary Reality Check

MCP provides no caller authentication. Any agent that can call phlegyas MCP tools can call
`supervisor_approve`. The security model is therefore:

1. **Correctness guarantee:** Phlegyas enforces that the `workflow_id` matches, preventing
   cross-workflow approval pollution.
2. **Policy enforcement:** Confidence floor (0.3) and category ceiling (not `critical`) are
   enforced server-side.
3. **Audit trail:** Every supervisor approval is logged with `tier3_supervisor_approved` and
   the `supervisor_id`, `workflow_id`, and `reasoning`.
4. **Recursion guard:** `supervisor_id` != `agent_id` on the pending record.

This is analogous to the existing `ScriptTrustStore` model: a human-curated allowlist provides
trust signals, but the system is not a cryptographic boundary. The adversarial model for
`supervisor_approve` is: a malicious agent within the same workflow_id scope could approve
operations it should not. The defense is that Tier 1 is un-overridable and `critical` category
is un-overridable.

### Selected Approach: Alternative B — `supervisor_approve` Tool

**Audit tier labels:**

| Path | Tier Label |
|------|-----------|
| Supervisor approved | `tier3_supervisor_approved` |
| Supervisor denied | `tier3_supervisor_denied` |
| Supervisor escalated to human | `tier3_supervisor_escalated` |

**Revocation:** A human can revoke supervisor authority by calling a new `revoke_supervisor`
tool or by calling `submit_approval(request_id, decision="deny")` on a pending approval that
the supervisor has not yet acted on. The human's decision always takes precedence.

**Authority precedence:**
1. Human via `submit_approval` — highest authority
2. Supervisor via `supervisor_approve` — second
3. TTL expiry — auto-deny
4. No action — pending until expiry

---

## Data Model Changes

### PendingApproval Additions

```python
class PendingApproval:
    # ... existing fields ...

    # Resolution tracking (new fields)
    resolved_at: datetime | None = None
    resolved_by: str | None = None          # "human:<id>", "supervisor:<id>", "ttl_expiry"
    resolution: str | None = None           # "approved", "denied", "expired"

    # Supervisor delegation context (new field on creation)
    supervisor_id: str | None = None        # Set by supervisor when calling supervisor_approve
```

### New File: `~/.claude/pending-approvals/<request_id>.json`

Written atomically (write to `.tmp`, rename) to avoid partial reads.

### Resolved Approvals Buffer

New module-level dict `resolved_approvals: dict[str, PendingApproval]` with a 300-second TTL.
When `submit_approval` or `supervisor_approve` resolves a request, the record moves from
`pending_approvals` to `resolved_approvals`. `poll_approval` checks both. `cleanup_expired_pending`
also cleans `resolved_approvals`.

---

## New MCP Tools Summary

| Tool | Purpose | Caller |
|------|---------|--------|
| `poll_approval` | Check resolution status of a specific request_id | Subordinate agents |
| `supervisor_approve` | Approve/deny a pending request with delegation policy enforcement | Supervisor agents |

Existing tools retain full backward compatibility:
- `validate_operation` — unchanged interface; adds file-queue write on `pending` status
- `submit_approval` — unchanged interface; adds `resolved_approvals` buffer and file-queue update
- `get_pending_approvals` — unchanged; continues to return in-memory pending records
- `permissions__approve` — unchanged; adds optional macOS notification on `ask_user` path

---

## Security Considerations

### File Queue Information Exposure

The `input_summary` field in the file-queue JSON is truncated and sanitized using the existing
`_sanitize_value()` function. Full `input_data` is NOT written to the file. This limits exposure
of credential-adjacent data to other local processes.

### Supervisor Identity Spoofing

Phlegyas cannot verify that the caller of `supervisor_approve` is actually a supervisor. The
`workflow_id` matching requirement limits the blast radius: a spoofing agent would need to know
a valid `workflow_id` from an active workflow. In practice, `workflow_id` values are UUIDs
generated per-session, making guessing infeasible. The constraint is: if an agent within a
workflow is compromised, it could approve its sibling agents' requests. This is acceptable given
Tier 1 is un-overridable.

### osascript Subprocess

The osascript notification spawns a subprocess. The notification message is built from
`tool_name` and a truncated `reason` string, both sanitized. Shell injection is prevented by
passing the notification text as a Python string argument to `subprocess.run()` with `shell=False`
and explicit argument list construction (not f-string into shell command).

### File Permissions

`~/.claude/pending-approvals/` directory: 0700
Individual approval files: 0644

The directory itself is restricted to owner access. Individual files are readable by other
processes on the same user account (which is acceptable for inter-tool communication).

---

## Open Questions for PLAN.md

1. **`permissions__approve` file-queue behavior:** Should `permissions__approve` (blocking mode)
   also write to the file queue, or only `validate_operation`? If it writes to file-queue, what
   happens to the blocking future while the file-queue entry resolves via a different tool?
   Current recommendation: file-queue for `validate_operation` only in v0.3.0; defer
   `permissions__approve` file-queue polling to v0.4.0.

2. **`poll_approval` rate limiting:** No rate limiting in v0.3.0. Agents are expected to poll
   at reasonable intervals (guidance: 15-30s). If abuse becomes a concern, add per-agent rate
   limiting via the `agent_id` field.

3. **Supervisor policy as static config:** Static `~/.claude/supervisor-policy.json` is deferred
   to v0.4.0. v0.3.0 ships with runtime-only policy enforcement (workflow_id matching, category
   ceiling, confidence floor).

4. **Cross-session polling:** Can agents from different Claude Code sessions poll the same
   phlegyas MCP server? Only if they connect to the same phlegyas process (shared stdio). In
   practice, each Claude Code session has its own phlegyas process. The file-queue bridges this
   gap: any process with filesystem access can observe `~/.claude/pending-approvals/`.
