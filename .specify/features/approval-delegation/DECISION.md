# DECISION.md: Approval Delegation

**Version:** 1.0
**Date:** 2026-03-19
**Status:** Scoping complete, ready for design phase

---

## Use Case

Phlegyas guards 10+ concurrent Claude Code sessions, including headless Cygnus-supervised agent
fleets. When Tier 3 AI evaluation returns `ask_user`, the current behavior depends entirely on
whether Slack is configured:

- **Slack configured:** `permissions__approve` blocks and awaits a human button click.
  `validate_operation` fires a notification but returns `pending` immediately — the subordinate
  agent has no mechanism to resume after approval lands.
- **Slack not configured:** All `ask_user` decisions auto-deny. There is no fallback channel.
- **Supervisor agent present:** A Cygnus supervisor has full contextual knowledge of the workflow
  but has no formal authority to approve on behalf of supervised agents.

This creates three distinct capability gaps that must be addressed together because they share the
same core infrastructure: a structured **approval resolution path** that connects a pending request
to a final decision and resumes the blocked agent.

---

## Business Value

### Gap 1: Slack Flow Completion for validate_operation

A subordinate agent calls `validate_operation`, receives `status: "pending"` with a `request_id`,
notifies Slack, and then has no path forward. It cannot poll for resolution, cannot block waiting,
and cannot be notified when a human clicks Approve. The agent either gives up or spins in a polling
loop with no support from phlegyas.

**Value of fixing:** Unlocks the full async human-in-the-loop workflow. Agents can park pending
operations and continue unblocked work, then check back or receive notification when the human
decides. This is the foundational workflow for supervised autonomous agents.

### Gap 2: Non-Slack Notification Channels

Users running phlegyas without Slack (the majority of OSS users, personal setups, air-gapped
environments) get a silent auto-deny on any `ask_user` decision. They have no way to know an
approval was requested. The audit log captures it, but there is no active notification.

**Value of fixing:** Phlegyas becomes useful in a much wider range of environments. A user running
10 sessions on a Mac workstation without Slack should get a macOS notification, not a silent deny
that breaks agent workflows.

### Gap 3: Supervisor Agent Delegation

A Cygnus supervisor agent supervising a fleet of worker agents has full context about the current
task, workflow objectives, and risk posture. When a worker hits an `ask_user` decision, the
supervisor is the natural authority to evaluate it against task context — if confidence is
sufficient. Currently the supervisor has no formal channel to exercise this authority; it can only
call `submit_approval` as if it were a human.

**Value of fixing:** Reduces human interruptions for supervised workflows. The supervisor can
approve medium-confidence decisions (0.6-0.8 range) that align with the stated task, escalating
only genuinely ambiguous cases. Reduces latency from minutes (Slack round-trip) to seconds.

---

## Scope Decisions

### In Scope

1. **Polling mechanism for validate_operation** — agents can poll `get_pending_approvals` or a new
   `poll_approval` tool to check resolution status of their `request_id`.
2. **File-based queue** — `~/.claude/pending-approvals/` as a durable, Slack-independent
   notification and polling channel.
3. **macOS terminal notifications** — `osascript` + `say` for local workstation alerting.
4. **Supervisor delegation** — a formal `supervisor_approve` tool or an extension of
   `submit_approval` with `approver_type: "supervisor"` that enforces delegation policy constraints.
5. **Audit trail** — distinct tier labels for each approval path (supervisor, file-queue, osascript)
   with full provenance.
6. **Revocation** — human can revoke supervisor authority mid-workflow via MCP tool or config.

### Out of Scope (Future Phases)

- **Pharos web UI** — Phase 3 integration; phlegyas will expose the pending queue, Pharos will
  consume it.
- **Push-based agent wake-up** — agents polling is sufficient for v0.3.0; true push notification
  (websocket, SSE) requires additional infrastructure.
- **Multi-human approval workflows** — quorum approvals, approval routing by risk level.
- **Windows/Linux OS notifications** — macOS-first for v0.3.0; Linux can use file-queue.
- **Webhook/HTTP callback** — post to a URL when approval resolves; deferred to Phase 3.

### Non-Goals (Never)

- **Supervisor overrides Tier 1** — Tier 1 dangerous pattern decisions are absolute. No delegation
  mechanism can convert a Tier 1 deny into an approval.
- **Automated approval of `category: critical`** — operations classified as critical (confidence
  threshold 0.95) require a human. Supervisor delegation has a hard ceiling at `high_risk`.
- **Cross-session approval authority** — a supervisor can only approve operations from agents it
  spawned in the same workflow (enforced by `workflow_id`).

---

## Key Constraints

1. Must not break existing 334 tests or existing MCP tool contracts.
2. `PENDING_TTL_SECONDS` (default 1800s) applies to all pending approvals regardless of channel.
3. Tier 1 decisions are irrevocable — no approval channel can override them.
4. Audit log must capture the approval path with sufficient detail for forensic review.
5. File-queue must be readable by other processes (permissions 0644, not 0600).
6. Supervisor delegation must include a recursion guard — a supervisor cannot approve its own
   operations.
7. All new MCP tools must be backward-compatible with existing `validate_operation` callers.
