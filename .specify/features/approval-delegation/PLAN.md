# PLAN.md: Approval Delegation

**Version:** 1.0
**Date:** 2026-03-19
**Status:** Ready for implementation

---

## Implementation Strategy

Ship as v0.3.0. Three user stories map to the three design questions. Implement in order: Story 1
and Story 2 share infrastructure (file-queue, resolved_approvals buffer); Story 3 builds on Story 1.

**TDD approach:** Write tests before code for each new function. The 334 existing tests must
remain passing throughout.

**Complexity estimate:** 13 points (architecture with known unknowns)

---

## User Story 1: Agent Polling for validate_operation Resolution

**As a** subordinate agent that received `status: "pending"` from `validate_operation`,
**I want to** poll phlegyas with my `request_id` and get a definitive resolved status,
**so that** I can resume a parked operation or report it as skipped.

### Acceptance Criteria

1. `poll_approval(request_id=<uuid>)` returns `status: "pending"` while the request is unresolved.
2. After a human calls `submit_approval(request_id, decision="approve")`, a subsequent
   `poll_approval(request_id)` returns `status: "approved"` within 1 second.
3. After TTL expiry, `poll_approval(request_id)` returns `status: "expired"`.
4. For an unknown `request_id`, `poll_approval(request_id)` returns `found: false`.
5. Resolved records remain accessible via `poll_approval` for at least 300 seconds after
   resolution.
6. `submit_approval` retains its existing interface and response format.

### Tasks

**Task 1.1: Add resolved_approvals buffer to approver_mcp.py**

File: `phlegyas/approver_mcp.py`

- Add `resolved_approvals: dict[str, PendingApproval] = {}` at module level.
- Add `RESOLVED_TTL_SECONDS = 300` constant (not configurable in v0.3.0).
- Add `PendingApproval.resolved_at`, `resolved_by`, `resolution` fields to the dataclass.
- Update `PendingApproval.to_dict()` to include the new fields.
- Update `cleanup_expired_pending()` to also clean `resolved_approvals` by TTL.

**Task 1.2: Update submit_approval to populate resolved_approvals**

File: `phlegyas/approver_mcp.py` — `handle_submit_approval()`

- After writing audit log, move the `PendingApproval` to `resolved_approvals` with
  `resolved_at=datetime.now(UTC)`, `resolved_by=f"human:{approver_id}"`,
  `resolution=decision`.
- Remove from `pending_approvals` (existing behavior retained).

**Task 1.3: Implement poll_approval MCP tool**

Files:
- `phlegyas/approver_mcp.py` — add `poll_approval` to `list_tools()` and `call_tool()`
- `phlegyas/approver_mcp.py` — new `handle_poll_approval()` function

Tool schema:
```json
{
  "name": "poll_approval",
  "description": "Check the resolution status of a specific pending approval request. Returns current status including whether it has been approved, denied, or is still pending.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "request_id": {
        "type": "string",
        "description": "The request_id returned by validate_operation when status was 'pending'"
      }
    },
    "required": ["request_id"]
  }
}
```

Response:
```json
{
  "found": true,
  "status": "pending | approved | denied | expired",
  "decision": "approve | deny | null",
  "decided_by": "human:username | supervisor:agent-id | null",
  "decided_at": "ISO8601 | null",
  "reason": "string",
  "confidence": 0.65,
  "ttl_remaining_seconds": 847,
  "tool_name": "Bash",
  "workflow_id": "optional"
}
```

`handle_poll_approval()` logic:
1. Call `cleanup_expired_pending()`.
2. Check `pending_approvals[request_id]` → return with `status: "pending"`.
3. Check `resolved_approvals[request_id]` → return with resolved status.
4. Return `found: false` if in neither dict.

**Task 1.4: Write tests for poll_approval**

File: `tests/test_poll_approval.py` (new file)

Test classes:
- `TestPollApprovalPending` — request_id in pending state
- `TestPollApprovalResolved` — after submit_approval, record is accessible for 300s
- `TestPollApprovalExpired` — TTL expiry sets status to expired
- `TestPollApprovalNotFound` — unknown request_id returns found: false
- `TestPollApprovalResponseFormat` — all required fields present

Minimum: 15 tests.

**Dependencies:** Task 1.1 before 1.2, 1.3. Task 1.4 can be written before 1.1 (TDD).

---

## User Story 2: Non-Slack Notification Channels

**As a** user running phlegyas without Slack,
**I want to** be notified when an agent requests human approval,
**so that** I can respond before the request expires.

### Acceptance Criteria

1. When `validate_operation` creates a `pending` approval, a JSON file is written to
   `~/.claude/pending-approvals/<request_id>.json` within 1 second.
2. The file is readable by other local processes (permissions 0644; directory 0700).
3. File content includes `request_id`, `tool_name`, `input_summary`, `reason`, `expires_at`.
4. File does NOT include raw `input_data` (only `input_summary` — sanitized, truncated to 100 chars).
5. When `submit_approval` resolves the request, the file is updated with `status: "approved|denied"`
   and deleted after 60 seconds.
6. When TTL expires, the file is updated with `status: "expired"` and deleted after 60 seconds.
7. On macOS with `PHLEGYAS_NOTIFY_MACOS=true` (default on darwin), a system notification fires
   when a pending approval is created.
8. If `osascript` fails (non-Mac, no access), phlegyas logs a warning and continues; no exception.
9. `PHLEGYAS_NOTIFY_MACOS=false` suppresses macOS notifications.
10. Neither file-queue nor osascript failures affect the MCP response.

### Tasks

**Task 2.1: Create FileQueueWriter**

File: `phlegyas/file_queue.py` (new module)

```python
class FileQueueWriter:
    """
    Writes pending approval requests to ~/.claude/pending-approvals/ as JSON files.
    """
    DEFAULT_QUEUE_DIR = Path.home() / ".claude" / "pending-approvals"

    def __init__(self, queue_dir: Path | None = None): ...

    def write_pending(self, pending: PendingApproval, input_summary: str) -> Path | None:
        """Write pending approval file. Returns path or None on failure."""

    def resolve(self, request_id: str, resolution: str, decided_by: str) -> None:
        """Update file status to resolved. Schedule file deletion."""

    def delete_after(self, request_id: str, delay_seconds: int = 60) -> None:
        """Delete the file after delay_seconds (best-effort, fire-and-forget)."""

    @staticmethod
    def summarize_input(tool_name: str, input_data: dict) -> str:
        """Return a sanitized, 100-char summary of the tool input."""
```

File format:
```json
{
  "schema_version": 1,
  "request_id": "uuid",
  "tool_name": "Bash",
  "input_summary": "npm install some-package (truncated)",
  "reason": "AI reasoning...",
  "confidence": 0.65,
  "workflow_id": "optional",
  "agent_id": "optional",
  "created_at": "ISO8601",
  "expires_at": "ISO8601",
  "status": "pending"
}
```

Write pattern: write to `<queue_dir>/<request_id>.json.tmp`, then `os.rename()` for atomicity.
Directory creation: `mkdir -p` with 0700 permissions.
File permissions: 0644 after write.

**Task 2.2: Create MacOSNotifier**

File: `phlegyas/notifiers.py` (new module)

```python
class MacOSNotifier:
    """
    Sends macOS system notifications for pending approvals using osascript.
    """
    def notify(self, tool_name: str, reason: str, request_id: str) -> None:
        """
        Fire-and-forget macOS notification. Never raises.
        Spawns subprocess with shell=False to prevent injection.
        """

    @staticmethod
    def is_available() -> bool:
        """Return True if running on macOS and osascript is available."""
```

Notification text format:
```
Title: "Phlegyas: Approval Required"
Message: "<tool_name>: <reason[:80]> (id: <request_id[:8]>)"
```

subprocess call (safe, no shell):
```python
subprocess.run(
    ["osascript", "-e", f'display notification "{msg}" with title "{title}"'],
    timeout=3,
    capture_output=True,
)
```

**Task 2.3: Integrate notification channels into validate_operation**

File: `phlegyas/approver_mcp.py`

- Add module-level initialization:
  ```python
  file_queue = FileQueueWriter()
  macos_notifier = MacOSNotifier() if MacOSNotifier.is_available() and os.getenv("PHLEGYAS_NOTIFY_MACOS", "true").lower() != "false" else None
  ```
- In `handle_validate_operation()`, after creating a `PendingApproval` and before returning:
  ```python
  # Write to file queue (non-blocking; errors are swallowed)
  file_queue.write_pending(pending, FileQueueWriter.summarize_input(tool_name, input_data))
  # macOS notification (fire-and-forget)
  if macos_notifier:
      macos_notifier.notify(tool_name, evaluation.reasoning[:80], request_id)
  ```
- In `handle_submit_approval()`, after resolving the pending approval, call
  `file_queue.resolve(request_id, resolution, decided_by)`.
- In `cleanup_expired_pending()`, call `file_queue.resolve(request_id, "expired", "ttl_expiry")`
  for each expired record.

**Task 2.4: Write tests for FileQueueWriter**

File: `tests/test_file_queue.py` (new file)

Test classes:
- `TestFileQueueWriter` — write, resolve, delete lifecycle
- `TestFileQueueSummarizeInput` — sanitization, truncation
- `TestFileQueueAtomicWrite` — tmp file renamed, no partial reads
- `TestMacOSNotifier` — available check, subprocess call args, failure swallowing

Minimum: 20 tests. Use `tmp_path` pytest fixture for all filesystem operations.

**Dependencies:** Task 2.1 before 2.2, 2.3. Task 2.4 can be written before 2.1 (TDD).

---

## User Story 3: Supervisor Agent Delegation

**As a** Cygnus supervisor agent managing a fleet of workers,
**I want to** approve pending approval requests from my workers using the `supervisor_approve` tool,
**so that** I can reduce human interruptions for medium-confidence decisions within my workflow.

### Acceptance Criteria

1. A supervisor can approve/deny a pending request from a worker within the same `workflow_id`.
2. The supervisor cannot approve requests from a different `workflow_id`.
3. The supervisor cannot approve `tier1_dangerous` decisions (hard block — returns error).
4. The supervisor cannot approve `category: critical` decisions (hard block — returns error).
5. The supervisor cannot approve requests where `confidence < 0.3` (returns error).
6. The supervisor cannot approve its own requests (`supervisor_id == agent_id` on pending record).
7. Supervisor approvals are logged with tier `tier3_supervisor_approved` or `tier3_supervisor_denied`.
8. `escalate_to_human` decision leaves the request in pending state and logs
   `tier3_supervisor_escalated`.
9. A human can still call `submit_approval` after a supervisor calls `escalate_to_human`.
10. After `supervisor_approve(decision="approve")`, a human can call `submit_approval` to override
    — human always wins, but only if the request is still in `pending_approvals`.
   (Note: once supervisor approves a request and moves it to `resolved_approvals`, the human can
   no longer override it — this is an accepted limitation of the v0.3.0 design.)

### Policy Constraints (Enforced Server-Side)

```python
SUPERVISOR_DELEGATION_POLICY = {
    "min_confidence": 0.3,              # Below this, supervisor cannot approve
    "blocked_categories": {"critical"}, # Supervisor cannot approve these
    "blocked_tiers": {"tier1_dangerous"},  # Supervisor cannot override tier 1
    "allow_escalate_to_human": True,    # Supervisor can escalate without deciding
}
```

### Tasks

**Task 3.1: Create SupervisorDelegationPolicy**

File: `phlegyas/supervisor_policy.py` (new module)

```python
@dataclass
class PolicyViolation:
    code: str       # "tier1_override", "critical_override", "low_confidence", "self_approval", "workflow_mismatch"
    message: str

class SupervisorDelegationPolicy:
    """Enforces delegation constraints for supervisor_approve."""

    def validate(
        self,
        pending: PendingApproval,
        supervisor_id: str,
        workflow_id: str,
        decision: str,
    ) -> PolicyViolation | None:
        """Return None if valid, PolicyViolation if constraint violated."""
```

Validation order (fail-fast):
1. `workflow_id` match (most common early rejection)
2. Tier 1 block
3. Category block
4. Confidence floor (only for "approve" decision, not "deny" or "escalate_to_human")
5. Self-approval guard

**Task 3.2: Implement supervisor_approve MCP tool**

Files:
- `phlegyas/approver_mcp.py` — add to `list_tools()` and `call_tool()`
- `phlegyas/approver_mcp.py` — new `handle_supervisor_approve()` function

Tool schema:
```json
{
  "name": "supervisor_approve",
  "description": "Approve, deny, or escalate a pending approval request on behalf of a supervised workflow. Enforces delegation policy constraints: cannot override Tier 1 dangerous decisions, cannot approve critical-category operations, cannot approve below confidence 0.3, and cannot approve own requests.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "request_id": { "type": "string" },
      "decision": { "type": "string", "enum": ["approve", "deny", "escalate_to_human"] },
      "supervisor_id": { "type": "string", "description": "Supervisor agent identifier" },
      "workflow_id": { "type": "string", "description": "Must match the workflow_id on the pending request" },
      "reasoning": { "type": "string", "description": "Supervisor's justification for the decision" }
    },
    "required": ["request_id", "decision", "supervisor_id", "workflow_id"]
  }
}
```

`handle_supervisor_approve()` logic:
1. Look up `request_id` in `pending_approvals` (not `resolved_approvals`).
2. If not found → error response.
3. Run `SupervisorDelegationPolicy.validate()`. If violation → error response with `code` and `message`.
4. If `decision == "escalate_to_human"`:
   - Log audit entry with tier `tier3_supervisor_escalated`.
   - Update file-queue file with `escalated_by: "supervisor:<id>"` note.
   - Return success without moving record to `resolved_approvals`.
5. If `decision == "approve"` or `"deny"`:
   - Set `pending.resolved_by = f"supervisor:{supervisor_id}"`.
   - Move to `resolved_approvals`.
   - Write audit log with appropriate tier label.
   - Update file-queue file.
   - Return success.

**Task 3.3: Write tests for supervisor_approve**

File: `tests/test_supervisor_approve.py` (new file)

Test classes:
- `TestSupervisorApprovePolicy` — each constraint violation scenario
- `TestSupervisorApproveSuccess` — approve/deny/escalate happy paths
- `TestSupervisorApproveAuditTrail` — correct tier labels in audit log
- `TestSupervisorApproveWorkflowIsolation` — wrong workflow_id rejected
- `TestSupervisorApproveRecursionGuard` — self-approval rejected
- `TestSupervisorPolicyDataclass` — unit tests for PolicyViolation and SupervisorDelegationPolicy

Minimum: 25 tests.

**Task 3.4: Write tests for SupervisorDelegationPolicy**

File: `tests/test_supervisor_policy.py` (new file, unit tests for the policy module)

Minimum: 12 tests.

**Dependencies:** Task 3.1 before 3.2. Task 3.3 and 3.4 can be written before 3.1 (TDD).
Story 1 must be complete first (resolved_approvals infrastructure required by supervisor_approve).

---

## Task Execution Order

```
Story 1 (Polling)           Story 2 (Notifications)      Story 3 (Supervisor)
-----------                 -----------------------       --------------------
1.4 [TDD: write tests]      2.4 [TDD: write tests]        3.4 [TDD: policy tests]
1.1 [resolved_approvals]    2.1 [FileQueueWriter]         3.3 [TDD: tool tests]
1.2 [submit_approval]       2.2 [MacOSNotifier]           |
1.3 [poll_approval tool]    2.3 [integration]             |
|                           |                             |
Story 1 complete            Story 2 complete              |
                            |                             |
                   Story 1 + 2 complete                   |
                                                     3.1 [policy module]
                                                     3.2 [supervisor_approve tool]
                                                     Story 3 complete
```

Parallelizable: Story 1 and Story 2 can be developed in parallel (no cross-dependencies until
2.3). Story 3 depends on Story 1 infrastructure (resolved_approvals).

---

## Files Changed Summary

| File | Change Type | Story |
|------|------------|-------|
| `phlegyas/approver_mcp.py` | Modified | 1, 2, 3 |
| `phlegyas/file_queue.py` | New | 2 |
| `phlegyas/notifiers.py` | New | 2 |
| `phlegyas/supervisor_policy.py` | New | 3 |
| `tests/test_poll_approval.py` | New | 1 |
| `tests/test_file_queue.py` | New | 2 |
| `tests/test_supervisor_approve.py` | New | 3 |
| `tests/test_supervisor_policy.py` | New | 3 |

Existing test files: zero modifications required. All new tests are in new files.
Existing MCP tools: backward compatible; no interface changes.

---

## New Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PHLEGYAS_NOTIFY_MACOS` | `true` on darwin | Enable macOS system notifications |
| `PHLEGYAS_QUEUE_DIR` | `~/.claude/pending-approvals` | File queue directory |
| `PHLEGYAS_QUEUE_ENABLED` | `true` | Disable file queue (e.g., in tests) |

The `PHLEGYAS_QUEUE_ENABLED=false` flag is important for test isolation. Tests that exercise
`validate_operation` should not write to `~/.claude/pending-approvals/` by default. The
`test_file_queue.py` tests will use `tmp_path` fixtures with a custom `queue_dir`.

---

## Validation Checkpoints

**After Story 1:**
- `pytest tests/test_poll_approval.py -v` — all green
- `pytest` — all 334 original tests still passing + new poll_approval tests
- Manual: call `validate_operation`, mock `submit_approval`, call `poll_approval` — see resolved.

**After Story 2:**
- `pytest tests/test_file_queue.py -v` — all green
- `pytest` — all tests passing
- Manual (macOS): trigger a pending approval, observe file in `~/.claude/pending-approvals/` and
  system notification.

**After Story 3:**
- `pytest tests/test_supervisor_approve.py tests/test_supervisor_policy.py -v` — all green
- `pytest` — all tests passing
- Manual: simulate supervisor approving worker request within same workflow_id.
- Manual: verify cross-workflow_id rejection.

---

## Documentation Updates

After all stories complete, update `CLAUDE.md`:
1. Add `poll_approval` tool to the MCP tools section.
2. Add `supervisor_approve` tool to the MCP tools section.
3. Add file-queue section under "Configuration" with directory path.
4. Add new environment variables to the env var table.
5. Update "Task Agent Permission Validation" code example to show the polling pattern.

Update `examples/` directory:
- `examples/supervisor_workflow.py` — example Cygnus supervisor using `supervisor_approve`.
- `examples/agent_polling.py` — example subordinate agent polling pattern.
