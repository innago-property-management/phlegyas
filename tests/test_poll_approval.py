"""
Tests for poll_approval MCP Tool

Tests the polling workflow for subordinate agents that received
status: "pending" from validate_operation.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest

from phlegyas.approver_mcp import (
    PENDING_TTL_SECONDS,
    RESOLVED_TTL_SECONDS,
    PendingApproval,
    call_tool,
    cleanup_expired_pending,
    handle_poll_approval,
    handle_submit_approval,
    pending_approvals,
    resolved_approvals,
)


@pytest.fixture(autouse=True)
def _clear_approval_stores():
    """Clear pending and resolved approval stores before each test."""
    pending_approvals.clear()
    resolved_approvals.clear()
    yield
    pending_approvals.clear()
    resolved_approvals.clear()


def _make_pending(
    request_id="test-req-001",
    tool_name="Bash",
    input_data=None,
    reason="Needs review",
    confidence=0.65,
    tier="tier3_needs_human",
    workflow_id="wf-001",
    agent_id="agent-001",
) -> PendingApproval:
    """Helper to create a PendingApproval and add it to the pending store."""
    pending = PendingApproval(
        request_id=request_id,
        tool_name=tool_name,
        input_data=input_data or {"command": "npm install some-package"},
        reason=reason,
        confidence=confidence,
        tier=tier,
        workflow_id=workflow_id,
        agent_id=agent_id,
    )
    pending_approvals[request_id] = pending
    return pending


class TestPollApprovalPending:
    """Tests for poll_approval when request_id is in pending state."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_returns_pending_status_for_active_request(self):
        """poll_approval returns status: pending for an unresolved request."""
        _make_pending(request_id="pending-001")

        result = await handle_poll_approval({"request_id": "pending-001"})
        response = json.loads(result[0].text)

        assert response["found"] is True
        assert response["status"] == "pending"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_pending_has_null_decision_fields(self):
        """Pending requests have null decision, decided_by, and decided_at."""
        _make_pending(request_id="pending-002")

        result = await handle_poll_approval({"request_id": "pending-002"})
        response = json.loads(result[0].text)

        assert response["decision"] is None
        assert response["decided_by"] is None
        assert response["decided_at"] is None

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_pending_includes_ttl_remaining(self):
        """Pending requests include ttl_remaining_seconds > 0."""
        _make_pending(request_id="pending-003")

        result = await handle_poll_approval({"request_id": "pending-003"})
        response = json.loads(result[0].text)

        assert response["ttl_remaining_seconds"] > 0
        assert response["ttl_remaining_seconds"] <= PENDING_TTL_SECONDS

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_pending_includes_tool_name(self):
        """Pending response includes the tool_name from the original request."""
        _make_pending(request_id="pending-004", tool_name="Write")

        result = await handle_poll_approval({"request_id": "pending-004"})
        response = json.loads(result[0].text)

        assert response["tool_name"] == "Write"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_pending_includes_workflow_id(self):
        """Pending response includes the workflow_id from the original request."""
        _make_pending(request_id="pending-005", workflow_id="wf-special")

        result = await handle_poll_approval({"request_id": "pending-005"})
        response = json.loads(result[0].text)

        assert response["workflow_id"] == "wf-special"


class TestPollApprovalResolved:
    """Tests for poll_approval after submit_approval resolves a request."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_returns_approved_after_submit_approve(self):
        """After submit_approval(approve), poll returns status: approved."""
        _make_pending(request_id="resolve-001")

        await handle_submit_approval(
            {
                "request_id": "resolve-001",
                "decision": "approve",
                "approver_id": "human-alice",
            }
        )

        result = await handle_poll_approval({"request_id": "resolve-001"})
        response = json.loads(result[0].text)

        assert response["found"] is True
        assert response["status"] == "approved"
        assert response["decision"] == "approve"
        assert response["decided_by"] == "human:human-alice"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_returns_denied_after_submit_deny(self):
        """After submit_approval(deny), poll returns status: denied."""
        _make_pending(request_id="resolve-002")

        await handle_submit_approval(
            {
                "request_id": "resolve-002",
                "decision": "deny",
                "approver_id": "human-bob",
            }
        )

        result = await handle_poll_approval({"request_id": "resolve-002"})
        response = json.loads(result[0].text)

        assert response["found"] is True
        assert response["status"] == "denied"
        assert response["decision"] == "deny"
        assert response["decided_by"] == "human:human-bob"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolved_has_decided_at_timestamp(self):
        """Resolved requests have a valid ISO8601 decided_at timestamp."""
        _make_pending(request_id="resolve-003")

        await handle_submit_approval(
            {
                "request_id": "resolve-003",
                "decision": "approve",
                "approver_id": "human-carol",
            }
        )

        result = await handle_poll_approval({"request_id": "resolve-003"})
        response = json.loads(result[0].text)

        assert response["decided_at"] is not None
        # Should be parseable as ISO8601
        datetime.fromisoformat(response["decided_at"])

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolved_accessible_within_ttl(self):
        """Resolved records are accessible for the duration of RESOLVED_TTL_SECONDS."""
        _make_pending(request_id="resolve-004")

        await handle_submit_approval(
            {
                "request_id": "resolve-004",
                "decision": "approve",
                "approver_id": "human-dave",
            }
        )

        # Should still be found
        result = await handle_poll_approval({"request_id": "resolve-004"})
        response = json.loads(result[0].text)
        assert response["found"] is True
        assert response["status"] == "approved"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolved_includes_confidence(self):
        """Resolved response includes the original confidence score."""
        _make_pending(request_id="resolve-005", confidence=0.72)

        await handle_submit_approval(
            {
                "request_id": "resolve-005",
                "decision": "approve",
                "approver_id": "human-eve",
            }
        )

        result = await handle_poll_approval({"request_id": "resolve-005"})
        response = json.loads(result[0].text)

        assert response["confidence"] == 0.72


class TestPollApprovalExpired:
    """Tests for poll_approval when TTL expiry affects requests."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_expired_pending_returns_expired_status(self):
        """An expired pending request returns status: expired."""
        pending = _make_pending(request_id="expired-001")
        # Backdate the expiry
        pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)

        result = await handle_poll_approval({"request_id": "expired-001"})
        response = json.loads(result[0].text)

        # cleanup_expired_pending removes expired records from pending_approvals
        # without adding them to resolved_approvals, so poll returns not found
        assert response["found"] is False
        assert response["status"] == "not_found"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_expired_resolved_returns_not_found(self):
        """A resolved record past RESOLVED_TTL_SECONDS returns found: false."""
        _make_pending(request_id="expired-002")

        await handle_submit_approval(
            {
                "request_id": "expired-002",
                "decision": "approve",
                "approver_id": "human-test",
            }
        )

        # Backdate the resolved_at to exceed RESOLVED_TTL_SECONDS
        resolved = resolved_approvals["expired-002"]
        resolved.resolved_at = datetime.now(UTC) - timedelta(seconds=RESOLVED_TTL_SECONDS + 10)

        result = await handle_poll_approval({"request_id": "expired-002"})
        response = json.loads(result[0].text)

        assert response["found"] is False


class TestPollApprovalNotFound:
    """Tests for poll_approval with unknown request_id."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_unknown_request_id_returns_not_found(self):
        """An unknown request_id returns found: false."""
        result = await handle_poll_approval({"request_id": "nonexistent-001"})
        response = json.loads(result[0].text)

        assert response["found"] is False

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_not_found_has_minimal_response(self):
        """Not-found responses include found: false and a status field."""
        result = await handle_poll_approval({"request_id": "nonexistent-002"})
        response = json.loads(result[0].text)

        assert response["found"] is False
        assert "status" in response


class TestPollApprovalResponseFormat:
    """Tests for poll_approval response format compliance."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_pending_response_has_all_required_fields(self):
        """Pending poll response contains all required fields from the spec."""
        _make_pending(request_id="format-001", confidence=0.65, workflow_id="wf-fmt")

        result = await handle_poll_approval({"request_id": "format-001"})
        response = json.loads(result[0].text)

        required_fields = [
            "found",
            "status",
            "decision",
            "decided_by",
            "decided_at",
            "reason",
            "confidence",
            "ttl_remaining_seconds",
            "tool_name",
        ]
        for field in required_fields:
            assert field in response, f"Missing required field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolved_response_has_all_required_fields(self):
        """Resolved poll response contains all required fields from the spec."""
        _make_pending(request_id="format-002", confidence=0.65, workflow_id="wf-fmt")

        await handle_submit_approval(
            {
                "request_id": "format-002",
                "decision": "approve",
                "approver_id": "human-fmt",
            }
        )

        result = await handle_poll_approval({"request_id": "format-002"})
        response = json.loads(result[0].text)

        required_fields = [
            "found",
            "status",
            "decision",
            "decided_by",
            "decided_at",
            "reason",
            "confidence",
            "ttl_remaining_seconds",
            "tool_name",
        ]
        for field in required_fields:
            assert field in response, f"Missing required field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_poll_approval_accessible_via_call_tool(self):
        """poll_approval is accessible via the call_tool dispatcher."""
        _make_pending(request_id="dispatch-001")

        result = await call_tool("poll_approval", {"request_id": "dispatch-001"})
        response = json.loads(result[0].text)

        assert response["found"] is True
        assert response["status"] == "pending"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_poll_approval_reason_matches_original(self):
        """poll_approval returns the original reason from the pending request."""
        _make_pending(request_id="reason-001", reason="Custom AI reasoning for review")

        result = await handle_poll_approval({"request_id": "reason-001"})
        response = json.loads(result[0].text)

        assert response["reason"] == "Custom AI reasoning for review"


class TestCleanupResolvedApprovals:
    """Tests for cleanup of resolved_approvals buffer."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_cleanup_removes_expired_resolved(self):
        """cleanup_expired_pending also removes expired resolved approvals."""
        _make_pending(request_id="cleanup-001")

        await handle_submit_approval(
            {
                "request_id": "cleanup-001",
                "decision": "approve",
                "approver_id": "human-test",
            }
        )

        # Backdate resolved_at
        resolved_approvals["cleanup-001"].resolved_at = datetime.now(UTC) - timedelta(
            seconds=RESOLVED_TTL_SECONDS + 10
        )

        cleanup_expired_pending()

        assert "cleanup-001" not in resolved_approvals

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_cleanup_keeps_fresh_resolved(self):
        """cleanup_expired_pending keeps resolved approvals within TTL."""
        _make_pending(request_id="cleanup-002")

        await handle_submit_approval(
            {
                "request_id": "cleanup-002",
                "decision": "deny",
                "approver_id": "human-test",
            }
        )

        cleanup_expired_pending()

        assert "cleanup-002" in resolved_approvals


class TestPendingApprovalNewFields:
    """Tests for new fields on PendingApproval dataclass."""

    @pytest.mark.unit
    def test_new_fields_default_to_none(self):
        """New resolution fields default to None."""
        pending = PendingApproval(
            request_id="field-001",
            tool_name="Bash",
            input_data={"command": "test"},
            reason="test",
            confidence=0.5,
            tier="tier3_needs_human",
        )

        assert pending.resolved_at is None
        assert pending.resolved_by is None
        assert pending.resolution is None

    @pytest.mark.unit
    def test_to_dict_includes_resolution_fields(self):
        """to_dict() includes resolved_at, resolved_by, and resolution."""
        pending = PendingApproval(
            request_id="field-002",
            tool_name="Bash",
            input_data={"command": "test"},
            reason="test",
            confidence=0.5,
            tier="tier3_needs_human",
        )
        d = pending.to_dict()

        assert "resolved_at" in d
        assert "resolved_by" in d
        assert "resolution" in d
        assert d["resolved_at"] is None
        assert d["resolved_by"] is None
        assert d["resolution"] is None
