"""
Tests for supervisor_approve MCP Tool

Tests the supervisor delegation workflow where a supervisor agent
can approve, deny, or escalate pending approval requests from
workers within the same workflow.
"""

import json
from unittest.mock import patch

import pytest

from phlegyas.approver_mcp import (
    PendingApproval,
    call_tool,
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


class TestSupervisorApproveSuccess:
    """Tests for successful supervisor approve/deny/escalate paths."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_approve_happy_path(self):
        """Supervisor can approve a pending request from the same workflow."""
        _make_pending(request_id="happy-001", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "happy-001",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
                "reasoning": "Safe operation, approving",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is True
        assert response["decision"] == "approve"
        assert response["request_id"] == "happy-001"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_deny_happy_path(self):
        """Supervisor can deny a pending request from the same workflow."""
        _make_pending(request_id="happy-002", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "happy-002",
                "decision": "deny",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
                "reasoning": "Operation not needed",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is True
        assert response["decision"] == "deny"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_escalate_happy_path(self):
        """Supervisor can escalate a pending request to human."""
        _make_pending(request_id="happy-003", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "happy-003",
                "decision": "escalate_to_human",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
                "reasoning": "Need human review for this one",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is True
        assert response["decision"] == "escalate_to_human"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_approve_moves_to_resolved(self):
        """Approved request is moved from pending to resolved."""
        _make_pending(request_id="move-001", workflow_id="wf-001", agent_id="worker-001")

        await call_tool(
            "supervisor_approve",
            {
                "request_id": "move-001",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )

        assert "move-001" not in pending_approvals
        assert "move-001" in resolved_approvals

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_deny_moves_to_resolved(self):
        """Denied request is moved from pending to resolved."""
        _make_pending(request_id="move-002", workflow_id="wf-001", agent_id="worker-001")

        await call_tool(
            "supervisor_approve",
            {
                "request_id": "move-002",
                "decision": "deny",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )

        assert "move-002" not in pending_approvals
        assert "move-002" in resolved_approvals

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_escalate_keeps_in_pending(self):
        """Escalated request stays in pending for human to act on."""
        _make_pending(request_id="esc-001", workflow_id="wf-001", agent_id="worker-001")

        await call_tool(
            "supervisor_approve",
            {
                "request_id": "esc-001",
                "decision": "escalate_to_human",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )

        assert "esc-001" in pending_approvals
        assert "esc-001" not in resolved_approvals

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolved_by_set_to_supervisor(self):
        """Resolved record has resolved_by set to supervisor:<id>."""
        _make_pending(request_id="resolvedby-001", workflow_id="wf-001", agent_id="worker-001")

        await call_tool(
            "supervisor_approve",
            {
                "request_id": "resolvedby-001",
                "decision": "approve",
                "supervisor_id": "sup-alpha",
                "workflow_id": "wf-001",
            },
        )

        resolved = resolved_approvals["resolvedby-001"]
        assert resolved.resolved_by == "supervisor:sup-alpha"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolved_at_is_set(self):
        """Resolved record has resolved_at timestamp set."""
        _make_pending(request_id="resolvedat-001", workflow_id="wf-001", agent_id="worker-001")

        await call_tool(
            "supervisor_approve",
            {
                "request_id": "resolvedat-001",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )

        resolved = resolved_approvals["resolvedat-001"]
        assert resolved.resolved_at is not None

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolution_field_set_on_approve(self):
        """Resolution field is set to 'approve' on approval."""
        _make_pending(request_id="res-001", workflow_id="wf-001", agent_id="worker-001")

        await call_tool(
            "supervisor_approve",
            {
                "request_id": "res-001",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )

        resolved = resolved_approvals["res-001"]
        assert resolved.resolution == "approve"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_resolution_field_set_on_deny(self):
        """Resolution field is set to 'deny' on denial."""
        _make_pending(request_id="res-002", workflow_id="wf-001", agent_id="worker-001")

        await call_tool(
            "supervisor_approve",
            {
                "request_id": "res-002",
                "decision": "deny",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )

        resolved = resolved_approvals["res-002"]
        assert resolved.resolution == "deny"


class TestSupervisorApprovePolicy:
    """Tests for policy constraint violations via the MCP tool."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_workflow_mismatch_returns_error(self):
        """Mismatched workflow_id returns error with policy violation code."""
        _make_pending(request_id="pol-001", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "pol-001",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-WRONG",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"] == "policy_violation"
        assert response["violation_code"] == "workflow_mismatch"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_tier1_dangerous_returns_error(self):
        """tier1_dangerous pending request returns policy violation error."""
        _make_pending(
            request_id="pol-002",
            workflow_id="wf-001",
            agent_id="worker-001",
            tier="tier1_dangerous",
        )

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "pol-002",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"] == "policy_violation"
        assert response["violation_code"] == "tier1_override"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_low_confidence_approve_returns_error(self):
        """Low confidence blocks approval via policy."""
        _make_pending(
            request_id="pol-003",
            workflow_id="wf-001",
            agent_id="worker-001",
            confidence=0.2,
        )

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "pol-003",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"] == "policy_violation"
        assert response["violation_code"] == "low_confidence"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_low_confidence_deny_allowed(self):
        """Low confidence does not block deny decision."""
        _make_pending(
            request_id="pol-004",
            workflow_id="wf-001",
            agent_id="worker-001",
            confidence=0.1,
        )

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "pol-004",
                "decision": "deny",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_self_approval_returns_error(self):
        """Self-approval (supervisor_id == agent_id) returns error."""
        _make_pending(
            request_id="pol-005",
            workflow_id="wf-001",
            agent_id="supervisor-001",
        )

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "pol-005",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"] == "policy_violation"
        assert response["violation_code"] == "self_approval"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_request_not_found_returns_error(self):
        """Unknown request_id returns not_found error."""
        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "nonexistent-001",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"] == "not_found"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_already_resolved_returns_error(self):
        """A request already in resolved_approvals returns not_found."""
        _make_pending(request_id="pol-006", workflow_id="wf-001", agent_id="worker-001")

        # Resolve it first via submit_approval
        await handle_submit_approval(
            {
                "request_id": "pol-006",
                "decision": "approve",
                "approver_id": "human-test",
            }
        )

        # Now try supervisor_approve — should fail since it's in resolved, not pending
        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "pol-006",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["error"] == "not_found"


class TestSupervisorApproveAuditTrail:
    """Tests for correct audit tier labels on supervisor decisions."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_approve_audit_tier_label(self):
        """Supervisor approval writes tier3_supervisor_approved to audit."""
        _make_pending(request_id="audit-001", workflow_id="wf-001", agent_id="worker-001")

        with patch("phlegyas.approver_mcp.write_audit_log") as mock_audit:
            await call_tool(
                "supervisor_approve",
                {
                    "request_id": "audit-001",
                    "decision": "approve",
                    "supervisor_id": "supervisor-001",
                    "workflow_id": "wf-001",
                    "reasoning": "Looks good",
                },
            )

            mock_audit.assert_called_once()
            call_args = mock_audit.call_args
            assert call_args[0][3] == "tier3_supervisor_approved"  # tier argument

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_deny_audit_tier_label(self):
        """Supervisor denial writes tier3_supervisor_denied to audit."""
        _make_pending(request_id="audit-002", workflow_id="wf-001", agent_id="worker-001")

        with patch("phlegyas.approver_mcp.write_audit_log") as mock_audit:
            await call_tool(
                "supervisor_approve",
                {
                    "request_id": "audit-002",
                    "decision": "deny",
                    "supervisor_id": "supervisor-001",
                    "workflow_id": "wf-001",
                    "reasoning": "Not needed",
                },
            )

            mock_audit.assert_called_once()
            call_args = mock_audit.call_args
            assert call_args[0][3] == "tier3_supervisor_denied"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_escalate_audit_tier_label(self):
        """Supervisor escalation writes tier3_supervisor_escalated to audit."""
        _make_pending(request_id="audit-003", workflow_id="wf-001", agent_id="worker-001")

        with patch("phlegyas.approver_mcp.write_audit_log") as mock_audit:
            await call_tool(
                "supervisor_approve",
                {
                    "request_id": "audit-003",
                    "decision": "escalate_to_human",
                    "supervisor_id": "supervisor-001",
                    "workflow_id": "wf-001",
                    "reasoning": "Needs human eyes",
                },
            )

            mock_audit.assert_called_once()
            call_args = mock_audit.call_args
            assert call_args[0][3] == "tier3_supervisor_escalated"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_audit_includes_supervisor_reasoning(self):
        """Audit log entry includes the supervisor's reasoning."""
        _make_pending(request_id="audit-004", workflow_id="wf-001", agent_id="worker-001")

        with patch("phlegyas.approver_mcp.write_audit_log") as mock_audit:
            await call_tool(
                "supervisor_approve",
                {
                    "request_id": "audit-004",
                    "decision": "approve",
                    "supervisor_id": "supervisor-001",
                    "workflow_id": "wf-001",
                    "reasoning": "Verified safe operation in context",
                },
            )

            call_args = mock_audit.call_args
            reason = call_args[0][4]  # reason argument
            assert "supervisor-001" in reason
            assert "Verified safe operation in context" in reason


class TestSupervisorApproveWorkflowIsolation:
    """Tests for workflow isolation enforcement."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_cross_workflow_approve_rejected(self):
        """Supervisor from wf-002 cannot approve request from wf-001."""
        _make_pending(request_id="iso-001", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "iso-001",
                "decision": "approve",
                "supervisor_id": "supervisor-002",
                "workflow_id": "wf-002",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["violation_code"] == "workflow_mismatch"
        # Verify request remains in pending
        assert "iso-001" in pending_approvals

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_cross_workflow_deny_rejected(self):
        """Supervisor from wf-002 cannot deny request from wf-001 either."""
        _make_pending(request_id="iso-002", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "iso-002",
                "decision": "deny",
                "supervisor_id": "supervisor-002",
                "workflow_id": "wf-002",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["violation_code"] == "workflow_mismatch"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_same_workflow_approve_allowed(self):
        """Supervisor from same workflow can approve."""
        _make_pending(request_id="iso-003", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "iso-003",
                "decision": "approve",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is True


class TestSupervisorApproveRecursionGuard:
    """Tests for self-approval prevention."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_self_approval_blocked(self):
        """Agent cannot approve its own pending request."""
        _make_pending(
            request_id="rec-001",
            workflow_id="wf-001",
            agent_id="agent-x",
            confidence=0.65,
        )

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "rec-001",
                "decision": "approve",
                "supervisor_id": "agent-x",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["violation_code"] == "self_approval"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_self_denial_blocked(self):
        """Agent cannot deny its own pending request either."""
        _make_pending(
            request_id="rec-002",
            workflow_id="wf-001",
            agent_id="agent-x",
            confidence=0.65,
        )

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "rec-002",
                "decision": "deny",
                "supervisor_id": "agent-x",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["success"] is False
        assert response["violation_code"] == "self_approval"


class TestSupervisorApproveHumanOverride:
    """Tests for human override scenarios."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_human_can_act_after_escalation(self):
        """After supervisor escalates, human can still submit_approval."""
        _make_pending(request_id="override-001", workflow_id="wf-001", agent_id="worker-001")

        # Supervisor escalates
        await call_tool(
            "supervisor_approve",
            {
                "request_id": "override-001",
                "decision": "escalate_to_human",
                "supervisor_id": "supervisor-001",
                "workflow_id": "wf-001",
            },
        )

        # Human approves via submit_approval
        result = await handle_submit_approval(
            {
                "request_id": "override-001",
                "decision": "approve",
                "approver_id": "human-admin",
            }
        )
        response = json.loads(result[0].text)

        assert response["success"] is True
        assert response["decision"] == "approve"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_response_includes_supervisor_id(self):
        """Successful response includes the supervisor_id."""
        _make_pending(request_id="meta-001", workflow_id="wf-001", agent_id="worker-001")

        result = await call_tool(
            "supervisor_approve",
            {
                "request_id": "meta-001",
                "decision": "approve",
                "supervisor_id": "sup-alpha-99",
                "workflow_id": "wf-001",
            },
        )
        response = json.loads(result[0].text)

        assert response["supervisor_id"] == "sup-alpha-99"


class TestSupervisorApproveToolRegistration:
    """Tests for tool registration in list_tools."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_supervisor_approve_in_list_tools(self):
        """supervisor_approve is listed in list_tools."""
        from phlegyas.approver_mcp import list_tools

        tools = await list_tools()
        tool_names = [t.name for t in tools]

        assert "supervisor_approve" in tool_names

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_supervisor_approve_schema_has_required_fields(self):
        """supervisor_approve schema requires request_id, decision, supervisor_id, workflow_id."""
        from phlegyas.approver_mcp import list_tools

        tools = await list_tools()
        sa_tool = next(t for t in tools if t.name == "supervisor_approve")

        required = sa_tool.inputSchema["required"]
        assert "request_id" in required
        assert "decision" in required
        assert "supervisor_id" in required
        assert "workflow_id" in required
