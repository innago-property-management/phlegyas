"""
Tests for SupervisorDelegationPolicy

Unit tests for the policy module that enforces delegation constraints
when a supervisor agent attempts to approve/deny a pending request.
"""

import pytest

from phlegyas.approver_mcp import PendingApproval
from phlegyas.supervisor_policy import PolicyViolation, SupervisorDelegationPolicy


@pytest.fixture
def policy():
    """Create a fresh SupervisorDelegationPolicy instance."""
    return SupervisorDelegationPolicy()


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
    """Helper to create a PendingApproval for policy testing."""
    return PendingApproval(
        request_id=request_id,
        tool_name=tool_name,
        input_data=input_data or {"command": "npm install some-package"},
        reason=reason,
        confidence=confidence,
        tier=tier,
        workflow_id=workflow_id,
        agent_id=agent_id,
    )


class TestWorkflowIdValidation:
    """Tests for workflow_id matching validation."""

    @pytest.mark.unit
    def test_workflow_id_mismatch_rejected(self, policy):
        """Supervisor cannot approve request from a different workflow_id."""
        pending = _make_pending(workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-999", "approve")

        assert violation is not None
        assert violation.code == "workflow_mismatch"

    @pytest.mark.unit
    def test_pending_with_no_workflow_id_rejected(self, policy):
        """Supervisor cannot approve request that has no workflow_id."""
        pending = _make_pending(workflow_id=None)
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is not None
        assert violation.code == "workflow_mismatch"

    @pytest.mark.unit
    def test_matching_workflow_id_passes(self, policy):
        """Matching workflow_id passes validation (when all other checks pass)."""
        pending = _make_pending(workflow_id="wf-001", agent_id="agent-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is None


class TestTier1Block:
    """Tests for tier1_dangerous blocking."""

    @pytest.mark.unit
    def test_tier1_dangerous_blocked(self, policy):
        """Supervisor cannot approve tier1_dangerous decisions."""
        pending = _make_pending(tier="tier1_dangerous", workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is not None
        assert violation.code == "tier1_override"

    @pytest.mark.unit
    def test_tier1_dangerous_blocked_even_for_deny(self, policy):
        """Supervisor cannot act on tier1_dangerous decisions even to deny them."""
        pending = _make_pending(tier="tier1_dangerous", workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "deny")

        assert violation is not None
        assert violation.code == "tier1_override"

    @pytest.mark.unit
    def test_tier3_needs_human_not_blocked(self, policy):
        """tier3_needs_human is not in BLOCKED_TIERS and passes."""
        pending = _make_pending(tier="tier3_needs_human", workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is None


class TestConfidenceFloor:
    """Tests for minimum confidence enforcement."""

    @pytest.mark.unit
    def test_confidence_below_threshold_blocks_approve(self, policy):
        """Supervisor cannot approve when confidence < 0.3."""
        pending = _make_pending(confidence=0.2, workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is not None
        assert violation.code == "low_confidence"

    @pytest.mark.unit
    def test_confidence_below_threshold_allows_deny(self, policy):
        """Supervisor can deny even when confidence < 0.3."""
        pending = _make_pending(confidence=0.2, workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "deny")

        assert violation is None

    @pytest.mark.unit
    def test_confidence_exactly_at_threshold_passes(self, policy):
        """Confidence exactly at 0.3 should pass validation."""
        pending = _make_pending(confidence=0.3, workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is None

    @pytest.mark.unit
    def test_none_confidence_blocks_approve(self, policy):
        """None confidence blocks approval (treated as unknown/zero)."""
        pending = _make_pending(confidence=None, workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is not None
        assert violation.code == "low_confidence"

    @pytest.mark.unit
    def test_none_confidence_allows_deny(self, policy):
        """None confidence allows deny decision."""
        pending = _make_pending(confidence=None, workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "deny")

        assert violation is None

    @pytest.mark.unit
    def test_confidence_below_threshold_allows_escalate(self, policy):
        """Supervisor can escalate_to_human even when confidence < 0.3."""
        pending = _make_pending(confidence=0.1, workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "escalate_to_human")

        assert violation is None


class TestSelfApprovalGuard:
    """Tests for self-approval prevention."""

    @pytest.mark.unit
    def test_self_approval_rejected(self, policy):
        """Supervisor cannot approve its own requests."""
        pending = _make_pending(agent_id="supervisor-001", workflow_id="wf-001", confidence=0.5)
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is not None
        assert violation.code == "self_approval"

    @pytest.mark.unit
    def test_different_agent_id_passes(self, policy):
        """Different supervisor_id and agent_id passes self-approval check."""
        pending = _make_pending(agent_id="agent-worker-001", workflow_id="wf-001")
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation is None


class TestPolicyViolationDataclass:
    """Tests for the PolicyViolation data structure."""

    @pytest.mark.unit
    def test_policy_violation_has_code_and_message(self):
        """PolicyViolation stores code and message."""
        violation = PolicyViolation(code="test_code", message="Test message")

        assert violation.code == "test_code"
        assert violation.message == "Test message"


class TestValidationOrder:
    """Tests confirming fail-fast validation order."""

    @pytest.mark.unit
    def test_workflow_mismatch_checked_before_tier1(self, policy):
        """workflow_id mismatch is checked before tier1 block."""
        pending = _make_pending(
            tier="tier1_dangerous",
            workflow_id="wf-001",
            agent_id="supervisor-001",  # would also trigger self-approval
            confidence=0.1,  # would also trigger low confidence
        )
        violation = policy.validate(pending, "supervisor-001", "wf-WRONG", "approve")

        # Should fail on workflow_mismatch first, not tier1_override
        assert violation.code == "workflow_mismatch"

    @pytest.mark.unit
    def test_tier1_checked_before_confidence(self, policy):
        """Tier 1 block is checked before confidence floor."""
        pending = _make_pending(
            tier="tier1_dangerous",
            workflow_id="wf-001",
            confidence=0.1,
        )
        violation = policy.validate(pending, "supervisor-001", "wf-001", "approve")

        assert violation.code == "tier1_override"
