"""
Supervisor Delegation Policy

Enforces constraints on supervisor agent approvals to prevent
unsafe delegation patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from phlegyas.approver_mcp import PendingApproval


@dataclass
class PolicyViolation:
    """Represents a policy constraint violation."""

    code: str  # "tier1_override", "critical_override", "low_confidence", "self_approval", "workflow_mismatch"
    message: str


class SupervisorDelegationPolicy:
    """
    Enforces delegation constraints for supervisor_approve.

    Validation order (fail-fast):
    1. workflow_id match
    2. Tier 1 block
    3. Confidence floor (approve only)
    4. Self-approval guard
    """

    BLOCKED_TIERS = {"tier1_dangerous"}
    MIN_CONFIDENCE = 0.3

    def validate(
        self,
        pending: PendingApproval,
        supervisor_id: str,
        workflow_id: str,
        decision: str,
    ) -> PolicyViolation | None:
        """Return None if valid, PolicyViolation if constraint violated."""

        # 1. workflow_id match
        if pending.workflow_id is None or pending.workflow_id != workflow_id:
            return PolicyViolation(
                code="workflow_mismatch",
                message=f"Workflow ID mismatch: supervisor provided '{workflow_id}', "
                f"pending has '{pending.workflow_id}'",
            )

        # 2. Tier 1 block
        if pending.tier in self.BLOCKED_TIERS:
            return PolicyViolation(
                code="tier1_override",
                message=f"Cannot override {pending.tier} decisions — these require human review",
            )

        # 3. Confidence floor (only for "approve" decision)
        if decision == "approve":
            if pending.confidence is None or pending.confidence < self.MIN_CONFIDENCE:
                return PolicyViolation(
                    code="low_confidence",
                    message=f"Cannot approve with confidence {pending.confidence} "
                    f"(minimum: {self.MIN_CONFIDENCE})",
                )

        # 4. Self-approval guard
        if supervisor_id == pending.agent_id:
            return PolicyViolation(
                code="self_approval",
                message=f"Supervisor '{supervisor_id}' cannot approve its own requests",
            )

        return None
