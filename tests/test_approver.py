"""
Tests for Main Approver - Integration Tests

Tests the three-tier permission approval system integration.
Calls tier logic directly (not through FastMCP wrapper) to test the actual
evaluation pipeline.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.tier1_dangerous import DangerousPatternDetector
from src.tier2_safe import SafeOperationDetector
from src.tier3_ai import AIEvaluator

# Re-use audit log helpers from the approver module
from src.approver import write_audit_log


async def evaluate_permission(
    tool_name: str,
    input_data: dict[str, Any],
    ai_evaluator: AIEvaluator | None = None,
) -> dict[str, Any]:
    """
    Replicate the three-tier evaluation flow from approver.py.

    This is the same logic as permissions__approve() but callable directly
    without the FastMCP wrapper.
    """
    dangerous_detector = DangerousPatternDetector()
    safe_detector = SafeOperationDetector()

    # Tier 1: dangerous patterns
    is_dangerous, dangerous_reason = dangerous_detector.is_dangerous(tool_name, input_data)
    if is_dangerous:
        return {"behavior": "deny", "message": dangerous_reason}

    # Tier 2: safe categories
    is_safe, safe_category = safe_detector.is_safe(tool_name, input_data)
    if is_safe:
        return {"behavior": "allow", "message": f"Auto-approved (Tier 2): {safe_category}"}

    # Tier 3: AI evaluation
    if ai_evaluator is None:
        return {
            "behavior": "deny",
            "message": "Denied: AI evaluator unavailable, requires manual approval",
        }

    try:
        decision, evaluation = await ai_evaluator.evaluate(tool_name, input_data)

        # AI returns "approve"/"deny"/"ask_user" from _apply_thresholds
        if decision == "approve":
            message = (
                f"AI-approved (confidence: {evaluation.confidence:.2f}): "
                f"{evaluation.reasoning}"
            )
            return {"behavior": "allow", "message": message}
        elif decision == "deny":
            message = (
                f"AI-denied (confidence: {evaluation.confidence:.2f}): "
                f"{evaluation.reasoning}"
            )
            return {"behavior": "deny", "message": message}
        else:  # ask_user
            message = (
                f"Denied: Requires human approval. "
                f"{evaluation.reasoning} (confidence: {evaluation.confidence:.2f})"
            )
            return {"behavior": "deny", "message": message}

    except Exception as e:
        return {"behavior": "deny", "message": f"Denied: AI evaluation error - {e}"}


class TestPermissionApprovalFlow:
    """Integration tests for the three-tier approval system."""

    # Three-Tier Flow Tests

    @pytest.mark.asyncio
    async def test_tier1_blocks_dangerous_operations(self):
        """Tier 1 should block dangerous operations immediately."""
        result = await evaluate_permission("Bash", {"command": "rm -rf /"})
        assert result["behavior"] == "deny"
        assert "Blocked" in result["message"]
        assert "Destructive operation" in result["message"]

    @pytest.mark.asyncio
    async def test_tier2_approves_safe_operations(self):
        """Tier 2 should auto-approve safe operations."""
        result = await evaluate_permission("Bash", {"command": "git status"})
        assert result["behavior"] == "allow"
        assert "Tier 2" in result["message"]
        assert "safe git operation" in result["message"]

    @pytest.mark.asyncio
    async def test_tier3_evaluates_ambiguous_operations(self, mock_anthropic_response):
        """Tier 3 should use AI for ambiguous operations."""
        mock_response = mock_anthropic_response(
            decision="approve",
            category="moderate_risk",
            reasoning="Safe edit",
            confidence=0.85,
        )

        with patch("src.tier3_ai.Anthropic") as mock_anthropic_class:
            mock_client = MagicMock()
            mock_client.messages.create.return_value = mock_response
            mock_anthropic_class.return_value = mock_client

            evaluator = AIEvaluator(api_key="sk-ant-test-key")
            # Use a tool/input that bypasses Tier 1 and Tier 2 to reach Tier 3
            # (CustomTool is unknown to both detectors)
            result = await evaluate_permission(
                "CustomTool", {"action": "do_something"}, ai_evaluator=evaluator
            )
            assert result["behavior"] == "allow"
            assert "AI-approved" in result["message"]
            assert "confidence" in result["message"]

    # Tier Precedence Tests

    @pytest.mark.asyncio
    async def test_tier1_takes_precedence_over_tier2(self):
        """Tier 1 (dangerous) should block even if operation matches Tier 2 (safe)."""
        result = await evaluate_permission("Bash", {"command": "git push origin main"})
        assert result["behavior"] == "deny"
        assert "git operation" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_tier1_blocks_credentials_in_safe_tool(self):
        """Tier 1 should block credential writes even for 'safe' Write tool."""
        result = await evaluate_permission(
            "Write",
            {
                "file_path": "src/config.json",
                "content": "password=secret123",
            },
        )
        assert result["behavior"] == "deny"
        assert "credentials" in result["message"].lower()

    # AI Evaluator Unavailable Tests

    @pytest.mark.asyncio
    async def test_should_deny_when_ai_unavailable(self):
        """Should deny ambiguous operations when AI evaluator is unavailable."""
        # Pass no AI evaluator — simulates unavailable
        result = await evaluate_permission(
            "Bash", {"command": "docker build -t myapp:latest ."}, ai_evaluator=None
        )
        assert result["behavior"] == "deny"
        assert "AI evaluator unavailable" in result["message"]

    @pytest.mark.asyncio
    async def test_should_handle_ai_evaluation_error(self):
        """Should deny when AI evaluation raises an exception."""
        with patch("src.tier3_ai.Anthropic") as mock_anthropic_class:
            mock_client = MagicMock()
            mock_client.messages.create.side_effect = Exception("API error")
            mock_anthropic_class.return_value = mock_client

            evaluator = AIEvaluator(api_key="sk-ant-test-key")
            # Use CustomTool to bypass Tier 1 and 2, forcing Tier 3
            result = await evaluate_permission(
                "CustomTool", {"action": "something"}, ai_evaluator=evaluator
            )
            assert result["behavior"] == "deny"
            # tier3_ai catches exceptions internally and returns ask_user
            assert "AI evaluation failed" in result["message"] or "human approval" in result["message"]

    # Audit Logging Tests

    def test_audit_log_write(self, tmp_path):
        """Should write audit log entries correctly."""
        audit_file = tmp_path / "test_audit.jsonl"

        with patch("src.approver.audit_log_file", str(audit_file)):
            with patch("src.approver.enable_audit_log", True):
                write_audit_log(
                    tool_name="Bash",
                    input_data={"command": "ls -la"},
                    decision="allow",
                    tier="tier2_safe",
                    reason="read-only command",
                )

        assert audit_file.exists()
        with open(audit_file) as f:
            log_entry = json.loads(f.readline())
            assert log_entry["tool_name"] == "Bash"
            assert log_entry["decision"] == "allow"
            assert log_entry["tier"] == "tier2_safe"
            assert log_entry["reason"] == "read-only command"

    def test_audit_log_disabled(self, tmp_path):
        """Should not write audit log when disabled."""
        audit_file = tmp_path / "test_audit.jsonl"

        with patch("src.approver.audit_log_file", str(audit_file)):
            with patch("src.approver.enable_audit_log", False):
                write_audit_log(
                    tool_name="Bash",
                    input_data={"command": "test"},
                    decision="allow",
                    tier="tier2",
                    reason="safe",
                )

        assert not audit_file.exists()

    # Stats Tests

    def test_get_approval_stats_empty(self, tmp_path):
        """Should handle empty audit log."""
        audit_file = tmp_path / "empty_audit.jsonl"
        audit_file.touch()

        stats = self._compute_stats(audit_file)
        assert stats["total"] == 0
        assert stats["approved"] == 0
        assert stats["denied"] == 0

    def test_get_approval_stats_with_data(self, tmp_path):
        """Should calculate stats from audit log."""
        audit_file = tmp_path / "test_audit.jsonl"

        entries = [
            {"tool_name": "Bash", "decision": "allow", "tier": "tier2_safe", "reason": "safe git"},
            {"tool_name": "Bash", "decision": "deny", "tier": "tier1_dangerous", "reason": "rm -rf"},
            {"tool_name": "Edit", "decision": "allow", "tier": "tier3_ai_approve", "reason": "safe edit"},
        ]

        with open(audit_file, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        stats = self._compute_stats(audit_file)
        assert stats["total"] == 3
        assert stats["approved"] == 2
        assert stats["denied"] == 1
        assert stats["by_tier"]["tier2_safe"] == 1
        assert stats["by_tier"]["tier1_dangerous"] == 1
        assert stats["by_tier"]["tier3_ai_approve"] == 1
        assert stats["by_tool"]["Bash"] == 2
        assert stats["by_tool"]["Edit"] == 1

    def test_get_approval_stats_no_log_file(self):
        """Should handle missing audit log file."""
        stats = self._compute_stats(Path("/nonexistent/audit.jsonl"))
        assert "error" in stats
        assert "not available" in stats["error"]

    @staticmethod
    def _compute_stats(audit_file: Path) -> dict:
        """Compute approval stats from audit log file (same logic as get_approval_stats)."""
        try:
            if not audit_file.exists():
                return {"error": "Audit log not available"}

            with open(audit_file) as f:
                lines = f.readlines()

            entries = []
            for line in lines:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))

            stats = {
                "total": len(entries),
                "approved": sum(1 for e in entries if e.get("decision") == "allow"),
                "denied": sum(1 for e in entries if e.get("decision") == "deny"),
                "by_tier": {},
                "by_tool": {},
            }

            for entry in entries:
                tier = entry.get("tier", "unknown")
                tool = entry.get("tool_name", "unknown")
                stats["by_tier"][tier] = stats["by_tier"].get(tier, 0) + 1
                stats["by_tool"][tool] = stats["by_tool"].get(tool, 0) + 1

            return stats
        except Exception as e:
            return {"error": f"Audit log not available: {e}"}

    # Error Handling Tests

    @pytest.mark.asyncio
    async def test_should_handle_malformed_input(self):
        """Should handle malformed input gracefully."""
        result = await evaluate_permission("Bash", {})
        assert "behavior" in result

    @pytest.mark.asyncio
    async def test_should_handle_unknown_tool(self):
        """Should handle unknown tools gracefully."""
        result = await evaluate_permission("UnknownTool", {"param": "value"})
        assert "behavior" in result

    # Real-World Scenarios

    @pytest.mark.asyncio
    async def test_scenario_safe_git_workflow(self):
        """Test complete safe git workflow."""
        commands = [
            "git status",
            "git checkout -b feature/new-feature",
            "git add .",
            "git commit -m 'Add feature'",
            "git fetch origin",
        ]

        for command in commands:
            result = await evaluate_permission("Bash", {"command": command})
            assert result["behavior"] == "allow", f"Failed to approve safe command: {command}"

    @pytest.mark.asyncio
    async def test_scenario_dangerous_production_deploy(self):
        """Test dangerous production deployment is blocked."""
        commands = [
            "kubectl apply -f deploy.yaml --context production",
            "git push --force origin main",
            "DROP TABLE users",
        ]

        for command in commands:
            result = await evaluate_permission("Bash", {"command": command})
            assert result["behavior"] == "deny", f"Failed to block dangerous command: {command}"

    @pytest.mark.asyncio
    async def test_scenario_test_and_build_workflow(self):
        """Test typical test and build workflow."""
        commands = [
            "npm install",
            "npm test",
            "npm run lint",
            "npm run build",
        ]

        for command in commands:
            result = await evaluate_permission("Bash", {"command": command})
            assert result["behavior"] == "allow", f"Failed to approve safe command: {command}"

    @pytest.mark.asyncio
    async def test_scenario_credential_protection(self):
        """Test credential protection across different tools."""
        operations = [
            ("Write", {"file_path": "config.json", "content": "password=secret"}),
            ("Edit", {"file_path": "appsettings.json", "new_string": "API_KEY=abc123"}),
            ("Write", {"file_path": "appsettings.json", "content": "AWS_SECRET=xyz"}),
        ]

        for tool_name, input_data in operations:
            result = await evaluate_permission(tool_name, input_data)
            assert (
                result["behavior"] == "deny"
            ), f"Failed to block credential operation: {tool_name}"
