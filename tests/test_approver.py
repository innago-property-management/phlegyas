"""
Tests for Main Approver - Integration Tests

Tests the three-tier permission approval system integration.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.approver import (
    ai_evaluator,
    dangerous_detector,
    safe_detector,
    write_audit_log,
)


class TestPermissionApprovalFlow:
    """Integration tests for the three-tier approval system."""

    # Three-Tier Flow Tests

    @pytest.mark.asyncio
    async def test_tier1_blocks_dangerous_operations(self, monkeypatch):
        """Tier 1 should block dangerous operations immediately."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        # Import after setting env var
        from src.approver import permissions__approve

        result = await permissions__approve("Bash", {"command": "rm -rf /"})
        assert result["behavior"] == "deny"
        assert "Blocked" in result["message"]
        assert "Destructive operation" in result["message"]

    @pytest.mark.asyncio
    async def test_tier2_approves_safe_operations(self, monkeypatch):
        """Tier 2 should auto-approve safe operations."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        result = await permissions__approve("Bash", {"command": "git status"})
        assert result["behavior"] == "allow"
        assert "Tier 2" in result["message"]
        assert "safe git operation" in result["message"]

    @pytest.mark.asyncio
    async def test_tier3_evaluates_ambiguous_operations(
        self, monkeypatch, mock_anthropic_response
    ):
        """Tier 3 should use AI for ambiguous operations."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        # Mock AI response
        mock_response = mock_anthropic_response(
            decision="approve", category="moderate_risk", reasoning="Safe edit", confidence=0.85
        )

        with patch("src.tier3_ai.Anthropic") as mock_anthropic_class:
            mock_client = MagicMock()
            mock_client.messages.create.return_value = mock_response
            mock_anthropic_class.return_value = mock_client

            from src.approver import permissions__approve

            result = await permissions__approve("Edit", {"file_path": "src/new_code.py"})
            assert result["behavior"] == "allow"
            assert "AI-approved" in result["message"] or "confidence" in result["message"]

    # Tier Precedence Tests

    @pytest.mark.asyncio
    async def test_tier1_takes_precedence_over_tier2(self, monkeypatch):
        """Tier 1 (dangerous) should block even if operation matches Tier 2 (safe)."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        # git push is in safe patterns, but to main/master triggers Tier 1
        result = await permissions__approve("Bash", {"command": "git push origin main"})
        assert result["behavior"] == "deny"
        assert "git operation" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_tier1_blocks_credentials_in_safe_tool(self, monkeypatch):
        """Tier 1 should block credential writes even for 'safe' Write tool."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        result = await permissions__approve(
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
    async def test_should_deny_when_ai_unavailable(self, monkeypatch):
        """Should deny ambiguous operations when AI evaluator is unavailable."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        # Force reload to trigger AI initialization failure
        import importlib

        import src.approver

        importlib.reload(src.approver)

        from src.approver import permissions__approve

        # Operation that's not in Tier 1 or Tier 2 (ambiguous)
        result = await permissions__approve(
            "Bash", {"command": "docker build -t myapp:latest ."}
        )
        assert result["behavior"] == "deny"
        assert "AI evaluator unavailable" in result["message"]

    @pytest.mark.asyncio
    async def test_should_handle_ai_evaluation_error(self, monkeypatch, mock_anthropic_response):
        """Should deny when AI evaluation raises an exception."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with patch("src.tier3_ai.Anthropic") as mock_anthropic_class:
            mock_client = MagicMock()
            mock_client.messages.create.side_effect = Exception("API error")
            mock_anthropic_class.return_value = mock_client

            from src.approver import permissions__approve

            result = await permissions__approve(
                "Bash", {"command": "docker run -it myapp:latest"}
            )
            assert result["behavior"] == "deny"
            assert "AI evaluation error" in result["message"]

    # Audit Logging Tests

    def test_audit_log_write(self, tmp_path):
        """Should write audit log entries correctly."""
        audit_file = tmp_path / "test_audit.jsonl"

        # Temporarily override audit log file
        with patch("src.approver.audit_log_file", str(audit_file)):
            with patch("src.approver.enable_audit_log", True):
                write_audit_log(
                    tool_name="Bash",
                    input_data={"command": "ls -la"},
                    decision="allow",
                    tier="tier2_safe",
                    reason="read-only command",
                )

        # Verify log entry
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

        # Verify no log file created
        assert not audit_file.exists()

    @pytest.mark.asyncio
    async def test_get_approval_stats_empty(self, monkeypatch, tmp_path):
        """Should handle empty audit log."""
        audit_file = tmp_path / "empty_audit.jsonl"
        audit_file.touch()

        monkeypatch.setenv("ENABLE_AUDIT_LOG", "true")

        with patch("src.approver.audit_log_file", str(audit_file)):
            from src.approver import get_approval_stats

            stats = await get_approval_stats()
            assert stats["total"] == 0
            assert stats["approved"] == 0
            assert stats["denied"] == 0

    @pytest.mark.asyncio
    async def test_get_approval_stats_with_data(self, monkeypatch, tmp_path):
        """Should calculate stats from audit log."""
        audit_file = tmp_path / "test_audit.jsonl"

        # Write test data
        entries = [
            {
                "tool_name": "Bash",
                "decision": "allow",
                "tier": "tier2_safe",
                "reason": "safe git",
            },
            {
                "tool_name": "Bash",
                "decision": "deny",
                "tier": "tier1_dangerous",
                "reason": "rm -rf",
            },
            {
                "tool_name": "Edit",
                "decision": "allow",
                "tier": "tier3_ai_approve",
                "reason": "safe edit",
            },
        ]

        with open(audit_file, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        monkeypatch.setenv("ENABLE_AUDIT_LOG", "true")

        with patch("src.approver.audit_log_file", str(audit_file)):
            from src.approver import get_approval_stats

            stats = await get_approval_stats()
            assert stats["total"] == 3
            assert stats["approved"] == 2
            assert stats["denied"] == 1
            assert stats["by_tier"]["tier2_safe"] == 1
            assert stats["by_tier"]["tier1_dangerous"] == 1
            assert stats["by_tier"]["tier3_ai_approve"] == 1
            assert stats["by_tool"]["Bash"] == 2
            assert stats["by_tool"]["Edit"] == 1

    @pytest.mark.asyncio
    async def test_get_approval_stats_no_log_file(self, monkeypatch):
        """Should handle missing audit log file."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "true")

        with patch("src.approver.audit_log_file", "/nonexistent/audit.jsonl"):
            from src.approver import get_approval_stats

            stats = await get_approval_stats()
            assert "error" in stats
            assert "not available" in stats["error"]

    # Error Handling Tests

    @pytest.mark.asyncio
    async def test_should_handle_malformed_input(self, monkeypatch):
        """Should handle malformed input gracefully."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        # Missing required fields
        result = await permissions__approve("Bash", {})
        # Should not crash, should handle gracefully
        assert "behavior" in result

    @pytest.mark.asyncio
    async def test_should_handle_unknown_tool(self, monkeypatch):
        """Should handle unknown tools gracefully."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        result = await permissions__approve("UnknownTool", {"param": "value"})
        # Should fall through to Tier 3 or deny
        assert "behavior" in result

    # Real-World Scenarios

    @pytest.mark.asyncio
    async def test_scenario_safe_git_workflow(self, monkeypatch):
        """Test complete safe git workflow."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        # Should all be approved by Tier 2
        commands = [
            "git status",
            "git checkout -b feature/new-feature",
            "git add .",
            "git commit -m 'Add feature'",
            "git push origin feature/new-feature",
        ]

        for command in commands:
            result = await permissions__approve("Bash", {"command": command})
            assert (
                result["behavior"] == "allow"
            ), f"Failed to approve safe command: {command}"

    @pytest.mark.asyncio
    async def test_scenario_dangerous_production_deploy(self, monkeypatch):
        """Test dangerous production deployment is blocked."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        # Should all be blocked by Tier 1
        commands = [
            "kubectl apply -f deploy.yaml --context production",
            "git push --force origin main",
            "DROP TABLE users",
        ]

        for command in commands:
            result = await permissions__approve("Bash", {"command": command})
            assert result["behavior"] == "deny", f"Failed to block dangerous command: {command}"

    @pytest.mark.asyncio
    async def test_scenario_test_and_build_workflow(self, monkeypatch):
        """Test typical test and build workflow."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        commands = [
            "npm install",
            "npm test",
            "npm run lint",
            "npm run build",
        ]

        for command in commands:
            result = await permissions__approve("Bash", {"command": command})
            assert (
                result["behavior"] == "allow"
            ), f"Failed to approve safe command: {command}"

    @pytest.mark.asyncio
    async def test_scenario_credential_protection(self, monkeypatch):
        """Test credential protection across different tools."""
        monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")

        from src.approver import permissions__approve

        # Should all be blocked by Tier 1
        operations = [
            ("Write", {"file_path": "config.json", "content": "password=secret"}),
            ("Edit", {"file_path": "src/auth.py", "new_string": "API_KEY=abc123"}),
            ("Bash", {"command": "echo 'AWS_SECRET=xyz' > credentials.txt"}),
        ]

        for tool_name, input_data in operations:
            result = await permissions__approve(tool_name, input_data)
            assert result["behavior"] == "deny", f"Failed to block credential operation: {tool_name}"
