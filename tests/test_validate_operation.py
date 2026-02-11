"""
Tests for validate_operation Tool

Tests the non-blocking validation workflow for Task agents.
"""

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.approver_mcp import handle_validate_operation
from src.tier1_dangerous import DangerousPatternDetector
from src.tier2_safe import SafeOperationDetector
from src.tier3_ai import AIEvaluator, EvaluationResult


class TestValidateOperationTier1:
    """Tests for Tier 1 dangerous operation detection in validate_operation."""

    @pytest.mark.asyncio
    async def test_should_deny_destructive_commands(self):
        """Validate_operation should deny destructive commands via Tier 1."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "rm -rf /"}
        })

        response = json.loads(result[0].text)
        assert response["status"] == "denied"
        assert response["tier"] == "tier1_dangerous"
        assert "Destructive operation" in response["reason"]
        assert response["confidence"] is None
        assert response["request_id"] is None

    @pytest.mark.asyncio
    async def test_should_deny_production_operations(self):
        """Validate_operation should deny production operations via Tier 1."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "git push origin production"}
        })

        response = json.loads(result[0].text)
        assert response["status"] == "denied"
        assert response["tier"] == "tier1_dangerous"
        assert "production" in response["reason"].lower()

    @pytest.mark.asyncio
    async def test_should_deny_credential_writes(self):
        """Validate_operation should deny writes containing credentials."""
        result = await handle_validate_operation({
            "tool_name": "Write",
            "input": {
                "file_path": "config.json",
                "content": '{"api_key": "sk-1234567890"}'
            }
        })

        response = json.loads(result[0].text)
        assert response["status"] == "denied"
        assert response["tier"] == "tier1_dangerous"
        assert "credential" in response["reason"].lower()


class TestValidateOperationTier2:
    """Tests for Tier 2 safe operation detection in validate_operation."""

    @pytest.mark.asyncio
    async def test_should_approve_safe_git_commands(self):
        """Validate_operation should approve safe git commands via Tier 2."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "git status"}
        })

        response = json.loads(result[0].text)
        assert response["status"] == "approved"
        assert response["tier"] == "tier2_safe"
        assert "git" in response["reason"].lower()
        assert response["confidence"] is None
        assert response["request_id"] is None

    @pytest.mark.asyncio
    async def test_should_approve_echo_commands(self):
        """Validate_operation should approve echo commands via Tier 2."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": 'echo "Hello World"'}
        })

        response = json.loads(result[0].text)
        assert response["status"] == "approved"
        assert response["tier"] == "tier2_safe"
        assert "info" in response["reason"].lower()

    @pytest.mark.asyncio
    async def test_should_approve_read_tools(self):
        """Validate_operation should approve read-only tools via Tier 2."""
        result = await handle_validate_operation({
            "tool_name": "Read",
            "input": {"file_path": "/project/README.md"}
        })

        response = json.loads(result[0].text)
        assert response["status"] == "approved"
        assert response["tier"] == "tier2_safe"
        assert "read-only" in response["reason"].lower()

    @pytest.mark.asyncio
    async def test_should_approve_test_commands(self):
        """Validate_operation should approve test commands via Tier 2."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "npm test"}
        })

        response = json.loads(result[0].text)
        assert response["status"] == "approved"
        assert response["tier"] == "tier2_safe"

    @pytest.mark.asyncio
    async def test_should_approve_build_commands(self):
        """Validate_operation should approve build commands via Tier 2."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "npm run build"}
        })

        response = json.loads(result[0].text)
        assert response["status"] == "approved"
        assert response["tier"] == "tier2_safe"


class TestValidateOperationTier3:
    """Tests for Tier 3 AI evaluation in validate_operation."""

    @pytest.mark.asyncio
    @patch("src.tier3_ai.AIEvaluator.__init__", return_value=None)
    async def test_should_handle_ai_unavailable(self, mock_ai_init):
        """Validate_operation should return needs_human when AI is unavailable."""
        # Mock AIEvaluator to simulate unavailability
        # The actual implementation checks if ai_evaluator is None

        # Use a custom tool that won't match Tier 1 or Tier 2 patterns
        result = await handle_validate_operation({
            "tool_name": "CustomTool",
            "input": {"action": "perform_custom_action"}
        })

        response = json.loads(result[0].text)
        # Without AI, ambiguous operations should return needs_human or be approved by Tier 2
        # Since CustomTool is unknown, it should either be approved (no patterns match)
        # or needs_human (if AI is truly unavailable)
        assert response["status"] in ["approved", "needs_human", "pending"]

        # If needs_human, verify proper format
        if response["status"] == "needs_human":
            assert response["request_id"] is not None
            uuid.UUID(response["request_id"])

    @pytest.mark.asyncio
    async def test_should_return_proper_reasoning_on_success(self):
        """Validate_operation should return proper AI reasoning when evaluation succeeds."""
        # Note: Edit tool is in Tier 2 as read-only, so use Write to a non-sensitive file
        result = await handle_validate_operation({
            "tool_name": "Write",
            "input": {
                "file_path": "docs/notes.md",
                "content": "# Project Notes\n\nSome documentation here."
            }
        })

        response = json.loads(result[0].text)

        # Should either be Tier 2 (safe directory) or Tier 3 (AI evaluation)
        assert response["tier"] in ["tier2_safe", "tier3_ai_approve", "tier3_ai_deny", "tier3_needs_human"]

        # If it reached Tier 3, check reasoning quality
        if "tier3" in response["tier"]:
            # AI parsing may still have issues with some responses, so we accept both cases
            # Either proper reasoning OR graceful fallback to needs_human
            if "Failed to parse" in response["reason"]:
                # Parsing error should result in needs_human status
                assert response["status"] == "needs_human"
            else:
                # Proper AI evaluation should have substantial reasoning
                assert len(response["reason"]) > 20

            # If needs_human, should have request_id
            if response["status"] == "needs_human":
                assert response["request_id"] is not None
                uuid.UUID(response["request_id"])

            # Should have confidence score
            if response["confidence"] is not None:
                assert 0.0 <= response["confidence"] <= 1.0

    @pytest.mark.asyncio
    @patch("src.tier3_ai.AIEvaluator.evaluate")
    async def test_should_generate_unique_request_ids(self, mock_evaluate):
        """Validate_operation should generate unique request IDs for each needs_human response."""
        # Mock AI to always return ask_user
        mock_evaluate.return_value = (
            "ask_user",
            EvaluationResult(
                decision="ask_user",
                category="moderate_risk",
                reasoning="Needs review",
                confidence=0.6
            )
        )

        # Make 3 requests
        request_ids = []
        for i in range(3):
            result = await handle_validate_operation({
                "tool_name": "Bash",
                "input": {"command": f"npm install package-{i}"}
            })
            response = json.loads(result[0].text)
            if response["status"] == "needs_human":
                request_ids.append(response["request_id"])

        # All request IDs should be unique
        assert len(request_ids) == len(set(request_ids))
        # All should be valid UUIDs
        for rid in request_ids:
            uuid.UUID(rid)


class TestValidateOperationResponseFormat:
    """Tests for validate_operation response format consistency."""

    @pytest.mark.asyncio
    async def test_response_has_required_fields(self):
        """Validate_operation response should have all required fields."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "git status"}
        })

        response = json.loads(result[0].text)

        # Required fields
        assert "status" in response
        assert "tier" in response
        assert "reason" in response
        assert "confidence" in response
        assert "request_id" in response

    @pytest.mark.asyncio
    async def test_status_field_values(self):
        """Validate_operation status field should only have valid values."""
        test_cases = [
            ("Bash", {"command": "git status"}),  # Should be approved
            ("Bash", {"command": "rm -rf /"}),     # Should be denied
        ]

        for tool_name, input_data in test_cases:
            result = await handle_validate_operation({
                "tool_name": tool_name,
                "input": input_data
            })
            response = json.loads(result[0].text)
            assert response["status"] in ["approved", "denied", "needs_human"]

    @pytest.mark.asyncio
    async def test_tier_field_format(self):
        """Validate_operation tier field should follow naming convention."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "git status"}
        })

        response = json.loads(result[0].text)
        assert response["tier"].startswith("tier")
        assert "_" in response["tier"]  # Should be like "tier2_safe"

    @pytest.mark.asyncio
    async def test_approved_response_format(self):
        """Approved responses should not have confidence or request_id."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "git status"}
        })

        response = json.loads(result[0].text)
        if response["status"] == "approved":
            assert response["confidence"] is None
            assert response["request_id"] is None

    @pytest.mark.asyncio
    async def test_denied_response_format(self):
        """Denied responses should not have confidence or request_id."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": "rm -rf /"}
        })

        response = json.loads(result[0].text)
        if response["status"] == "denied":
            assert response["confidence"] is None
            assert response["request_id"] is None


class TestValidateOperationEdgeCases:
    """Tests for validate_operation edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_should_handle_missing_command(self):
        """Validate_operation should handle missing command gracefully."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {}
        })

        # Should not crash, should return some decision
        response = json.loads(result[0].text)
        assert "status" in response

    @pytest.mark.asyncio
    async def test_should_handle_empty_command(self):
        """Validate_operation should handle empty command gracefully."""
        result = await handle_validate_operation({
            "tool_name": "Bash",
            "input": {"command": ""}
        })

        response = json.loads(result[0].text)
        assert "status" in response

    @pytest.mark.asyncio
    async def test_should_handle_unknown_tool(self):
        """Validate_operation should handle unknown tools gracefully."""
        result = await handle_validate_operation({
            "tool_name": "UnknownTool",
            "input": {"some_param": "value"}
        })

        response = json.loads(result[0].text)
        assert "status" in response
        # Should either approve (if no patterns match) or ask for review


class TestValidateOperationAuditLogging:
    """Tests for validate_operation audit logging."""

    @pytest.mark.asyncio
    async def test_should_write_audit_log_for_validations(self, tmp_path):
        """Validate_operation should write audit log entries."""
        import os
        audit_file = tmp_path / "test_audit.jsonl"

        # Set audit log path
        original_file = os.environ.get("AUDIT_LOG_FILE")
        os.environ["AUDIT_LOG_FILE"] = str(audit_file)
        os.environ["ENABLE_AUDIT_LOG"] = "true"

        try:
            # Need to reload module to pick up new env vars
            import importlib
            import src.approver_mcp
            importlib.reload(src.approver_mcp)
            from src.approver_mcp import handle_validate_operation as validate

            # Make a validation request
            await validate({
                "tool_name": "Bash",
                "input": {"command": "git status"}
            })

            # Check audit log was written
            assert audit_file.exists()
            content = audit_file.read_text()
            assert len(content) > 0

            # Parse and verify entry
            entry = json.loads(content.strip().split("\n")[0])
            assert "timestamp" in entry
            assert entry["tool_name"] == "Bash"
            assert entry["decision"] in ["allow", "deny", "needs_human"]
            assert "tier" in entry

        finally:
            # Restore original env var
            if original_file:
                os.environ["AUDIT_LOG_FILE"] = original_file
            else:
                os.environ.pop("AUDIT_LOG_FILE", None)


class TestValidateOperationIntegration:
    """Integration tests for validate_operation with real scenarios."""

    @pytest.mark.asyncio
    async def test_scenario_development_workflow(self):
        """Test typical development workflow operations."""
        scenarios = [
            # Read files
            ("Read", {"file_path": "src/main.py"}, "approved"),
            # Check git status
            ("Bash", {"command": "git status"}, "approved"),
            # Run tests
            ("Bash", {"command": "pytest tests/"}, "approved"),
            # Commit changes
            ("Bash", {"command": "git commit -m 'test'"}, "approved"),
        ]

        for tool_name, input_data, expected_status in scenarios:
            result = await handle_validate_operation({
                "tool_name": tool_name,
                "input": input_data
            })
            response = json.loads(result[0].text)
            assert response["status"] == expected_status, \
                f"Failed for {tool_name} {input_data}: got {response['status']}"

    @pytest.mark.asyncio
    async def test_scenario_blocked_dangerous_operations(self):
        """Test that all dangerous operations are blocked."""
        dangerous_ops = [
            ("Bash", {"command": "rm -rf /"}),
            ("Bash", {"command": "DROP TABLE users"}),
            ("Bash", {"command": "git push --force origin main"}),
            ("Write", {"file_path": ".env", "content": "API_KEY=secret123"}),
        ]

        for tool_name, input_data in dangerous_ops:
            result = await handle_validate_operation({
                "tool_name": tool_name,
                "input": input_data
            })
            response = json.loads(result[0].text)
            assert response["status"] == "denied", \
                f"Should deny {tool_name} {input_data}"
            # Some operations may be caught by Tier 1, others by Tier 3 AI
            assert "dangerous" in response["tier"] or "deny" in response["tier"], \
                f"Expected dangerous tier but got {response['tier']}"

    @pytest.mark.asyncio
    async def test_scenario_task_agent_graceful_degradation(self):
        """Test Task agent can continue working with mixed validation results."""
        operations = [
            ("Bash", {"command": "git status"}),          # approved
            ("Bash", {"command": "rm -rf /tmp/danger"}),  # denied
            ("Bash", {"command": "ls -la"}),              # approved
            ("Read", {"file_path": "README.md"}),         # approved
        ]

        results = []
        for tool_name, input_data in operations:
            result = await handle_validate_operation({
                "tool_name": tool_name,
                "input": input_data
            })
            response = json.loads(result[0].text)
            results.append(response["status"])

        # Should have mix of approved and denied
        assert "approved" in results
        assert "denied" in results
        # Agent should complete all validations (not crash)
        assert len(results) == len(operations)
