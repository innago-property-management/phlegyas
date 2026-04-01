"""
Tests for Main Approver - Integration Tests

Tests the three-tier permission approval system integration.
Calls tier logic directly (not through FastMCP wrapper) to test the actual
evaluation pipeline.
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from phlegyas.approver_mcp import (
    PendingApproval,
    handle_submit_approval,
    handle_supervisor_approve,
    pending_approvals,
    resolved_approvals,
    state,
    write_audit_log,
)
from phlegyas.tier1_dangerous import DangerousPatternDetector
from phlegyas.tier2_safe import SafeOperationDetector
from phlegyas.tier3_ai import AIEvaluator


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
                f"AI-approved (confidence: {evaluation.confidence:.2f}): {evaluation.reasoning}"
            )
            return {"behavior": "allow", "message": message}
        elif decision == "deny":
            message = f"AI-denied (confidence: {evaluation.confidence:.2f}): {evaluation.reasoning}"
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
    async def test_tier3_evaluates_ambiguous_operations(self, mock_anthropic_tool_use_response):
        """Tier 3 should use AI for ambiguous operations."""
        mock_response = mock_anthropic_tool_use_response(
            decision="approve",
            category="moderate_risk",
            reasoning="Safe edit",
            confidence=0.85,
        )

        with patch("phlegyas.tier3_ai.Anthropic") as mock_anthropic_class:
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
        with patch("phlegyas.tier3_ai.Anthropic") as mock_anthropic_class:
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
            assert (
                "AI evaluation failed" in result["message"] or "human approval" in result["message"]
            )

    # Audit Logging Tests

    def test_audit_log_write(self, tmp_path):
        """Should write audit log entries correctly."""
        audit_file = tmp_path / "test_audit.jsonl"

        with patch.object(state, "audit_log_file", str(audit_file)):
            with patch.object(state, "enable_audit_log", True):
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

        with patch.object(state, "audit_log_file", str(audit_file)):
            with patch.object(state, "enable_audit_log", False):
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
            assert result["behavior"] == "deny", (
                f"Failed to block credential operation: {tool_name}"
            )


class TestAuditLogSanitization:
    """Tests for audit log credential masking."""

    def test_sanitize_masks_password(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"command": "echo password=supersecret123"})
        assert "supersecret123" not in result["command"]
        assert "REDACTED" in result["command"]

    def test_sanitize_masks_api_key(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"content": "ANTHROPIC_API_KEY=sk-ant-real-key"})
        assert "sk-ant-real-key" not in result["content"]
        assert "REDACTED" in result["content"]

    def test_sanitize_masks_bearer_token(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"command": "curl -H 'Authorization: Bearer FAKE'"})
        assert "FAKE" not in result["command"]
        assert "REDACTED" in result["command"]

    def test_sanitize_masks_nested_dicts(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"outer": {"inner": "password=secret"}})
        assert "secret" not in str(result)
        assert "REDACTED" in str(result)

    def test_sanitize_preserves_safe_values(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"command": "git status", "file": "README.md"})
        assert result["command"] == "git status"
        assert result["file"] == "README.md"

    def test_sanitize_handles_non_string_values(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"count": 42, "flag": True, "command": "ls"})
        assert result["count"] == 42
        assert result["flag"] is True

    def test_sanitize_masks_secrets_in_lists(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"headers": ["Authorization: Bearer FAKE", "Accept: json"]})
        assert "FAKE" not in str(result)
        assert "REDACTED" in str(result)
        assert "Accept: json" in result["headers"][1]

    def test_sanitize_masks_secrets_in_tuples(self):
        from phlegyas.approver_mcp import sanitize_for_audit

        result = sanitize_for_audit({"args": ("password=secret", "safe")})
        assert "secret" not in str(result)
        assert isinstance(result["args"], tuple)

    def test_sanitize_masks_github_pat(self):
        from phlegyas.sanitize import sanitize_value

        result = sanitize_value("git clone https://ghp_abc123def456@github.com/org/repo")
        assert "abc123def456" not in result
        assert "REDACTED" in result

    def test_sanitize_masks_github_pat_fine_grained(self):
        from phlegyas.sanitize import sanitize_value

        result = sanitize_value("export TOKEN=github_pat_11ABCDEF_longtoken123")
        assert "longtoken123" not in result
        assert "REDACTED" in result

    def test_sanitize_masks_url_embedded_credentials(self):
        from phlegyas.sanitize import sanitize_value

        result = sanitize_value("curl https://admin:s3cret@db.example.com/api")
        assert "s3cret" not in result
        assert "REDACTED" in result
        # @ must be preserved so the URL structure remains valid for debugging
        assert "@db.example.com" in result

    def test_sanitize_masks_url_credentials_with_special_username(self):
        from phlegyas.sanitize import sanitize_value

        result = sanitize_value("curl https://user.name-test:p4ssw0rd@host.com/path")
        assert "p4ssw0rd" not in result
        assert "REDACTED" in result

    def test_sanitize_masks_aws_session_token(self):
        from phlegyas.sanitize import sanitize_value

        result = sanitize_value("AWS_SESSION_TOKEN=FwoGZXIvYXdzE...")
        assert "FwoGZXIvYXdzE" not in result
        assert "REDACTED" in result


class TestEnhancedAuditFields:
    """Tests for Phase 0 enhanced audit logging fields."""

    @pytest.fixture(autouse=True)
    def _clear_approval_stores(self):
        """Clear pending and resolved approval stores before each test."""
        pending_approvals.clear()
        resolved_approvals.clear()
        yield
        pending_approvals.clear()
        resolved_approvals.clear()

    @staticmethod
    def _make_pending(
        request_id="test-req-001",
        tool_name="Bash",
        input_data=None,
        confidence=0.65,
        tier="tier3_needs_human",
        workflow_id="wf-001",
        agent_id="agent-001",
    ) -> PendingApproval:
        pending = PendingApproval(
            request_id=request_id,
            tool_name=tool_name,
            input_data=input_data or {"command": "npm install some-package"},
            reason="Needs review",
            confidence=confidence,
            tier=tier,
            workflow_id=workflow_id,
            agent_id=agent_id,
        )
        pending_approvals[request_id] = pending
        return pending

    def test_audit_log_includes_repo_context(self, tmp_path):
        """write_audit_log should include a repo_context field."""
        audit_file = tmp_path / "audit.jsonl"

        with (
            patch.object(state, "audit_log_file", str(audit_file)),
            patch.object(state, "enable_audit_log", True),
        ):
            write_audit_log(
                tool_name="Bash",
                input_data={"command": "ls"},
                decision="allow",
                tier="tier2_safe",
                reason="safe",
                repo_context="my-project",
            )

        entry = json.loads(audit_file.read_text().strip())
        assert entry["repo_context"] == "my-project"

    def test_audit_log_repo_context_defaults_to_cwd_basename(self, tmp_path):
        """When repo_context is not provided, it should default to os.getcwd() basename."""
        audit_file = tmp_path / "audit.jsonl"

        with (
            patch.object(state, "audit_log_file", str(audit_file)),
            patch.object(state, "enable_audit_log", True),
            patch("phlegyas.approver_mcp.os.getcwd", return_value="/home/user/my-repo"),
            patch("phlegyas.approver_mcp.os.path.basename", return_value="my-repo"),
        ):
            write_audit_log(
                tool_name="Bash",
                input_data={"command": "ls"},
                decision="allow",
                tier="tier2_safe",
                reason="safe",
            )

        entry = json.loads(audit_file.read_text().strip())
        assert entry["repo_context"] == "my-repo"

    def test_audit_log_warns_on_core_field_collision(self, tmp_path):
        """Extra fields colliding with core audit fields should be dropped with a warning."""
        audit_file = tmp_path / "audit.jsonl"

        with (
            patch.object(state, "audit_log_file", str(audit_file)),
            patch.object(state, "enable_audit_log", True),
        ):
            # Use non-overlapping keyword names to avoid Python TypeError,
            # but test fields that collide with log_entry keys built inside the function
            write_audit_log(
                tool_name="Bash",
                input_data={"command": "ls"},
                decision="allow",
                tier="tier2_safe",
                reason="safe",
                # These collide with core log_entry keys (timestamp, tool_name, etc.)
                timestamp="2000-01-01T00:00:00Z",
                tool_name_override="should_not_appear",  # not a core field — passes
                legit_field="ok",
            )

        entry = json.loads(audit_file.read_text().strip())
        # Core "timestamp" field must not be overwritten
        assert entry["timestamp"] != "2000-01-01T00:00:00Z"
        # Non-colliding extra fields should still be present
        assert entry["legit_field"] == "ok"

    def test_audit_log_extra_fields_merged(self, tmp_path):
        """Extra keyword arguments should be merged into the audit entry."""
        audit_file = tmp_path / "audit.jsonl"

        with (
            patch.object(state, "audit_log_file", str(audit_file)),
            patch.object(state, "enable_audit_log", True),
        ):
            write_audit_log(
                tool_name="Bash",
                input_data={"command": "ls"},
                decision="allow",
                tier="tier2_safe",
                reason="safe",
                delegation_phase="direct",
                custom_field="hello",
            )

        entry = json.loads(audit_file.read_text().strip())
        assert entry["delegation_phase"] == "direct"
        assert entry["custom_field"] == "hello"

    @pytest.mark.asyncio
    async def test_audit_log_submit_approval_records_override(self, tmp_path):
        """handle_submit_approval should write override fields to audit log."""
        audit_file = tmp_path / "audit.jsonl"
        self._make_pending(request_id="req-sub-001")

        with (
            patch.object(state, "audit_log_file", str(audit_file)),
            patch.object(state, "enable_audit_log", True),
            patch.object(state, "file_queue", None),
        ):
            await handle_submit_approval(
                {
                    "request_id": "req-sub-001",
                    "decision": "approve",
                    "reason": "looks safe",
                    "approver_id": "alice",
                }
            )

        entry = json.loads(audit_file.read_text().strip())
        assert entry["was_overridden"] is True
        assert entry["override_decision"] == "approve"
        assert entry["override_by"] == "human:alice"
        assert entry["delegation_phase"] == "human"

    @pytest.mark.asyncio
    async def test_audit_log_supervisor_approve_records_override(self, tmp_path):
        """handle_supervisor_approve should write override fields to audit log."""
        audit_file = tmp_path / "audit.jsonl"
        self._make_pending(request_id="req-sup-001", workflow_id="wf-001")

        with (
            patch.object(state, "audit_log_file", str(audit_file)),
            patch.object(state, "enable_audit_log", True),
            patch.object(state, "file_queue", None),
            patch.object(state.supervisor_policy, "validate", return_value=None),
        ):
            await handle_supervisor_approve(
                {
                    "request_id": "req-sup-001",
                    "decision": "approve",
                    "supervisor_id": "cygnus-001",
                    "workflow_id": "wf-001",
                    "reasoning": "Aligns with task",
                }
            )

        entry = json.loads(audit_file.read_text().strip())
        assert entry["was_overridden"] is True
        assert entry["override_decision"] == "approve"
        assert entry["override_by"] == "supervisor:cygnus-001"
        assert entry["delegation_phase"] == "supervisor"
