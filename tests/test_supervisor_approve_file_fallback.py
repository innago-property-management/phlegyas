"""
Tests for supervisor_approve file queue fallback.

When a pending approval exists only as a file (hook-originated),
handle_supervisor_approve should find it via FileQueueWriter.read_pending()
and process it normally.
"""

import json
from pathlib import Path

import pytest

from phlegyas.approver_mcp import (
    PendingApproval,
    _load_pending_from_file,
    call_tool,
    pending_approvals,
    resolved_approvals,
    state,
)
from phlegyas.file_queue import FileQueueWriter

# ---------------------------------------------------------------------------
# FileQueueWriter.read_pending unit tests
# ---------------------------------------------------------------------------


class TestReadPending:
    """Unit tests for FileQueueWriter.read_pending()."""

    @pytest.mark.unit
    def test_read_pending_valid_file(self, tmp_path: Path):
        """read_pending returns parsed dict for a valid JSON file."""
        fq = FileQueueWriter(queue_dir=tmp_path)
        data = {
            "schema_version": 1,
            "request_id": "req-001",
            "tool_name": "Bash",
            "input_summary": "npm install foo",
            "reason": "Needs review",
            "confidence": 0.65,
            "workflow_id": "wf-001",
            "agent_id": "agent-001",
            "created_at": "2026-03-30T12:00:00+00:00",
            "expires_at": "2026-03-30T12:30:00+00:00",
            "status": "pending",
        }
        file_path = tmp_path / "req-001.json"
        file_path.write_text(json.dumps(data))

        result = fq.read_pending("req-001")

        assert result is not None
        assert result["request_id"] == "req-001"
        assert result["tool_name"] == "Bash"
        assert result["confidence"] == 0.65

    @pytest.mark.unit
    def test_read_pending_missing_file_returns_none(self, tmp_path: Path):
        """read_pending returns None when file does not exist."""
        fq = FileQueueWriter(queue_dir=tmp_path)

        result = fq.read_pending("nonexistent-id")

        assert result is None

    @pytest.mark.unit
    def test_read_pending_invalid_json_returns_none(self, tmp_path: Path):
        """read_pending returns None for a file with invalid JSON."""
        fq = FileQueueWriter(queue_dir=tmp_path)
        file_path = tmp_path / "bad-json.json"
        file_path.write_text("{this is not valid json!!!")

        result = fq.read_pending("bad-json")

        assert result is None


# ---------------------------------------------------------------------------
# _load_pending_from_file unit tests
# ---------------------------------------------------------------------------


class TestLoadPendingFromFile:
    """Unit tests for _load_pending_from_file helper."""

    @pytest.mark.unit
    def test_load_pending_from_file_constructs_pending_approval(self, tmp_path: Path):
        """Constructs a PendingApproval from valid file data."""
        fq = FileQueueWriter(queue_dir=tmp_path)
        data = {
            "schema_version": 1,
            "request_id": "req-002",
            "tool_name": "Bash",
            "input_summary": "npm install bar",
            "reason": "AI uncertain",
            "confidence": 0.72,
            "workflow_id": "wf-002",
            "agent_id": "agent-002",
            "created_at": "2026-03-30T12:00:00+00:00",
            "expires_at": "2026-03-30T12:30:00+00:00",
            "status": "pending",
        }
        (tmp_path / "req-002.json").write_text(json.dumps(data))

        result = _load_pending_from_file("req-002", fq)

        assert isinstance(result, PendingApproval)
        assert result.request_id == "req-002"
        assert result.tool_name == "Bash"
        assert result.confidence == 0.72
        assert result.workflow_id == "wf-002"
        assert result.agent_id == "agent-002"
        assert result.reason == "AI uncertain"
        assert result.tier == "tier3_needs_human"

    @pytest.mark.unit
    def test_load_pending_from_file_sets_default_confidence(self, tmp_path: Path):
        """Sets confidence to 0.5 when file has confidence=None (hook-originated)."""
        fq = FileQueueWriter(queue_dir=tmp_path)
        data = {
            "schema_version": 1,
            "request_id": "req-hook",
            "tool_name": "Bash",
            "input_summary": "make deploy",
            "reason": "Hook-originated",
            "confidence": None,
            "workflow_id": "wf-003",
            "agent_id": "agent-003",
            "created_at": "2026-03-30T12:00:00+00:00",
            "expires_at": "2026-03-30T12:30:00+00:00",
            "status": "pending",
        }
        (tmp_path / "req-hook.json").write_text(json.dumps(data))

        result = _load_pending_from_file("req-hook", fq)

        assert result is not None
        assert result.confidence == 0.5

    @pytest.mark.unit
    def test_load_pending_from_file_missing_file_returns_none(self, tmp_path: Path):
        """Returns None when the file doesn't exist."""
        fq = FileQueueWriter(queue_dir=tmp_path)

        result = _load_pending_from_file("ghost-id", fq)

        assert result is None


# ---------------------------------------------------------------------------
# handle_supervisor_approve file fallback integration tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_approval_stores():
    """Clear pending and resolved approval stores before each test."""
    pending_approvals.clear()
    resolved_approvals.clear()
    yield
    pending_approvals.clear()
    resolved_approvals.clear()


class TestSupervisorApproveFileFallback:
    """Integration tests for supervisor_approve with file queue fallback."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_supervisor_approve_finds_hook_pending_from_file(self, tmp_path: Path):
        """supervisor_approve resolves a hook-originated pending found only in file queue."""
        fq = FileQueueWriter(queue_dir=tmp_path)
        data = {
            "schema_version": 1,
            "request_id": "hook-req-001",
            "tool_name": "Bash",
            "input_summary": "npm install something",
            "reason": "Hook needs review",
            "confidence": 0.65,
            "workflow_id": "wf-100",
            "agent_id": "worker-100",
            "created_at": "2026-03-30T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "status": "pending",
        }
        (tmp_path / "hook-req-001.json").write_text(json.dumps(data))

        original_fq = state.file_queue
        state.file_queue = fq
        try:
            result = await call_tool(
                "supervisor_approve",
                {
                    "request_id": "hook-req-001",
                    "decision": "approve",
                    "supervisor_id": "supervisor-100",
                    "workflow_id": "wf-100",
                    "reasoning": "Safe operation",
                },
            )
        finally:
            state.file_queue = original_fq

        response = json.loads(result[0].text)
        assert response["success"] is True
        assert response["decision"] == "approve"
        assert response["tool_name"] == "Bash"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_supervisor_approve_file_missing_returns_not_found(self, tmp_path: Path):
        """supervisor_approve returns not_found when neither memory nor file has the request."""
        fq = FileQueueWriter(queue_dir=tmp_path)
        # No file written — nothing to find

        original_fq = state.file_queue
        state.file_queue = fq
        try:
            result = await call_tool(
                "supervisor_approve",
                {
                    "request_id": "nonexistent-req",
                    "decision": "approve",
                    "supervisor_id": "supervisor-200",
                    "workflow_id": "wf-200",
                },
            )
        finally:
            state.file_queue = original_fq

        response = json.loads(result[0].text)
        assert response["success"] is False
        assert response["error"] == "not_found"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_supervisor_approve_prefers_memory_over_file(self, tmp_path: Path):
        """When pending exists in both memory and file, memory is used (file not read)."""
        # Set up in-memory pending
        in_memory = PendingApproval(
            request_id="dual-req-001",
            tool_name="Bash",
            input_data={"command": "npm install"},
            reason="In-memory reason",
            confidence=0.75,
            tier="tier3_needs_human",
            workflow_id="wf-300",
            agent_id="worker-300",
        )
        pending_approvals["dual-req-001"] = in_memory

        # Also write a file with different reason (should NOT be used)
        fq = FileQueueWriter(queue_dir=tmp_path)
        data = {
            "schema_version": 1,
            "request_id": "dual-req-001",
            "tool_name": "Bash",
            "input_summary": "npm install",
            "reason": "File reason — should not appear",
            "confidence": 0.65,
            "workflow_id": "wf-300",
            "agent_id": "worker-300",
            "created_at": "2026-03-30T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "status": "pending",
        }
        (tmp_path / "dual-req-001.json").write_text(json.dumps(data))

        original_fq = state.file_queue
        state.file_queue = fq
        try:
            result = await call_tool(
                "supervisor_approve",
                {
                    "request_id": "dual-req-001",
                    "decision": "approve",
                    "supervisor_id": "supervisor-300",
                    "workflow_id": "wf-300",
                    "reasoning": "Approved",
                },
            )
        finally:
            state.file_queue = original_fq

        response = json.loads(result[0].text)
        assert response["success"] is True
        # Verify it was the in-memory one that got resolved
        assert "dual-req-001" in resolved_approvals
        assert resolved_approvals["dual-req-001"].reason == "In-memory reason"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_supervisor_approve_file_resolves_queue_file(self, tmp_path: Path):
        """After resolving a file-originated pending, the queue file is updated."""
        fq = FileQueueWriter(queue_dir=tmp_path)
        data = {
            "schema_version": 1,
            "request_id": "resolve-req-001",
            "tool_name": "Bash",
            "input_summary": "npm install baz",
            "reason": "Needs review",
            "confidence": 0.65,
            "workflow_id": "wf-400",
            "agent_id": "worker-400",
            "created_at": "2026-03-30T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "status": "pending",
        }
        file_path = tmp_path / "resolve-req-001.json"
        file_path.write_text(json.dumps(data))

        original_fq = state.file_queue
        state.file_queue = fq
        try:
            await call_tool(
                "supervisor_approve",
                {
                    "request_id": "resolve-req-001",
                    "decision": "approve",
                    "supervisor_id": "supervisor-400",
                    "workflow_id": "wf-400",
                    "reasoning": "Looks good",
                },
            )
        finally:
            state.file_queue = original_fq

        # The file should now reflect the resolved status
        updated = json.loads(file_path.read_text())
        assert updated["status"] == "approve"
        assert updated["decided_by"] == "supervisor:supervisor-400"
