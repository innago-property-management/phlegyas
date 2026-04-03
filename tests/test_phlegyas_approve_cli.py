"""
Tests for bin/phlegyas-approve CLI script.

Tests the resolve and list functions via subprocess invocation.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = str(Path(__file__).parent.parent / "bin" / "phlegyas-approve")


def _write_pending(queue_dir: Path, request_id: str, **overrides) -> Path:
    """Write a minimal pending approval file."""
    data = {
        "schema_version": 1,
        "request_id": request_id,
        "tool_name": "Bash",
        "input_summary": "test command",
        "reason": "test reason",
        "confidence": 0.5,
        "workflow_id": None,
        "agent_id": None,
        "created_at": "2026-04-01T10:00:00+00:00",
        "expires_at": "2026-04-01T10:30:00+00:00",
        "status": "pending",
        **overrides,
    }
    path = queue_dir / f"{request_id}.json"
    path.write_text(json.dumps(data, indent=2))
    os.chmod(str(path), 0o600)
    return path


@pytest.mark.unit
class TestResolveApproval:
    """Tests for the resolve (approve/deny) path."""

    def test_approve_writes_status(self, tmp_path):
        """approve should set status=approved in the file."""
        rid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        _write_pending(tmp_path, rid)

        result = subprocess.run(
            [SCRIPT, "approve", rid],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / f"{rid}.json").read_text())
        assert data["status"] == "approved"
        assert "human:" in data["decided_by"]
        assert data["decided_at"] is not None

    def test_deny_writes_status(self, tmp_path):
        """deny should set status=denied in the file."""
        rid = "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"
        _write_pending(tmp_path, rid)

        result = subprocess.run(
            [SCRIPT, "deny", rid],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / f"{rid}.json").read_text())
        assert data["status"] == "denied"

    def test_resolve_atomic_permissions(self, tmp_path):
        """Resolved file should retain 0o600 permissions."""
        rid = "11111111-2222-3333-4444-555555555555"
        path = _write_pending(tmp_path, rid)

        subprocess.run(
            [SCRIPT, "approve", rid],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_resolve_no_tmp_file_left(self, tmp_path):
        """No .tmp file should remain after resolution."""
        rid = "11111111-2222-3333-4444-666666666666"
        _write_pending(tmp_path, rid)

        subprocess.run(
            [SCRIPT, "approve", rid],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert not (tmp_path / f"{rid}.json.tmp").exists()

    def test_reject_invalid_uuid(self, tmp_path):
        """Non-UUID request_id should be rejected."""
        result = subprocess.run(
            [SCRIPT, "approve", "not-a-uuid"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "Invalid request_id" in result.stderr

    def test_reject_path_traversal(self, tmp_path):
        """Path traversal attempts should be rejected by UUID validation."""
        result = subprocess.run(
            [SCRIPT, "approve", "../../etc/passwd"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "Invalid request_id" in result.stderr


@pytest.mark.unit
class TestListPending:
    """Tests for the list command."""

    def test_list_empty_dir(self, tmp_path):
        """list on empty directory should show no pending message."""
        result = subprocess.run(
            [SCRIPT, "list"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "No pending" in result.stdout

    def test_list_shows_pending(self, tmp_path):
        """list should show pending approval details."""
        rid = "aaaaaaaa-bbbb-cccc-dddd-111111111111"
        _write_pending(tmp_path, rid, tool_name="Bash", input_summary="npm install lodash")

        result = subprocess.run(
            [SCRIPT, "list"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "aaaaaaaa" in result.stdout
        assert "Bash" in result.stdout

    def test_list_skips_resolved(self, tmp_path):
        """list should not show resolved approvals."""
        rid = "aaaaaaaa-bbbb-cccc-dddd-222222222222"
        _write_pending(tmp_path, rid, status="approved")

        result = subprocess.run(
            [SCRIPT, "list"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "No pending" in result.stdout


@pytest.mark.unit
class TestClean:
    """Tests for the clean command."""

    def test_clean_removes_resolved(self, tmp_path):
        """clean should remove resolved files."""
        rid = "aaaaaaaa-bbbb-cccc-dddd-333333333333"
        _write_pending(tmp_path, rid, status="approved")

        result = subprocess.run(
            [SCRIPT, "clean"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert not (tmp_path / f"{rid}.json").exists()

    def test_clean_removes_expired(self, tmp_path):
        """clean should remove expired pending files."""
        rid = "aaaaaaaa-bbbb-cccc-dddd-444444444444"
        _write_pending(tmp_path, rid, expires_at="2020-01-01T00:00:00+00:00")

        result = subprocess.run(
            [SCRIPT, "clean"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert not (tmp_path / f"{rid}.json").exists()

    def test_clean_keeps_valid_pending(self, tmp_path):
        """clean should not remove non-expired pending files."""
        rid = "aaaaaaaa-bbbb-cccc-dddd-555555555555"
        _write_pending(tmp_path, rid, expires_at="2099-12-31T23:59:59+00:00")

        result = subprocess.run(
            [SCRIPT, "clean"],
            env={**os.environ, "PHLEGYAS_QUEUE_DIR": str(tmp_path)},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert (tmp_path / f"{rid}.json").exists()
