"""
Unit tests for phlegyas.hook_blocking module.

Tests cover all functions in the blocking hook module:
- Mode detection (is_blocking_mode)
- Config parsing (get_blocking_config)
- Pending approval creation (create_pending_approval)
- File queue polling (poll_for_resolution)
- Supervisor notification (notify_supervisor)
- Human escalation notification (notify_human_escalation)
- Full delegation chain (run_blocking_delegation)
"""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# is_blocking_mode
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIsBlockingMode:
    def test_returns_true_when_env_is_blocking(self, monkeypatch):
        monkeypatch.setenv("PHLEGYAS_APPROVAL_MODE", "blocking")
        from phlegyas.hook_blocking import is_blocking_mode

        assert is_blocking_mode() is True

    def test_returns_false_when_env_is_advisory(self, monkeypatch):
        monkeypatch.setenv("PHLEGYAS_APPROVAL_MODE", "advisory")
        from phlegyas.hook_blocking import is_blocking_mode

        assert is_blocking_mode() is False

    def test_returns_false_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("PHLEGYAS_APPROVAL_MODE", raising=False)
        from phlegyas.hook_blocking import is_blocking_mode

        assert is_blocking_mode() is False


# ---------------------------------------------------------------------------
# get_blocking_config
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetBlockingConfig:
    def test_defaults(self, monkeypatch):
        # Clear all relevant env vars
        for var in (
            "PHLEGYAS_SUPERVISOR_TIMEOUT_SECONDS",
            "PHLEGYAS_HUMAN_TIMEOUT_SECONDS",
            "PHLEGYAS_POLL_INTERVAL_SECONDS",
            "PHLEGYAS_QUEUE_DIR",
            "CYGNUS_SUPERVISOR_ID",
            "CYGNUS_WORKFLOW_ID",
            "CYGNUS_AGENT_ID",
            "CYGNUS_API_URL",
        ):
            monkeypatch.delenv(var, raising=False)

        from phlegyas.hook_blocking import get_blocking_config

        config = get_blocking_config()
        assert config.supervisor_timeout == 60
        assert config.human_timeout == 120
        assert config.poll_interval == 2.0
        assert config.queue_dir == Path.home() / ".claude" / "pending-approvals"
        assert config.supervisor_id is None
        assert config.workflow_id is None
        assert config.agent_id is None
        assert config.cygnus_api_url == "http://localhost:4000"

    def test_custom_values(self, monkeypatch):
        monkeypatch.setenv("PHLEGYAS_SUPERVISOR_TIMEOUT_SECONDS", "30")
        monkeypatch.setenv("PHLEGYAS_HUMAN_TIMEOUT_SECONDS", "60")
        monkeypatch.setenv("PHLEGYAS_POLL_INTERVAL_SECONDS", "0.5")
        monkeypatch.setenv("PHLEGYAS_QUEUE_DIR", "/tmp/test-queue")
        monkeypatch.setenv("CYGNUS_SUPERVISOR_ID", "sup-001")
        monkeypatch.setenv("CYGNUS_WORKFLOW_ID", "wf-001")
        monkeypatch.setenv("CYGNUS_AGENT_ID", "agent-001")
        monkeypatch.setenv("CYGNUS_API_URL", "http://localhost:5000")

        from phlegyas.hook_blocking import get_blocking_config

        config = get_blocking_config()
        assert config.supervisor_timeout == 30
        assert config.human_timeout == 60
        assert config.poll_interval == 0.5
        assert config.queue_dir == Path("/tmp/test-queue")
        assert config.supervisor_id == "sup-001"
        assert config.workflow_id == "wf-001"
        assert config.agent_id == "agent-001"
        assert config.cygnus_api_url == "http://localhost:5000"

    def test_malformed_timeout_env_falls_back(self, monkeypatch):
        """Non-numeric env vars should fall back to defaults, not raise."""
        monkeypatch.setenv("PHLEGYAS_SUPERVISOR_TIMEOUT_SECONDS", "not_a_number")
        monkeypatch.setenv("PHLEGYAS_HUMAN_TIMEOUT_SECONDS", "also_bad")
        monkeypatch.setenv("PHLEGYAS_POLL_INTERVAL_SECONDS", "nope")
        monkeypatch.delenv("CYGNUS_SUPERVISOR_ID", raising=False)
        monkeypatch.delenv("CYGNUS_WORKFLOW_ID", raising=False)
        monkeypatch.delenv("CYGNUS_AGENT_ID", raising=False)
        monkeypatch.delenv("CYGNUS_API_URL", raising=False)
        monkeypatch.delenv("PHLEGYAS_QUEUE_DIR", raising=False)

        from phlegyas.hook_blocking import get_blocking_config

        config = get_blocking_config()
        assert config.supervisor_timeout == 60
        assert config.human_timeout == 120
        assert config.poll_interval == 2.0


# ---------------------------------------------------------------------------
# create_pending_approval
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCreatePendingApproval:
    def test_writes_file_with_correct_schema(self, tmp_path):
        from phlegyas.hook_blocking import BlockingConfig, create_pending_approval

        config = BlockingConfig(queue_dir=tmp_path)
        request_id = create_pending_approval(
            tool_name="Bash",
            input_data={"command": "npm install lodash"},
            config=config,
        )

        assert request_id is not None
        file_path = tmp_path / f"{request_id}.json"
        assert file_path.exists()

        data = json.loads(file_path.read_text())
        assert data["tool_name"] == "Bash"
        assert data["status"] == "pending"
        assert data["source"] == "hook"
        assert data["schema_version"] == 2
        assert "request_id" in data
        assert "created_at" in data
        assert "expires_at" in data

    def test_includes_supervisor_id_from_config(self, tmp_path):
        from phlegyas.hook_blocking import BlockingConfig, create_pending_approval

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-001",
            workflow_id="wf-001",
            agent_id="agent-001",
        )
        request_id = create_pending_approval(
            tool_name="Bash",
            input_data={"command": "npm install lodash"},
            config=config,
        )

        data = json.loads((tmp_path / f"{request_id}.json").read_text())
        assert data["supervisor_id"] == "sup-001"
        assert data["workflow_id"] == "wf-001"
        assert data["agent_id"] == "agent-001"

    def test_returns_none_on_write_failure(self, tmp_path):
        from phlegyas.hook_blocking import BlockingConfig, create_pending_approval

        # Point to a directory that doesn't exist inside a read-only parent
        bad_dir = tmp_path / "nonexistent" / "deep" / "path"
        # Make parent read-only so mkdir fails
        (tmp_path / "nonexistent").mkdir()
        (tmp_path / "nonexistent").chmod(0o000)

        config = BlockingConfig(queue_dir=bad_dir)
        try:
            request_id = create_pending_approval(
                tool_name="Bash",
                input_data={"command": "ls"},
                config=config,
            )
            assert request_id is None
        finally:
            # Restore permissions for cleanup
            (tmp_path / "nonexistent").chmod(0o755)


# ---------------------------------------------------------------------------
# poll_for_resolution
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPollForResolution:
    def test_returns_approve_immediately(self, tmp_path):
        from phlegyas.hook_blocking import poll_for_resolution

        request_id = "test-req-001"
        file_path = tmp_path / f"{request_id}.json"
        file_path.write_text(json.dumps({"status": "approve"}))

        result = poll_for_resolution(
            request_id=request_id,
            timeout_seconds=2,
            poll_interval=0.1,
            queue_dir=tmp_path,
        )
        assert result == "approve"

    def test_returns_deny_when_denied(self, tmp_path):
        from phlegyas.hook_blocking import poll_for_resolution

        request_id = "test-req-002"
        file_path = tmp_path / f"{request_id}.json"
        file_path.write_text(json.dumps({"status": "deny"}))

        result = poll_for_resolution(
            request_id=request_id,
            timeout_seconds=2,
            poll_interval=0.1,
            queue_dir=tmp_path,
        )
        assert result == "deny"

    def test_returns_none_on_timeout(self, tmp_path):
        from phlegyas.hook_blocking import poll_for_resolution

        request_id = "test-req-003"
        file_path = tmp_path / f"{request_id}.json"
        file_path.write_text(json.dumps({"status": "pending"}))

        start = time.monotonic()
        result = poll_for_resolution(
            request_id=request_id,
            timeout_seconds=0.3,
            poll_interval=0.1,
            queue_dir=tmp_path,
        )
        elapsed = time.monotonic() - start
        assert result is None
        assert elapsed >= 0.3

    def test_handles_json_decode_error(self, tmp_path):
        from phlegyas.hook_blocking import poll_for_resolution

        request_id = "test-req-004"
        file_path = tmp_path / f"{request_id}.json"
        # Write invalid JSON initially
        file_path.write_text("{broken json")

        # Overwrite with valid approve after a short delay (simulate mid-write)
        import threading

        def fix_file():
            time.sleep(0.15)
            file_path.write_text(json.dumps({"status": "approve"}))

        t = threading.Thread(target=fix_file)
        t.start()

        result = poll_for_resolution(
            request_id=request_id,
            timeout_seconds=1,
            poll_interval=0.1,
            queue_dir=tmp_path,
        )
        t.join()
        assert result == "approve"

    def test_normalizes_approved_to_approve(self, tmp_path):
        from phlegyas.hook_blocking import poll_for_resolution

        request_id = "test-req-005"
        file_path = tmp_path / f"{request_id}.json"
        file_path.write_text(json.dumps({"status": "approved"}))

        result = poll_for_resolution(
            request_id=request_id,
            timeout_seconds=2,
            poll_interval=0.1,
            queue_dir=tmp_path,
        )
        assert result == "approve"

    def test_returns_escalate_to_human(self, tmp_path):
        from phlegyas.hook_blocking import poll_for_resolution

        request_id = "test-req-006"
        file_path = tmp_path / f"{request_id}.json"
        file_path.write_text(json.dumps({"status": "escalate_to_human"}))

        result = poll_for_resolution(
            request_id=request_id,
            timeout_seconds=2,
            poll_interval=0.1,
            queue_dir=tmp_path,
        )
        assert result == "escalate_to_human"


# ---------------------------------------------------------------------------
# notify_supervisor
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNotifySupervisor:
    @patch("phlegyas.hook_blocking.urllib.request.urlopen")
    @patch("phlegyas.hook_blocking.MacOSNotifier")
    def test_calls_http_post(self, mock_notifier_cls, mock_urlopen):
        from phlegyas.hook_blocking import BlockingConfig, notify_supervisor

        config = BlockingConfig(
            supervisor_id="sup-001",
            workflow_id="wf-001",
            agent_id="agent-001",
            cygnus_api_url="http://localhost:4000",
        )

        notify_supervisor(
            request_id="req-001",
            tool_name="Bash",
            input_summary="npm install lodash",
            config=config,
        )

        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "http://localhost:4000/api/approvals/notify"
        assert req.method == "POST"

        body = json.loads(req.data.decode())
        assert body["type"] == "worker_blocked"
        assert body["request_id"] == "req-001"
        assert body["supervisor_id"] == "sup-001"

    @patch(
        "phlegyas.hook_blocking.urllib.request.urlopen", side_effect=Exception("Connection refused")
    )
    @patch("phlegyas.hook_blocking.MacOSNotifier")
    def test_handles_connection_error_gracefully(self, mock_notifier_cls, mock_urlopen):
        from phlegyas.hook_blocking import BlockingConfig, notify_supervisor

        config = BlockingConfig(supervisor_id="sup-001")

        # Should not raise
        notify_supervisor(
            request_id="req-001",
            tool_name="Bash",
            input_summary="npm install",
            config=config,
        )

    @patch("phlegyas.hook_blocking.urllib.request.urlopen")
    @patch("phlegyas.hook_blocking.MacOSNotifier")
    def test_calls_macos_notifier(self, mock_notifier_cls, mock_urlopen):
        from phlegyas.hook_blocking import BlockingConfig, notify_supervisor

        mock_instance = MagicMock()
        mock_notifier_cls.return_value = mock_instance

        config = BlockingConfig(supervisor_id="sup-001")

        notify_supervisor(
            request_id="req-001",
            tool_name="Bash",
            input_summary="npm install",
            config=config,
        )

        mock_instance.notify.assert_called_once()


# ---------------------------------------------------------------------------
# run_blocking_delegation
# ---------------------------------------------------------------------------


@pytest.mark.unit
@patch("phlegyas.hook_blocking.MacOSNotifier")
@patch("phlegyas.hook_blocking.urllib.request.urlopen")
class TestRunBlockingDelegation:
    def test_returns_0_when_supervisor_approves(self, _mock_urlopen, _mock_notifier, tmp_path):
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-001",
            workflow_id="wf-001",
            supervisor_timeout=1,
            human_timeout=1,
            poll_interval=0.1,
        )

        import threading

        def approve_after_delay():
            time.sleep(0.15)
            # Find the pending file and resolve it
            files = list(tmp_path.glob("*.json"))
            assert len(files) == 1
            data = json.loads(files[0].read_text())
            data["status"] = "approve"
            files[0].write_text(json.dumps(data))

        t = threading.Thread(target=approve_after_delay)
        t.start()

        result = run_blocking_delegation(
            tool_name="Bash",
            input_data={"command": "npm install lodash"},
            config=config,
        )
        t.join()
        assert result == 0

    def test_returns_2_when_supervisor_denies(self, _mock_urlopen, _mock_notifier, tmp_path):
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-001",
            workflow_id="wf-001",
            supervisor_timeout=1,
            human_timeout=1,
            poll_interval=0.1,
        )

        import threading

        def deny_after_delay():
            time.sleep(0.15)
            files = list(tmp_path.glob("*.json"))
            assert len(files) == 1
            data = json.loads(files[0].read_text())
            data["status"] = "deny"
            files[0].write_text(json.dumps(data))

        t = threading.Thread(target=deny_after_delay)
        t.start()

        result = run_blocking_delegation(
            tool_name="Bash",
            input_data={"command": "npm install lodash"},
            config=config,
        )
        t.join()
        assert result == 2

    def test_escalates_to_human_on_supervisor_timeout(
        self, _mock_urlopen, _mock_notifier, tmp_path
    ):
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-001",
            workflow_id="wf-001",
            supervisor_timeout=0.3,
            human_timeout=1,
            poll_interval=0.1,
        )

        import threading

        def approve_in_human_phase():
            # Wait for supervisor phase to timeout, then approve in human phase
            time.sleep(0.5)
            files = list(tmp_path.glob("*.json"))
            assert len(files) == 1
            data = json.loads(files[0].read_text())
            data["status"] = "approve"
            files[0].write_text(json.dumps(data))

        t = threading.Thread(target=approve_in_human_phase)
        t.start()

        result = run_blocking_delegation(
            tool_name="Bash",
            input_data={"command": "npm install lodash"},
            config=config,
        )
        t.join()
        assert result == 0

    def test_returns_2_on_all_timeout(self, _mock_urlopen, _mock_notifier, tmp_path):
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-001",
            workflow_id="wf-001",
            supervisor_timeout=0.3,
            human_timeout=0.3,
            poll_interval=0.1,
        )

        result = run_blocking_delegation(
            tool_name="Bash",
            input_data={"command": "npm install lodash"},
            config=config,
        )
        assert result == 2

    def test_skips_supervisor_phase_when_no_supervisor_id(
        self, _mock_urlopen, _mock_notifier, tmp_path
    ):
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id=None,
            workflow_id=None,
            supervisor_timeout=0.3,
            human_timeout=1,
            poll_interval=0.1,
        )

        import threading

        def approve_quickly():
            time.sleep(0.15)
            files = list(tmp_path.glob("*.json"))
            assert len(files) == 1
            data = json.loads(files[0].read_text())
            data["status"] = "approve"
            files[0].write_text(json.dumps(data))

        t = threading.Thread(target=approve_quickly)
        t.start()

        start = time.monotonic()
        result = run_blocking_delegation(
            tool_name="Bash",
            input_data={"command": "npm install lodash"},
            config=config,
        )
        elapsed = time.monotonic() - start
        t.join()

        assert result == 0
        # Should resolve well before supervisor_timeout + human_timeout
        assert elapsed < 1.0
