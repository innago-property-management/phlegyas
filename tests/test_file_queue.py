"""
Tests for FileQueueWriter and MacOSNotifier (User Story 2).

Tests file-based pending approval queue and macOS notification channels.
"""

import json
import threading
import time
from pathlib import Path
from unittest.mock import patch


class TestFileQueueWriter:
    """Tests for FileQueueWriter write, resolve, and delete lifecycle."""

    def _make_pending(
        self,
        request_id="test-req-001",
        tool_name="Bash",
        reason="Needs review",
        confidence=0.65,
        workflow_id=None,
        agent_id=None,
    ):
        """Create a minimal PendingApproval-like object for testing."""
        from phlegyas.approver_mcp import PendingApproval

        return PendingApproval(
            request_id=request_id,
            tool_name=tool_name,
            input_data={"command": "npm install some-package"},
            reason=reason,
            confidence=confidence,
            tier="tier3_needs_human",
            workflow_id=workflow_id,
            agent_id=agent_id,
        )

    def test_write_pending_creates_json_file(self, tmp_path):
        """write_pending should create a JSON file named <request_id>.json."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        result = writer.write_pending(pending, "npm install some-package")

        assert result is not None
        expected_path = tmp_path / "test-req-001.json"
        assert expected_path.exists()
        assert result == expected_path

    def test_write_pending_file_contains_required_fields(self, tmp_path):
        """Written file should contain all required schema fields."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending(workflow_id="wf-123", agent_id="agent-42")
        writer.write_pending(pending, "npm install some-package")

        data = json.loads((tmp_path / "test-req-001.json").read_text())
        assert data["schema_version"] == 1
        assert data["request_id"] == "test-req-001"
        assert data["tool_name"] == "Bash"
        assert data["input_summary"] == "npm install some-package"
        assert data["reason"] == "Needs review"
        assert data["confidence"] == 0.65
        assert data["workflow_id"] == "wf-123"
        assert data["agent_id"] == "agent-42"
        assert data["status"] == "pending"
        assert "created_at" in data
        assert "expires_at" in data

    def test_write_pending_does_not_include_raw_input_data(self, tmp_path):
        """Written file must NOT contain raw input_data (security)."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        writer.write_pending(pending, "npm install some-pkg")

        content = (tmp_path / "test-req-001.json").read_text()
        data = json.loads(content)
        assert "input_data" not in data
        # Also check raw text doesn't contain the original command object
        assert "some-package" not in content  # input_data had "some-package"

    def test_write_pending_creates_directory_if_missing(self, tmp_path):
        """write_pending should create the queue directory with 0o700 permissions."""
        from phlegyas.file_queue import FileQueueWriter

        queue_dir = tmp_path / "subdir" / "pending-approvals"
        writer = FileQueueWriter(queue_dir=queue_dir)
        pending = self._make_pending()
        writer.write_pending(pending, "test summary")

        assert queue_dir.exists()
        assert queue_dir.is_dir()
        # Check directory permissions (0o700)
        mode = queue_dir.stat().st_mode & 0o777
        assert mode == 0o700

    def test_write_pending_file_permissions(self, tmp_path):
        """Written files should have 0o644 permissions."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        writer.write_pending(pending, "test summary")

        file_path = tmp_path / "test-req-001.json"
        mode = file_path.stat().st_mode & 0o777
        assert mode == 0o644

    def test_resolve_updates_file_status(self, tmp_path):
        """resolve should update the file's status field."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        writer.write_pending(pending, "test summary")

        writer.resolve("test-req-001", "approved", "human:alice")

        data = json.loads((tmp_path / "test-req-001.json").read_text())
        assert data["status"] == "approved"
        assert data["decided_by"] == "human:alice"
        assert "decided_at" in data

    def test_resolve_nonexistent_file_does_not_raise(self, tmp_path):
        """resolve on a missing file should log a warning but not raise."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        # Should not raise
        writer.resolve("nonexistent-id", "denied", "human:bob")

    def test_resolve_with_expired_status(self, tmp_path):
        """resolve should support 'expired' as a resolution status."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        writer.write_pending(pending, "test summary")

        writer.resolve("test-req-001", "expired", "ttl_expiry")

        data = json.loads((tmp_path / "test-req-001.json").read_text())
        assert data["status"] == "expired"
        assert data["decided_by"] == "ttl_expiry"

    def test_delete_after_removes_file(self, tmp_path):
        """delete_after should remove the file after the specified delay."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        writer.write_pending(pending, "test summary")

        file_path = tmp_path / "test-req-001.json"
        assert file_path.exists()

        # Use delay_seconds=0 for immediate deletion in tests
        writer.delete_after("test-req-001", delay_seconds=0)
        # Give the background thread a moment
        time.sleep(0.2)
        assert not file_path.exists()

    def test_delete_after_missing_file_does_not_raise(self, tmp_path):
        """delete_after on a missing file should not raise."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        # Should not raise
        writer.delete_after("nonexistent-id", delay_seconds=0)
        time.sleep(0.2)  # Let thread finish

    def test_write_pending_error_returns_none(self, tmp_path):
        """write_pending should return None and not raise on errors."""
        from unittest.mock import patch

        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()

        # Simulate a write error by making open() fail
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            result = writer.write_pending(pending, "test summary")
            assert result is None

    def test_default_queue_dir(self):
        """Default queue directory should be ~/.claude/pending-approvals."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter()
        assert writer.queue_dir == Path.home() / ".claude" / "pending-approvals"

    def test_custom_queue_dir(self, tmp_path):
        """Custom queue directory should override the default."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path / "custom")
        assert writer.queue_dir == tmp_path / "custom"


class TestFileQueueSummarizeInput:
    """Tests for FileQueueWriter.summarize_input static method."""

    def test_summarize_bash_command(self):
        """Should extract command from Bash tool input."""
        from phlegyas.file_queue import FileQueueWriter

        result = FileQueueWriter.summarize_input("Bash", {"command": "npm install lodash"})
        assert "npm install lodash" in result

    def test_summarize_truncates_to_100_chars(self):
        """Summary should be truncated to 100 characters max."""
        from phlegyas.file_queue import FileQueueWriter

        long_command = "npm install " + "very-long-package-name-" * 20
        result = FileQueueWriter.summarize_input("Bash", {"command": long_command})
        assert len(result) <= 100

    def test_summarize_sanitizes_credentials(self):
        """Summary should mask sensitive patterns via _sanitize_value."""
        from phlegyas.file_queue import FileQueueWriter

        result = FileQueueWriter.summarize_input(
            "Bash",
            {"command": "curl -H 'Authorization: Bearer sk-secret-token' https://api.example.com"},
        )
        assert "sk-secret-token" not in result
        assert "REDACTED" in result

    def test_summarize_write_tool(self):
        """Should extract file_path from Write tool input."""
        from phlegyas.file_queue import FileQueueWriter

        result = FileQueueWriter.summarize_input(
            "Write", {"file_path": "/project/config.py", "content": "x = 1"}
        )
        assert "config.py" in result

    def test_summarize_edit_tool(self):
        """Should extract file_path from Edit tool input."""
        from phlegyas.file_queue import FileQueueWriter

        result = FileQueueWriter.summarize_input(
            "Edit", {"file_path": "/project/main.py", "old_string": "a", "new_string": "b"}
        )
        assert "main.py" in result

    def test_summarize_unknown_tool(self):
        """Should produce a generic summary for unknown tools."""
        from phlegyas.file_queue import FileQueueWriter

        result = FileQueueWriter.summarize_input(
            "CustomTool", {"action": "deploy", "target": "staging"}
        )
        assert len(result) > 0
        assert len(result) <= 100

    def test_summarize_empty_input(self):
        """Should handle empty input dict gracefully."""
        from phlegyas.file_queue import FileQueueWriter

        result = FileQueueWriter.summarize_input("Bash", {})
        assert isinstance(result, str)
        assert len(result) <= 100

    def test_summarize_input_sanitization_error_returns_fallback(self, monkeypatch):
        """summarize_input should return a safe fallback if sanitization raises."""
        import phlegyas.file_queue
        from phlegyas.file_queue import FileQueueWriter

        def boom(*_args, **_kwargs):
            raise RuntimeError("sanitization failed")

        monkeypatch.setattr(phlegyas.file_queue, "_sanitize_value", boom)

        result = FileQueueWriter.summarize_input("SomeTool", {"foo": "bar"})
        assert isinstance(result, str)
        assert "summary unavailable" in result.lower()


class TestFileQueueAtomicWrite:
    """Tests for atomic write behavior (tmp file renamed)."""

    def test_no_tmp_files_remain_after_write(self, tmp_path):
        """After write_pending, no .tmp files should remain."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        writer.write_pending(pending, "test summary")

        tmp_files = list(tmp_path.glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_final_file_is_valid_json(self, tmp_path):
        """The final file should be valid, parseable JSON."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)
        pending = self._make_pending()
        writer.write_pending(pending, "test summary")

        content = (tmp_path / "test-req-001.json").read_text()
        data = json.loads(content)  # Should not raise
        assert isinstance(data, dict)

    def test_concurrent_writes_produce_separate_files(self, tmp_path):
        """Multiple concurrent writes should not corrupt each other."""
        from phlegyas.file_queue import FileQueueWriter

        writer = FileQueueWriter(queue_dir=tmp_path)

        def write_one(req_id):
            pending = self._make_pending(request_id=req_id)
            writer.write_pending(pending, f"summary for {req_id}")

        threads = []
        for i in range(5):
            t = threading.Thread(target=write_one, args=(f"req-{i}",))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        files = list(tmp_path.glob("*.json"))
        assert len(files) == 5
        for f in files:
            data = json.loads(f.read_text())
            assert data["schema_version"] == 1

    def _make_pending(self, request_id="test-req-001", **kwargs):
        """Helper to create PendingApproval for atomic write tests."""
        from phlegyas.approver_mcp import PendingApproval

        return PendingApproval(
            request_id=request_id,
            tool_name=kwargs.get("tool_name", "Bash"),
            input_data={"command": "test"},
            reason="Needs review",
            confidence=0.65,
            tier="tier3_needs_human",
        )


class TestMacOSNotifier:
    """Tests for MacOSNotifier notification channel."""

    def test_is_available_on_darwin(self):
        """is_available should return True on macOS with osascript."""
        from phlegyas.notifiers import MacOSNotifier

        with (
            patch("sys.platform", "darwin"),
            patch("shutil.which", return_value="/usr/bin/osascript"),
        ):
            assert MacOSNotifier.is_available() is True

    def test_is_not_available_on_linux(self):
        """is_available should return False on non-macOS platforms."""
        from phlegyas.notifiers import MacOSNotifier

        with patch("sys.platform", "linux"):
            assert MacOSNotifier.is_available() is False

    def test_is_not_available_without_osascript(self):
        """is_available should return False when osascript is not found."""
        from phlegyas.notifiers import MacOSNotifier

        with patch("sys.platform", "darwin"), patch("shutil.which", return_value=None):
            assert MacOSNotifier.is_available() is False

    @patch("subprocess.run")
    def test_notify_calls_osascript(self, mock_run):
        """notify should invoke osascript with correct arguments."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        notifier.notify("Bash", "Needs human review for risky command", "abc12345-def")

        mock_run.assert_called_once()
        args = mock_run.call_args
        cmd_list = args[0][0]
        assert cmd_list[0] == "osascript"
        assert cmd_list[1] == "-e"
        assert "Phlegyas: Approval Required" in cmd_list[2]
        assert "Bash" in cmd_list[2]
        # request_id should be truncated to first 8 chars
        assert "abc12345" in cmd_list[2]

    @patch("subprocess.run")
    def test_notify_uses_shell_false(self, mock_run):
        """notify should use shell=False for security."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        notifier.notify("Bash", "test reason", "req-123")

        args = mock_run.call_args
        # shell should not be True (default is False, but verify no explicit True)
        kwargs = args[1] if args[1] else {}
        assert kwargs.get("shell", False) is False

    @patch("subprocess.run")
    def test_notify_truncates_reason_to_80_chars(self, mock_run):
        """notify should truncate the reason to 80 characters."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        long_reason = "A" * 200
        notifier.notify("Bash", long_reason, "req-123")

        cmd_list = mock_run.call_args[0][0]
        notification_text = cmd_list[2]
        # The reason portion should not contain the full 200-char string
        assert "A" * 200 not in notification_text
        assert "A" * 80 in notification_text

    @patch("subprocess.run")
    def test_notify_sets_timeout(self, mock_run):
        """notify should set a timeout on the subprocess call."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        notifier.notify("Bash", "test", "req-123")

        kwargs = mock_run.call_args[1] if mock_run.call_args[1] else {}
        assert kwargs.get("timeout") == 3

    @patch("subprocess.run", side_effect=Exception("osascript crashed"))
    def test_notify_swallows_exceptions(self, mock_run):
        """notify should never raise exceptions."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        # Should not raise
        notifier.notify("Bash", "test reason", "req-123")

    @patch("subprocess.run", side_effect=TimeoutError("timed out"))
    def test_notify_swallows_timeout(self, mock_run):
        """notify should handle timeout gracefully."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        # Should not raise
        notifier.notify("Bash", "test reason", "req-123")

    @patch("subprocess.run")
    def test_notify_message_format(self, mock_run):
        """Notification message should follow format: '<tool>: <reason> (id: <id[:8]>)'."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        notifier.notify("Write", "Modifying production config", "abcdef12-3456-7890")

        cmd_list = mock_run.call_args[0][0]
        notification_text = cmd_list[2]
        assert "Write" in notification_text
        assert "Modifying production config" in notification_text
        assert "abcdef12" in notification_text

    @patch("subprocess.run")
    def test_notify_escapes_double_quotes_in_reason(self, mock_run):
        """Double quotes in reason must be escaped for valid AppleScript."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        notifier.notify("Bash", 'Requires "production" access', "req-12345678")

        cmd_list = mock_run.call_args[0][0]
        applescript_arg = cmd_list[2]
        # The embedded quotes should be escaped, not bare
        assert '"production"' not in applescript_arg.split("display notification")[1].split(
            "with title"
        )[0].replace('\\"', "")
        assert '\\"production\\"' in applescript_arg

    @patch("subprocess.run")
    def test_notify_escapes_backslashes_in_reason(self, mock_run):
        """Backslashes in reason must be escaped for valid AppleScript."""
        from phlegyas.notifiers import MacOSNotifier

        notifier = MacOSNotifier()
        notifier.notify("Bash", "path\\to\\file", "req-12345678")

        cmd_list = mock_run.call_args[0][0]
        applescript_arg = cmd_list[2]
        assert "path\\\\to\\\\file" in applescript_arg
