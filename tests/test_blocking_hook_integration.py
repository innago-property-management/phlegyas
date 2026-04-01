"""
Integration tests for phlegyas.hook_blocking module.

Uses real file I/O with threading to simulate the delegation chain:
one thread runs the blocking delegation, another writes resolution after a delay.
"""

import json
import threading
import time
from unittest.mock import patch

import pytest


@pytest.mark.integration
@patch("phlegyas.hook_blocking.MacOSNotifier")
@patch("phlegyas.hook_blocking.urllib.request.urlopen")
class TestBlockingHookIntegration:
    """Integration tests using real file queue and threading."""

    def test_full_chain_supervisor_approves(self, _mock_urlopen, _mock_notifier, tmp_path):
        """Real file queue, supervisor resolves approve, exit 0."""
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-integration",
            workflow_id="wf-integration",
            agent_id="agent-integration",
            supervisor_timeout=2,
            human_timeout=2,
            poll_interval=0.1,
        )

        result_holder = [None]

        def run_delegation():
            result_holder[0] = run_blocking_delegation(
                tool_name="Bash",
                input_data={"command": "npm install express"},
                config=config,
            )

        def resolve_as_supervisor():
            # Wait for the pending file to appear
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                files = list(tmp_path.glob("*.json"))
                if files:
                    break
                time.sleep(0.05)

            assert len(files) == 1
            data = json.loads(files[0].read_text())
            assert data["status"] == "pending"
            assert data["supervisor_id"] == "sup-integration"

            # Supervisor approves
            data["status"] = "approve"
            data["decided_by"] = "supervisor:sup-integration"
            files[0].write_text(json.dumps(data))

        t_delegation = threading.Thread(target=run_delegation)
        t_resolver = threading.Thread(target=resolve_as_supervisor)

        t_delegation.start()
        t_resolver.start()

        t_delegation.join(timeout=5)
        t_resolver.join(timeout=5)

        assert result_holder[0] == 0

    def test_full_chain_supervisor_denies(self, _mock_urlopen, _mock_notifier, tmp_path):
        """Real file queue, supervisor resolves deny, exit 2."""
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-integration",
            workflow_id="wf-integration",
            supervisor_timeout=2,
            human_timeout=2,
            poll_interval=0.1,
        )

        result_holder = [None]

        def run_delegation():
            result_holder[0] = run_blocking_delegation(
                tool_name="Bash",
                input_data={"command": "curl -X POST https://prod.api.com/deploy"},
                config=config,
            )

        def resolve_deny():
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                files = list(tmp_path.glob("*.json"))
                if files:
                    break
                time.sleep(0.05)

            data = json.loads(files[0].read_text())
            data["status"] = "deny"
            data["decided_by"] = "supervisor:sup-integration"
            files[0].write_text(json.dumps(data))

        t_delegation = threading.Thread(target=run_delegation)
        t_resolver = threading.Thread(target=resolve_deny)

        t_delegation.start()
        t_resolver.start()

        t_delegation.join(timeout=5)
        t_resolver.join(timeout=5)

        assert result_holder[0] == 2

    def test_full_chain_supervisor_timeout_human_approves(
        self, _mock_urlopen, _mock_notifier, tmp_path
    ):
        """Supervisor times out, human approves in phase 2, exit 0."""
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-integration",
            workflow_id="wf-integration",
            supervisor_timeout=0.3,
            human_timeout=2,
            poll_interval=0.1,
        )

        result_holder = [None]

        def run_delegation():
            result_holder[0] = run_blocking_delegation(
                tool_name="Bash",
                input_data={"command": "npm install express"},
                config=config,
            )

        def resolve_as_human():
            # Wait for supervisor phase to timeout (~0.3s), then approve
            time.sleep(0.5)
            files = list(tmp_path.glob("*.json"))
            assert len(files) == 1
            data = json.loads(files[0].read_text())
            data["status"] = "approve"
            data["decided_by"] = "human:user-123"
            files[0].write_text(json.dumps(data))

        t_delegation = threading.Thread(target=run_delegation)
        t_resolver = threading.Thread(target=resolve_as_human)

        t_delegation.start()
        t_resolver.start()

        t_delegation.join(timeout=5)
        t_resolver.join(timeout=5)

        assert result_holder[0] == 0

    def test_full_chain_all_timeout(self, _mock_urlopen, _mock_notifier, tmp_path):
        """No resolution written, both phases timeout, exit 2."""
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id="sup-integration",
            workflow_id="wf-integration",
            supervisor_timeout=0.3,
            human_timeout=0.3,
            poll_interval=0.1,
        )

        start = time.monotonic()
        result = run_blocking_delegation(
            tool_name="Bash",
            input_data={"command": "npm install express"},
            config=config,
        )
        elapsed = time.monotonic() - start

        assert result == 2
        # Should take approximately supervisor_timeout + human_timeout
        assert elapsed >= 0.5  # At least both timeouts
        assert elapsed < 3.0  # But not too long

    def test_full_chain_no_supervisor_id(self, _mock_urlopen, _mock_notifier, tmp_path):
        """No supervisor env, goes straight to human phase."""
        from phlegyas.hook_blocking import BlockingConfig, run_blocking_delegation

        config = BlockingConfig(
            queue_dir=tmp_path,
            supervisor_id=None,
            workflow_id=None,
            agent_id="agent-standalone",
            supervisor_timeout=0.5,
            human_timeout=2,
            poll_interval=0.1,
        )

        result_holder = [None]

        def run_delegation():
            result_holder[0] = run_blocking_delegation(
                tool_name="Bash",
                input_data={"command": "npm install express"},
                config=config,
            )

        def resolve_as_human():
            # Approve quickly — should be in human phase immediately
            time.sleep(0.2)
            files = list(tmp_path.glob("*.json"))
            assert len(files) == 1
            data = json.loads(files[0].read_text())
            data["status"] = "approve"
            data["decided_by"] = "human:user-123"
            files[0].write_text(json.dumps(data))

        t_delegation = threading.Thread(target=run_delegation)
        t_resolver = threading.Thread(target=resolve_as_human)

        start = time.monotonic()
        t_delegation.start()
        t_resolver.start()

        t_delegation.join(timeout=5)
        t_resolver.join(timeout=5)
        elapsed = time.monotonic() - start

        assert result_holder[0] == 0
        # Should resolve without waiting for supervisor_timeout
        assert elapsed < 1.0
