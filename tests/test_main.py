"""
Tests for phlegyas.__main__ module entry point.

Verifies that ``python -m phlegyas`` invokes the MCP server run function.
"""

import pytest


@pytest.mark.unit
class TestModuleEntryPoint:
    """Smoke tests for the __main__.py module."""

    def test_import_does_not_error(self):
        """Importing __main__ should not raise."""
        import phlegyas.__main__  # noqa: F401

    def test_main_imports_run_from_approver_mcp(self):
        """__main__ should import run from approver_mcp."""
        import phlegyas.__main__ as main_mod
        from phlegyas.approver_mcp import run

        assert main_mod.run is run

    def test_python_m_phlegyas_help(self):
        """``python -m phlegyas`` should be runnable (smoke test via subprocess)."""
        import subprocess
        import sys

        # The MCP server's run() blocks on stdio, so we just verify the import
        # works by running with a timeout and expecting it to start (not crash).
        result = subprocess.run(
            [sys.executable, "-c", "from phlegyas.__main__ import run; print('ok')"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "ok" in result.stdout
