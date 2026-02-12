"""Allow running as ``python -m claude_permission_approver`` or ``python -m src``."""

from src.approver_mcp import run

if __name__ == "__main__":
    run()
