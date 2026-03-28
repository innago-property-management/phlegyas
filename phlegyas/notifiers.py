"""
Notification channels for pending approval requests.

Provides macOS system notifications via osascript. All methods are
fire-and-forget and never raise exceptions.
"""

import logging
import re
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)


class MacOSNotifier:
    """
    Sends macOS system notifications for pending approvals using osascript.

    All methods swallow exceptions — notification failures must never
    disrupt the MCP response path.
    """

    def notify(self, tool_name: str, reason: str, request_id: str) -> None:
        """
        Fire-and-forget macOS notification. Never raises.

        Spawns subprocess with shell=False to prevent injection.
        """
        try:
            title = "Phlegyas: Approval Required"

            # Sanitize tool_name: alphanumeric + underscore + hyphen only, max 100 chars
            safe_tool = re.sub(r"[^a-zA-Z0-9_\-]", "", tool_name)[:100]

            # Sanitize reason: strip non-printable characters, truncate to 200 chars
            safe_reason = re.sub(r"[^\x20-\x7E]", "", reason)[:200]

            short_id = request_id[:8]
            truncated_reason = safe_reason[:80]
            msg = f"{safe_tool}: {truncated_reason} (id: {short_id})"

            # Escape double quotes and backslashes for AppleScript string literals
            msg = msg.replace("\\", "\\\\").replace('"', '\\"')
            title = title.replace("\\", "\\\\").replace('"', '\\"')

            subprocess.run(
                ["osascript", "-e", f'display notification "{msg}" with title "{title}"'],
                timeout=3,
                capture_output=True,
            )
            logger.debug(f"macOS notification sent for {request_id}")

        except Exception as e:
            logger.warning(f"macOS notification failed: {e}")

    @staticmethod
    def is_available() -> bool:
        """Return True if running on macOS and osascript is available."""
        if sys.platform != "darwin":
            return False
        return shutil.which("osascript") is not None
