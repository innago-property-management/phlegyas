"""
File-based queue for pending approval requests.

Writes pending approvals as JSON files to ~/.claude/pending-approvals/
so that external processes (Pharos, scripts, Cygnus supervisor) can
observe and act on them without MCP access.
"""

import json
import logging
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phlegyas.sanitize import sanitize_value as _sanitize_value

logger = logging.getLogger(__name__)


class FileQueueWriter:
    """
    Writes pending approval requests to ~/.claude/pending-approvals/ as JSON files.

    All public methods swallow exceptions and log warnings — the file queue
    must never disrupt the MCP response path.
    """

    DEFAULT_QUEUE_DIR = Path.home() / ".claude" / "pending-approvals"

    def __init__(self, queue_dir: Path | None = None, resolve_ttl: int | None = None):
        self.queue_dir = queue_dir if queue_dir is not None else self.DEFAULT_QUEUE_DIR
        if resolve_ttl is not None:
            self.resolve_ttl = resolve_ttl
        else:
            try:
                self.resolve_ttl = int(os.getenv("PHLEGYAS_QUEUE_RESOLVE_TTL_SECONDS", "300"))
            except ValueError:
                logger.warning("Invalid PHLEGYAS_QUEUE_RESOLVE_TTL_SECONDS, using default 300")
                self.resolve_ttl = 300

    def write_pending(self, pending: Any, input_summary: str) -> Path | None:
        """
        Write pending approval to a JSON file atomically.

        Returns the path to the written file, or None on failure.
        """
        try:
            self._ensure_dir()

            data = {
                "schema_version": 1,
                "request_id": pending.request_id,
                "tool_name": pending.tool_name,
                "input_summary": input_summary,
                "reason": pending.reason,
                "confidence": pending.confidence,
                "workflow_id": pending.workflow_id,
                "agent_id": pending.agent_id,
                "created_at": pending.created_at.isoformat(),
                "expires_at": pending.expires_at.isoformat(),
                "status": "pending",
            }

            final_path = self.queue_dir / f"{pending.request_id}.json"
            tmp_path = self.queue_dir / f"{pending.request_id}.json.tmp"

            # Atomic write: chmod tmp before rename to avoid brief
            # window where file has umask-default permissions
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)

            os.chmod(str(tmp_path), 0o600)
            os.rename(str(tmp_path), str(final_path))

            logger.info(f"Wrote pending approval file: {final_path}")
            return final_path

        except Exception as e:
            logger.warning(f"Failed to write pending approval file: {e}")
            # Clean up tmp file if it exists
            try:
                tmp_candidate = self.queue_dir / f"{pending.request_id}.json.tmp"
                if tmp_candidate.exists():
                    tmp_candidate.unlink()
            except Exception as cleanup_err:
                logger.warning(f"Failed to clean up temp file: {cleanup_err}")
            return None

    def resolve(self, request_id: str, resolution: str, decided_by: str) -> None:
        """
        Update the file's status to resolved and schedule deletion.

        If the file does not exist, logs a warning and returns.
        """
        try:
            file_path = self.queue_dir / f"{request_id}.json"
            if not file_path.exists():
                logger.warning(f"Cannot resolve: file not found for {request_id}")
                return

            data = json.loads(file_path.read_text())
            data["status"] = resolution
            data["decided_by"] = decided_by
            data["decided_at"] = datetime.now(UTC).isoformat()

            # Atomic update: chmod tmp before rename (same as write_pending)
            tmp_path = self.queue_dir / f"{request_id}.json.tmp"
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(str(tmp_path), 0o600)
            os.rename(str(tmp_path), str(file_path))

            logger.info(f"Resolved approval file: {request_id} -> {resolution}")

            # Schedule deletion after configurable TTL (default 300s)
            # to give external watchers (Cygnus/Pharos) time to observe resolution
            self.delete_after(request_id, delay_seconds=self.resolve_ttl)

        except Exception as e:
            logger.warning(f"Failed to resolve approval file {request_id}: {e}")

    def delete_after(self, request_id: str, delay_seconds: int = 60) -> None:
        """
        Delete the approval file after a delay (best-effort, fire-and-forget).

        Runs in a daemon thread so it does not block the caller.
        """

        def _delete():
            try:
                if delay_seconds > 0:
                    time.sleep(delay_seconds)
                file_path = self.queue_dir / f"{request_id}.json"
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"Deleted approval file: {request_id}")
            except Exception as e:
                logger.warning(f"Failed to delete approval file {request_id}: {e}")

        thread = threading.Thread(target=_delete, daemon=True)
        thread.start()

    @staticmethod
    def summarize_input(tool_name: str, input_data: dict) -> str:
        """
        Return a sanitized, 100-char summary of the tool input.

        Extracts the most relevant field based on tool type, sanitizes
        credentials, and truncates to 100 characters.
        """
        try:
            # Sanitize the input first
            sanitized = _sanitize_value(input_data)

            # Extract the most relevant field based on tool type
            if tool_name == "Bash":
                summary = sanitized.get("command", "")
            elif tool_name in ("Write", "Edit"):
                summary = sanitized.get("file_path", "")
            else:
                # For unknown tools, create a generic key=value summary
                parts = []
                for key, value in sanitized.items():
                    parts.append(f"{key}={value}")
                summary = ", ".join(parts)

            if not summary:
                summary = f"{tool_name}: (no input)"

            # Truncate to 100 chars
            if len(summary) > 100:
                summary = summary[:97] + "..."

            return summary

        except Exception as e:
            logger.warning(f"Failed to summarize input: {e}")
            return f"{tool_name}: (summary unavailable)"

    def _ensure_dir(self) -> None:
        """Create the queue directory with 0o700 permissions if it doesn't exist."""
        if not self.queue_dir.exists():
            self.queue_dir.mkdir(parents=True, mode=0o700)
        # Ensure permissions even if directory already existed
        os.chmod(str(self.queue_dir), 0o700)
