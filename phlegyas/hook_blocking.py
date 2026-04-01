"""
Blocking approval hook logic for Cygnus fleet workers.

This module contains the core logic for the blocking mode of the
phlegyas-guardrail hook. In blocking mode, the hook creates a pending
approval in the file queue and polls for resolution through a two-phase
delegation chain: supervisor first, then human escalation.

The hook script (~/.claude/hooks/phlegyas-guardrail.py) imports from
this module — keeping it a thin entrypoint while all testable logic
lives here.
"""

import json
import logging
import os
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from phlegyas.file_queue import FileQueueWriter
from phlegyas.notifiers import MacOSNotifier

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mode detection
# ---------------------------------------------------------------------------


def is_blocking_mode() -> bool:
    """Return True when PHLEGYAS_APPROVAL_MODE is exactly 'blocking'."""
    return os.getenv("PHLEGYAS_APPROVAL_MODE", "advisory").lower() == "blocking"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class BlockingConfig:
    """Configuration for the blocking delegation chain."""

    supervisor_timeout: int = 60
    human_timeout: int = 120
    poll_interval: float = 2.0
    queue_dir: Path = field(default_factory=lambda: Path.home() / ".claude" / "pending-approvals")
    supervisor_id: str | None = None
    workflow_id: str | None = None
    agent_id: str | None = None
    cygnus_api_url: str = "http://localhost:4000"


def get_blocking_config() -> BlockingConfig:
    """Build a BlockingConfig from environment variables with defaults."""
    queue_dir_str = os.getenv("PHLEGYAS_QUEUE_DIR")
    queue_dir = (
        Path(queue_dir_str) if queue_dir_str else Path.home() / ".claude" / "pending-approvals"
    )

    return BlockingConfig(
        supervisor_timeout=int(os.getenv("PHLEGYAS_SUPERVISOR_TIMEOUT_SECONDS", "60")),
        human_timeout=int(os.getenv("PHLEGYAS_HUMAN_TIMEOUT_SECONDS", "120")),
        poll_interval=float(os.getenv("PHLEGYAS_POLL_INTERVAL_SECONDS", "2")),
        queue_dir=queue_dir,
        supervisor_id=os.getenv("CYGNUS_SUPERVISOR_ID"),
        workflow_id=os.getenv("CYGNUS_WORKFLOW_ID"),
        agent_id=os.getenv("CYGNUS_AGENT_ID"),
        cygnus_api_url=os.getenv("CYGNUS_API_URL", "http://localhost:4000"),
    )


# ---------------------------------------------------------------------------
# Pending approval creation
# ---------------------------------------------------------------------------


def create_pending_approval(
    tool_name: str,
    input_data: dict,
    config: BlockingConfig,
) -> str | None:
    """
    Create a pending approval file in the queue directory.

    Generates a UUID request_id, writes via FileQueueWriter with
    source="hook" and optional supervisor_id. Returns the request_id
    on success or None on failure.
    """
    try:
        request_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        ttl = config.supervisor_timeout + config.human_timeout + 60  # buffer

        # Build a minimal object compatible with FileQueueWriter.write_pending()
        # which accesses attributes on the pending object.
        pending = _MinimalPending(
            request_id=request_id,
            tool_name=tool_name,
            reason="Ambiguous operation (blocking hook evaluation)",
            confidence=0.5,  # midpoint — no full AI pipeline in hook context
            workflow_id=config.workflow_id,
            agent_id=config.agent_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )

        writer = FileQueueWriter(queue_dir=config.queue_dir, resolve_ttl=0)
        input_summary = FileQueueWriter.summarize_input(tool_name, input_data)

        result = writer.write_pending(
            pending,
            input_summary,
            supervisor_id=config.supervisor_id,
            source="hook",
        )

        if result is None:
            logger.error("FileQueueWriter.write_pending returned None")
            return None

        logger.info(f"Created pending approval {request_id} for {tool_name}")
        return request_id

    except Exception as e:
        logger.error(f"Failed to create pending approval: {e}")
        return None


@dataclass
class _MinimalPending:
    """Minimal duck-typed object compatible with FileQueueWriter.write_pending()."""

    request_id: str
    tool_name: str
    reason: str
    confidence: float
    workflow_id: str | None
    agent_id: str | None
    created_at: datetime
    expires_at: datetime


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------


def poll_for_resolution(
    request_id: str,
    timeout_seconds: float,
    poll_interval: float,
    queue_dir: Path,
) -> str | None:
    """
    Poll the file queue for a resolution on the given request_id.

    Returns:
        "approve" — approved (normalizes "approved" too)
        "deny" — denied (normalizes "denied" too)
        "escalate_to_human" — supervisor explicitly escalated
        None — timed out without resolution
    """
    deadline = time.monotonic() + timeout_seconds
    queue_file = queue_dir / f"{request_id}.json"

    while time.monotonic() < deadline:
        try:
            if queue_file.exists():
                data = json.loads(queue_file.read_text())
                status = data.get("status", "pending")

                if status in ("approve", "approved"):
                    return "approve"
                if status in ("deny", "denied"):
                    return "deny"
                if status == "escalate_to_human":
                    return "escalate_to_human"
                if status == "expired":
                    return "deny"
                # "pending" — keep polling
        except (json.JSONDecodeError, OSError):
            # File in mid-write or read error; retry next cycle
            pass

        time.sleep(poll_interval)

    return None  # Timed out


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def notify_supervisor(
    request_id: str,
    tool_name: str,
    input_summary: str,
    config: BlockingConfig,
) -> None:
    """
    Best-effort notification to the Cygnus supervisor.

    1. HTTP POST to cygnus_api_url/api/approvals/notify (stdlib urllib, 2s timeout)
    2. macOS system notification

    Never raises, never blocks beyond the 2s HTTP timeout.
    """
    # HTTP POST to Cygnus supervisor API
    try:
        data = json.dumps(
            {
                "type": "worker_blocked",
                "request_id": request_id,
                "workflow_id": config.workflow_id,
                "agent_id": config.agent_id,
                "supervisor_id": config.supervisor_id,
                "tool_name": tool_name,
                "input_summary": input_summary,
            }
        ).encode()

        req = urllib.request.Request(
            f"{config.cygnus_api_url}/api/approvals/notify",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception as exc:
        logger.debug("HTTP notification to supervisor failed for %s: %s", request_id, exc)

    # macOS notification
    try:
        notifier = MacOSNotifier()
        notifier.notify(
            tool_name=tool_name,
            reason=f"Worker blocked: {input_summary}",
            request_id=request_id,
        )
    except Exception as exc:
        logger.debug("macOS notification failed for %s: %s", request_id, exc)


def notify_human_escalation(
    request_id: str,
    tool_name: str,
    input_summary: str,
    config: BlockingConfig,
) -> None:
    """
    Notify human that supervisor timed out and approval is needed.

    1. Slack notification (if phlegyas[slack] is installed and configured)
    2. macOS system notification

    Never raises.
    """
    # Slack notification (best-effort)
    try:
        from phlegyas.slack import SlackApprovalService

        if SlackApprovalService.is_available():
            import asyncio

            service = SlackApprovalService()

            async def _send():
                await service.notify_pending(
                    tool_name=tool_name,
                    input_data={"summary": input_summary},
                    reasoning=f"Supervisor timeout — escalated to human: {input_summary}",
                    category="moderate_risk",
                    request_id=request_id,
                )

            asyncio.run(_send())
    except Exception as exc:
        logger.debug("Slack escalation failed for %s: %s", request_id, exc)

    # macOS notification
    try:
        notifier = MacOSNotifier()
        notifier.notify(
            tool_name=tool_name,
            reason=f"Supervisor timeout — needs human approval: {input_summary}",
            request_id=request_id,
        )
    except Exception as exc:
        logger.debug("macOS escalation notification failed for %s: %s", request_id, exc)


# ---------------------------------------------------------------------------
# Full delegation chain
# ---------------------------------------------------------------------------


def run_blocking_delegation(
    tool_name: str,
    input_data: dict,
    config: BlockingConfig,
) -> int:
    """
    Run the two-phase blocking delegation chain.

    Phase 1: Notify supervisor, poll for supervisor_timeout seconds.
    Phase 2: Escalate to human, poll for human_timeout seconds.

    If supervisor_id is absent, skip Phase 1 and go directly to Phase 2.

    Returns:
        0 — approved (allow tool)
        2 — denied (block tool)
    """
    # Create pending approval in file queue
    request_id = create_pending_approval(tool_name, input_data, config)
    if request_id is None:
        logger.error("Failed to create pending approval — fail closed")
        return 2  # Fail closed

    input_summary = FileQueueWriter.summarize_input(tool_name, input_data)

    has_supervisor = config.supervisor_id is not None and config.workflow_id is not None

    # Phase 1: Supervisor delegation
    if has_supervisor:
        notify_supervisor(request_id, tool_name, input_summary, config)

        result = poll_for_resolution(
            request_id=request_id,
            timeout_seconds=config.supervisor_timeout,
            poll_interval=config.poll_interval,
            queue_dir=config.queue_dir,
        )

        if result == "approve":
            return 0
        if result == "deny":
            return 2
        if result == "escalate_to_human":
            pass  # Fall through to Phase 2
        # None (timeout) — fall through to Phase 2

    # Phase 2: Human escalation
    notify_human_escalation(request_id, tool_name, input_summary, config)

    result = poll_for_resolution(
        request_id=request_id,
        timeout_seconds=config.human_timeout,
        poll_interval=config.poll_interval,
        queue_dir=config.queue_dir,
    )

    if result == "approve":
        return 0

    # Deny on timeout or explicit deny (safe default)
    return 2
