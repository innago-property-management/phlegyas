"""
Phlegyas - Official MCP SDK Implementation

Three-tier intelligent permission gate for AI agents using official mcp.server
"""

import asyncio
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from phlegyas.file_queue import FileQueueWriter
from phlegyas.notifiers import MacOSNotifier
from phlegyas.sanitize import sanitize_value as _sanitize_value
from phlegyas.supervisor_policy import SupervisorDelegationPolicy
from phlegyas.tier1_dangerous import DangerousPatternDetector
from phlegyas.tier2_5_trust import ScriptTrustStore
from phlegyas.tier2_safe import SafeOperationDetector, SafePatternStore
from phlegyas.tier3_ai import AIEvaluator

# Conditional import — slack is an optional dependency
try:
    from phlegyas.slack import SlackApprovalService

    _slack_available = True
except ImportError:
    _slack_available = False

# Load environment variables
load_dotenv()

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — kept at module level for backward-compatible test imports
# ---------------------------------------------------------------------------
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))  # 1 hour default
CACHE_ENABLED = os.getenv("ENABLE_APPROVAL_CACHE", "true").lower() == "true"
CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "1000"))
PENDING_TTL_SECONDS = int(os.getenv("PENDING_TTL_SECONDS", "1800"))  # 30 min default
PENDING_MAX_SIZE = int(os.getenv("PENDING_MAX_SIZE", "100"))
RESOLVED_TTL_SECONDS = 300  # 5 minutes — not configurable in v0.3.0


class PendingApproval:
    """Represents a parked operation awaiting human approval."""

    def __init__(
        self,
        request_id: str,
        tool_name: str,
        input_data: dict[str, Any],
        reason: str,
        confidence: float | None,
        tier: str,
        workflow_id: str | None = None,
        agent_id: str | None = None,
        pending_ttl_seconds: int = 1800,
    ):
        self.request_id = request_id
        self.tool_name = tool_name
        self.input_data = input_data
        self.reason = reason
        self.confidence = confidence
        self.tier = tier
        self.workflow_id = workflow_id
        self.agent_id = agent_id
        self.created_at = datetime.now(UTC)
        self.expires_at = self.created_at + timedelta(seconds=pending_ttl_seconds)
        self.status = "pending"  # pending, approved, denied, expired
        # Resolution tracking (populated when resolved via submit_approval or supervisor_approve)
        self.resolved_at: datetime | None = None
        self.resolved_by: str | None = None  # "human:<id>", "supervisor:<id>", "ttl_expiry"
        self.resolution: str | None = None  # "approved", "denied", "expired"

    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "input_data": self.input_data,
            "reason": self.reason,
            "confidence": self.confidence,
            "tier": self.tier,
            "workflow_id": self.workflow_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status,
            "ttl_remaining_seconds": max(
                0, int((self.expires_at - datetime.now(UTC)).total_seconds())
            ),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "resolution": self.resolution,
        }


class ApproverState:
    """Encapsulates all mutable server state and detector/service instances.

    A single module-level instance is created at import time (preserving current
    behaviour).  Tests can create fresh instances for isolation.
    """

    def __init__(self) -> None:
        # -- Detectors --
        self.dangerous_detector = DangerousPatternDetector()
        self.supervisor_policy = SupervisorDelegationPolicy()
        safe_pattern_store = SafePatternStore()
        self.safe_detector = SafeOperationDetector(user_store=safe_pattern_store)
        self.trust_store = ScriptTrustStore()

        # -- AI evaluator --
        self.ai_evaluator: AIEvaluator | None = None
        try:
            model = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
            approval_threshold = float(os.getenv("APPROVAL_CONFIDENCE_THRESHOLD", "0.8"))
            denial_threshold = float(os.getenv("DENIAL_CONFIDENCE_THRESHOLD", "0.2"))
            self.ai_evaluator = AIEvaluator(
                model=model,
                approval_threshold=approval_threshold,
                denial_threshold=denial_threshold,
            )
            logger.info(f"AI evaluator initialized with model: {model}")
        except Exception as e:
            logger.warning(f"AI evaluator initialization failed: {e}")
            logger.warning("Only Tier 1 (dangerous) and Tier 2 (safe) will be available")

        # -- Slack escalation (optional) --
        self.slack_service = None
        if _slack_available and SlackApprovalService.is_available():
            try:
                self.slack_service = SlackApprovalService()
                self.slack_service.start_background()
                logger.info("Slack escalation service initialized and connected")
            except Exception as e:
                logger.warning(f"Slack service initialization failed: {e}")
                logger.warning("Human escalation via Slack will not be available")
        else:
            logger.info(
                "Slack escalation not configured (set SLACK_BOT_TOKEN + SLACK_APP_TOKEN to enable)"
            )

        # -- File queue & macOS notifier --
        _queue_enabled = os.getenv("PHLEGYAS_QUEUE_ENABLED", "true").lower() == "true"
        self.file_queue: FileQueueWriter | None = FileQueueWriter() if _queue_enabled else None
        if self.file_queue:
            logger.info(f"File queue enabled: {self.file_queue.queue_dir}")
        else:
            logger.info("File queue disabled (PHLEGYAS_QUEUE_ENABLED=false)")

        _notify_macos = os.getenv("PHLEGYAS_NOTIFY_MACOS", "true").lower() != "false"
        self.macos_notifier: MacOSNotifier | None = (
            MacOSNotifier() if _notify_macos and MacOSNotifier.is_available() else None
        )
        if self.macos_notifier:
            logger.info("macOS notifications enabled")

        # -- Audit config --
        self.enable_audit_log: bool = os.getenv("ENABLE_AUDIT_LOG", "true").lower() == "true"
        self.audit_log_file: str = os.getenv("AUDIT_LOG_FILE", "audit.jsonl")

        # -- Cache config (mirrors module-level constants for instance isolation) --
        self.cache_ttl_seconds: int = CACHE_TTL_SECONDS
        self.cache_enabled: bool = CACHE_ENABLED
        self.cache_max_size: int = CACHE_MAX_SIZE

        # -- Pending config --
        self.pending_ttl_seconds: int = PENDING_TTL_SECONDS
        self.pending_max_size: int = PENDING_MAX_SIZE
        self.resolved_ttl_seconds: int = RESOLVED_TTL_SECONDS

        # -- Mutable state --
        self.approval_cache: dict[str, tuple[str, Any, datetime]] = {}
        self.pending_approvals: dict[str, PendingApproval] = {}
        self.resolved_approvals: dict[str, PendingApproval] = {}
        self.cache_metrics: dict[str, int] = {
            "hits": 0,
            "misses": 0,
            "expired": 0,
            "evictions": 0,
        }


# ---------------------------------------------------------------------------
# Module-level singleton + backward-compatible aliases
# ---------------------------------------------------------------------------
state = ApproverState()

# Dict aliases — same object, so test code doing pending_approvals.clear() works
pending_approvals = state.pending_approvals
resolved_approvals = state.resolved_approvals
approval_cache = state.approval_cache
cache_metrics = state.cache_metrics

# Instance aliases for conftest.py cleanup
ai_evaluator = state.ai_evaluator


def cleanup_expired_pending():
    """Remove expired pending approvals and enforce max size."""
    expired = [
        req_id for req_id, pending in state.pending_approvals.items() if pending.is_expired()
    ]
    for req_id in expired:
        pending = state.pending_approvals.pop(req_id)
        logger.info(f"Expired pending approval: {req_id} for {pending.tool_name}")
        write_audit_log(
            pending.tool_name,
            pending.input_data,
            "expired",
            pending.tier,
            f"Approval expired after {state.pending_ttl_seconds}s",
            pending.confidence,
        )
        if state.file_queue:
            state.file_queue.resolve(req_id, "expired", "ttl_expiry")

    # Evict oldest if over capacity (shouldn't happen in episodic use, but defense-in-depth)
    while len(state.pending_approvals) > state.pending_max_size:
        oldest_id = min(
            state.pending_approvals, key=lambda k: state.pending_approvals[k].created_at
        )
        evicted = state.pending_approvals.pop(oldest_id)
        logger.warning(
            f"Evicted pending approval (over {state.pending_max_size} limit): {oldest_id}"
        )
        write_audit_log(
            evicted.tool_name,
            evicted.input_data,
            "evicted",
            evicted.tier,
            f"Evicted: pending queue over {state.pending_max_size} limit",
            evicted.confidence,
        )

    # Clean up expired resolved approvals
    expired_resolved = [
        req_id
        for req_id, resolved in state.resolved_approvals.items()
        if resolved.resolved_at
        and (datetime.now(UTC) - resolved.resolved_at).total_seconds() > state.resolved_ttl_seconds
    ]
    for req_id in expired_resolved:
        state.resolved_approvals.pop(req_id)
        logger.debug(f"Cleaned up expired resolved approval: {req_id}")


def sanitize_for_audit(input_data: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive values in input data before writing to audit log."""
    return _sanitize_value(input_data)


def write_audit_log(
    tool_name: str,
    input_data: dict[str, Any],
    decision: str,
    tier: str,
    reason: str,
    confidence: float | None = None,
):
    """Write decision to audit log. Sensitive values are masked."""
    if not state.enable_audit_log:
        return

    log_entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "tool_name": tool_name,
        "input": sanitize_for_audit(input_data),
        "decision": decision,
        "tier": tier,
        "reason": reason,
        "confidence": confidence,
    }

    try:
        with open(state.audit_log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


def compute_operation_hash(tool_name: str, input_data: dict[str, Any]) -> str:
    """
    Compute a hash for an operation to use as cache key.

    Hash is based on tool name and input parameters (deterministic).
    """
    # Create a stable string representation
    operation_str = json.dumps(
        {"tool": tool_name, "input": input_data}, sort_keys=True, default=str
    )
    return hashlib.sha256(operation_str.encode()).hexdigest()


def get_cached_decision(operation_hash: str) -> tuple[str, Any, datetime] | None:
    """
    Get cached decision if available and not expired.

    Returns: (decision, evaluation_result, timestamp) or None if not cached/expired
    """
    if not state.cache_enabled:
        return None

    if operation_hash not in state.approval_cache:
        state.cache_metrics["misses"] += 1
        return None

    decision, evaluation, timestamp = state.approval_cache[operation_hash]

    # Check if cache entry is expired
    if datetime.now(UTC) - timestamp > timedelta(seconds=state.cache_ttl_seconds):
        del state.approval_cache[operation_hash]
        state.cache_metrics["expired"] += 1
        logger.debug(f"Cache entry expired for hash {operation_hash[:8]}...")
        return None

    state.cache_metrics["hits"] += 1
    logger.debug(f"Cache hit for hash {operation_hash[:8]}...")
    return decision, evaluation, timestamp


def cache_decision(operation_hash: str, decision: str, evaluation: Any):
    """
    Cache a Tier 3 decision for future use. Evicts oldest entry if at capacity.
    """
    if not state.cache_enabled:
        return

    # Evict oldest entry if at capacity
    if len(state.approval_cache) >= state.cache_max_size:
        oldest_key = min(state.approval_cache, key=lambda k: state.approval_cache[k][2])
        del state.approval_cache[oldest_key]
        state.cache_metrics["evictions"] += 1
        logger.debug(f"Cache evicted oldest entry (size was {state.cache_max_size})")

    state.approval_cache[operation_hash] = (decision, evaluation, datetime.now(UTC))
    logger.debug(
        f"Cached decision for hash {operation_hash[:8]}... (cache size: {len(state.approval_cache)})"
    )


# Create MCP server
app = Server("phlegyas")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="permissions__approve",
            description="Intelligent permission approval using three-tier evaluation",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "The tool Claude Code wants to use (e.g., 'Bash', 'Edit', 'Write')",
                    },
                    "input": {
                        "type": "object",
                        "description": "The parameters for that tool",
                    },
                    "tool_use_id": {
                        "type": "string",
                        "description": "Optional tool use identifier from MCP protocol",
                    },
                },
                "required": ["tool_name", "input"],
            },
        ),
        Tool(
            name="validate_operation",
            description="Validate an operation before execution (for Task agents). Returns structured approval status: 'approved', 'denied', or 'pending' (awaiting human approval with TTL).",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "The tool to validate (e.g., 'Bash', 'Edit', 'Write')",
                    },
                    "input": {
                        "type": "object",
                        "description": "The parameters for that tool",
                    },
                    "workflow_id": {
                        "type": "string",
                        "description": "Optional workflow correlation ID for tracking",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Optional agent ID making the request",
                    },
                },
                "required": ["tool_name", "input"],
            },
        ),
        Tool(
            name="get_approval_stats",
            description="Get statistics about approval decisions from the audit log",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="submit_approval",
            description="Submit human decision for a pending approval request. Use this to approve or deny operations that were escalated for human review.",
            inputSchema={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The request_id from the pending approval",
                    },
                    "decision": {
                        "type": "string",
                        "enum": ["approve", "deny"],
                        "description": "Human decision: approve or deny the operation",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Optional reason for the decision",
                    },
                    "approver_id": {
                        "type": "string",
                        "description": "Identifier of the human approver (e.g., username, email)",
                    },
                },
                "required": ["request_id", "decision"],
            },
        ),
        Tool(
            name="poll_approval",
            description="Check the resolution status of a specific pending approval request. Returns current status including whether it has been approved, denied, or is still pending.",
            inputSchema={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The request_id returned by validate_operation when status was 'pending'",
                    },
                },
                "required": ["request_id"],
            },
        ),
        Tool(
            name="get_pending_approvals",
            description="List all pending approval requests awaiting human decision. Returns operations that were escalated and are still within their TTL window.",
            inputSchema={
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "Optional: filter by workflow correlation ID",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Optional: filter by agent ID",
                    },
                },
            },
        ),
        Tool(
            name="supervisor_approve",
            description="Approve, deny, or escalate a pending approval request on behalf of a supervised workflow. Enforces delegation policy constraints: cannot override Tier 1 dangerous decisions, cannot approve below confidence 0.3, and cannot approve own requests.",
            inputSchema={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The request_id of the pending approval to act on",
                    },
                    "decision": {
                        "type": "string",
                        "enum": ["approve", "deny", "escalate_to_human"],
                        "description": "Supervisor decision: approve, deny, or escalate to human",
                    },
                    "supervisor_id": {
                        "type": "string",
                        "description": "Supervisor agent identifier",
                    },
                    "workflow_id": {
                        "type": "string",
                        "description": "Must match the workflow_id on the pending request",
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Supervisor's justification for the decision",
                    },
                },
                "required": ["request_id", "decision", "supervisor_id", "workflow_id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    if name == "permissions__approve":
        return await handle_permissions_approve(arguments)
    elif name == "validate_operation":
        return await handle_validate_operation(arguments)
    elif name == "get_approval_stats":
        return await handle_get_approval_stats(arguments)
    elif name == "submit_approval":
        return await handle_submit_approval(arguments)
    elif name == "poll_approval":
        return await handle_poll_approval(arguments)
    elif name == "get_pending_approvals":
        return await handle_get_pending_approvals(arguments)
    elif name == "supervisor_approve":
        return await handle_supervisor_approve(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")


@dataclass
class TierResult:
    """Structured result from the tier evaluation pipeline."""

    tier: str  # e.g. "tier1_dangerous", "tier2_safe", "tier3_ai_approve"
    decision: str  # "allow", "deny", "ask_user", "no_ai"
    reason: str
    confidence: float | None = None
    evaluation: Any = None  # Full EvaluationResult from Tier 3 AI


async def _evaluate_tiers(tool_name: str, input_data: dict[str, Any]) -> TierResult:
    """
    Run the shared tier-evaluation pipeline (Tiers 1 → 2 → 2.5 → 3).

    Returns a TierResult with the decision from whichever tier resolved first.
    Audit logging and logger calls for Tiers 1-2.5 are handled here (identical
    across all callers).  Tier 3 audit logging is left to the caller since
    response formatting differs per handler.
    """
    # Tier 1: Check for dangerous patterns
    is_dangerous, dangerous_reason = state.dangerous_detector.is_dangerous(tool_name, input_data)
    if is_dangerous:
        logger.warning(f"DENIED (Tier 1): {dangerous_reason}")
        write_audit_log(tool_name, input_data, "deny", "tier1_dangerous", dangerous_reason)
        return TierResult(tier="tier1_dangerous", decision="deny", reason=dangerous_reason)

    # Tier 2: Check for safe categories
    is_safe, safe_category = state.safe_detector.is_safe(tool_name, input_data)
    if is_safe:
        logger.info(f"APPROVED (Tier 2): {safe_category}")
        write_audit_log(tool_name, input_data, "allow", "tier2_safe", safe_category)
        return TierResult(tier="tier2_safe", decision="allow", reason=safe_category)

    # Tier 2.5: Check script trust store (TOFU - Trust On First Use)
    is_trusted, trust_category = state.trust_store.is_trusted(tool_name, input_data)
    if is_trusted:
        logger.info(f"APPROVED (Tier 2.5): {trust_category}")
        write_audit_log(tool_name, input_data, "allow", "tier2_5_trusted_script", trust_category)
        return TierResult(tier="tier2_5_trusted_script", decision="allow", reason=trust_category)
    elif trust_category:
        logger.warning(
            f"Tier 2.5 trust-store degradation - falling through to Tier 3: {trust_category}"
        )

    # Tier 3: AI evaluation
    if state.ai_evaluator is None:
        return TierResult(
            tier="tier3_no_ai",
            decision="no_ai",
            reason="AI evaluator unavailable, requires manual approval",
        )

    decision, evaluation = await state.ai_evaluator.evaluate(tool_name, input_data)

    if decision == "approve":
        return TierResult(
            tier="tier3_ai_approve",
            decision="allow",
            reason=evaluation.reasoning,
            confidence=evaluation.confidence,
            evaluation=evaluation,
        )
    elif decision == "deny":
        return TierResult(
            tier="tier3_ai_deny",
            decision="deny",
            reason=evaluation.reasoning,
            confidence=evaluation.confidence,
            evaluation=evaluation,
        )
    else:  # ask_user
        return TierResult(
            tier="tier3_needs_human",
            decision="ask_user",
            reason=evaluation.reasoning,
            confidence=evaluation.confidence,
            evaluation=evaluation,
        )


async def handle_permissions_approve(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle permissions__approve tool call."""
    tool_name = arguments["tool_name"]
    input_data = arguments["input"]
    logger.info(f"Permission request: {tool_name}")
    logger.debug(f"Input keys: {list(input_data.keys())}")

    try:
        tier_result = await _evaluate_tiers(tool_name, input_data)
    except Exception as e:
        message = f"Denied: AI evaluation error: {str(e)}"
        logger.error(f"DENIED (Tier 3 error): {message}")
        write_audit_log(tool_name, input_data, "deny", "tier3_error", str(e))
        result = {"behavior": "deny", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 1: dangerous — deny with raw reason
    if tier_result.tier == "tier1_dangerous":
        result = {"behavior": "deny", "message": tier_result.reason, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 2 / 2.5: safe — allow with human-readable label
    if tier_result.tier in ("tier2_safe", "tier2_5_trusted_script"):
        tier_label = "Tier 2" if tier_result.tier == "tier2_safe" else "Tier 2.5"
        message = f"Auto-approved ({tier_label}): {tier_result.reason}"
        result = {"behavior": "allow", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 3: no AI evaluator — deny
    if tier_result.decision == "no_ai":
        message = "Denied: AI evaluator unavailable, requires manual approval"
        logger.warning(f"DENIED (Tier 3): {message}")
        write_audit_log(tool_name, input_data, "deny", "tier3_no_ai", message)
        result = {"behavior": "deny", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 3: AI approved
    if tier_result.decision == "allow":
        message = f"AI-approved (confidence: {tier_result.confidence:.2f}): {tier_result.reason}"
        logger.info(f"APPROVED (Tier 3): {message}")
        write_audit_log(
            tool_name,
            input_data,
            "allow",
            "tier3_ai_approve",
            tier_result.reason,
            tier_result.confidence,
        )
        result = {"behavior": "allow", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 3: AI denied
    if tier_result.decision == "deny":
        message = f"AI-denied (confidence: {tier_result.confidence:.2f}): {tier_result.reason}"
        logger.warning(f"DENIED (Tier 3): {message}")
        write_audit_log(
            tool_name,
            input_data,
            "deny",
            "tier3_ai_deny",
            tier_result.reason,
            tier_result.confidence,
        )
        result = {"behavior": "deny", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 3: ask_user — escalate to Slack if configured, else deny
    evaluation = tier_result.evaluation
    if state.slack_service is not None:
        logger.info(f"Escalating to Slack: {tier_result.reason}")
        slack_decision = await state.slack_service.request_approval(
            tool_name=tool_name,
            input_data=input_data,
            reasoning=tier_result.reason,
            category=evaluation.category,
        )
        behavior = "allow" if slack_decision == "allow" else "deny"
        tier_label = "tier3_slack_approved" if slack_decision == "allow" else "tier3_slack_denied"
        message = f"Slack human decision: {slack_decision} — {tier_result.reason}"
        write_audit_log(
            tool_name,
            input_data,
            behavior,
            tier_label,
            message,
            tier_result.confidence,
        )
        result = {"behavior": behavior, "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # No Slack configured: deny
    message = (
        f"Denied: Requires human approval. "
        f"{tier_result.reason} (confidence: {tier_result.confidence:.2f})"
    )
    if evaluation.suggested_message:
        message = evaluation.suggested_message

    logger.warning(f"DENIED (Tier 3 - needs human): {message}")
    write_audit_log(
        tool_name,
        input_data,
        "deny",
        "tier3_needs_human",
        tier_result.reason,
        tier_result.confidence,
    )
    result = {"behavior": "deny", "message": message, "updatedInput": {}}
    return [TextContent(type="text", text=json.dumps(result))]


def _notify_pending(
    pending: PendingApproval,
    tool_name: str,
    input_data: dict[str, Any],
    reason: str,
    request_id: str,
) -> None:
    """Write to file queue and fire macOS notification for a new pending approval."""
    if state.file_queue:
        summary = FileQueueWriter.summarize_input(tool_name, input_data)
        state.file_queue.write_pending(pending, summary)
    if state.macos_notifier:
        state.macos_notifier.notify(tool_name, reason[:80], request_id)


def _validate_create_pending(
    tool_name: str,
    input_data: dict[str, Any],
    workflow_id: str | None,
    agent_id: str | None,
    *,
    reason: str,
    tier: str,
    confidence: float | None,
    log_level: str = "warning",
    request_id: str | None = None,
) -> list[TextContent]:
    """Create a pending approval, notify, audit-log, and return the response."""
    if request_id is None:
        request_id = str(uuid.uuid4())

    getattr(logger, log_level)(f"PENDING (Tier 3): {reason}")

    pending = PendingApproval(
        request_id=request_id,
        tool_name=tool_name,
        input_data=input_data,
        reason=reason,
        confidence=confidence,
        tier=tier,
        workflow_id=workflow_id,
        agent_id=agent_id,
        pending_ttl_seconds=state.pending_ttl_seconds,
    )
    state.pending_approvals[request_id] = pending

    _notify_pending(pending, tool_name, input_data, reason, request_id)

    write_audit_log(tool_name, input_data, "pending", tier, reason, confidence)
    result = {
        "status": "pending",
        "tier": tier,
        "reason": reason,
        "confidence": confidence,
        "request_id": request_id,
        "expires_at": pending.expires_at.isoformat(),
        "ttl_seconds": state.pending_ttl_seconds,
    }
    return [TextContent(type="text", text=json.dumps(result))]


async def handle_validate_operation(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Handle validate_operation tool call.

    Returns structured validation response for Task agents:
    - status: "approved" | "denied" | "pending"
    - tier: Which tier made the decision
    - reason: Explanation
    - confidence: AI confidence (if tier3)
    - request_id: UUID for tracking human approvals (if pending)
    - expires_at: ISO timestamp when pending approval expires (if pending)
    """
    # Clean up expired pending approvals
    cleanup_expired_pending()

    tool_name = arguments["tool_name"]
    input_data = arguments["input"]
    workflow_id = arguments.get("workflow_id")
    agent_id = arguments.get("agent_id")

    logger.info(f"Validation request: {tool_name}")
    logger.debug(f"Input keys: {list(input_data.keys())}")

    # Check Tier 3 cache before running full pipeline
    operation_hash = compute_operation_hash(tool_name, input_data)
    cached = get_cached_decision(operation_hash)

    if cached is not None:
        # Cache hit — use cached Tier 3 decision (skip Tiers 1-2.5 re-evaluation)
        decision, evaluation, cached_time = cached
        logger.info(f"Using cached decision from {cached_time.isoformat()} (Tier 3 cache hit)")
        tier_result = TierResult(
            tier="tier3_ai_approve" if decision == "approve" else "tier3_ai_deny",
            decision="allow" if decision == "approve" else "deny",
            reason=evaluation.reasoning,
            confidence=evaluation.confidence,
            evaluation=evaluation,
        )
    else:
        # Cache miss — run full pipeline
        try:
            tier_result = await _evaluate_tiers(tool_name, input_data)
        except Exception as e:
            return _validate_create_pending(
                tool_name,
                input_data,
                workflow_id,
                agent_id,
                reason=f"AI evaluation error: {str(e)}",
                tier="tier3_error",
                confidence=None,
                log_level="error",
            )

        # Cache Tier 3 AI decisions for future use
        if tier_result.tier in ("tier3_ai_approve", "tier3_ai_deny") and tier_result.evaluation:
            raw_decision = "approve" if tier_result.decision == "allow" else "deny"
            cache_decision(operation_hash, raw_decision, tier_result.evaluation)

    # Tiers 1-2.5: audit logging already done by _evaluate_tiers; format response
    if tier_result.tier in ("tier1_dangerous",):
        result = {
            "status": "denied",
            "tier": tier_result.tier,
            "reason": tier_result.reason,
            "confidence": None,
            "request_id": None,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    if tier_result.tier in ("tier2_safe", "tier2_5_trusted_script"):
        result = {
            "status": "approved",
            "tier": tier_result.tier,
            "reason": tier_result.reason,
            "confidence": None,
            "request_id": None,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 3: no AI evaluator — park as pending
    if tier_result.decision == "no_ai":
        return _validate_create_pending(
            tool_name,
            input_data,
            workflow_id,
            agent_id,
            reason=tier_result.reason,
            tier="tier3_no_ai",
            confidence=None,
            log_level="warning",
        )

    # Tier 3: AI approved
    if tier_result.decision == "allow":
        logger.info(f"APPROVED (Tier 3): {tier_result.reason}")
        write_audit_log(
            tool_name,
            input_data,
            "allow",
            "tier3_ai_approve",
            tier_result.reason,
            tier_result.confidence,
        )
        result = {
            "status": "approved",
            "tier": "tier3_ai_approve",
            "reason": tier_result.reason,
            "confidence": tier_result.confidence,
            "request_id": None,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 3: AI denied
    if tier_result.decision == "deny":
        logger.warning(f"DENIED (Tier 3): {tier_result.reason}")
        write_audit_log(
            tool_name,
            input_data,
            "deny",
            "tier3_ai_deny",
            tier_result.reason,
            tier_result.confidence,
        )
        result = {
            "status": "denied",
            "tier": "tier3_ai_deny",
            "reason": tier_result.reason,
            "confidence": tier_result.confidence,
            "request_id": None,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 3: ask_user — park as pending
    evaluation = tier_result.evaluation

    # Notify Slack if configured (fire-and-forget)
    request_id = str(uuid.uuid4())
    if state.slack_service is not None:
        asyncio.create_task(
            state.slack_service.notify_pending(
                tool_name=tool_name,
                input_data=input_data,
                reasoning=tier_result.reason,
                category=evaluation.category,
                request_id=request_id,
            )
        )

    return _validate_create_pending(
        tool_name,
        input_data,
        workflow_id,
        agent_id,
        reason=tier_result.reason,
        tier="tier3_needs_human",
        confidence=tier_result.confidence,
        log_level="warning",
        request_id=request_id,
    )


async def handle_get_approval_stats(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle get_approval_stats tool call."""
    if not state.enable_audit_log or not os.path.exists(state.audit_log_file):
        return [TextContent(type="text", text=json.dumps({"error": "Audit log not available"}))]

    try:
        stats = {
            "total": 0,
            "approved": 0,
            "denied": 0,
            "by_tier": {},
            "by_tool": {},
            "cache": {
                "hits": state.cache_metrics["hits"],
                "misses": state.cache_metrics["misses"],
                "expired": state.cache_metrics["expired"],
                "evictions": state.cache_metrics["evictions"],
                "size": len(state.approval_cache),
                "max_size": state.cache_max_size,
            },
            "pending": {
                "count": len(state.pending_approvals),
                "max_size": state.pending_max_size,
            },
        }

        with open(state.audit_log_file) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    stats["total"] += 1

                    if entry["decision"] == "allow":
                        stats["approved"] += 1
                    else:
                        stats["denied"] += 1

                    tier = entry["tier"]
                    stats["by_tier"][tier] = stats["by_tier"].get(tier, 0) + 1

                    tool = entry["tool_name"]
                    stats["by_tool"][tool] = stats["by_tool"].get(tool, 0) + 1

                except json.JSONDecodeError:
                    continue

        return [TextContent(type="text", text=json.dumps(stats))]

    except Exception as e:
        return [
            TextContent(
                type="text", text=json.dumps({"error": f"Failed to read audit log: {str(e)}"})
            )
        ]


async def handle_submit_approval(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Handle submit_approval tool call.

    Allows humans to approve or deny pending operations.
    """
    request_id = arguments["request_id"]
    decision = arguments["decision"]  # "approve" or "deny"
    reason = arguments.get("reason", "")
    approver_id = arguments.get("approver_id", "unknown")

    # Clean up expired approvals first
    cleanup_expired_pending()

    # Check if pending approval exists
    if request_id not in state.pending_approvals:
        result = {
            "success": False,
            "error": "not_found",
            "message": f"Pending approval {request_id} not found. It may have expired or already been processed.",
        }
        return [TextContent(type="text", text=json.dumps(result))]

    pending = state.pending_approvals[request_id]

    # Check if expired
    if pending.is_expired():
        state.pending_approvals.pop(request_id, None)
        result = {
            "success": False,
            "error": "expired",
            "message": f"Pending approval {request_id} has expired.",
            "expired_at": pending.expires_at.isoformat(),
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Process the decision
    if decision == "approve":
        pending.status = "approved"
        final_decision = "allow"
        logger.info(f"APPROVED by human ({approver_id}): {pending.tool_name} - {reason}")
    else:
        pending.status = "denied"
        final_decision = "deny"
        logger.info(f"DENIED by human ({approver_id}): {pending.tool_name} - {reason}")

    # Write to audit log
    write_audit_log(
        pending.tool_name,
        pending.input_data,
        final_decision,
        f"{pending.tier}_human_{'approved' if decision == 'approve' else 'denied'}",
        f"Human decision by {approver_id}: {reason}"
        if reason
        else f"Human decision by {approver_id}",
        pending.confidence,
    )

    # Move from pending to resolved_approvals buffer
    pending.resolved_at = datetime.now(UTC)
    pending.resolved_by = f"human:{approver_id}"
    pending.resolution = decision  # "approve" or "deny"
    state.pending_approvals.pop(request_id)
    state.resolved_approvals[request_id] = pending

    # Update file queue
    if state.file_queue:
        state.file_queue.resolve(request_id, decision, f"human:{approver_id}")

    result = {
        "success": True,
        "request_id": request_id,
        "decision": decision,
        "tool_name": pending.tool_name,
        "approver_id": approver_id,
        "reason": reason,
        "workflow_id": pending.workflow_id,
        "agent_id": pending.agent_id,
    }
    return [TextContent(type="text", text=json.dumps(result))]


async def handle_poll_approval(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Handle poll_approval tool call.

    Checks the resolution status of a specific pending approval request.
    Agents use this to poll for the outcome of a validate_operation that
    returned status: "pending".
    """
    request_id = arguments["request_id"]

    # Clean up expired pending and resolved approvals first
    cleanup_expired_pending()

    # Check pending_approvals
    if request_id in state.pending_approvals:
        pending = state.pending_approvals[request_id]
        result = {
            "found": True,
            "status": "pending",
            "decision": None,
            "decided_by": None,
            "decided_at": None,
            "reason": pending.reason,
            "confidence": pending.confidence,
            "ttl_remaining_seconds": max(
                0, int((pending.expires_at - datetime.now(UTC)).total_seconds())
            ),
            "tool_name": pending.tool_name,
            "workflow_id": pending.workflow_id,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Check resolved_approvals
    if request_id in state.resolved_approvals:
        resolved = state.resolved_approvals[request_id]
        # Map resolution to status explicitly
        _resolution_status = {"approve": "approved", "deny": "denied", "expired": "expired"}
        status = _resolution_status.get(resolved.resolution, resolved.resolution or "denied")
        result = {
            "found": True,
            "status": status,
            "decision": resolved.resolution,
            "decided_by": resolved.resolved_by,
            "decided_at": resolved.resolved_at.isoformat() if resolved.resolved_at else None,
            "reason": resolved.reason,
            "confidence": resolved.confidence,
            "ttl_remaining_seconds": max(
                0,
                int(
                    state.resolved_ttl_seconds
                    - (datetime.now(UTC) - resolved.resolved_at).total_seconds()
                ),
            )
            if resolved.resolved_at
            else 0,
            "tool_name": resolved.tool_name,
            "workflow_id": resolved.workflow_id,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Not found in either dict
    result = {
        "found": False,
        "status": "not_found",
    }
    return [TextContent(type="text", text=json.dumps(result))]


async def handle_supervisor_approve(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Handle supervisor_approve tool call.

    Allows a supervisor agent to approve, deny, or escalate a pending
    approval request from a worker within the same workflow. Enforces
    delegation policy constraints server-side.
    """
    request_id = arguments["request_id"]
    decision = arguments["decision"]  # "approve", "deny", or "escalate_to_human"
    supervisor_id = arguments["supervisor_id"]
    workflow_id = arguments["workflow_id"]
    reasoning = arguments.get("reasoning", "")

    # Clean up expired approvals first
    cleanup_expired_pending()

    # Look up request_id in pending_approvals (NOT resolved_approvals)
    if request_id not in state.pending_approvals:
        result = {
            "success": False,
            "error": "not_found",
            "message": f"Pending approval {request_id} not found. "
            "It may have expired, already been resolved, or never existed.",
        }
        return [TextContent(type="text", text=json.dumps(result))]

    pending = state.pending_approvals[request_id]

    # Check if expired (belt-and-suspenders, matches handle_submit_approval)
    if pending.is_expired():
        state.pending_approvals.pop(request_id, None)
        result = {
            "success": False,
            "error": "expired",
            "message": f"Pending approval {request_id} has expired.",
            "expired_at": pending.expires_at.isoformat(),
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Run delegation policy validation
    violation = state.supervisor_policy.validate(pending, supervisor_id, workflow_id, decision)
    if violation is not None:
        result = {
            "success": False,
            "error": "policy_violation",
            "violation_code": violation.code,
            "message": violation.message,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Build reason string for audit
    audit_reason = (
        f"Supervisor {supervisor_id}: {reasoning}"
        if reasoning
        else f"Supervisor {supervisor_id} decision"
    )

    if decision == "escalate_to_human":
        # Log audit but keep in pending for human to act on
        write_audit_log(
            pending.tool_name,
            pending.input_data,
            "escalated",
            "tier3_supervisor_escalated",
            audit_reason,
            pending.confidence,
        )

        result = {
            "success": True,
            "request_id": request_id,
            "decision": decision,
            "supervisor_id": supervisor_id,
            "message": "Request escalated to human. It remains pending for human review.",
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # approve or deny — resolve the request
    final_decision = "allow" if decision == "approve" else "deny"
    tier_label = "tier3_supervisor_approved" if decision == "approve" else "tier3_supervisor_denied"

    # Update pending approval fields
    pending.resolved_at = datetime.now(UTC)
    pending.resolved_by = f"supervisor:{supervisor_id}"
    pending.resolution = decision  # "approve" or "deny"
    pending.status = "approved" if decision == "approve" else "denied"

    # Move from pending to resolved
    state.pending_approvals.pop(request_id)
    state.resolved_approvals[request_id] = pending

    # Update file queue
    if state.file_queue:
        state.file_queue.resolve(request_id, decision, f"supervisor:{supervisor_id}")

    # Write audit log
    write_audit_log(
        pending.tool_name,
        pending.input_data,
        final_decision,
        tier_label,
        audit_reason,
        pending.confidence,
    )

    logger.info(
        f"Supervisor {supervisor_id} {'approved' if decision == 'approve' else 'denied'} request {request_id} for {pending.tool_name}"
    )

    result = {
        "success": True,
        "request_id": request_id,
        "decision": decision,
        "supervisor_id": supervisor_id,
        "tool_name": pending.tool_name,
        "workflow_id": pending.workflow_id,
        "agent_id": pending.agent_id,
    }
    return [TextContent(type="text", text=json.dumps(result))]


async def handle_get_pending_approvals(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Handle get_pending_approvals tool call.

    Lists all pending approval requests, optionally filtered by workflow_id or agent_id.
    """
    # Clean up expired approvals first
    cleanup_expired_pending()

    workflow_id_filter = arguments.get("workflow_id")
    agent_id_filter = arguments.get("agent_id")

    pending_list = []
    for _request_id, pending in state.pending_approvals.items():
        # Apply filters
        if workflow_id_filter and pending.workflow_id != workflow_id_filter:
            continue
        if agent_id_filter and pending.agent_id != agent_id_filter:
            continue

        pending_list.append(pending.to_dict())

    result = {
        "count": len(pending_list),
        "pending_ttl_seconds": state.pending_ttl_seconds,
        "pending": pending_list,
    }
    return [TextContent(type="text", text=json.dumps(result))]


async def main():
    """Run the MCP server."""
    logger.info("Starting Phlegyas MCP server...")
    logger.info(f"Audit logging: {'enabled' if state.enable_audit_log else 'disabled'}")
    if state.ai_evaluator:
        logger.info(f"AI evaluation: enabled (model: {state.ai_evaluator.model})")
    else:
        logger.info("AI evaluation: disabled")
    if state.slack_service:
        logger.info("Slack escalation: enabled")
    else:
        logger.info("Slack escalation: disabled")

    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())
    finally:
        if state.slack_service:
            state.slack_service.close()


def run():
    """Synchronous entry point for console_scripts."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
