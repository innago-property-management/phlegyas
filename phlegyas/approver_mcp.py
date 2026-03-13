"""
Phlegyas - Official MCP SDK Implementation

Three-tier intelligent permission gate for AI agents using official mcp.server
"""

import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from phlegyas.tier1_dangerous import DangerousPatternDetector
from phlegyas.tier2_5_trust import ScriptTrustStore
from phlegyas.tier2_safe import SafeOperationDetector, SafePatternStore
from phlegyas.tier3_ai import AIEvaluator

# Load environment variables
load_dotenv()

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize detectors
dangerous_detector = DangerousPatternDetector()
safe_pattern_store = SafePatternStore()
safe_detector = SafeOperationDetector(user_store=safe_pattern_store)
trust_store = ScriptTrustStore()

# Approval cache for Tier 3 decisions (improves performance for repeated operations)
# Cache format: {operation_hash: (decision, evaluation_result, timestamp)}
approval_cache = {}
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))  # 1 hour default
CACHE_ENABLED = os.getenv("ENABLE_APPROVAL_CACHE", "true").lower() == "true"
CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "1000"))

# Pending approvals store for async human approval workflow
# Format: {request_id: PendingApproval}
pending_approvals: dict[str, "PendingApproval"] = {}
PENDING_TTL_SECONDS = int(os.getenv("PENDING_TTL_SECONDS", "1800"))  # 30 min default
PENDING_MAX_SIZE = int(os.getenv("PENDING_MAX_SIZE", "100"))

# Cache metrics (reset each session — MCP server is episodic, not always-on)
cache_metrics = {"hits": 0, "misses": 0, "expired": 0, "evictions": 0}


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
        self.expires_at = self.created_at + timedelta(seconds=PENDING_TTL_SECONDS)
        self.status = "pending"  # pending, approved, denied, expired

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
        }


def cleanup_expired_pending():
    """Remove expired pending approvals and enforce max size."""
    expired = [req_id for req_id, pending in pending_approvals.items() if pending.is_expired()]
    for req_id in expired:
        pending = pending_approvals.pop(req_id)
        logger.info(f"Expired pending approval: {req_id} for {pending.tool_name}")
        write_audit_log(
            pending.tool_name,
            pending.input_data,
            "expired",
            pending.tier,
            f"Approval expired after {PENDING_TTL_SECONDS}s",
            pending.confidence,
        )

    # Evict oldest if over capacity (shouldn't happen in episodic use, but defense-in-depth)
    while len(pending_approvals) > PENDING_MAX_SIZE:
        oldest_id = min(pending_approvals, key=lambda k: pending_approvals[k].created_at)
        evicted = pending_approvals.pop(oldest_id)
        logger.warning(f"Evicted pending approval (over {PENDING_MAX_SIZE} limit): {oldest_id}")
        write_audit_log(
            evicted.tool_name,
            evicted.input_data,
            "evicted",
            evicted.tier,
            f"Evicted: pending queue over {PENDING_MAX_SIZE} limit",
            evicted.confidence,
        )


# Initialize AI evaluator
ai_evaluator = None
try:
    model = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
    approval_threshold = float(os.getenv("APPROVAL_CONFIDENCE_THRESHOLD", "0.8"))
    denial_threshold = float(os.getenv("DENIAL_CONFIDENCE_THRESHOLD", "0.2"))

    ai_evaluator = AIEvaluator(
        model=model,
        approval_threshold=approval_threshold,
        denial_threshold=denial_threshold,
    )
    logger.info(f"AI evaluator initialized with model: {model}")
except Exception as e:
    logger.warning(f"AI evaluator initialization failed: {e}")
    logger.warning("Only Tier 1 (dangerous) and Tier 2 (safe) will be available")

# Audit log configuration
enable_audit_log = os.getenv("ENABLE_AUDIT_LOG", "true").lower() == "true"
audit_log_file = os.getenv("AUDIT_LOG_FILE", "audit.jsonl")


# Patterns for masking sensitive values in audit logs
_SENSITIVE_PATTERNS = [
    re.compile(r"(password\s*=\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(secret\s*=\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*=?\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(AWS_SECRET\S*\s*=?\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(ANTHROPIC_API_KEY\s*=?\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(Bearer\s+)(\S+)", re.IGNORECASE),
    re.compile(r"(sk-ant-\S{4})\S+", re.IGNORECASE),
    re.compile(r"(xoxb-\S{4})\S+", re.IGNORECASE),
    re.compile(r"(token\s*=\s*)(\S+)", re.IGNORECASE),
]


def _sanitize_value(value: Any) -> Any:
    """Recursively mask sensitive patterns in a value."""
    if isinstance(value, str):
        masked = value
        for pattern in _SENSITIVE_PATTERNS:
            masked = pattern.sub(lambda m: m.group(1) + "***REDACTED***", masked)
        return masked
    elif isinstance(value, dict):
        return {k: _sanitize_value(v) for k, v in value.items()}
    elif isinstance(value, list | tuple):
        sanitized = [_sanitize_value(item) for item in value]
        return type(value)(sanitized)
    return value


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
    if not enable_audit_log:
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
        with open(audit_log_file, "a") as f:
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
    if not CACHE_ENABLED:
        return None

    if operation_hash not in approval_cache:
        cache_metrics["misses"] += 1
        return None

    decision, evaluation, timestamp = approval_cache[operation_hash]

    # Check if cache entry is expired
    if datetime.now(UTC) - timestamp > timedelta(seconds=CACHE_TTL_SECONDS):
        del approval_cache[operation_hash]
        cache_metrics["expired"] += 1
        logger.debug(f"Cache entry expired for hash {operation_hash[:8]}...")
        return None

    cache_metrics["hits"] += 1
    logger.debug(f"Cache hit for hash {operation_hash[:8]}...")
    return decision, evaluation, timestamp


def cache_decision(operation_hash: str, decision: str, evaluation: Any):
    """
    Cache a Tier 3 decision for future use. Evicts oldest entry if at capacity.
    """
    if not CACHE_ENABLED:
        return

    # Evict oldest entry if at capacity
    if len(approval_cache) >= CACHE_MAX_SIZE:
        oldest_key = min(approval_cache, key=lambda k: approval_cache[k][2])
        del approval_cache[oldest_key]
        cache_metrics["evictions"] += 1
        logger.debug(f"Cache evicted oldest entry (size was {CACHE_MAX_SIZE})")

    approval_cache[operation_hash] = (decision, evaluation, datetime.now(UTC))
    logger.debug(
        f"Cached decision for hash {operation_hash[:8]}... (cache size: {len(approval_cache)})"
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
    elif name == "get_pending_approvals":
        return await handle_get_pending_approvals(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")


async def handle_permissions_approve(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle permissions__approve tool call."""
    tool_name = arguments["tool_name"]
    input_data = arguments["input"]
    _tool_use_id = arguments.get("tool_use_id")

    logger.info(f"Permission request: {tool_name}")
    logger.debug(f"Input keys: {list(input_data.keys())}")

    # Tier 1: Check for dangerous patterns
    is_dangerous, dangerous_reason = dangerous_detector.is_dangerous(tool_name, input_data)
    if is_dangerous:
        logger.warning(f"DENIED (Tier 1): {dangerous_reason}")
        write_audit_log(tool_name, input_data, "deny", "tier1_dangerous", dangerous_reason)
        result = {"behavior": "deny", "message": dangerous_reason, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 2: Check for safe categories
    is_safe, safe_category = safe_detector.is_safe(tool_name, input_data)
    if is_safe:
        message = f"Auto-approved (Tier 2): {safe_category}"
        logger.info(f"APPROVED (Tier 2): {safe_category}")
        write_audit_log(tool_name, input_data, "allow", "tier2_safe", safe_category)
        result = {"behavior": "allow", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 2.5: Check script trust store (TOFU - Trust On First Use)
    is_trusted, trust_category = trust_store.is_trusted(tool_name, input_data)
    if is_trusted:
        message = f"Auto-approved (Tier 2.5): {trust_category}"
        logger.info(f"APPROVED (Tier 2.5): {trust_category}")
        write_audit_log(tool_name, input_data, "allow", "tier2_5_trusted_script", trust_category)
        result = {"behavior": "allow", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]
    elif trust_category:
        logger.warning(
            f"Tier 2.5 trust-store degradation - falling through to Tier 3: {trust_category}"
        )

    # Tier 3: AI evaluation
    if ai_evaluator is None:
        message = "Denied: AI evaluator unavailable, requires manual approval"
        logger.warning(f"DENIED (Tier 3): {message}")
        write_audit_log(tool_name, input_data, "deny", "tier3_no_ai", message)
        result = {"behavior": "deny", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    try:
        decision, evaluation = await ai_evaluator.evaluate(tool_name, input_data)

        if decision == "approve":
            message = (
                f"AI-approved (confidence: {evaluation.confidence:.2f}): {evaluation.reasoning}"
            )
            logger.info(f"APPROVED (Tier 3): {message}")
            write_audit_log(
                tool_name,
                input_data,
                "allow",
                "tier3_ai_approve",
                evaluation.reasoning,
                evaluation.confidence,
            )
            result = {"behavior": "allow", "message": message, "updatedInput": {}}
            return [TextContent(type="text", text=json.dumps(result))]

        elif decision == "deny":
            message = f"AI-denied (confidence: {evaluation.confidence:.2f}): {evaluation.reasoning}"
            logger.warning(f"DENIED (Tier 3): {message}")
            write_audit_log(
                tool_name,
                input_data,
                "deny",
                "tier3_ai_deny",
                evaluation.reasoning,
                evaluation.confidence,
            )
            result = {"behavior": "deny", "message": message, "updatedInput": {}}
            return [TextContent(type="text", text=json.dumps(result))]

        else:  # ask_user
            message = (
                f"Denied: Requires human approval. "
                f"{evaluation.reasoning} (confidence: {evaluation.confidence:.2f})"
            )
            if evaluation.suggested_message:
                message = evaluation.suggested_message

            logger.warning(f"DENIED (Tier 3 - needs human): {message}")
            write_audit_log(
                tool_name,
                input_data,
                "deny",
                "tier3_needs_human",
                evaluation.reasoning,
                evaluation.confidence,
            )
            result = {"behavior": "deny", "message": message, "updatedInput": {}}
            return [TextContent(type="text", text=json.dumps(result))]

    except Exception as e:
        message = f"Denied: AI evaluation error: {str(e)}"
        logger.error(f"DENIED (Tier 3 error): {message}")
        write_audit_log(tool_name, input_data, "deny", "tier3_error", str(e))
        result = {"behavior": "deny", "message": message, "updatedInput": {}}
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
    import uuid

    # Clean up expired pending approvals
    cleanup_expired_pending()

    tool_name = arguments["tool_name"]
    input_data = arguments["input"]
    workflow_id = arguments.get("workflow_id")
    agent_id = arguments.get("agent_id")

    logger.info(f"Validation request: {tool_name}")
    logger.debug(f"Input keys: {list(input_data.keys())}")

    # Tier 1: Check for dangerous patterns
    is_dangerous, dangerous_reason = dangerous_detector.is_dangerous(tool_name, input_data)
    if is_dangerous:
        logger.warning(f"DENIED (Tier 1): {dangerous_reason}")
        write_audit_log(tool_name, input_data, "deny", "tier1_dangerous", dangerous_reason)
        result = {
            "status": "denied",
            "tier": "tier1_dangerous",
            "reason": dangerous_reason,
            "confidence": None,
            "request_id": None,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 2: Check for safe categories
    is_safe, safe_category = safe_detector.is_safe(tool_name, input_data)
    if is_safe:
        logger.info(f"APPROVED (Tier 2): {safe_category}")
        write_audit_log(tool_name, input_data, "allow", "tier2_safe", safe_category)
        result = {
            "status": "approved",
            "tier": "tier2_safe",
            "reason": safe_category,
            "confidence": None,
            "request_id": None,
        }
        return [TextContent(type="text", text=json.dumps(result))]

    # Tier 2.5: Check script trust store (TOFU - Trust On First Use)
    is_trusted, trust_category = trust_store.is_trusted(tool_name, input_data)
    if is_trusted:
        logger.info(f"APPROVED (Tier 2.5): {trust_category}")
        write_audit_log(tool_name, input_data, "allow", "tier2_5_trusted_script", trust_category)
        result = {
            "status": "approved",
            "tier": "tier2_5_trusted_script",
            "reason": trust_category,
            "confidence": None,
            "request_id": None,
        }
        return [TextContent(type="text", text=json.dumps(result))]
    elif trust_category:
        logger.warning(
            f"Tier 2.5 trust-store degradation - falling through to Tier 3: {trust_category}"
        )

    # Tier 3: AI evaluation (with caching)
    operation_hash = compute_operation_hash(tool_name, input_data)

    # Check cache first
    cached = get_cached_decision(operation_hash)
    if cached is not None:
        decision, evaluation, cached_time = cached
        logger.info(f"Using cached decision from {cached_time.isoformat()} (Tier 3 cache hit)")
        # Note: We still write to audit log for cache hits to track all validation requests
    else:
        # Cache miss - need to evaluate
        if ai_evaluator is None:
            message = "AI evaluator unavailable, requires manual approval"
            logger.warning(f"PENDING (Tier 3): {message}")
            request_id = str(uuid.uuid4())

            # Create and store pending approval
            pending = PendingApproval(
                request_id=request_id,
                tool_name=tool_name,
                input_data=input_data,
                reason=message,
                confidence=None,
                tier="tier3_no_ai",
                workflow_id=workflow_id,
                agent_id=agent_id,
            )
            pending_approvals[request_id] = pending

            write_audit_log(tool_name, input_data, "pending", "tier3_no_ai", message)
            result = {
                "status": "pending",
                "tier": "tier3_no_ai",
                "reason": message,
                "confidence": None,
                "request_id": request_id,
                "expires_at": pending.expires_at.isoformat(),
                "ttl_seconds": PENDING_TTL_SECONDS,
            }
            return [TextContent(type="text", text=json.dumps(result))]

        decision, evaluation = await ai_evaluator.evaluate(tool_name, input_data)
        # Cache the decision for future use
        cache_decision(operation_hash, decision, evaluation)

    # Process the decision (whether from cache or fresh evaluation)
    try:
        if decision == "approve":
            logger.info(f"APPROVED (Tier 3): {evaluation.reasoning}")
            write_audit_log(
                tool_name,
                input_data,
                "allow",
                "tier3_ai_approve",
                evaluation.reasoning,
                evaluation.confidence,
            )
            result = {
                "status": "approved",
                "tier": "tier3_ai_approve",
                "reason": evaluation.reasoning,
                "confidence": evaluation.confidence,
                "request_id": None,
            }
            return [TextContent(type="text", text=json.dumps(result))]

        elif decision == "deny":
            logger.warning(f"DENIED (Tier 3): {evaluation.reasoning}")
            write_audit_log(
                tool_name,
                input_data,
                "deny",
                "tier3_ai_deny",
                evaluation.reasoning,
                evaluation.confidence,
            )
            result = {
                "status": "denied",
                "tier": "tier3_ai_deny",
                "reason": evaluation.reasoning,
                "confidence": evaluation.confidence,
                "request_id": None,
            }
            return [TextContent(type="text", text=json.dumps(result))]

        else:  # ask_user - requires human approval
            logger.warning(f"PENDING (Tier 3): {evaluation.reasoning}")
            request_id = str(uuid.uuid4())

            # Create and store pending approval
            pending = PendingApproval(
                request_id=request_id,
                tool_name=tool_name,
                input_data=input_data,
                reason=evaluation.reasoning,
                confidence=evaluation.confidence,
                tier="tier3_needs_human",
                workflow_id=workflow_id,
                agent_id=agent_id,
            )
            pending_approvals[request_id] = pending

            write_audit_log(
                tool_name,
                input_data,
                "pending",
                "tier3_needs_human",
                evaluation.reasoning,
                evaluation.confidence,
            )
            result = {
                "status": "pending",
                "tier": "tier3_needs_human",
                "reason": evaluation.reasoning,
                "confidence": evaluation.confidence,
                "request_id": request_id,
                "expires_at": pending.expires_at.isoformat(),
                "ttl_seconds": PENDING_TTL_SECONDS,
            }
            return [TextContent(type="text", text=json.dumps(result))]

    except Exception as e:
        logger.error(f"PENDING (Tier 3 error): {str(e)}")
        request_id = str(uuid.uuid4())

        # Create and store pending approval for error case
        pending = PendingApproval(
            request_id=request_id,
            tool_name=tool_name,
            input_data=input_data,
            reason=f"AI evaluation error: {str(e)}",
            confidence=None,
            tier="tier3_error",
            workflow_id=workflow_id,
            agent_id=agent_id,
        )
        pending_approvals[request_id] = pending

        write_audit_log(tool_name, input_data, "pending", "tier3_error", str(e))
        result = {
            "status": "pending",
            "tier": "tier3_error",
            "reason": f"AI evaluation error: {str(e)}",
            "confidence": None,
            "request_id": request_id,
            "expires_at": pending.expires_at.isoformat(),
            "ttl_seconds": PENDING_TTL_SECONDS,
        }
        return [TextContent(type="text", text=json.dumps(result))]


async def handle_get_approval_stats(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle get_approval_stats tool call."""
    if not enable_audit_log or not os.path.exists(audit_log_file):
        return [TextContent(type="text", text=json.dumps({"error": "Audit log not available"}))]

    try:
        stats = {
            "total": 0,
            "approved": 0,
            "denied": 0,
            "by_tier": {},
            "by_tool": {},
            "cache": {
                "hits": cache_metrics["hits"],
                "misses": cache_metrics["misses"],
                "expired": cache_metrics["expired"],
                "evictions": cache_metrics["evictions"],
                "size": len(approval_cache),
                "max_size": CACHE_MAX_SIZE,
            },
            "pending": {
                "count": len(pending_approvals),
                "max_size": PENDING_MAX_SIZE,
            },
        }

        with open(audit_log_file) as f:
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
    if request_id not in pending_approvals:
        result = {
            "success": False,
            "error": "not_found",
            "message": f"Pending approval {request_id} not found. It may have expired or already been processed.",
        }
        return [TextContent(type="text", text=json.dumps(result))]

    pending = pending_approvals[request_id]

    # Check if expired
    if pending.is_expired():
        pending_approvals.pop(request_id, None)
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
        f"{pending.tier}_human_{decision}d",
        f"Human decision by {approver_id}: {reason}"
        if reason
        else f"Human decision by {approver_id}",
        pending.confidence,
    )

    # Remove from pending
    pending_approvals.pop(request_id)

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
    for _request_id, pending in pending_approvals.items():
        # Apply filters
        if workflow_id_filter and pending.workflow_id != workflow_id_filter:
            continue
        if agent_id_filter and pending.agent_id != agent_id_filter:
            continue

        pending_list.append(pending.to_dict())

    result = {
        "count": len(pending_list),
        "pending_ttl_seconds": PENDING_TTL_SECONDS,
        "pending": pending_list,
    }
    return [TextContent(type="text", text=json.dumps(result))]


async def main():
    """Run the MCP server."""
    logger.info("Starting Phlegyas MCP server...")
    logger.info(f"Audit logging: {'enabled' if enable_audit_log else 'disabled'}")
    if ai_evaluator:
        logger.info(f"AI evaluation: enabled (model: {ai_evaluator.model})")
    else:
        logger.info("AI evaluation: disabled")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def run():
    """Synchronous entry point for console_scripts."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
