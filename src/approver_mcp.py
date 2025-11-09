"""
Claude Permission Approver - Official MCP SDK Implementation

Three-tier intelligent permission approval system using official mcp.server
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from src.tier1_dangerous import DangerousPatternDetector
from src.tier2_safe import SafeOperationDetector
from src.tier3_ai import AIEvaluator

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
safe_detector = SafeOperationDetector()

# Approval cache for Tier 3 decisions (improves performance for repeated operations)
# Cache format: {operation_hash: (decision, evaluation_result, timestamp)}
approval_cache = {}
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))  # 1 hour default
CACHE_ENABLED = os.getenv("ENABLE_APPROVAL_CACHE", "true").lower() == "true"

# Initialize AI evaluator
ai_evaluator = None
try:
    model = os.getenv("CLAUDE_MODEL", "claude-3-5-haiku-20241022")
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


def write_audit_log(
    tool_name: str,
    input_data: dict[str, Any],
    decision: str,
    tier: str,
    reason: str,
    confidence: float | None = None,
):
    """Write decision to audit log."""
    if not enable_audit_log:
        return

    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "tool_name": tool_name,
        "input": input_data,
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
        {"tool": tool_name, "input": input_data},
        sort_keys=True,
        default=str
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
        return None

    decision, evaluation, timestamp = approval_cache[operation_hash]

    # Check if cache entry is expired
    if datetime.utcnow() - timestamp > timedelta(seconds=CACHE_TTL_SECONDS):
        # Remove expired entry
        del approval_cache[operation_hash]
        logger.debug(f"Cache entry expired for hash {operation_hash[:8]}...")
        return None

    logger.debug(f"Cache hit for hash {operation_hash[:8]}...")
    return decision, evaluation, timestamp


def cache_decision(operation_hash: str, decision: str, evaluation: Any):
    """
    Cache a Tier 3 decision for future use.

    Args:
        operation_hash: Hash of the operation
        decision: The decision (allow/deny/ask_user)
        evaluation: The EvaluationResult object
    """
    if not CACHE_ENABLED:
        return

    approval_cache[operation_hash] = (decision, evaluation, datetime.utcnow())
    logger.debug(f"Cached decision for hash {operation_hash[:8]}... (cache size: {len(approval_cache)})")


# Create MCP server
app = Server("claude-permission-approver")


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
            description="Validate an operation before execution (for Task agents). Returns structured approval status without enforcing it.",
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
    else:
        raise ValueError(f"Unknown tool: {name}")


async def handle_permissions_approve(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle permissions__approve tool call."""
    tool_name = arguments["tool_name"]
    input_data = arguments["input"]
    tool_use_id = arguments.get("tool_use_id")

    logger.info(f"Permission request: {tool_name}")
    logger.debug(f"Input: {json.dumps(input_data, indent=2)}")

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

    # Tier 3: AI evaluation
    if ai_evaluator is None:
        message = "Denied: AI evaluator unavailable, requires manual approval"
        logger.warning(f"DENIED (Tier 3): {message}")
        write_audit_log(tool_name, input_data, "deny", "tier3_no_ai", message)
        result = {"behavior": "deny", "message": message, "updatedInput": {}}
        return [TextContent(type="text", text=json.dumps(result))]

    try:
        decision, evaluation = await ai_evaluator.evaluate(tool_name, input_data)

        if decision == "allow":
            message = (
                f"AI-approved (confidence: {evaluation.confidence:.2f}): "
                f"{evaluation.reasoning}"
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
            message = (
                f"AI-denied (confidence: {evaluation.confidence:.2f}): "
                f"{evaluation.reasoning}"
            )
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
    - status: "approved" | "denied" | "needs_human"
    - tier: Which tier made the decision
    - reason: Explanation
    - confidence: AI confidence (if tier3)
    - request_id: UUID for tracking human approvals (if needs_human)
    """
    import uuid

    tool_name = arguments["tool_name"]
    input_data = arguments["input"]

    logger.info(f"Validation request: {tool_name}")
    logger.debug(f"Input: {json.dumps(input_data, indent=2)}")

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
            logger.warning(f"NEEDS_HUMAN (Tier 3): {message}")
            write_audit_log(tool_name, input_data, "needs_human", "tier3_no_ai", message)
            request_id = str(uuid.uuid4())
            result = {
                "status": "needs_human",
                "tier": "tier3_no_ai",
                "reason": message,
                "confidence": None,
                "request_id": request_id,
            }
            return [TextContent(type="text", text=json.dumps(result))]

        decision, evaluation = await ai_evaluator.evaluate(tool_name, input_data)
        # Cache the decision for future use
        cache_decision(operation_hash, decision, evaluation)

    # Process the decision (whether from cache or fresh evaluation)
    try:

        if decision == "allow":
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

        else:  # ask_user
            logger.warning(f"NEEDS_HUMAN (Tier 3): {evaluation.reasoning}")
            write_audit_log(
                tool_name,
                input_data,
                "needs_human",
                "tier3_needs_human",
                evaluation.reasoning,
                evaluation.confidence,
            )
            request_id = str(uuid.uuid4())
            result = {
                "status": "needs_human",
                "tier": "tier3_needs_human",
                "reason": evaluation.reasoning,
                "confidence": evaluation.confidence,
                "request_id": request_id,
            }
            return [TextContent(type="text", text=json.dumps(result))]

    except Exception as e:
        logger.error(f"NEEDS_HUMAN (Tier 3 error): {str(e)}")
        write_audit_log(tool_name, input_data, "needs_human", "tier3_error", str(e))
        request_id = str(uuid.uuid4())
        result = {
            "status": "needs_human",
            "tier": "tier3_error",
            "reason": f"AI evaluation error: {str(e)}",
            "confidence": None,
            "request_id": request_id,
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
        return [TextContent(type="text", text=json.dumps({"error": f"Failed to read audit log: {str(e)}"}))]


async def main():
    """Run the MCP server."""
    logger.info("Starting Claude Permission Approver MCP server...")
    logger.info(f"Audit logging: {'enabled' if enable_audit_log else 'disabled'}")
    if ai_evaluator:
        logger.info(f"AI evaluation: enabled (model: {ai_evaluator.model})")
    else:
        logger.info("AI evaluation: disabled")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
