"""
Claude Permission Approver - Main FastMCP Server

Three-tier intelligent permission approval system:
- Tier 1: Block dangerous operations (instant)
- Tier 2: Auto-approve safe operations (instant)
- Tier 3: AI evaluation for ambiguous cases (sub-second)
"""

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP

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

# Initialize FastMCP server
mcp = FastMCP("Claude Permission Approver")

# Initialize detectors
dangerous_detector = DangerousPatternDetector()
safe_detector = SafeOperationDetector()

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
        "timestamp": datetime.now(UTC).isoformat(),
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


@mcp.tool()
async def permissions__approve(
    tool_name: str, input: dict[str, Any], tool_use_id: str | None = None
) -> dict[str, Any]:
    """
    Intelligent permission approval using three-tier evaluation.

    Args:
        tool_name: The tool Claude Code wants to use (e.g., "Bash", "Edit", "Write")
        input: The parameters for that tool
        tool_use_id: Optional tool use identifier from MCP protocol

    Returns:
        Permission decision dict:
        - {"behavior": "allow", "message": "..."} - Operation approved
        - {"behavior": "deny", "message": "..."} - Operation blocked
    """

    logger.info(f"Permission request: {tool_name}")
    logger.debug(f"Input: {json.dumps(input, indent=2)}")

    # Tier 1: Check for dangerous patterns (highest priority)
    is_dangerous, dangerous_reason = dangerous_detector.is_dangerous(tool_name, input)
    if is_dangerous:
        logger.warning(f"DENIED (Tier 1): {dangerous_reason}")
        write_audit_log(tool_name, input, "deny", "tier1_dangerous", dangerous_reason)
        return {"behavior": "deny", "message": dangerous_reason}

    # Tier 2: Check for safe categories (auto-approve)
    is_safe, safe_category = safe_detector.is_safe(tool_name, input)
    if is_safe:
        message = f"Auto-approved (Tier 2): {safe_category}"
        logger.info(f"APPROVED (Tier 2): {safe_category}")
        write_audit_log(tool_name, input, "allow", "tier2_safe", safe_category)
        return {"behavior": "allow", "message": message}

    # Tier 3: AI evaluation for ambiguous cases
    if ai_evaluator is None:
        # If AI evaluator not available, deny by default (conservative)
        message = "Denied: AI evaluator unavailable, requires manual approval"
        logger.warning(f"DENIED (Tier 3): {message}")
        write_audit_log(tool_name, input, "deny", "tier3_no_ai", message)
        return {"behavior": "deny", "message": message}

    try:
        decision, evaluation = await ai_evaluator.evaluate(tool_name, input)

        if decision == "approve":
            message = (
                f"AI-approved (confidence: {evaluation.confidence:.2f}): {evaluation.reasoning}"
            )
            logger.info(f"APPROVED (Tier 3): {message}")
            write_audit_log(
                tool_name,
                input,
                "allow",
                "tier3_ai_approve",
                evaluation.reasoning,
                evaluation.confidence,
            )
            return {"behavior": "allow", "message": message}

        elif decision == "deny":
            message = f"AI-denied (confidence: {evaluation.confidence:.2f}): {evaluation.reasoning}"
            logger.warning(f"DENIED (Tier 3): {message}")
            write_audit_log(
                tool_name,
                input,
                "deny",
                "tier3_ai_deny",
                evaluation.reasoning,
                evaluation.confidence,
            )
            return {"behavior": "deny", "message": message}

        else:  # ask_user
            # For now, deny operations that need human approval
            # TODO: Integrate with Slack/Teams for human escalation
            message = (
                f"Denied: Requires human approval. "
                f"{evaluation.reasoning} (confidence: {evaluation.confidence:.2f})"
            )
            if evaluation.suggested_message:
                message = evaluation.suggested_message

            logger.warning(f"DENIED (Tier 3 - needs human): {message}")
            write_audit_log(
                tool_name,
                input,
                "deny",
                "tier3_needs_human",
                evaluation.reasoning,
                evaluation.confidence,
            )
            return {"behavior": "deny", "message": message}

    except Exception as e:
        # If AI evaluation fails, deny by default
        message = f"Denied: AI evaluation error: {str(e)}"
        logger.error(f"DENIED (Tier 3 error): {message}")
        write_audit_log(tool_name, input, "deny", "tier3_error", str(e))
        return {"behavior": "deny", "message": message}


@mcp.tool()
async def get_approval_stats() -> dict[str, Any]:
    """
    Get statistics about approval decisions from the audit log.

    Returns summary of approvals, denials, and decision breakdown by tier.
    """
    if not enable_audit_log or not os.path.exists(audit_log_file):
        return {"error": "Audit log not available"}

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

        return stats

    except Exception as e:
        return {"error": f"Failed to read audit log: {str(e)}"}


if __name__ == "__main__":
    logger.info("Starting Claude Permission Approver MCP server...")
    logger.info(f"Audit logging: {'enabled' if enable_audit_log else 'disabled'}")
    if ai_evaluator:
        logger.info(f"AI evaluation: enabled (model: {ai_evaluator.model})")
    else:
        logger.info("AI evaluation: disabled")

    mcp.run()
