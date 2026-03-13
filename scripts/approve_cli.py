#!/usr/bin/env python3
"""
CLI for phlegyas — evaluate tool permissions from the command line.

Calls the three-tier evaluation pipeline directly (no MCP server needed).

Usage:
    python approve_cli.py Bash "git push origin main"
    python approve_cli.py --json Bash "npm install lodash"
    python approve_cli.py --no-ai Bash "curl https://example.com"
    python approve_cli.py Edit '{"file_path": ".env", "old_string": "x", "new_string": "y"}'
"""

import argparse
import asyncio
import json
import os
import sys

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from dotenv import load_dotenv  # noqa: E402

from phlegyas.tier1_dangerous import DangerousPatternDetector  # noqa: E402
from phlegyas.tier2_safe import SafeOperationDetector  # noqa: E402
from phlegyas.tier3_ai import AIEvaluator  # noqa: E402


def build_input(tool_name: str, raw_input: str) -> dict:
    """Turn raw CLI input into the dict the evaluators expect."""
    # If it looks like JSON, parse it
    stripped = raw_input.strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

    # For Bash, wrap bare string as {"command": "..."}
    if tool_name.lower() == "bash":
        return {"command": raw_input}

    # For Write/Edit, wrap as {"file_path": "..."}
    if tool_name.lower() in ("write", "edit"):
        return {"file_path": raw_input}

    # Fallback: generic input
    return {"input": raw_input}


def evaluate_sync(tool_name: str, input_data: dict, use_ai: bool = True) -> dict:
    """Run three-tier evaluation and return structured result."""

    # --- Tier 1: Dangerous? ---
    dangerous = DangerousPatternDetector()
    is_dangerous, reason = dangerous.is_dangerous(tool_name, input_data)
    if is_dangerous:
        return {
            "decision": "deny",
            "tier": "tier1_dangerous",
            "reason": reason,
        }

    # --- Tier 2: Safe? ---
    safe = SafeOperationDetector()
    is_safe, category = safe.is_safe(tool_name, input_data)
    if is_safe:
        return {
            "decision": "allow",
            "tier": "tier2_safe",
            "reason": category,
        }

    # --- Tier 3: AI evaluation ---
    if not use_ai:
        return {
            "decision": "unknown",
            "tier": "tier3_skipped",
            "reason": "AI evaluation disabled (--no-ai)",
        }

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "decision": "unknown",
            "tier": "tier3_skipped",
            "reason": "No ANTHROPIC_API_KEY set — cannot run AI evaluation",
        }

    try:
        evaluator = AIEvaluator(
            api_key=api_key,
            model=os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001"),
        )
        decision, evaluation = asyncio.run(evaluator.evaluate(tool_name, input_data))
        return {
            "decision": decision,
            "tier": f"tier3_ai_{decision}",
            "reason": evaluation.reasoning,
            "confidence": evaluation.confidence,
            "category": evaluation.category,
        }
    except Exception as e:
        return {
            "decision": "error",
            "tier": "tier3_error",
            "reason": str(e),
        }


def print_pretty(result: dict, tool_name: str, input_data: dict) -> None:
    """Human-readable colored output."""
    decision = result["decision"]
    tier = result["tier"]
    reason = result["reason"]

    # Decision icon + color
    if decision == "allow":
        icon = "\033[32m✓ ALLOW\033[0m"
    elif decision == "deny":
        icon = "\033[31m✗ DENY\033[0m"
    elif decision == "ask_user":
        icon = "\033[33m? ASK_USER\033[0m"
    else:
        icon = "\033[33m~ UNKNOWN\033[0m"

    # Tier label
    tier_labels = {
        "tier1_dangerous": "\033[31mTier 1 (Dangerous)\033[0m",
        "tier2_safe": "\033[32mTier 2 (Safe)\033[0m",
        "tier3_ai_allow": "\033[36mTier 3 (AI → Allow)\033[0m",
        "tier3_ai_deny": "\033[36mTier 3 (AI → Deny)\033[0m",
        "tier3_ai_ask_user": "\033[36mTier 3 (AI → Ask)\033[0m",
        "tier3_skipped": "\033[33mTier 3 (Skipped)\033[0m",
        "tier3_error": "\033[31mTier 3 (Error)\033[0m",
    }
    tier_display = tier_labels.get(tier, tier)

    print(f"  {icon}  [{tier_display}]")
    print(f"  Tool:   {tool_name}")

    # Show input compactly
    if "command" in input_data:
        print(f"  Input:  {input_data['command']}")
    elif "file_path" in input_data:
        print(f"  Input:  {input_data['file_path']}")
    else:
        print(f"  Input:  {json.dumps(input_data)}")

    print(f"  Reason: {reason}")

    if "confidence" in result:
        conf = result["confidence"]
        bar_len = int(conf * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  Confidence: {conf:.0%} [{bar}]")

    # Exit code hint
    if decision == "deny":
        print("\n  Exit code: 1")


def main():
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

    parser = argparse.ArgumentParser(
        description="Evaluate tool permissions using three-tier approval pipeline",
        epilog="Examples:\n"
        '  approve Bash "git status"\n'
        '  approve Bash "rm -rf /"\n'
        '  approve --json Edit \'{"file_path": ".env"}\'\n'
        '  approve --no-ai Bash "npm install"\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("tool_name", help="Tool to evaluate (Bash, Read, Edit, Write, Glob, etc.)")
    parser.add_argument(
        "input",
        help='Command string or JSON object (e.g. "git status" or \'{"file_path": "x"}\')',
    )
    parser.add_argument("--json", action="store_true", help="Output JSON (for scripting)")
    parser.add_argument("--no-ai", action="store_true", help="Skip Tier 3 AI evaluation")

    args = parser.parse_args()

    input_data = build_input(args.tool_name, args.input)
    result = evaluate_sync(args.tool_name, input_data, use_ai=not args.no_ai)

    if args.json:
        print(json.dumps(result))
    else:
        print_pretty(result, args.tool_name, input_data)

    # Exit code: 0 = allow, 1 = deny, 2 = unknown/ask
    if result["decision"] == "allow":
        sys.exit(0)
    elif result["decision"] == "deny":
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
