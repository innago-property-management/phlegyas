"""
CLI for managing the Tier 2.5 Script Trust Store.

Usage examples:

    # Trust a script
    claude-trust /path/to/deploy.sh --note "nightly deploy"

    # List all trusted scripts
    claude-trust --list

    # Revoke trust for a script
    claude-trust --revoke /path/to/deploy.sh

    # Verify all hashes are still valid
    claude-trust --verify
"""

import argparse
import json
import sys
from pathlib import Path

from src.tier2_5_trust import ScriptTrustStore


def cmd_trust(args: argparse.Namespace, store: ScriptTrustStore) -> int:
    """Add a script to the trust store."""
    try:
        entry = store.trust(args.path, note=args.note or "")
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Trusted: {Path(args.path).resolve()}")
    print(f"  Hash:        {entry['content_hash']}")
    print(f"  Approved by: {entry['approved_by']}")
    print(f"  Approved at: {entry['approved_at']}")
    if entry["note"]:
        print(f"  Note:        {entry['note']}")
    return 0


def cmd_list(store: ScriptTrustStore) -> int:
    """List all trusted scripts."""
    entries = store.list_trusted()

    if not entries:
        print("No trusted scripts.")
        return 0

    print(f"Trusted scripts ({len(entries)}):")
    for path, entry in sorted(entries.items()):
        print(f"\n  {path}")
        print(f"    hash:        {entry['content_hash']}")
        print(f"    approved_by: {entry['approved_by']}")
        print(f"    approved_at: {entry['approved_at']}")
        if entry.get("note"):
            print(f"    note:        {entry['note']}")
    return 0


def cmd_revoke(args: argparse.Namespace, store: ScriptTrustStore) -> int:
    """Remove a script from the trust store."""
    removed = store.revoke(args.revoke)
    if removed:
        print(f"Revoked: {Path(args.revoke).resolve()}")
        return 0

    print(f"Not found in trust store: {args.revoke}", file=sys.stderr)
    return 1


def cmd_verify(store: ScriptTrustStore) -> int:
    """Verify all trusted scripts against stored hashes."""
    problems = store.verify()

    if not problems:
        entries = store.list_trusted()
        count = len(entries)
        print(f"All {count} trusted script(s) verified successfully.")
        return 0

    print(f"Found {len(problems)} problem(s):", file=sys.stderr)
    for problem in problems:
        issue = problem["issue"]
        path = problem["path"]

        if issue == "file_missing":
            print(f"  MISSING      {path}", file=sys.stderr)
        elif issue == "hash_mismatch":
            print(f"  HASH CHANGED {path}", file=sys.stderr)
            print(f"    stored:  {problem['stored_hash']}", file=sys.stderr)
            print(f"    current: {problem['current_hash']}", file=sys.stderr)
        else:
            print(f"  UNKNOWN ISSUE ({issue}) {path}", file=sys.stderr)

    return 1


def pieces_checkpoint(action: str, path: str, entry: dict[str, str] | None) -> None:
    """
    Fire-and-forget Pieces memory checkpoint on trust store changes.

    Uses Pieces OS local REST API (port 1000) directly — no MCP bridge needed.
    Best-effort: silently skips if Pieces OS isn't running.
    """
    from datetime import UTC, datetime

    if action == "trust":
        note = entry.get("note", "") if entry else ""
        text = (
            f"Script Trust Store: trusted {Path(path).name}\n"
            f"Path: {path}\n"
            f"Hash: {entry['content_hash']}\n"
            f"Note: {note or '(none)'}\n"
            f"At: {entry['approved_at']}"
        )
    else:
        text = (
            f"Script Trust Store: revoked {Path(path).name}\n"
            f"Path: {path}\n"
            f"At: {datetime.now(UTC).isoformat()}"
        )

    # Write to append-only changelog alongside trust store
    changelog_path = Path.home() / ".claude" / "trusted-scripts.log"
    try:
        with open(changelog_path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now(UTC).isoformat()}] {action}: {path}")
            if entry and entry.get("content_hash"):
                f.write(f" ({entry['content_hash'][:20]}...)")
            if entry and entry.get("note"):
                f.write(f" — {entry['note']}")
            f.write("\n")
    except OSError:
        pass

    # Best-effort Pieces OS checkpoint via local REST API
    try:
        import urllib.request

        payload = json.dumps({
            "application": {"id": "claude-permission-approver"},
            "text": text,
        }).encode()
        req = urllib.request.Request(
            "http://localhost:1000/assets/create",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass  # Pieces OS not running — changelog is the durable record


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="claude-trust",
        description="Manage the Tier 2.5 Script Trust Store for claude-permission-approver.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  Trust a script:
    claude-trust /path/to/deploy.sh --note "nightly deploy script"

  List all trusted scripts:
    claude-trust --list

  Revoke trust:
    claude-trust --revoke /path/to/deploy.sh

  Verify all hashes:
    claude-trust --verify
        """,
    )

    # Positional argument for the trust action
    parser.add_argument(
        "path",
        nargs="?",
        metavar="SCRIPT_PATH",
        help="Path to the script to trust (omit when using --list, --revoke, --verify)",
    )
    parser.add_argument(
        "--note",
        metavar="TEXT",
        default="",
        help="Optional description for why this script is trusted",
    )

    # Action flags
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "--list",
        action="store_true",
        help="List all trusted scripts",
    )
    action_group.add_argument(
        "--revoke",
        metavar="SCRIPT_PATH",
        help="Revoke trust for the given script",
    )
    action_group.add_argument(
        "--verify",
        action="store_true",
        help="Verify all trusted scripts against stored hashes",
    )

    # Optional store path override (useful for testing)
    parser.add_argument(
        "--store",
        metavar="PATH",
        default=None,
        help="Path to trust store JSON file (default: ~/.claude/trusted-scripts.json)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the claude-trust CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    store_path = Path(args.store) if args.store else None
    store = ScriptTrustStore(store_path=store_path, on_change=pieces_checkpoint)

    if args.list:
        return cmd_list(store)

    if args.revoke:
        return cmd_revoke(args, store)

    if args.verify:
        return cmd_verify(store)

    if args.path:
        return cmd_trust(args, store)

    # No action specified
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
