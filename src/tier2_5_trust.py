"""
Tier 2.5: Script Trust Store (TOFU - Trust On First Use)

Provides content-hash-based trust for shell scripts that fall through Tier 2
but shouldn't require AI evaluation on every run. A human explicitly trusts a
script once; subsequent executions are approved automatically as long as the
file content hasn't changed.

Store format (~/.claude/trusted-scripts.json):
{
    "/abs/path/to/script.sh": {
        "content_hash": "sha256:<hex>",
        "approved_by": "human",
        "approved_at": "ISO8601",
        "note": "optional description"
    }
}

Security notes:
- Trust store is a HUMAN-CURATED allowlist, NOT a security boundary.
- Tier 1 dangerous-pattern checks run BEFORE Tier 2.5 and cannot be bypassed.
- File permissions (0600) limit read access on multi-user systems.
- Content hashing protects against accidental script modification slipping
  through unnoticed; it is NOT a cryptographic guarantee.
"""

import hashlib
import json
import logging
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Callback type for trust store mutations: (action, path, entry_or_none)
OnChangeCallback = Callable[[str, str, dict[str, str] | None], None]

# Default store location - matches the ~/.claude/ convention used by Claude Code
DEFAULT_STORE_PATH = Path.home() / ".claude" / "trusted-scripts.json"

# Patterns that indicate a shell script execution
# Order matters: more-specific patterns checked first
_BASH_SH_PREFIX = re.compile(
    r"^(?:bash|sh)\s+(?:-c\s+)?([^\s;|&]+\.sh)\b",
    re.IGNORECASE,
)
_DIRECT_EXECUTION = re.compile(
    r"^(\./[^\s;|&]+\.sh|/[^\s;|&]+\.sh)\b",
    re.IGNORECASE,
)


class ScriptTrustStore:
    """
    Manages a persistent allowlist of trusted shell scripts keyed by absolute path.

    Each entry stores a SHA-256 content hash computed at trust-time.  Before
    approving a script execution, the current file hash is compared against the
    stored hash; any mismatch causes the decision to fall through to Tier 3.
    """

    def __init__(
        self,
        store_path: Path | None = None,
        on_change: OnChangeCallback | None = None,
    ) -> None:
        self._path = Path(store_path) if store_path is not None else DEFAULT_STORE_PATH
        self._data: dict[str, dict[str, str]] = {}
        self._on_change = on_change
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_trusted(self, tool_name: str, input_data: dict[str, Any]) -> tuple[bool, str | None]:
        """
        Check whether a Bash command executes a trusted, unmodified script.

        Args:
            tool_name: The tool being evaluated (only "Bash" is relevant here).
            input_data: Tool input parameters; "command" key is used for Bash.

        Returns:
            Tuple of (is_trusted, category_or_reason).
            - (True, "trusted_script") if the script is trusted and hash matches.
            - (False, "hash_mismatch:<path>") if content changed since trusting.
            - (False, "file_missing:<path>") if the trusted file no longer exists.
            - (False, None) if the command is not a script execution or not in store.
        """
        if tool_name != "Bash":
            return False, None

        command = input_data.get("command", "")
        script_path = self._extract_script_path(command)

        if script_path is None:
            return False, None

        # Resolve relative paths relative to cwd for lookup
        resolved = str(Path(script_path).resolve()) if not script_path.startswith("/") else script_path

        # Try both the raw path and the resolved path
        entry = self._data.get(script_path) or self._data.get(resolved)
        if entry is None:
            return False, None

        # Check file existence
        lookup_path = script_path if script_path in self._data else resolved
        if not Path(lookup_path).exists():
            logger.warning(f"Trusted script no longer exists: {lookup_path}")
            return False, f"file_missing:{lookup_path}"

        # Verify content hash
        current_hash = self._compute_hash(lookup_path)
        stored_hash = entry["content_hash"]

        if current_hash != stored_hash:
            logger.warning(
                f"Hash mismatch for trusted script {lookup_path}: "
                f"stored={stored_hash[:20]}... current={current_hash[:20]}..."
            )
            return False, f"hash_mismatch:{lookup_path}"

        logger.info(f"Approved (Tier 2.5): trusted script {lookup_path}")
        return True, "trusted_script"

    def trust(self, path: str, note: str = "") -> dict[str, str]:
        """
        Add a script to the trust store.

        Computes the SHA-256 hash of the current file contents and records it
        along with metadata.  Persists the updated store to disk immediately.

        Args:
            path: Absolute or relative path to the script file.
            note: Optional human-readable description of why the script is trusted.

        Returns:
            The newly created trust entry dict.

        Raises:
            FileNotFoundError: If the script file does not exist.
        """
        resolved = str(Path(path).resolve())

        if not Path(resolved).exists():
            raise FileNotFoundError(f"Script not found: {resolved}")

        content_hash = self._compute_hash(resolved)
        entry: dict[str, str] = {
            "content_hash": content_hash,
            "approved_by": "human",
            "approved_at": datetime.now(UTC).isoformat(),
            "note": note,
        }
        self._data[resolved] = entry
        self._save()

        logger.info(f"Trusted script added: {resolved} ({content_hash[:20]}...)")
        if self._on_change:
            self._on_change("trust", resolved, entry)
        return entry

    def revoke(self, path: str) -> bool:
        """
        Remove a script from the trust store.

        Args:
            path: Path to the script (will be resolved to absolute form).

        Returns:
            True if the entry existed and was removed, False if not found.
        """
        resolved = str(Path(path).resolve())

        # Try resolved path first, then raw
        if resolved in self._data:
            del self._data[resolved]
            self._save()
            logger.info(f"Trusted script revoked: {resolved}")
            if self._on_change:
                self._on_change("revoke", resolved, None)
            return True

        if path in self._data:
            del self._data[path]
            self._save()
            logger.info(f"Trusted script revoked: {path}")
            if self._on_change:
                self._on_change("revoke", path, None)
            return True

        return False

    def list_trusted(self) -> dict[str, dict[str, str]]:
        """
        Return a copy of all trust store entries.

        Returns:
            Dict mapping script paths to their metadata entries.
        """
        return dict(self._data)

    def verify(self) -> list[dict[str, str]]:
        """
        Check all trusted scripts against their stored hashes.

        Returns:
            List of dicts describing problems found.  Each dict has:
            - "path": the script path
            - "issue": "file_missing" or "hash_mismatch"
            - "stored_hash": the hash recorded at trust time (hash_mismatch only)
            - "current_hash": the hash computed now (hash_mismatch only)

        Empty list means everything is consistent.
        """
        problems: list[dict[str, str]] = []

        for path, entry in self._data.items():
            if not Path(path).exists():
                problems.append({"path": path, "issue": "file_missing"})
                continue

            current_hash = self._compute_hash(path)
            stored_hash = entry["content_hash"]

            if current_hash != stored_hash:
                problems.append(
                    {
                        "path": path,
                        "issue": "hash_mismatch",
                        "stored_hash": stored_hash,
                        "current_hash": current_hash,
                    }
                )

        return problems

    # ------------------------------------------------------------------
    # Script path extraction
    # ------------------------------------------------------------------

    def _extract_script_path(self, command: str) -> str | None:
        """
        Extract the script path from a shell command string.

        Recognises:
        - ``/absolute/path/to/script.sh``
        - ``./relative/script.sh``
        - ``bash /path/to/script.sh``
        - ``bash ./script.sh``
        - ``sh /path/to/script.sh``
        - ``sh -c /path/to/script.sh``

        Returns None for commands that are not shell script executions.
        """
        command = command.strip()

        # bash/sh prefix patterns
        m = _BASH_SH_PREFIX.match(command)
        if m:
            return m.group(1)

        # Direct execution: /abs/path.sh or ./rel/path.sh
        m = _DIRECT_EXECUTION.match(command)
        if m:
            return m.group(1)

        return None

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    def _compute_hash(self, path: str) -> str:
        """
        Compute SHA-256 hash of a file's contents.

        Returns:
            String in the form "sha256:<hexdigest>".
        """
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        return f"sha256:{digest}"

    def _load(self) -> None:
        """Load trust store from disk, initialising empty if not present."""
        if not self._path.exists():
            self._data = {}
            return

        try:
            self._data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(f"Could not read trust store at {self._path}: {exc}")
            self._data = {}

    def _save(self) -> None:
        """Persist trust store to disk with 0600 permissions."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        serialised = json.dumps(self._data, indent=2, ensure_ascii=False)
        self._path.write_text(serialised, encoding="utf-8")
        # Restrict permissions to owner read/write only
        os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)
