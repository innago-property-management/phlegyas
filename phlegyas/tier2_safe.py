"""
Tier 2: Safe Operation Auto-Approval

Automatically approves operations in known-safe categories.
No AI evaluation needed - these are always approved.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default store location - matches the ~/.claude/ convention
DEFAULT_SAFE_PATTERNS_PATH = Path.home() / ".claude" / "safe-patterns.json"

# Valid regex flag names accepted in safe-patterns.json "flags" arrays
_VALID_RE_FLAGS = frozenset(
    {
        "IGNORECASE",
        "MULTILINE",
        "DOTALL",
        "VERBOSE",
        "ASCII",
        "UNICODE",
    }
)


class SafePatternStore:
    """
    Loads user-configurable safe patterns from ~/.claude/safe-patterns.json.

    JSON schema (version 1):
    {
        "version": 1,
        "patterns": {
            "safe_bash": [{"regex": "...", "category": "...", "description": "...", "flags": ["IGNORECASE"]}],
            "safe_tools": ["ToolName"],
            "safe_write_dirs": ["/path/"],
            "sensitive_files": ["pattern"]
        }
    }
    """

    def __init__(self, store_path: Path | None = None) -> None:
        self._path = Path(store_path) if store_path is not None else DEFAULT_SAFE_PATTERNS_PATH
        self.bash_patterns: list[tuple[re.Pattern, str]] = []
        self.tool_names: set[str] = set()
        self.write_dirs: list[str] = []
        self.sensitive_files: list[str] = []
        self._load()

    def _load(self) -> None:
        """Load and validate the safe-patterns.json file."""
        if not self._path.exists():
            return

        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(f"Could not read safe-patterns store at {self._path}: {exc}")
            return

        if not isinstance(data, dict) or data.get("version") != 1:
            logger.warning(f"Invalid safe-patterns schema at {self._path}: expected version 1")
            return

        patterns = data.get("patterns", {})
        if not isinstance(patterns, dict):
            return

        # Load bash patterns
        for entry in patterns.get("safe_bash", []):
            if not isinstance(entry, dict) or "regex" not in entry:
                continue
            try:
                flags = 0
                for flag_name in entry.get("flags", []):
                    if flag_name not in _VALID_RE_FLAGS:
                        logger.warning(
                            f"Skipping unrecognized regex flag in safe-patterns: {flag_name!r}"
                        )
                        continue
                    flags |= getattr(re, flag_name)
                compiled = re.compile(entry["regex"], flags)
                category = entry.get("category", "user-defined")
                self.bash_patterns.append((compiled, category))
            except (re.error, TypeError) as exc:
                logger.warning(
                    f"Skipping invalid regex in safe-patterns: {entry['regex']!r}: {exc}"
                )

        # Load tool names
        for tool in patterns.get("safe_tools", []):
            if isinstance(tool, str):
                self.tool_names.add(tool)

        # Load write dirs
        for d in patterns.get("safe_write_dirs", []):
            if isinstance(d, str):
                self.write_dirs.append(d)

        # Load sensitive files
        for f in patterns.get("sensitive_files", []):
            if isinstance(f, str):
                self.sensitive_files.append(f)


class SafeOperationDetector:
    """Detects safe operations that can be auto-approved."""

    def __init__(self, user_store: SafePatternStore | None = None) -> None:
        self._user_store = user_store
        # Merge user patterns on top of builtins (augment, never replace)
        self._merged_read_only_tools = set(self.READ_ONLY_TOOLS)
        self._merged_safe_write_dirs = list(self._BUILTIN_SAFE_WRITE_DIRS)
        self._merged_sensitive_files = list(self._BUILTIN_SENSITIVE_FILES)
        self._user_bash_patterns: list[tuple[re.Pattern, str]] = []

        if user_store:
            self._merged_read_only_tools |= user_store.tool_names
            self._merged_safe_write_dirs.extend(user_store.write_dirs)
            self._merged_sensitive_files.extend(user_store.sensitive_files)
            self._user_bash_patterns = list(user_store.bash_patterns)

    # Git operations that are read-only or safe
    SAFE_GIT_PATTERNS = [
        re.compile(r"^git\s+status", re.IGNORECASE),
        re.compile(r"^git\s+log", re.IGNORECASE),
        re.compile(r"^git\s+diff", re.IGNORECASE),
        re.compile(r"^git\s+branch(\s+-[av])?$", re.IGNORECASE),
        re.compile(r"^git\s+show", re.IGNORECASE),
        re.compile(r"^git\s+checkout\s+-b\s+feature/", re.IGNORECASE),
        re.compile(r"^git\s+checkout\s+-b\s+fix/", re.IGNORECASE),
        re.compile(r"^git\s+checkout\s+-b\s+feat/", re.IGNORECASE),
        re.compile(r"^git\s+add", re.IGNORECASE),
        re.compile(r"^git\s+commit", re.IGNORECASE),
        re.compile(r"^git\s+stash", re.IGNORECASE),
        re.compile(r"^git\s+fetch", re.IGNORECASE),
        re.compile(r"^git\s+pull\s+origin\s+(?!main|master)", re.IGNORECASE),
    ]

    # Test commands (always safe)
    SAFE_TEST_PATTERNS = [
        re.compile(r"^npm\s+test", re.IGNORECASE),
        re.compile(r"^npm\s+run\s+test", re.IGNORECASE),
        re.compile(r"^yarn\s+test", re.IGNORECASE),
        re.compile(r"^pnpm\s+test", re.IGNORECASE),
        re.compile(r"^dotnet\s+test", re.IGNORECASE),
        re.compile(r"^pytest", re.IGNORECASE),
        re.compile(r"^python\s+-m\s+pytest", re.IGNORECASE),
        re.compile(r"^cargo\s+test", re.IGNORECASE),
        re.compile(r"^go\s+test", re.IGNORECASE),
        re.compile(r"^mvn\s+test", re.IGNORECASE),
        re.compile(r"^gradle\s+test", re.IGNORECASE),
    ]

    # Linting and formatting (always safe)
    SAFE_LINT_PATTERNS = [
        re.compile(r"^npm\s+run\s+lint", re.IGNORECASE),
        re.compile(r"^eslint", re.IGNORECASE),
        re.compile(r"^dotnet\s+format", re.IGNORECASE),
        re.compile(r"^black\s+", re.IGNORECASE),
        re.compile(r"^ruff\s+", re.IGNORECASE),
        re.compile(r"^prettier\s+", re.IGNORECASE),
        re.compile(r"^rustfmt\s+", re.IGNORECASE),
    ]

    # Build commands (safe, no side effects)
    SAFE_BUILD_PATTERNS = [
        re.compile(r"^npm\s+(run\s+)?build", re.IGNORECASE),
        re.compile(r"^yarn\s+build", re.IGNORECASE),
        re.compile(r"^pnpm\s+build", re.IGNORECASE),
        re.compile(r"^dotnet\s+build", re.IGNORECASE),
        re.compile(r"^cargo\s+build", re.IGNORECASE),
        re.compile(r"^go\s+build", re.IGNORECASE),
        re.compile(r"^mvn\s+compile", re.IGNORECASE),
        re.compile(r"^gradle\s+build", re.IGNORECASE),
    ]

    # Info/list commands (read-only)
    SAFE_INFO_PATTERNS = [
        re.compile(r"^ls(\s+|$)", re.IGNORECASE),
        re.compile(r"^pwd$", re.IGNORECASE),
        re.compile(r"^echo\s+", re.IGNORECASE),
        re.compile(r"^cat\s+", re.IGNORECASE),
        re.compile(r"^head\s+", re.IGNORECASE),
        re.compile(r"^tail\s+", re.IGNORECASE),
        re.compile(r"^grep\s+", re.IGNORECASE),
        # find removed from auto-approve — dangerous variants (find -exec) fall through to Tier 3
        re.compile(r"^tree\s+", re.IGNORECASE),
        re.compile(r"^ps\s+", re.IGNORECASE),
        re.compile(r"^env$", re.IGNORECASE),
        re.compile(r"^printenv", re.IGNORECASE),
        re.compile(r"^which\s+", re.IGNORECASE),
        re.compile(r"^whereis\s+", re.IGNORECASE),
        re.compile(r"^file\s+", re.IGNORECASE),
        re.compile(r"^stat\s+", re.IGNORECASE),
        re.compile(r"^wc\s+", re.IGNORECASE),
        re.compile(r"^diff\s+", re.IGNORECASE),
        re.compile(r"^icalBuddy\s+", re.IGNORECASE),
        re.compile(r"^remindctl\s+", re.IGNORECASE),
        re.compile(r"^uname(\s+|$)", re.IGNORECASE),
        re.compile(r"^hostname$", re.IGNORECASE),
        re.compile(r"^whoami$", re.IGNORECASE),
        re.compile(r"^id(\s+|$)", re.IGNORECASE),
        re.compile(r"^date(\s+|$)", re.IGNORECASE),
        re.compile(r"^uptime$", re.IGNORECASE),
        re.compile(r"^df(\s+|$)", re.IGNORECASE),
        re.compile(r"^du\s+", re.IGNORECASE),
        re.compile(r"^free(\s+|$)", re.IGNORECASE),
        re.compile(r"^top\s+-[bl]", re.IGNORECASE),
        re.compile(r"^pip\s+list", re.IGNORECASE),
        re.compile(r"^pip\s+show\s+", re.IGNORECASE),
        re.compile(r"^pip\s+freeze", re.IGNORECASE),
        re.compile(r"^npm\s+list", re.IGNORECASE),
        re.compile(r"^npm\s+ls", re.IGNORECASE),
        re.compile(r"^npm\s+outdated", re.IGNORECASE),
        re.compile(r"^dotnet\s+--list-(sdks|runtimes)", re.IGNORECASE),
        re.compile(r"^dotnet\s+--version", re.IGNORECASE),
        re.compile(r"^dotnet\s+--info", re.IGNORECASE),
        re.compile(r"^python3?\s+--version", re.IGNORECASE),
        re.compile(r"^node\s+--version", re.IGNORECASE),
        re.compile(r"^ruby\s+--version", re.IGNORECASE),
        re.compile(r"^java\s+--version", re.IGNORECASE),
        re.compile(r"^sw_vers", re.IGNORECASE),
        re.compile(r"^xcodebuild\s+-version", re.IGNORECASE),
        re.compile(r"^brew\s+(list|info|search|outdated)", re.IGNORECASE),
        re.compile(r"^gh\s+(pr|issue|run|repo)\s+(list|view|status|checks)", re.IGNORECASE),
        re.compile(
            r"^gh\s+api\s+(?!.*(-X\s+(POST|PUT|PATCH|DELETE)|--method\s+(POST|PUT|PATCH|DELETE)))",
            re.IGNORECASE,
        ),
        re.compile(r"^jq\s+", re.IGNORECASE),
        re.compile(r"^sort(\s+|$)", re.IGNORECASE),
        re.compile(r"^uniq(\s+|$)", re.IGNORECASE),
        re.compile(r"^cut\s+", re.IGNORECASE),
        re.compile(r"^awk\s+", re.IGNORECASE),
        re.compile(r"^sed\s+-n\s+(?!.*-i)", re.IGNORECASE),
        re.compile(r"^basename\s+", re.IGNORECASE),
        re.compile(r"^dirname\s+", re.IGNORECASE),
        re.compile(r"^realpath\s+", re.IGNORECASE),
        re.compile(r"^readlink\s+", re.IGNORECASE),
        re.compile(r"^md5(sum)?\s+", re.IGNORECASE),
        re.compile(r"^sha256sum\s+", re.IGNORECASE),
        re.compile(r"^shasum\s+", re.IGNORECASE),
        # Shell builtins and misc
        re.compile(r"^(true|false|:)\s*$", re.IGNORECASE),
        re.compile(r"^sleep\s+", re.IGNORECASE),
        re.compile(r"^test\s+", re.IGNORECASE),
        re.compile(r"^\[", re.IGNORECASE),
        re.compile(r"^type\s+", re.IGNORECASE),
        re.compile(r"^command\s+-v\s+", re.IGNORECASE),
        re.compile(r"^export\s+", re.IGNORECASE),
        # macOS utilities
        re.compile(r"^say\s+", re.IGNORECASE),
        re.compile(r"^open\s+", re.IGNORECASE),
        re.compile(r"^pbcopy", re.IGNORECASE),
        re.compile(r"^pbpaste", re.IGNORECASE),
        # VibeTunnel
        re.compile(r"^vt\s+", re.IGNORECASE),
        # Process management (read-only)
        re.compile(r"^lsof\s+", re.IGNORECASE),
        re.compile(r"^pgrep\s+", re.IGNORECASE),
    ]

    # Filesystem operations (non-destructive, no data exfiltration risk)
    # NOTE: cp and mv deliberately excluded — can exfiltrate .env, credentials
    SAFE_FILESYSTEM_PATTERNS = [
        re.compile(r"^mkdir\s+", re.IGNORECASE),
        re.compile(r"^touch\s+", re.IGNORECASE),
        re.compile(r"^chmod\s+", re.IGNORECASE),
        re.compile(r"^ln\s+", re.IGNORECASE),
    ]

    # Package installation (generally safe in dev environments)
    SAFE_INSTALL_PATTERNS = [
        re.compile(r"^npm\s+install", re.IGNORECASE),
        re.compile(r"^yarn\s+(add|install)", re.IGNORECASE),
        re.compile(r"^pnpm\s+install", re.IGNORECASE),
        re.compile(r"^pip\s+install", re.IGNORECASE),
        re.compile(r"^dotnet\s+restore", re.IGNORECASE),
        re.compile(r"^cargo\s+build", re.IGNORECASE),  # Rust build includes deps
    ]

    # Web research tools (for Task agents doing research)
    SAFE_RESEARCH_PATTERNS = [
        re.compile(r"^curl\s+", re.IGNORECASE),
        re.compile(r"^wget\s+", re.IGNORECASE),
    ]

    # Dangerous curl/wget flags that bypass safe research auto-approve
    DANGEROUS_CURL_WGET = re.compile(
        r"-X\s*(DELETE|POST|PUT|PATCH)\b|--data\b|-d\s|-F\s|--upload-file\b|--form\b|--delete\b",
        re.IGNORECASE,
    )

    # Built-in safe write directories
    _BUILTIN_SAFE_WRITE_DIRS = [
        "/tmp/",
        "docs/research/",
        "tests/",
        "scripts/",
    ]

    # Built-in sensitive file patterns
    _BUILTIN_SENSITIVE_FILES = [".env", "secrets", "credentials", "package-lock.json", "yarn.lock"]

    # Read-only tool names (always safe)
    READ_ONLY_TOOLS = {
        "Read",
        "Glob",
        "Grep",
        "WebFetch",
        "WebSearch",
        "mcp__firecrawl__firecrawl_search",
        "mcp__firecrawl__firecrawl_map",
        "mcp__jetbrains__get_file_text_by_path",
        "mcp__jetbrains__find_files_by_name_keyword",
        "mcp__jetbrains__search_in_files_by_text",
        "mcp__jetbrains__find_files_by_glob",
        "mcp__jetbrains__list_directory_tree",
        "mcp__jetbrains__get_all_open_file_paths",
    }

    def is_safe(self, tool_name: str, input_data: dict[str, Any]) -> tuple[bool, str | None]:
        """
        Check if an operation is in a known-safe category.

        Args:
            tool_name: The tool being used (e.g., "Bash", "Read", "WebFetch")
            input_data: The parameters for the tool

        Returns:
            Tuple of (is_safe, category)
            - is_safe: True if operation can be auto-approved
            - category: Description of safe category (or None if not safe)
        """

        # Check read-only tools (builtin + user-defined)
        if tool_name in self._merged_read_only_tools:
            return True, f"read-only tool: {tool_name}"

        # Check Firecrawl scraping (safe for research)
        if tool_name == "mcp__firecrawl__firecrawl_scrape":
            return True, "web research: Firecrawl scrape"

        if tool_name == "mcp__firecrawl__firecrawl_extract":
            return True, "web research: Firecrawl extract"

        # Check Bash commands
        if tool_name == "Bash":
            command = input_data.get("command", "")
            return self._check_bash_command(command)

        # Check Write operations to specific directories
        if tool_name == "Write":
            file_path = input_data.get("file_path", "")
            return self._check_write_operation(file_path)

        # Check Edit operations
        if tool_name == "Edit":
            file_path = input_data.get("file_path", "")
            return self._check_edit_operation(file_path)

        return False, None

    # Prefixes that are safe setup boilerplate and can be stripped for matching
    _SAFE_PREFIXES = re.compile(
        r"^(?:source\s+\.?\.?/?\.?venv/bin/activate\s*&&\s*|cd\s+\S+\s*&&\s*)+",
        re.IGNORECASE,
    )

    def _check_bash_command(self, command: str) -> tuple[bool, str | None]:
        """Check if bash command is in a safe category."""

        # Strip safe prefixes (venv activation, cd) before pattern matching
        command = self._SAFE_PREFIXES.sub("", command).strip()

        # Check git operations
        for pattern in self.SAFE_GIT_PATTERNS:
            if pattern.search(command):
                return True, "safe git operation"

        # Check test commands
        for pattern in self.SAFE_TEST_PATTERNS:
            if pattern.search(command):
                return True, "test command"

        # Check linting/formatting
        for pattern in self.SAFE_LINT_PATTERNS:
            if pattern.search(command):
                return True, "linting/formatting"

        # Check build commands
        for pattern in self.SAFE_BUILD_PATTERNS:
            if pattern.search(command):
                return True, "build command"

        # Check info/list commands
        for pattern in self.SAFE_INFO_PATTERNS:
            if pattern.search(command):
                return True, "read-only info command"

        # Check filesystem operations (mkdir, touch, chmod, ln — NOT cp/mv)
        for pattern in self.SAFE_FILESYSTEM_PATTERNS:
            if pattern.search(command):
                return True, "safe filesystem operation"

        # Check package installation
        for pattern in self.SAFE_INSTALL_PATTERNS:
            if pattern.search(command):
                return True, "package installation"

        # Check web research
        for pattern in self.SAFE_RESEARCH_PATTERNS:
            if pattern.search(command):
                # Only safe if not using dangerous flags
                if not self.DANGEROUS_CURL_WGET.search(command):
                    return True, "web research"

        # Check user-defined bash patterns
        for compiled, category in self._user_bash_patterns:
            if compiled.search(command):
                return True, category

        return False, None

    def _check_write_operation(self, file_path: str) -> tuple[bool, str | None]:
        """Check if write operation is to a safe directory."""

        # Relative paths are generally safe in project context
        if not file_path.startswith("/"):
            # Check against full merged sensitive list (builtins + user-defined)
            if any(pattern in file_path.lower() for pattern in self._merged_sensitive_files):
                return False, None
            return True, "project-relative write"

        # Check absolute paths against safe directories (builtin + user-defined)
        for safe_dir in self._merged_safe_write_dirs:
            if file_path.startswith(safe_dir):
                return True, f"write to safe directory: {safe_dir}"

        return False, None

    def _check_edit_operation(self, file_path: str) -> tuple[bool, str | None]:
        """Check if edit operation is to a safe file."""

        # Sensitive files that shouldn't be auto-edited (builtin + user-defined)
        if any(pattern in file_path.lower() for pattern in self._merged_sensitive_files):
            return False, None

        # Project files are generally safe to edit
        return True, "project file edit"
