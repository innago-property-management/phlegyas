"""
Tier 2: Safe Operation Auto-Approval

Automatically approves operations in known-safe categories.
No AI evaluation needed - these are always approved.
"""

import re
from typing import Any


class SafeOperationDetector:
    """Detects safe operations that can be auto-approved."""

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
        re.compile(r"^find\s+", re.IGNORECASE),
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

        # Check read-only tools
        if tool_name in self.READ_ONLY_TOOLS:
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

    def _check_bash_command(self, command: str) -> tuple[bool, str | None]:
        """Check if bash command is in a safe category."""

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

        # Check package installation
        for pattern in self.SAFE_INSTALL_PATTERNS:
            if pattern.search(command):
                return True, "package installation"

        # Check web research
        for pattern in self.SAFE_RESEARCH_PATTERNS:
            if pattern.search(command):
                # Only safe if not using dangerous flags
                if "-X DELETE" not in command and "--delete" not in command:
                    return True, "web research"

        return False, None

    def _check_write_operation(self, file_path: str) -> tuple[bool, str | None]:
        """Check if write operation is to a safe directory."""

        # Safe directories for Task agents
        safe_dirs = [
            "/tmp/",
            "docs/research/",
            "tests/",
            "scripts/",
        ]

        # Relative paths are generally safe in project context
        if not file_path.startswith("/"):
            # But still check for sensitive files
            if any(pattern in file_path.lower() for pattern in [".env", "secrets", "credentials"]):
                return False, None
            return True, "project-relative write"

        # Check absolute paths against safe directories
        for safe_dir in safe_dirs:
            if file_path.startswith(safe_dir):
                return True, f"write to safe directory: {safe_dir}"

        return False, None

    def _check_edit_operation(self, file_path: str) -> tuple[bool, str | None]:
        """Check if edit operation is to a safe file."""

        # Similar logic to write operations
        # Generally safer since it's modifying existing files, not creating new ones

        # Sensitive files that shouldn't be auto-edited
        sensitive = [".env", "secrets", "credentials", "package-lock.json", "yarn.lock"]

        if any(pattern in file_path.lower() for pattern in sensitive):
            return False, None

        # Project files are generally safe to edit
        return True, "project file edit"
