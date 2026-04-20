"""
Tier 1: Dangerous Pattern Detection

Immediately denies operations that match known dangerous patterns.
No AI evaluation needed - these are always blocked.
"""

import re
from typing import Any


class DangerousPatternDetector:
    """Detects dangerous operations that should always be denied."""

    # Regex for stripping known wrapper prefixes before pattern matching.
    # Matches: env, command, nice, nohup, timeout <digits>, sudo
    _PREFIX_RE = re.compile(
        r"^(?:env|command|nice|nohup|timeout\s+\d+[smhd]?|sudo)\s+", re.IGNORECASE
    )

    DESTRUCTIVE_PATTERNS = [
        re.compile(r"rm\s+-rf", re.IGNORECASE),
        re.compile(r"DROP\s+(TABLE|DATABASE)", re.IGNORECASE),
        re.compile(r"DELETE\s+FROM.*WHERE", re.IGNORECASE),
        re.compile(r"TRUNCATE\s+TABLE", re.IGNORECASE),
        re.compile(r"format\s+[cC]:", re.IGNORECASE),  # Windows format drive
        re.compile(r"mkfs\.", re.IGNORECASE),  # Linux format filesystem
        re.compile(r"find\s+.*-delete", re.IGNORECASE),  # find -delete
        re.compile(r"find\s+.*-exec\s+rm", re.IGNORECASE),  # find -exec rm
        re.compile(r"python\d*(?:\.\d+)?\s+-c\s+.*(?:rmtree|unlink|remove)", re.IGNORECASE),
        re.compile(
            r"perl\s+-e\s+.*(?:rmtree|unlink|remove)", re.IGNORECASE
        ),  # perl destructive ops
        re.compile(
            r"xargs\s+(?:-\S+\s+)*rm\b", re.IGNORECASE
        ),  # xargs rm (only flag-shaped -tokens before rm, handles -I{} -J% forms)
    ]

    OBFUSCATION_PATTERNS = [
        re.compile(r"eval\s+\$\(", re.IGNORECASE),  # eval $(...)
        re.compile(r'eval\s+"\$\(', re.IGNORECASE),  # eval "$(..." — blocks all subshell evals
        re.compile(r"eval\s+'", re.IGNORECASE),  # eval '...'
        re.compile(r"base64\s+(-d|--decode).*\|\s*(bash|sh|zsh)", re.IGNORECASE),
        re.compile(r"echo\s+-e\s+.*\|\s*(bash|sh|zsh)", re.IGNORECASE),
        re.compile(r"printf\s+.*\|\s*(bash|sh|zsh)", re.IGNORECASE),
    ]

    DANGEROUS_INFRA_PATTERNS = [
        re.compile(r"terraform\s+destroy", re.IGNORECASE),
        re.compile(
            r"terraform\s+apply\s+.*-destroy", re.IGNORECASE
        ),  # terraform apply --destroy / -destroy
        re.compile(
            r"kubectl\s+delete\s+(namespace|ns|deployment|service|pod|secret|configmap|daemonset|ingress)\b",
            re.IGNORECASE,
        ),
        # pv/pvc/statefulset excluded from instant-deny — agents in argocd repo
        # legitimately delete PVCs and scale statefulsets to zero.
        # These fall through to Tier 3 → human approval via confidence cap.
        re.compile(
            r"kubectl\s+delete\s+(-f\s|--filename[=\s])", re.IGNORECASE
        ),  # kubectl delete -f <file>
        re.compile(r"aws\s+s3\s+rb\s+.*--force", re.IGNORECASE),
        re.compile(r"aws\s+s3\s+rm\s+.*--recursive", re.IGNORECASE),  # aws s3 rm --recursive
        re.compile(r"aws\s+.*--no-dry-run", re.IGNORECASE),  # EC2 APIs only; defense-in-depth
        re.compile(r"helm\s+(uninstall|delete)\s+", re.IGNORECASE),  # helm uninstall / helm delete
    ]

    # PRODUCTION_PATTERNS use negative lookbehinds to avoid matching "nonprod"
    # variants (nonprod, non-prod, non_prod, nonproduction). Lookbehinds apply
    # only to the production token itself — other occurrences in the command
    # (e.g. flag values) cannot mask a production-named target.
    PRODUCTION_PATTERNS = [
        re.compile(r"(?<!non)(?<!non-)(?<!non_)production", re.IGNORECASE),
        re.compile(r"(?<!non)(?<!non-)(?<!non_)prod[-_]", re.IGNORECASE),
        re.compile(r"--env=(?<!non)(?<!non-)(?<!non_)prod", re.IGNORECASE),
        re.compile(r"master(?:_|\b)", re.IGNORECASE),  # Master database/branch operations
        re.compile(r"main(?:_|\b)", re.IGNORECASE),  # Main branch operations
    ]

    CREDENTIAL_PATTERNS = [
        re.compile(r"password\s*=", re.IGNORECASE),
        re.compile(r"secret\s*=", re.IGNORECASE),
        re.compile(r"api[_-]?key", re.IGNORECASE),
        re.compile(r"AWS_SECRET", re.IGNORECASE),
        re.compile(r"ANTHROPIC_API_KEY", re.IGNORECASE),
        re.compile(r"Bearer\s+", re.IGNORECASE),
    ]

    DANGEROUS_GIT_PATTERNS = [
        re.compile(r"git\s+push\s+--force", re.IGNORECASE),
        re.compile(r"git\s+push\s+-f", re.IGNORECASE),
        re.compile(r"git\s+reset\s+--hard", re.IGNORECASE),
        re.compile(r"git\s+clean\s+-[fF]d", re.IGNORECASE),
        re.compile(r"git\s+push.*origin\s+(main|master)", re.IGNORECASE),
    ]

    NETWORK_PATTERNS = [
        re.compile(r"curl.*-X\s+DELETE", re.IGNORECASE),
        re.compile(r"wget.*--delete-after", re.IGNORECASE),
    ]

    def is_dangerous(self, tool_name: str, input_data: dict[str, Any]) -> tuple[bool, str | None]:
        """
        Check if an operation matches dangerous patterns.

        Args:
            tool_name: The tool being used (e.g., "Bash", "Edit", "Write")
            input_data: The parameters for the tool

        Returns:
            Tuple of (is_dangerous, reason)
            - is_dangerous: True if operation should be blocked
            - reason: Explanation of why it's dangerous (or None if safe)
        """
        if tool_name == "Bash":
            command = input_data.get("command", "")
            return self._check_bash_command(command)

        if tool_name == "Edit":
            # Check if editing sensitive files
            file_path = input_data.get("file_path", "")
            new_string = input_data.get("new_string", "")

            if self._is_sensitive_file(file_path):
                if self._contains_credentials(new_string):
                    return True, "Blocked: Attempting to add credentials to tracked file"

        if tool_name == "Write":
            file_path = input_data.get("file_path", "")
            content = input_data.get("content", "")

            if self._is_sensitive_file(file_path):
                if self._contains_credentials(content):
                    return True, "Blocked: Attempting to write credentials to tracked file"

        return False, None

    def _strip_command_prefix(self, command: str) -> str:
        """Strip known wrapper prefixes (env, sudo, nice, etc.) iteratively.

        Handles chained prefixes like 'sudo env rm -rf /'.
        """
        stripped = command.strip()
        while True:
            match = self._PREFIX_RE.match(stripped)
            if not match:
                break
            stripped = stripped[match.end() :]
        return stripped

    def _check_bash_command(self, command: str) -> tuple[bool, str | None]:
        """Check if bash command matches dangerous patterns."""
        if command is None:
            return False, None

        # Strip wrapper prefixes so patterns match the underlying command
        stripped = self._strip_command_prefix(command)

        # Check obfuscation patterns (on original command, before stripping)
        for pattern in self.OBFUSCATION_PATTERNS:
            if pattern.search(command):
                return True, f"Blocked: Command obfuscation detected - {pattern.pattern}"

        # Check destructive operations
        for pattern in self.DESTRUCTIVE_PATTERNS:
            if pattern.search(stripped):
                return True, f"Blocked: Destructive operation detected - {pattern.pattern}"

        # Check dangerous git operations (before production patterns so
        # "git push origin main" is caught as a git operation, not production)
        for pattern in self.DANGEROUS_GIT_PATTERNS:
            if pattern.search(stripped):
                return True, f"Blocked: Dangerous git operation detected - {pattern.pattern}"

        # Check dangerous infrastructure operations
        for pattern in self.DANGEROUS_INFRA_PATTERNS:
            if pattern.search(stripped):
                return (
                    True,
                    f"Blocked: Dangerous infrastructure operation detected - {pattern.pattern}",
                )

        # Check production operations (PRODUCTION_PATTERNS use negative
        # lookbehinds to allow nonprod/non-prod/nonproduction)
        for pattern in self.PRODUCTION_PATTERNS:
            if pattern.search(stripped):
                return (
                    True,
                    f"Blocked: Production environment operation detected - {pattern.pattern}",
                )

        # Check network operations
        for pattern in self.NETWORK_PATTERNS:
            if pattern.search(stripped):
                return True, f"Blocked: Potentially dangerous network operation - {pattern.pattern}"

        return False, None

    def _is_sensitive_file(self, file_path: str) -> bool:
        """Check if file path is sensitive (not .gitignored)."""
        sensitive_patterns = [
            ".env",
            "secrets",
            "config.json",
            "appsettings.json",
            ".aws/credentials",
            ".ssh/",
            "id_rsa",
        ]

        file_lower = file_path.lower()

        return any(pattern in file_lower for pattern in sensitive_patterns)

    def _contains_credentials(self, content: str) -> bool:
        """Check if content contains credential patterns."""
        for pattern in self.CREDENTIAL_PATTERNS:
            if pattern.search(content):
                return True
        return False
