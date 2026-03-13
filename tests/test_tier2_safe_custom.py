"""
Tests for Tier 2 user-configurable safe patterns (SafePatternStore + integration).

Tests SafePatternStore loading/validation and SafeOperationDetector merging behavior.
"""

import json
import re

from phlegyas.tier2_safe import SafeOperationDetector, SafePatternStore

# ---------------------------------------------------------------------------
# SafePatternStore tests
# ---------------------------------------------------------------------------


class TestSafePatternStore:
    """Test suite for SafePatternStore file loading and validation."""

    def test_loads_valid_json(self, tmp_path):
        """Should load a well-formed safe-patterns.json."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "patterns": {
                        "safe_bash": [
                            {
                                "regex": r"^make\s+",
                                "category": "build command",
                                "description": "GNU make",
                            }
                        ],
                        "safe_tools": ["mcp__custom__read"],
                        "safe_write_dirs": ["/opt/outputs/"],
                        "sensitive_files": ["config/prod.yaml"],
                    },
                }
            )
        )
        store = SafePatternStore(store_path=store_file)

        assert len(store.bash_patterns) == 1
        assert store.bash_patterns[0][1] == "build command"
        assert "mcp__custom__read" in store.tool_names
        assert "/opt/outputs/" in store.write_dirs
        assert "config/prod.yaml" in store.sensitive_files

    def test_empty_on_missing_file(self, tmp_path):
        """Should return empty patterns when file doesn't exist."""
        store = SafePatternStore(store_path=tmp_path / "nonexistent.json")

        assert store.bash_patterns == []
        assert store.tool_names == set()
        assert store.write_dirs == []
        assert store.sensitive_files == []

    def test_empty_on_malformed_json(self, tmp_path):
        """Should return empty patterns for invalid JSON."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text("{not valid json!!!")
        store = SafePatternStore(store_path=store_file)

        assert store.bash_patterns == []
        assert store.tool_names == set()

    def test_empty_on_bad_schema_missing_version(self, tmp_path):
        """Should return empty patterns when version key is missing."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(json.dumps({"patterns": {}}))
        store = SafePatternStore(store_path=store_file)

        assert store.bash_patterns == []

    def test_empty_on_bad_schema_wrong_version(self, tmp_path):
        """Should return empty patterns when version != 1."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(json.dumps({"version": 99, "patterns": {}}))
        store = SafePatternStore(store_path=store_file)

        assert store.bash_patterns == []

    def test_compiles_regex(self, tmp_path):
        """Should compile regex strings into re.Pattern objects."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "patterns": {
                        "safe_bash": [
                            {"regex": r"^make\s+", "category": "build", "description": "make"}
                        ]
                    },
                }
            )
        )
        store = SafePatternStore(store_path=store_file)

        compiled, category = store.bash_patterns[0]
        assert isinstance(compiled, re.Pattern)
        assert compiled.search("make build")

    def test_compiles_regex_with_flags(self, tmp_path):
        """Should compile regex with user-specified flags (e.g. IGNORECASE)."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "patterns": {
                        "safe_bash": [
                            {
                                "regex": r"^Make\s+",
                                "category": "build",
                                "description": "make",
                                "flags": ["IGNORECASE"],
                            }
                        ]
                    },
                }
            )
        )
        store = SafePatternStore(store_path=store_file)

        compiled, _ = store.bash_patterns[0]
        assert compiled.search("make all")  # lowercase should match with IGNORECASE

    def test_skips_invalid_regex(self, tmp_path):
        """Should skip entries with invalid regex and still load the rest."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "patterns": {
                        "safe_bash": [
                            {"regex": r"[invalid", "category": "bad", "description": "bad regex"},
                            {"regex": r"^make\s+", "category": "build", "description": "make"},
                        ]
                    },
                }
            )
        )
        store = SafePatternStore(store_path=store_file)

        assert len(store.bash_patterns) == 1
        assert store.bash_patterns[0][1] == "build"

    def test_custom_store_path(self, tmp_path):
        """Should use the provided store_path."""
        custom = tmp_path / "custom" / "patterns.json"
        custom.parent.mkdir(parents=True)
        custom.write_text(
            json.dumps(
                {
                    "version": 1,
                    "patterns": {
                        "safe_tools": ["CustomTool"],
                    },
                }
            )
        )
        store = SafePatternStore(store_path=custom)

        assert "CustomTool" in store.tool_names

    def test_default_path(self):
        """Default path should be ~/.claude/safe-patterns.json."""
        store = SafePatternStore()
        from pathlib import Path

        assert store._path == Path.home() / ".claude" / "safe-patterns.json"

    def test_missing_patterns_key_gives_empty(self, tmp_path):
        """Should handle version=1 with missing patterns key gracefully."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(json.dumps({"version": 1}))
        store = SafePatternStore(store_path=store_file)

        assert store.bash_patterns == []
        assert store.tool_names == set()


# ---------------------------------------------------------------------------
# SafeOperationDetector with user patterns tests
# ---------------------------------------------------------------------------


class TestSafeOperationDetectorWithUserPatterns:
    """Test SafeOperationDetector merging user patterns on top of builtins."""

    def _make_store(self, tmp_path, patterns_dict):
        """Helper: create a SafePatternStore from a patterns dict."""
        store_file = tmp_path / "safe-patterns.json"
        store_file.write_text(json.dumps({"version": 1, "patterns": patterns_dict}))
        return SafePatternStore(store_path=store_file)

    def test_user_bash_pattern_works(self, tmp_path):
        """User-defined bash patterns should approve matching commands."""
        store = self._make_store(
            tmp_path,
            {
                "safe_bash": [
                    {"regex": r"^make\s+", "category": "build command", "description": "make"}
                ]
            },
        )
        detector = SafeOperationDetector(user_store=store)

        is_safe, category = detector.is_safe("Bash", {"command": "make build"})
        assert is_safe is True
        assert "build command" in category

    def test_user_tool_name_works(self, tmp_path):
        """User-defined tool names should be approved."""
        store = self._make_store(tmp_path, {"safe_tools": ["mcp__custom__reader"]})
        detector = SafeOperationDetector(user_store=store)

        is_safe, category = detector.is_safe("mcp__custom__reader", {"query": "test"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_user_write_dir_works(self, tmp_path):
        """User-defined write dirs should approve writes to those paths."""
        store = self._make_store(tmp_path, {"safe_write_dirs": ["/opt/outputs/"]})
        detector = SafeOperationDetector(user_store=store)

        is_safe, category = detector.is_safe("Write", {"file_path": "/opt/outputs/report.txt"})
        assert is_safe is True
        assert "safe directory" in category

    def test_user_sensitive_file_blocks_write(self, tmp_path):
        """User-defined sensitive files should block writes."""
        store = self._make_store(tmp_path, {"sensitive_files": ["config/prod.yaml"]})
        detector = SafeOperationDetector(user_store=store)

        # Relative path with sensitive pattern should be blocked
        is_safe, _ = detector.is_safe("Write", {"file_path": "config/prod.yaml"})
        assert is_safe is False

    def test_user_sensitive_file_blocks_edit(self, tmp_path):
        """User-defined sensitive files should block edits."""
        store = self._make_store(tmp_path, {"sensitive_files": ["config/prod.yaml"]})
        detector = SafeOperationDetector(user_store=store)

        is_safe, _ = detector.is_safe("Edit", {"file_path": "config/prod.yaml"})
        assert is_safe is False

    def test_builtins_still_work_with_user_store(self, tmp_path):
        """Built-in patterns should still work when a user store is provided."""
        store = self._make_store(tmp_path, {"safe_bash": []})
        detector = SafeOperationDetector(user_store=store)

        # Built-in git pattern
        is_safe, category = detector.is_safe("Bash", {"command": "git status"})
        assert is_safe is True
        assert "safe git operation" in category

        # Built-in read-only tool
        is_safe, category = detector.is_safe("Read", {"file_path": "test.py"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_augment_not_replace(self, tmp_path):
        """User patterns should augment built-in patterns, not replace them."""
        store = self._make_store(
            tmp_path,
            {
                "safe_bash": [
                    {"regex": r"^make\s+", "category": "build command", "description": "make"}
                ],
                "safe_tools": ["mcp__custom__reader"],
            },
        )
        detector = SafeOperationDetector(user_store=store)

        # User pattern works
        is_safe, _ = detector.is_safe("Bash", {"command": "make all"})
        assert is_safe is True

        # Built-in git pattern ALSO works
        is_safe, _ = detector.is_safe("Bash", {"command": "git status"})
        assert is_safe is True

        # Built-in Read tool ALSO works
        is_safe, _ = detector.is_safe("Read", {"file_path": "x.py"})
        assert is_safe is True

        # User tool name works
        is_safe, _ = detector.is_safe("mcp__custom__reader", {})
        assert is_safe is True

    def test_no_user_store_equals_original_behavior(self):
        """Default construction (no user_store) should behave identically."""
        detector = SafeOperationDetector()

        # Should still approve builtins
        is_safe, category = detector.is_safe("Bash", {"command": "git status"})
        assert is_safe is True

        # Should still reject unknown
        is_safe, _ = detector.is_safe("Bash", {"command": "rm -rf /"})
        assert is_safe is False

    def test_user_bash_pattern_checked_after_builtins(self, tmp_path):
        """User bash patterns are checked in addition to builtin categories."""
        store = self._make_store(
            tmp_path,
            {
                "safe_bash": [
                    {
                        "regex": r"^terraform\s+plan",
                        "category": "infra preview",
                        "description": "tf plan",
                    }
                ]
            },
        )
        detector = SafeOperationDetector(user_store=store)

        # User pattern
        is_safe, category = detector.is_safe("Bash", {"command": "terraform plan"})
        assert is_safe is True
        assert "infra preview" in category

        # Command NOT in any pattern
        is_safe, _ = detector.is_safe("Bash", {"command": "terraform apply"})
        assert is_safe is False
