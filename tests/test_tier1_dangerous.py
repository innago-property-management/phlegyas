"""
Tests for Tier 1: Dangerous Pattern Detection

Tests that dangerous operations are correctly identified and blocked.
"""

import pytest

from phlegyas.tier1_dangerous import DangerousPatternDetector


class TestDangerousPatternDetector:
    """Test suite for DangerousPatternDetector."""

    @pytest.fixture
    def detector(self):
        """Create a DangerousPatternDetector instance."""
        return DangerousPatternDetector()

    # Destructive Bash Commands Tests

    def test_should_block_rm_rf(self, detector):
        """Should block rm -rf commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "rm -rf /"})
        assert is_dangerous is True
        assert "Destructive operation" in reason

    def test_should_block_drop_table(self, detector):
        """Should block DROP TABLE commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "DROP TABLE users"})
        assert is_dangerous is True
        assert "Destructive operation" in reason

    def test_should_block_delete_from_where(self, detector):
        """Should block DELETE FROM...WHERE commands."""
        is_dangerous, reason = detector.is_dangerous(
            "Bash", {"command": "DELETE FROM customers WHERE id = 1"}
        )
        assert is_dangerous is True
        assert "Destructive operation" in reason

    def test_should_block_truncate_table(self, detector):
        """Should block TRUNCATE TABLE commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "TRUNCATE TABLE orders"})
        assert is_dangerous is True
        assert "Destructive operation" in reason

    def test_should_block_format_drive_windows(self, detector):
        """Should block Windows format drive commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "format c:"})
        assert is_dangerous is True
        assert "Destructive operation" in reason

    def test_should_block_mkfs_linux(self, detector):
        """Should block Linux mkfs commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "mkfs.ext4 /dev/sda"})
        assert is_dangerous is True
        assert "Destructive operation" in reason

    # Production Environment Tests

    def test_should_block_production_keyword(self, detector):
        """Should block commands with 'production' keyword."""
        is_dangerous, reason = detector.is_dangerous(
            "Bash", {"command": "kubectl apply -f deploy.yaml --context production"}
        )
        assert is_dangerous is True
        assert "Production environment" in reason

    def test_should_block_prod_db(self, detector):
        """Should block commands targeting prod-db."""
        is_dangerous, reason = detector.is_dangerous(
            "Bash", {"command": "psql -h prod-db.company.com"}
        )
        assert is_dangerous is True
        assert "Production environment" in reason

    def test_should_block_env_prod_flag(self, detector):
        """Should block commands with --env=prod flag."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "deploy.sh --env=prod"})
        assert is_dangerous is True
        assert "Production environment" in reason

    def test_should_block_master_branch_operations(self, detector):
        """Should block operations targeting master branch."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "git checkout master"})
        assert is_dangerous is True
        assert "Production environment" in reason

    def test_should_block_main_branch_operations(self, detector):
        """Should block operations targeting main branch."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "git checkout main"})
        assert is_dangerous is True
        assert "Production environment" in reason

    # Credential Pattern Tests

    def test_should_detect_password_in_edit(self, detector):
        """Should block editing files to add passwords."""
        is_dangerous, reason = detector.is_dangerous(
            "Edit",
            {
                "file_path": "src/config.json",
                "new_string": "password=secret123",
            },
        )
        assert is_dangerous is True
        assert "credentials" in reason.lower()

    def test_should_detect_api_key_in_write(self, detector):
        """Should block writing files with API keys."""
        is_dangerous, reason = detector.is_dangerous(
            "Write",
            {
                "file_path": "appsettings.json",
                "content": "api_key = abc123",
            },
        )
        assert is_dangerous is True
        assert "credentials" in reason.lower()

    def test_should_detect_aws_secret_in_content(self, detector):
        """Should detect AWS secret keys in content."""
        is_dangerous, reason = detector.is_dangerous(
            "Write",
            {
                "file_path": "config.json",
                "content": "AWS_SECRET_ACCESS_KEY=xyz789",
            },
        )
        assert is_dangerous is True
        assert "credentials" in reason.lower()

    def test_should_detect_bearer_token(self, detector):
        """Should detect Bearer tokens in content."""
        is_dangerous, reason = detector.is_dangerous(
            "Edit",
            {
                "file_path": "appsettings.json",
                "new_string": "Authorization: Bearer token123",
            },
        )
        assert is_dangerous is True
        assert "credentials" in reason.lower()

    def test_should_allow_credentials_in_gitignored_files(self, detector):
        """Should allow credentials in .env files (assumed gitignored)."""
        is_dangerous, reason = detector.is_dangerous(
            "Write",
            {
                "file_path": ".env",
                "content": "API_KEY=secret123",
            },
        )
        assert is_dangerous is False
        assert reason is None

    # Dangerous Git Operations Tests

    def test_should_block_git_push_force(self, detector):
        """Should block git push --force commands."""
        is_dangerous, reason = detector.is_dangerous(
            "Bash", {"command": "git push --force origin main"}
        )
        assert is_dangerous is True
        assert "git operation" in reason.lower()

    def test_should_block_git_push_f(self, detector):
        """Should block git push -f commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "git push -f origin dev"})
        assert is_dangerous is True
        assert "git operation" in reason.lower()

    def test_should_block_git_reset_hard(self, detector):
        """Should block git reset --hard commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "git reset --hard HEAD~5"})
        assert is_dangerous is True
        assert "git operation" in reason.lower()

    def test_should_block_git_clean_fd(self, detector):
        """Should block git clean -fd commands."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "git clean -fd"})
        assert is_dangerous is True
        assert "git operation" in reason.lower()

    def test_should_block_push_to_main(self, detector):
        """Should block git push to main branch."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "git push origin main"})
        assert is_dangerous is True
        assert "git operation" in reason.lower()

    def test_should_block_push_to_master(self, detector):
        """Should block git push to master branch."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "git push origin master"})
        assert is_dangerous is True
        assert "git operation" in reason.lower()

    # Network Pattern Tests

    def test_should_block_curl_delete(self, detector):
        """Should block curl DELETE requests."""
        is_dangerous, reason = detector.is_dangerous(
            "Bash", {"command": "curl -X DELETE https://api.example.com/users/123"}
        )
        assert is_dangerous is True
        assert "network operation" in reason.lower()

    def test_should_block_wget_delete_after(self, detector):
        """Should block wget --delete-after commands."""
        is_dangerous, reason = detector.is_dangerous(
            "Bash", {"command": "wget --delete-after http://example.com"}
        )
        assert is_dangerous is True
        assert "network operation" in reason.lower()

    # Edge Cases

    def test_should_handle_empty_command(self, detector):
        """Should handle empty command gracefully."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": ""})
        assert is_dangerous is False
        assert reason is None

    def test_should_handle_missing_command_key(self, detector):
        """Should handle missing command key gracefully."""
        is_dangerous, reason = detector.is_dangerous("Bash", {})
        assert is_dangerous is False
        assert reason is None

    def test_should_handle_none_values(self, detector):
        """Should handle None values gracefully."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": None})
        assert is_dangerous is False
        assert reason is None

    def test_should_be_case_insensitive(self, detector):
        """Should detect patterns case-insensitively."""
        is_dangerous, reason = detector.is_dangerous("Bash", {"command": "RM -RF /"})
        assert is_dangerous is True

    def test_should_handle_unknown_tools(self, detector):
        """Should return safe for unknown tools."""
        is_dangerous, reason = detector.is_dangerous("UnknownTool", {"param": "value"})
        assert is_dangerous is False
        assert reason is None

    # Multiple Pattern Tests

    def test_should_detect_multiple_dangerous_patterns(self, detector, dangerous_bash_commands):
        """Should detect all dangerous bash commands."""
        for command in dangerous_bash_commands:
            is_dangerous, reason = detector.is_dangerous("Bash", {"command": command})
            assert is_dangerous is True, f"Failed to detect dangerous command: {command}"
            assert reason is not None

    def test_should_detect_all_production_patterns(self, detector, production_commands):
        """Should detect all production environment commands."""
        for command in production_commands:
            is_dangerous, reason = detector.is_dangerous("Bash", {"command": command})
            assert is_dangerous is True, f"Failed to detect production command: {command}"
            assert reason is not None

    def test_should_detect_all_credential_patterns(self, detector, credential_patterns):
        """Should detect all credential patterns in writes."""
        for content in credential_patterns:
            is_dangerous, reason = detector.is_dangerous(
                "Write",
                {
                    "file_path": "src/config.json",
                    "content": content,
                },
            )
            assert is_dangerous is True, f"Failed to detect credential pattern: {content}"
            assert reason is not None
