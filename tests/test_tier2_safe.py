"""
Tests for Tier 2: Safe Operation Auto-Approval

Tests that safe operations are correctly identified and auto-approved.
"""

import pytest

from src.tier2_safe import SafeOperationDetector


class TestSafeOperationDetector:
    """Test suite for SafeOperationDetector."""

    @pytest.fixture
    def detector(self):
        """Create a SafeOperationDetector instance."""
        return SafeOperationDetector()

    # Read-Only Tools Tests

    def test_should_approve_read_tool(self, detector):
        """Should auto-approve Read tool."""
        is_safe, category = detector.is_safe("Read", {"file_path": "src/example.py"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_glob_tool(self, detector):
        """Should auto-approve Glob tool."""
        is_safe, category = detector.is_safe("Glob", {"pattern": "*.py"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_grep_tool(self, detector):
        """Should auto-approve Grep tool."""
        is_safe, category = detector.is_safe("Grep", {"pattern": "TODO"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_webfetch_tool(self, detector):
        """Should auto-approve WebFetch tool."""
        is_safe, category = detector.is_safe("WebFetch", {"url": "https://example.com"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_websearch_tool(self, detector):
        """Should auto-approve WebSearch tool."""
        is_safe, category = detector.is_safe("WebSearch", {"query": "python tutorials"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_firecrawl_search(self, detector):
        """Should auto-approve Firecrawl search tool."""
        is_safe, category = detector.is_safe("mcp__firecrawl__firecrawl_search", {"query": "test"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_firecrawl_map(self, detector):
        """Should auto-approve Firecrawl map tool."""
        is_safe, category = detector.is_safe("mcp__firecrawl__firecrawl_map", {"url": "test.com"})
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_firecrawl_scrape(self, detector):
        """Should auto-approve Firecrawl scrape tool."""
        is_safe, category = detector.is_safe(
            "mcp__firecrawl__firecrawl_scrape", {"url": "example.com"}
        )
        assert is_safe is True
        assert "web research" in category

    def test_should_approve_firecrawl_extract(self, detector):
        """Should auto-approve Firecrawl extract tool."""
        is_safe, category = detector.is_safe(
            "mcp__firecrawl__firecrawl_extract", {"urls": ["example.com"]}
        )
        assert is_safe is True
        assert "web research" in category

    def test_should_approve_jetbrains_get_file_text(self, detector):
        """Should auto-approve JetBrains get_file_text tool."""
        is_safe, category = detector.is_safe(
            "mcp__jetbrains__get_file_text_by_path", {"pathInProject": "src/main.py"}
        )
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_jetbrains_find_files(self, detector):
        """Should auto-approve JetBrains find_files tool."""
        is_safe, category = detector.is_safe(
            "mcp__jetbrains__find_files_by_name_keyword", {"nameKeyword": "test"}
        )
        assert is_safe is True
        assert "read-only tool" in category

    def test_should_approve_jetbrains_search_in_files(self, detector):
        """Should auto-approve JetBrains search_in_files tool."""
        is_safe, category = detector.is_safe(
            "mcp__jetbrains__search_in_files_by_text", {"searchText": "TODO"}
        )
        assert is_safe is True
        assert "read-only tool" in category

    # Safe Git Operations Tests

    def test_should_approve_git_status(self, detector):
        """Should approve git status."""
        is_safe, category = detector.is_safe("Bash", {"command": "git status"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_log(self, detector):
        """Should approve git log."""
        is_safe, category = detector.is_safe("Bash", {"command": "git log --oneline"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_diff(self, detector):
        """Should approve git diff."""
        is_safe, category = detector.is_safe("Bash", {"command": "git diff HEAD"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_branch_list(self, detector):
        """Should approve git branch listing."""
        is_safe, category = detector.is_safe("Bash", {"command": "git branch -a"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_show(self, detector):
        """Should approve git show."""
        is_safe, category = detector.is_safe("Bash", {"command": "git show HEAD"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_feature_branch_checkout(self, detector):
        """Should approve creating feature branches."""
        is_safe, category = detector.is_safe(
            "Bash", {"command": "git checkout -b feature/new-feature"}
        )
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_fix_branch_checkout(self, detector):
        """Should approve creating fix branches."""
        is_safe, category = detector.is_safe("Bash", {"command": "git checkout -b fix/bug-123"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_feat_branch_checkout(self, detector):
        """Should approve creating feat branches."""
        is_safe, category = detector.is_safe("Bash", {"command": "git checkout -b feat/api"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_add(self, detector):
        """Should approve git add."""
        is_safe, category = detector.is_safe("Bash", {"command": "git add ."})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_commit(self, detector):
        """Should approve git commit."""
        is_safe, category = detector.is_safe("Bash", {"command": "git commit -m 'test'"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_stash(self, detector):
        """Should approve git stash."""
        is_safe, category = detector.is_safe("Bash", {"command": "git stash"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_fetch(self, detector):
        """Should approve git fetch."""
        is_safe, category = detector.is_safe("Bash", {"command": "git fetch origin"})
        assert is_safe is True
        assert "safe git operation" in category

    def test_should_approve_git_pull_non_main(self, detector):
        """Should approve git pull from non-main branches."""
        is_safe, category = detector.is_safe("Bash", {"command": "git pull origin develop"})
        assert is_safe is True
        assert "safe git operation" in category

    # Test Commands Tests

    def test_should_approve_npm_test(self, detector):
        """Should approve npm test."""
        is_safe, category = detector.is_safe("Bash", {"command": "npm test"})
        assert is_safe is True
        assert "test command" in category

    def test_should_approve_npm_run_test(self, detector):
        """Should approve npm run test."""
        is_safe, category = detector.is_safe("Bash", {"command": "npm run test"})
        assert is_safe is True
        assert "test command" in category

    def test_should_approve_yarn_test(self, detector):
        """Should approve yarn test."""
        is_safe, category = detector.is_safe("Bash", {"command": "yarn test"})
        assert is_safe is True
        assert "test command" in category

    def test_should_approve_dotnet_test(self, detector):
        """Should approve dotnet test."""
        is_safe, category = detector.is_safe("Bash", {"command": "dotnet test"})
        assert is_safe is True
        assert "test command" in category

    def test_should_approve_pytest(self, detector):
        """Should approve pytest."""
        is_safe, category = detector.is_safe("Bash", {"command": "pytest tests/"})
        assert is_safe is True
        assert "test command" in category

    def test_should_approve_python_m_pytest(self, detector):
        """Should approve python -m pytest."""
        is_safe, category = detector.is_safe("Bash", {"command": "python -m pytest"})
        assert is_safe is True
        assert "test command" in category

    def test_should_approve_cargo_test(self, detector):
        """Should approve cargo test."""
        is_safe, category = detector.is_safe("Bash", {"command": "cargo test"})
        assert is_safe is True
        assert "test command" in category

    def test_should_approve_go_test(self, detector):
        """Should approve go test."""
        is_safe, category = detector.is_safe("Bash", {"command": "go test ./..."})
        assert is_safe is True
        assert "test command" in category

    # Linting/Formatting Tests

    def test_should_approve_npm_run_lint(self, detector):
        """Should approve npm run lint."""
        is_safe, category = detector.is_safe("Bash", {"command": "npm run lint"})
        assert is_safe is True
        assert "linting/formatting" in category

    def test_should_approve_eslint(self, detector):
        """Should approve eslint."""
        is_safe, category = detector.is_safe("Bash", {"command": "eslint src/"})
        assert is_safe is True
        assert "linting/formatting" in category

    def test_should_approve_dotnet_format(self, detector):
        """Should approve dotnet format."""
        is_safe, category = detector.is_safe("Bash", {"command": "dotnet format"})
        assert is_safe is True
        assert "linting/formatting" in category

    def test_should_approve_black(self, detector):
        """Should approve black."""
        is_safe, category = detector.is_safe("Bash", {"command": "black ."})
        assert is_safe is True
        assert "linting/formatting" in category

    def test_should_approve_ruff(self, detector):
        """Should approve ruff."""
        is_safe, category = detector.is_safe("Bash", {"command": "ruff check src/"})
        assert is_safe is True
        assert "linting/formatting" in category

    def test_should_approve_prettier(self, detector):
        """Should approve prettier."""
        is_safe, category = detector.is_safe("Bash", {"command": "prettier --check ."})
        assert is_safe is True
        assert "linting/formatting" in category

    # Build Commands Tests

    def test_should_approve_npm_build(self, detector):
        """Should approve npm build."""
        is_safe, category = detector.is_safe("Bash", {"command": "npm build"})
        assert is_safe is True
        assert "build command" in category

    def test_should_approve_npm_run_build(self, detector):
        """Should approve npm run build."""
        is_safe, category = detector.is_safe("Bash", {"command": "npm run build"})
        assert is_safe is True
        assert "build command" in category

    def test_should_approve_yarn_build(self, detector):
        """Should approve yarn build."""
        is_safe, category = detector.is_safe("Bash", {"command": "yarn build"})
        assert is_safe is True
        assert "build command" in category

    def test_should_approve_dotnet_build(self, detector):
        """Should approve dotnet build."""
        is_safe, category = detector.is_safe("Bash", {"command": "dotnet build"})
        assert is_safe is True
        assert "build command" in category

    def test_should_approve_cargo_build(self, detector):
        """Should approve cargo build."""
        is_safe, category = detector.is_safe("Bash", {"command": "cargo build --release"})
        assert is_safe is True
        assert "build command" in category

    def test_should_approve_go_build(self, detector):
        """Should approve go build."""
        is_safe, category = detector.is_safe("Bash", {"command": "go build ./cmd/app"})
        assert is_safe is True
        assert "build command" in category

    # Info/List Commands Tests

    def test_should_approve_ls(self, detector):
        """Should approve ls."""
        is_safe, category = detector.is_safe("Bash", {"command": "ls -la"})
        assert is_safe is True
        assert "read-only info command" in category

    def test_should_approve_pwd(self, detector):
        """Should approve pwd."""
        is_safe, category = detector.is_safe("Bash", {"command": "pwd"})
        assert is_safe is True
        assert "read-only info command" in category

    def test_should_approve_cat(self, detector):
        """Should approve cat."""
        is_safe, category = detector.is_safe("Bash", {"command": "cat package.json"})
        assert is_safe is True
        assert "read-only info command" in category

    def test_should_approve_grep(self, detector):
        """Should approve grep."""
        is_safe, category = detector.is_safe("Bash", {"command": "grep 'error' logs.txt"})
        assert is_safe is True
        assert "read-only info command" in category

    def test_should_approve_find(self, detector):
        """Should approve find."""
        is_safe, category = detector.is_safe("Bash", {"command": "find . -name '*.py'"})
        assert is_safe is True
        assert "read-only info command" in category

    def test_should_approve_ps(self, detector):
        """Should approve ps."""
        is_safe, category = detector.is_safe("Bash", {"command": "ps aux | grep node"})
        assert is_safe is True
        assert "read-only info command" in category

    # Package Installation Tests

    def test_should_approve_npm_install(self, detector):
        """Should approve npm install."""
        is_safe, category = detector.is_safe("Bash", {"command": "npm install"})
        assert is_safe is True
        assert "package installation" in category

    def test_should_approve_npm_install_package(self, detector):
        """Should approve npm install with package name."""
        is_safe, category = detector.is_safe("Bash", {"command": "npm install lodash"})
        assert is_safe is True
        assert "package installation" in category

    def test_should_approve_yarn_add(self, detector):
        """Should approve yarn add."""
        is_safe, category = detector.is_safe("Bash", {"command": "yarn add react"})
        assert is_safe is True
        assert "package installation" in category

    def test_should_approve_pip_install(self, detector):
        """Should approve pip install."""
        is_safe, category = detector.is_safe("Bash", {"command": "pip install requests"})
        assert is_safe is True
        assert "package installation" in category

    def test_should_approve_dotnet_restore(self, detector):
        """Should approve dotnet restore."""
        is_safe, category = detector.is_safe("Bash", {"command": "dotnet restore"})
        assert is_safe is True
        assert "package installation" in category

    # Web Research Tests

    def test_should_approve_safe_curl(self, detector):
        """Should approve safe curl requests."""
        is_safe, category = detector.is_safe(
            "Bash", {"command": "curl https://api.github.com/users/octocat"}
        )
        assert is_safe is True
        assert "web research" in category

    def test_should_approve_safe_wget(self, detector):
        """Should approve safe wget requests."""
        is_safe, category = detector.is_safe("Bash", {"command": "wget https://example.com/file"})
        assert is_safe is True
        assert "web research" in category

    def test_should_reject_curl_with_delete(self, detector):
        """Should reject curl with DELETE method."""
        is_safe, category = detector.is_safe(
            "Bash", {"command": "curl -X DELETE https://api.example.com"}
        )
        assert is_safe is False
        assert category is None

    # Write Operations Tests

    def test_should_approve_tmp_write(self, detector):
        """Should approve writes to /tmp/."""
        is_safe, category = detector.is_safe("Write", {"file_path": "/tmp/test.txt"})
        assert is_safe is True
        assert "safe directory" in category

    def test_should_approve_docs_research_write(self, detector):
        """Should approve writes to docs/research/."""
        is_safe, category = detector.is_safe("Write", {"file_path": "docs/research/notes.md"})
        assert is_safe is True
        assert "safe directory" in category or "project-relative write" in category

    def test_should_approve_tests_write(self, detector):
        """Should approve writes to tests/."""
        is_safe, category = detector.is_safe("Write", {"file_path": "tests/test_new.py"})
        assert is_safe is True
        assert "safe directory" in category or "project-relative write" in category

    def test_should_approve_scripts_write(self, detector):
        """Should approve writes to scripts/."""
        is_safe, category = detector.is_safe("Write", {"file_path": "scripts/deploy.sh"})
        assert is_safe is True
        assert "safe directory" in category or "project-relative write" in category

    def test_should_approve_project_relative_write(self, detector):
        """Should approve project-relative writes."""
        is_safe, category = detector.is_safe("Write", {"file_path": "src/new_feature.py"})
        assert is_safe is True
        assert "project-relative write" in category

    def test_should_reject_env_file_write(self, detector):
        """Should reject writes to .env files."""
        is_safe, category = detector.is_safe("Write", {"file_path": ".env"})
        assert is_safe is False
        assert category is None

    def test_should_reject_secrets_file_write(self, detector):
        """Should reject writes to secrets files."""
        is_safe, category = detector.is_safe("Write", {"file_path": "config/secrets.json"})
        assert is_safe is False
        assert category is None

    # Edit Operations Tests

    def test_should_approve_project_file_edit(self, detector):
        """Should approve editing project files."""
        is_safe, category = detector.is_safe("Edit", {"file_path": "src/main.py"})
        assert is_safe is True
        assert "project file edit" in category

    def test_should_reject_env_file_edit(self, detector):
        """Should reject editing .env files."""
        is_safe, category = detector.is_safe("Edit", {"file_path": ".env"})
        assert is_safe is False
        assert category is None

    def test_should_reject_package_lock_edit(self, detector):
        """Should reject editing package-lock.json."""
        is_safe, category = detector.is_safe("Edit", {"file_path": "package-lock.json"})
        assert is_safe is False
        assert category is None

    def test_should_reject_yarn_lock_edit(self, detector):
        """Should reject editing yarn.lock."""
        is_safe, category = detector.is_safe("Edit", {"file_path": "yarn.lock"})
        assert is_safe is False
        assert category is None

    # Batch Tests with Fixtures

    def test_should_approve_all_safe_git_commands(self, detector, safe_git_commands):
        """Should approve all safe git commands."""
        for command in safe_git_commands:
            is_safe, category = detector.is_safe("Bash", {"command": command})
            assert is_safe is True, f"Failed to approve safe git command: {command}"
            assert category is not None

    def test_should_approve_all_test_commands(self, detector, safe_test_commands):
        """Should approve all test commands."""
        for command in safe_test_commands:
            is_safe, category = detector.is_safe("Bash", {"command": command})
            assert is_safe is True, f"Failed to approve test command: {command}"
            assert "test command" in category

    def test_should_approve_all_lint_commands(self, detector, safe_lint_commands):
        """Should approve all linting/formatting commands."""
        for command in safe_lint_commands:
            is_safe, category = detector.is_safe("Bash", {"command": command})
            assert is_safe is True, f"Failed to approve lint command: {command}"
            assert "linting/formatting" in category

    def test_should_approve_all_build_commands(self, detector, safe_build_commands):
        """Should approve all build commands."""
        for command in safe_build_commands:
            is_safe, category = detector.is_safe("Bash", {"command": command})
            assert is_safe is True, f"Failed to approve build command: {command}"
            assert "build command" in category

    def test_should_approve_all_info_commands(self, detector, safe_info_commands):
        """Should approve all info commands."""
        for command in safe_info_commands:
            is_safe, category = detector.is_safe("Bash", {"command": command})
            assert is_safe is True, f"Failed to approve info command: {command}"
            assert "read-only info command" in category
