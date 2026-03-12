"""
Pytest configuration and shared fixtures for claude-permission-approver tests.
"""

import json
from typing import Any

import pytest


@pytest.fixture(autouse=True, scope="session")
def _cleanup_ai_evaluator():
    """Close the module-level Anthropic client to avoid unclosed SSL socket warnings."""
    yield
    try:
        from src.approver_mcp import ai_evaluator

        if ai_evaluator is not None:
            ai_evaluator.close()
    except Exception:
        pass


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up mock environment variables for testing."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-123")
    monkeypatch.setenv("PROJECT_NAME", "TestProject")
    monkeypatch.setenv("PROJECT_TYPE", "Test Software Project")
    monkeypatch.setenv("CURRENT_TASK", "Testing permission system")
    monkeypatch.setenv("ENABLE_AUDIT_LOG", "false")


@pytest.fixture
def sample_bash_input() -> dict[str, Any]:
    """Sample Bash tool input."""
    return {"command": "ls -la"}


@pytest.fixture
def sample_edit_input() -> dict[str, Any]:
    """Sample Edit tool input."""
    return {
        "file_path": "src/example.py",
        "old_string": "def foo():",
        "new_string": "def bar():",
    }


@pytest.fixture
def sample_write_input() -> dict[str, Any]:
    """Sample Write tool input."""
    return {
        "file_path": "docs/test.md",
        "content": "# Test Documentation",
    }


@pytest.fixture
def dangerous_bash_commands() -> list[str]:
    """Collection of dangerous bash commands for testing."""
    return [
        "rm -rf /",
        "DROP TABLE users",
        "DELETE FROM customers WHERE id = 1",
        "TRUNCATE TABLE orders",
        "format c:",
        "mkfs.ext4 /dev/sda",
        "git push --force origin main",
        "git push -f origin master",
        "git reset --hard HEAD~5",
        "git clean -fd",
        "curl -X DELETE https://api.production.com/users",
        "wget --delete-after http://example.com",
    ]


@pytest.fixture
def production_commands() -> list[str]:
    """Collection of commands targeting production environments."""
    return [
        "kubectl apply -f deploy.yaml --context production",
        "docker push myapp:latest --registry prod-registry.com",
        "psql -h prod-db.company.com -c 'SELECT * FROM users'",
        "ssh user@production-server.com",
        "git checkout main",
        "git checkout master",
    ]


@pytest.fixture
def credential_patterns() -> list[str]:
    """Collection of content with credential patterns."""
    return [
        "password=secret123",
        "SECRET=my-api-key",
        "api_key = abc123",
        "AWS_SECRET_ACCESS_KEY=xyz",
        "ANTHROPIC_API_KEY=sk-ant-123",
        "Authorization: Bearer token123",
    ]


@pytest.fixture
def safe_git_commands() -> list[str]:
    """Collection of safe git commands."""
    return [
        "git status",
        "git log",
        "git diff",
        "git branch -a",
        "git show HEAD",
        "git checkout -b feature/new-feature",
        "git checkout -b fix/bug-fix",
        "git add .",
        "git commit -m 'test commit'",
        "git stash",
        "git fetch origin",
        "git pull origin develop",
    ]


@pytest.fixture
def safe_test_commands() -> list[str]:
    """Collection of safe test commands."""
    return [
        "npm test",
        "npm run test",
        "yarn test",
        "pnpm test",
        "dotnet test",
        "pytest",
        "python -m pytest",
        "cargo test",
        "go test ./...",
        "mvn test",
        "gradle test",
        "source .venv/bin/activate && pytest -v",
    ]


@pytest.fixture
def safe_lint_commands() -> list[str]:
    """Collection of safe linting/formatting commands."""
    return [
        "npm run lint",
        "eslint .",
        "dotnet format",
        "black .",
        "ruff check",
        "prettier --check .",
        "rustfmt src/main.rs",
    ]


@pytest.fixture
def safe_build_commands() -> list[str]:
    """Collection of safe build commands."""
    return [
        "npm build",
        "npm run build",
        "yarn build",
        "pnpm build",
        "dotnet build",
        "cargo build",
        "go build",
        "mvn compile",
        "gradle build",
    ]


@pytest.fixture
def safe_info_commands() -> list[str]:
    """Collection of safe read-only info commands."""
    return [
        "ls -la",
        "pwd",
        "cat package.json",
        "head -n 10 README.md",
        "tail -f logfile.txt",
        "grep 'error' logs.txt",
        "find . -name '*.py'",
        "tree src/",
        "ps aux",
        "env",
        "printenv PATH",
        "which python",
        "whereis node",
        "file script.sh",
        "stat myfile.txt",
        "wc -l *.py",
        "diff old.txt new.txt",
        "icalBuddy eventsToday",
        "icalBuddy -n 10 eventsFrom:2026-03-11 to:2026-03-18",
        "remindctl list",
        "remindctl list --all",
        "remindctl create 'Buy milk' --due tomorrow",
        "remindctl create 'Review PR' --list Work",
        "uname -a",
        "hostname",
        "whoami",
        "id",
        "date",
        "uptime",
        "df -h",
        "du -sh src/",
        "pip list",
        "pip show anthropic",
        "pip freeze",
        "npm list",
        "npm ls --depth=0",
        "npm outdated",
        "dotnet --list-sdks",
        "dotnet --version",
        "dotnet --info",
        "python3 --version",
        "python --version",
        "node --version",
        "sw_vers",
        "brew list",
        "brew info python",
        "brew search mcp",
        "brew outdated",
        "gh pr list",
        "gh issue list",
        "gh run list",
        "gh api repos/owner/repo/pulls",
        "jq '.name' package.json",
        "sort names.txt",
        "uniq",
        "cut -d: -f1 /etc/passwd",
        "awk '{print $1}' file.txt",
        "sed -n '1,10p' file.txt",
        "basename /path/to/file.txt",
        "dirname /path/to/file.txt",
        "realpath ./script.sh",
        "shasum -a 256 file.bin",
        "source .venv/bin/activate && pip list",
        "cd /tmp && ls -la",
    ]


@pytest.fixture
def safe_install_commands() -> list[str]:
    """Collection of safe package installation commands."""
    return [
        "npm install",
        "npm install lodash",
        "yarn add react",
        "yarn install",
        "pnpm install",
        "pip install requests",
        "dotnet restore",
        "cargo build",  # Includes dependency installation
    ]


@pytest.fixture
def safe_research_commands() -> list[str]:
    """Collection of safe web research commands."""
    return [
        "curl https://api.github.com/users/octocat",
        "wget https://example.com/file.txt",
        "curl -H 'Accept: application/json' https://api.example.com",
    ]


@pytest.fixture
def mock_anthropic_response():
    """Factory for creating mock Anthropic API responses."""

    def _create_response(
        decision: str = "approve",
        category: str = "benign",
        reasoning: str = "Test reasoning",
        confidence: float = 0.9,
        suggested_message: str | None = None,
    ):
        """Create a mock Anthropic response."""
        response_data = {
            "decision": decision,
            "category": category,
            "reasoning": reasoning,
            "confidence": confidence,
        }
        if suggested_message:
            response_data["suggested_message"] = suggested_message

        class MockTextBlock:
            def __init__(self, text):
                self.text = text

        class MockMessage:
            def __init__(self, content):
                self.content = content

        json_text = json.dumps(response_data)
        return MockMessage([MockTextBlock(json_text)])

    return _create_response


@pytest.fixture
def mock_anthropic_tool_use_response():
    """Factory for creating mock Anthropic tool_use responses (structured output)."""

    def _create_response(
        decision: str = "approve",
        category: str = "benign",
        reasoning: str = "Test reasoning",
        confidence: float = 0.9,
        suggested_message: str | None = None,
    ):
        """Create a mock Anthropic response using tool_use blocks."""
        input_data = {
            "decision": decision,
            "category": category,
            "reasoning": reasoning,
            "confidence": confidence,
        }
        if suggested_message:
            input_data["suggested_message"] = suggested_message

        class MockToolUseBlock:
            def __init__(self, tool_input):
                self.type = "tool_use"
                self.name = "security_evaluation"
                self.input = tool_input

        class MockMessage:
            def __init__(self, content, stop_reason="tool_use"):
                self.content = content
                self.stop_reason = stop_reason

        return MockMessage([MockToolUseBlock(input_data)])

    return _create_response


@pytest.fixture
def mock_anthropic_response_with_markdown():
    """Factory for creating mock Anthropic responses wrapped in markdown."""

    def _create_response(
        decision: str = "approve",
        category: str = "benign",
        reasoning: str = "Test reasoning",
        confidence: float = 0.9,
    ):
        """Create a mock Anthropic response wrapped in markdown code blocks."""
        response_data = {
            "decision": decision,
            "category": category,
            "reasoning": reasoning,
            "confidence": confidence,
        }

        class MockTextBlock:
            def __init__(self, text):
                self.text = text

        class MockMessage:
            def __init__(self, content):
                self.content = content

        json_text = f"```json\n{json.dumps(response_data, indent=2)}\n```"
        return MockMessage([MockTextBlock(json_text)])

    return _create_response
