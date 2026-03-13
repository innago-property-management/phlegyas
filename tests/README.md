# Test Suite Documentation

This directory contains a comprehensive test suite for the phlegyas MCP server.

## Test Structure

```
tests/
├── conftest.py                    # Shared fixtures and test configuration
├── test_tier1_dangerous.py        # Tests for dangerous pattern detection (32 tests)
├── test_tier2_safe.py             # Tests for safe operation auto-approval (79 tests)
├── test_tier2_5_trust.py          # Tests for script trust store (27 tests)
├── test_tier3_ai.py               # Tests for AI evaluation (33 tests)
├── test_validate_operation.py     # Tests for Task agent validation workflow (23 tests)
└── test_approver.py               # Integration tests (18 tests)
```

## Test Categories

### Tier 1: Dangerous Pattern Detection (32 tests)
Tests that verify dangerous operations are correctly identified and blocked:
- Destructive bash commands (rm -rf, DROP TABLE, etc.)
- Production environment operations
- Credential exposure in files
- Dangerous git operations (push --force, reset --hard)
- Network DELETE operations

### Tier 2: Safe Operation Auto-Approval (79 tests)
Tests that verify safe operations are correctly identified and auto-approved:
- Read-only tools (Read, Glob, Grep, WebFetch, WebSearch, Firecrawl, JetBrains)
- Safe git operations (status, log, diff, feature branches, commit, add, stash)
- Test commands (npm test, pytest, go test, mvn test, gradle test, etc.)
- Linting and formatting (eslint, black, prettier, ruff, rustfmt)
- Build commands (npm build, cargo build, dotnet build, go build, etc.)
- Info commands (ls, cat, grep, find, ps, env, brew, gh, jq, awk, sed, etc.)
- Package installation (npm install, pip install, yarn add, dotnet restore)
- Web research (curl, wget)
- macOS utilities (icalBuddy, remindctl, sw_vers)
- gh api GET-only requests (mutating methods blocked)
- python -c deliberately excluded (falls to Tier 3)

### Tier 2.5: Script Trust Store (27 tests)
Tests for TOFU (Trust On First Use) script approval:
- Trust, revoke, list, verify operations
- SHA-256 content hash matching and mismatch detection
- Script path detection (bash, sh, direct execution)
- Tier 1 dangerous patterns still block trusted scripts
- on_change callback firing
- File permission enforcement (0600)
- Disk persistence

### Tier 3: AI Evaluation (33 tests)
Tests for AI-powered evaluation of ambiguous operations:
- Initialization and configuration
- Prompt building with project context
- Response parsing (JSON and markdown-wrapped)
- Confidence threshold application
- Critical operation escalation
- Error handling
- python -c and gh api mutation rejection

### Validate Operation (23 tests)
Tests for the Task agent validation workflow:
- Tier 1/2/2.5/3 routing via validate_operation tool
- Response format (status, tier, reason, confidence, request_id)
- Pending approval lifecycle and TTL
- Audit log integration
- Edge cases (empty input, unknown tools)

### Integration Tests (18 tests)
End-to-end tests for the complete approval system:
- Three-tier flow validation
- Tier precedence rules
- Audit logging
- Statistics retrieval
- Error handling
- Real-world scenarios

## Running Tests

### Prerequisites
```bash
# Install development dependencies
pip install -e ".[dev]"
```

### Run All Tests
```bash
pytest tests/
```

### Run Specific Test File
```bash
pytest tests/test_tier1_dangerous.py -v
pytest tests/test_tier2_safe.py -v
pytest tests/test_tier3_ai.py -v
pytest tests/test_approver.py -v
```

### Run Specific Test
```bash
pytest tests/test_tier1_dangerous.py::TestDangerousPatternDetector::test_should_block_rm_rf -v
```

### Run with Coverage (if pytest-cov installed)
```bash
pip install pytest-cov
pytest tests/ --cov=phlegyas --cov-report=html --cov-report=term-missing
```

### Run Tests Matching Pattern
```bash
# Run all tests with "git" in the name
pytest tests/ -k "git" -v

# Run all tests for credential detection
pytest tests/ -k "credential" -v

# Run all integration tests
pytest tests/test_approver.py -v
```

## Test Fixtures

The `conftest.py` file provides shared fixtures:

### Environment Fixtures
- `mock_env_vars` - Sets up mock environment variables for testing

### Input Fixtures
- `sample_bash_input` - Sample Bash tool input
- `sample_edit_input` - Sample Edit tool input
- `sample_write_input` - Sample Write tool input

### Command Collections
- `dangerous_bash_commands` - Collection of dangerous commands
- `production_commands` - Production environment commands
- `credential_patterns` - Credential pattern examples
- `safe_git_commands` - Safe git operations
- `safe_test_commands` - Test command examples
- `safe_lint_commands` - Linting/formatting commands
- `safe_build_commands` - Build command examples
- `safe_info_commands` - Read-only info commands
- `safe_install_commands` - Package installation commands
- `safe_research_commands` - Web research commands

### Mock Fixtures
- `mock_anthropic_response` - Factory for creating mock Anthropic API responses
- `mock_anthropic_response_with_markdown` - Factory for markdown-wrapped responses

## Writing New Tests

### Test Naming Convention
- Test files: `test_*.py`
- Test classes: `Test*`
- Test functions: `test_should_*` or `test_*`

### Example Test Structure
```python
import pytest
from phlegyas.tier1_dangerous import DangerousPatternDetector

class TestDangerousPatternDetector:
    """Test suite for DangerousPatternDetector."""

    @pytest.fixture
    def detector(self):
        """Create a DangerousPatternDetector instance."""
        return DangerousPatternDetector()

    def test_should_block_dangerous_command(self, detector):
        """Should block rm -rf commands."""
        is_dangerous, reason = detector.is_dangerous(
            "Bash",
            {"command": "rm -rf /"}
        )
        assert is_dangerous is True
        assert "Destructive operation" in reason
```

### Async Test Example
```python
import pytest
from phlegyas.tier3_ai import AIEvaluator

class TestAIEvaluator:
    @pytest.mark.asyncio
    async def test_should_evaluate_operation(self, evaluator, mock_anthropic_response, mocker):
        """Should evaluate operation and return decision."""
        mock_response = mock_anthropic_response(
            decision="approve",
            category="benign",
            reasoning="Safe operation",
            confidence=0.9
        )
        mocker.patch.object(
            evaluator.client.messages,
            "create",
            return_value=mock_response
        )

        decision, evaluation = await evaluator.evaluate("Bash", {"command": "ls"})
        assert decision == "approve"
        assert evaluation.confidence == 0.9
```

## Test Organization Best Practices

### Arrange-Act-Assert Pattern
```python
def test_example(self, detector):
    # Arrange
    command = "rm -rf /"

    # Act
    is_dangerous, reason = detector.is_dangerous("Bash", {"command": command})

    # Assert
    assert is_dangerous is True
    assert reason is not None
```

### Use Descriptive Test Names
```python
# ✅ Good - describes what and why
def test_should_block_rm_rf_command(self):
    ...

# ❌ Bad - not descriptive
def test_rm_rf(self):
    ...
```

### Test One Thing Per Test
```python
# ✅ Good - tests one scenario
def test_should_block_production_keyword(self):
    ...

def test_should_block_prod_db(self):
    ...

# ❌ Bad - tests multiple scenarios
def test_production_patterns(self):
    # Tests production keyword
    # Tests prod-db
    # Tests --env=prod
    ...
```

## Current Test Status

**Total Tests:** 233 (includes parametrized variants)
**Passing:** 233 (100%)

## Continuous Integration

To integrate with CI/CD pipelines:

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: pytest tests/ -v
```

## Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure tests pass before committing
3. Maintain test coverage above 80%
4. Follow existing test patterns and naming conventions
