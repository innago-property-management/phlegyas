"""
Tests for Tier 3: AI-Powered Evaluation

Tests for AI evaluation of ambiguous permission requests.
"""

import json

import pytest

from src.tier3_ai import AIEvaluator, EvaluationResult


class TestAIEvaluator:
    """Test suite for AIEvaluator."""

    @pytest.fixture
    def evaluator(self, mock_env_vars):
        """Create an AIEvaluator instance with mocked API key."""
        return AIEvaluator(
            api_key="sk-ant-test-key",
            model="claude-haiku-4-5-20251001",
            approval_threshold=0.8,
            denial_threshold=0.2,
        )

    # Initialization Tests

    def test_should_initialize_with_api_key(self):
        """Should initialize with explicit API key."""
        evaluator = AIEvaluator(api_key="sk-ant-test")
        assert evaluator.api_key == "sk-ant-test"
        assert evaluator.model == "claude-haiku-4-5-20251001"

    def test_should_initialize_with_env_var(self, mock_env_vars):
        """Should initialize with ANTHROPIC_API_KEY environment variable."""
        evaluator = AIEvaluator()
        assert evaluator.api_key == "sk-ant-test-key-123"

    def test_should_raise_error_without_api_key(self, monkeypatch):
        """Should raise error if no API key provided."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            AIEvaluator()

    def test_should_set_custom_thresholds(self):
        """Should accept custom confidence thresholds."""
        evaluator = AIEvaluator(api_key="sk-ant-test", approval_threshold=0.9, denial_threshold=0.1)
        assert evaluator.approval_threshold == 0.9
        assert evaluator.denial_threshold == 0.1

    def test_should_load_project_context_from_env(self, mock_env_vars):
        """Should load project context from environment variables."""
        evaluator = AIEvaluator(api_key="sk-ant-test")
        assert evaluator.project_name == "TestProject"
        assert evaluator.project_type == "Test Software Project"
        assert evaluator.current_task == "Testing permission system"

    # Evaluation Prompt Building Tests

    def test_should_build_evaluation_prompt(self, evaluator):
        """Should build complete evaluation prompt."""
        prompt = evaluator._build_evaluation_prompt("Bash", {"command": "ls -la"})
        assert "Bash" in prompt
        assert "ls -la" in prompt
        assert "TestProject" in prompt
        assert "approve" in prompt
        assert "deny" in prompt
        assert "ask_user" in prompt

    def test_should_include_confidence_thresholds_in_prompt(self, evaluator):
        """Should include confidence thresholds in prompt."""
        prompt = evaluator._build_evaluation_prompt("Bash", {"command": "test"})
        assert "80" in prompt  # 0.8 * 100 = 80%

    def test_should_include_project_context_in_prompt(self, evaluator):
        """Should include project context in prompt."""
        prompt = evaluator._build_evaluation_prompt("Write", {"file_path": "test.txt"})
        assert evaluator.project_name in prompt
        assert evaluator.project_type in prompt
        assert evaluator.current_task in prompt

    # Response Parsing Tests

    def test_should_parse_json_response(self, evaluator):
        """Should parse valid JSON response."""
        response_text = json.dumps(
            {
                "decision": "approve",
                "category": "benign",
                "reasoning": "Test reasoning",
                "confidence": 0.9,
            }
        )
        result = evaluator._parse_evaluation(response_text)
        assert isinstance(result, EvaluationResult)
        assert result.decision == "approve"
        assert result.category == "benign"
        assert result.reasoning == "Test reasoning"
        assert result.confidence == 0.9

    def test_should_parse_markdown_wrapped_json(self, evaluator):
        """Should parse JSON wrapped in markdown code blocks."""
        response_text = """```json
{
  "decision": "deny",
  "category": "critical",
  "reasoning": "Too dangerous",
  "confidence": 0.95
}
```"""
        result = evaluator._parse_evaluation(response_text)
        assert result.decision == "deny"
        assert result.category == "critical"
        assert result.confidence == 0.95

    def test_should_parse_generic_markdown_wrapped_json(self, evaluator):
        """Should parse JSON wrapped in generic markdown blocks."""
        response_text = """```
{
  "decision": "ask_user",
  "category": "moderate_risk",
  "reasoning": "Unclear",
  "confidence": 0.6
}
```"""
        result = evaluator._parse_evaluation(response_text)
        assert result.decision == "ask_user"
        assert result.category == "moderate_risk"

    def test_should_handle_invalid_json(self, evaluator):
        """Should return conservative ask_user for invalid JSON."""
        result = evaluator._parse_evaluation("This is not JSON")
        assert result.decision == "ask_user"
        assert result.category == "moderate_risk"
        assert "Failed to parse" in result.reasoning
        assert result.confidence == 0.5

    def test_should_handle_missing_fields(self, evaluator):
        """Should handle JSON with missing required fields."""
        response_text = json.dumps({"decision": "approve"})  # Missing other fields
        result = evaluator._parse_evaluation(response_text)
        # Pydantic validation should fail, should return ask_user
        assert result.decision == "ask_user"

    def test_should_parse_suggested_message(self, evaluator):
        """Should parse optional suggested_message field."""
        response_text = json.dumps(
            {
                "decision": "ask_user",
                "category": "high_risk",
                "reasoning": "Needs review",
                "confidence": 0.7,
                "suggested_message": "Please review this operation",
            }
        )
        result = evaluator._parse_evaluation(response_text)
        assert result.suggested_message == "Please review this operation"

    # Threshold Application Tests

    def test_should_approve_with_high_confidence(self, evaluator):
        """Should approve when confidence meets threshold."""
        evaluation = EvaluationResult(
            decision="approve",
            category="benign",
            reasoning="Safe operation",
            confidence=0.9,  # Above 0.8 threshold
        )
        decision = evaluator._apply_thresholds(evaluation)
        assert decision == "approve"

    def test_should_escalate_approve_with_low_confidence(self, evaluator):
        """Should escalate to ask_user when approve confidence is low."""
        evaluation = EvaluationResult(
            decision="approve",
            category="moderate_risk",
            reasoning="Somewhat safe",
            confidence=0.7,  # Below 0.8 threshold
        )
        decision = evaluator._apply_thresholds(evaluation)
        assert decision == "ask_user"

    def test_should_deny_with_high_confidence(self, evaluator):
        """Should deny when confidence is high."""
        evaluation = EvaluationResult(
            decision="deny",
            category="high_risk",
            reasoning="Dangerous operation",
            confidence=0.9,
        )
        decision = evaluator._apply_thresholds(evaluation)
        assert decision == "deny"

    def test_should_escalate_deny_with_low_confidence(self, evaluator):
        """Should escalate deny to ask_user when confidence is low."""
        evaluation = EvaluationResult(
            decision="deny",
            category="moderate_risk",
            reasoning="Possibly dangerous",
            confidence=0.6,  # Below 0.8 threshold
        )
        decision = evaluator._apply_thresholds(evaluation)
        assert decision == "ask_user"

    def test_should_escalate_critical_operations(self, evaluator):
        """Should escalate critical operations unless very high confidence."""
        evaluation = EvaluationResult(
            decision="approve",
            category="critical",
            reasoning="Critical operation",
            confidence=0.85,  # Below 0.95 for critical
        )
        decision = evaluator._apply_thresholds(evaluation)
        assert decision == "ask_user"

    def test_should_allow_critical_with_very_high_confidence(self, evaluator):
        """Should allow critical operations with very high confidence (≥0.95)."""
        evaluation = EvaluationResult(
            decision="approve",
            category="critical",
            reasoning="Critical but safe",
            confidence=0.96,
        )
        decision = evaluator._apply_thresholds(evaluation)
        assert decision == "approve"

    def test_should_preserve_ask_user_decision(self, evaluator):
        """Should preserve ask_user decision from AI."""
        evaluation = EvaluationResult(
            decision="ask_user",
            category="moderate_risk",
            reasoning="Ambiguous",
            confidence=0.7,
        )
        decision = evaluator._apply_thresholds(evaluation)
        assert decision == "ask_user"

    # Full Evaluation Tests (with mocked API)

    @pytest.mark.asyncio
    async def test_should_evaluate_and_approve(self, evaluator, mock_anthropic_response, mocker):
        """Should evaluate operation and return approval."""
        mock_response = mock_anthropic_response(
            decision="approve", category="benign", reasoning="Safe operation", confidence=0.9
        )
        mocker.patch.object(evaluator.client.messages, "create", return_value=mock_response)

        decision, evaluation = await evaluator.evaluate("Bash", {"command": "ls -la"})
        assert decision == "approve"
        assert evaluation.decision == "approve"
        assert evaluation.confidence == 0.9

    @pytest.mark.asyncio
    async def test_should_evaluate_and_deny(self, evaluator, mock_anthropic_response, mocker):
        """Should evaluate operation and return denial."""
        mock_response = mock_anthropic_response(
            decision="deny",
            category="critical",
            reasoning="Dangerous operation",
            confidence=0.95,
        )
        mocker.patch.object(evaluator.client.messages, "create", return_value=mock_response)

        decision, evaluation = await evaluator.evaluate("Bash", {"command": "rm -rf /"})
        assert decision == "deny"
        assert evaluation.category == "critical"

    @pytest.mark.asyncio
    async def test_should_evaluate_and_ask_user(self, evaluator, mock_anthropic_response, mocker):
        """Should evaluate operation and escalate to user."""
        mock_response = mock_anthropic_response(
            decision="ask_user",
            category="moderate_risk",
            reasoning="Ambiguous operation",
            confidence=0.6,
        )
        mocker.patch.object(evaluator.client.messages, "create", return_value=mock_response)

        decision, evaluation = await evaluator.evaluate("Edit", {"file_path": "config.json"})
        assert decision == "ask_user"

    @pytest.mark.asyncio
    async def test_should_handle_api_error(self, evaluator, mocker):
        """Should handle API errors gracefully."""
        mocker.patch.object(
            evaluator.client.messages,
            "create",
            side_effect=Exception("API connection failed"),
        )

        decision, evaluation = await evaluator.evaluate("Bash", {"command": "test"})
        assert decision == "ask_user"
        assert evaluation.category == "critical"
        assert "AI evaluation failed" in evaluation.reasoning

    @pytest.mark.asyncio
    async def test_should_escalate_low_confidence_approval(
        self, evaluator, mock_anthropic_response, mocker
    ):
        """Should escalate to ask_user when approval confidence is low."""
        mock_response = mock_anthropic_response(
            decision="approve",
            category="moderate_risk",
            reasoning="Probably safe",
            confidence=0.7,  # Below threshold
        )
        mocker.patch.object(evaluator.client.messages, "create", return_value=mock_response)

        decision, evaluation = await evaluator.evaluate("Write", {"file_path": "test.txt"})
        assert decision == "ask_user"  # Escalated due to low confidence

    @pytest.mark.asyncio
    async def test_should_parse_markdown_wrapped_response(
        self, evaluator, mock_anthropic_response_with_markdown, mocker
    ):
        """Should handle markdown-wrapped JSON responses."""
        mock_response = mock_anthropic_response_with_markdown(
            decision="approve", category="benign", reasoning="Safe", confidence=0.85
        )
        mocker.patch.object(evaluator.client.messages, "create", return_value=mock_response)

        decision, evaluation = await evaluator.evaluate("Bash", {"command": "pwd"})
        assert decision == "approve"
        assert evaluation.confidence == 0.85

    # Context Update Tests

    def test_should_update_project_name(self, evaluator):
        """Should update project name context."""
        evaluator.update_context(project_name="NewProject")
        assert evaluator.project_name == "NewProject"

    def test_should_update_current_task(self, evaluator):
        """Should update current task context."""
        evaluator.update_context(current_task="New task")
        assert evaluator.current_task == "New task"

    def test_should_update_both_context_fields(self, evaluator):
        """Should update multiple context fields."""
        evaluator.update_context(project_name="UpdatedProject", current_task="Updated task")
        assert evaluator.project_name == "UpdatedProject"
        assert evaluator.current_task == "Updated task"

    def test_should_preserve_context_when_none(self, evaluator):
        """Should preserve existing context when None is passed."""
        original_project = evaluator.project_name
        original_task = evaluator.current_task
        evaluator.update_context(project_name=None, current_task=None)
        assert evaluator.project_name == original_project
        assert evaluator.current_task == original_task

    # EvaluationResult Model Tests

    def test_evaluation_result_required_fields(self):
        """Should create EvaluationResult with required fields."""
        result = EvaluationResult(
            decision="approve", category="benign", reasoning="Test", confidence=0.9
        )
        assert result.decision == "approve"
        assert result.category == "benign"
        assert result.reasoning == "Test"
        assert result.confidence == 0.9
        assert result.suggested_message is None

    def test_evaluation_result_with_suggested_message(self):
        """Should create EvaluationResult with optional suggested_message."""
        result = EvaluationResult(
            decision="ask_user",
            category="high_risk",
            reasoning="Test",
            confidence=0.7,
            suggested_message="Please review",
        )
        assert result.suggested_message == "Please review"
