"""
Tier 3: AI-Powered Evaluation

Uses Claude to evaluate ambiguous permission requests that don't clearly
fall into dangerous or safe categories.
"""

import json
import os
from typing import Any

from anthropic import Anthropic
from pydantic import BaseModel


class EvaluationResult(BaseModel):
    """Result of AI evaluation."""

    decision: str  # "approve", "deny", or "ask_user"
    category: str  # "benign", "moderate_risk", "high_risk", "critical"
    reasoning: str
    confidence: float  # 0.0-1.0
    suggested_message: str | None = None


class AIEvaluator:
    """Uses Claude AI to evaluate ambiguous permission requests."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-haiku-4-5-20251001",
        approval_threshold: float = 0.8,
        denial_threshold: float = 0.2,
    ):
        """
        Initialize AI evaluator.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Claude model to use (Haiku for speed/cost, Sonnet for complexity)
            approval_threshold: Minimum confidence for auto-approval
            denial_threshold: Maximum confidence for auto-denial
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

        self.client = Anthropic(api_key=self.api_key)
        self.model = model
        self.approval_threshold = approval_threshold
        self.denial_threshold = denial_threshold

        # Project context (can be overridden)
        self.project_name = os.getenv("PROJECT_NAME", "Unknown")
        self.project_type = os.getenv("PROJECT_TYPE", "Software project")
        self.current_task = os.getenv("CURRENT_TASK", "Development work")

    def close(self):
        """Close the underlying HTTP client to release connections."""
        if self.client:
            self.client.close()

    async def evaluate(
        self, tool_name: str, input_data: dict[str, Any]
    ) -> tuple[str, EvaluationResult]:
        """
        Evaluate a permission request using Claude AI.

        Args:
            tool_name: The tool being used
            input_data: The parameters for the tool

        Returns:
            Tuple of (decision, evaluation_result)
            - decision: "allow", "deny", or "ask_user"
            - evaluation_result: Full evaluation details
        """

        prompt = self._build_evaluation_prompt(tool_name, input_data)

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}],
            )

            # Parse Claude's response
            response_text = response.content[0].text
            evaluation = self._parse_evaluation(response_text)

            # Apply confidence thresholds
            decision = self._apply_thresholds(evaluation)

            return decision, evaluation

        except Exception as e:
            # If AI evaluation fails, escalate to human
            return "ask_user", EvaluationResult(
                decision="ask_user",
                category="critical",
                reasoning=f"AI evaluation failed: {str(e)}",
                confidence=0.0,
                suggested_message="AI evaluation service unavailable - manual approval required",
            )

    def _build_evaluation_prompt(self, tool_name: str, input_data: dict[str, Any]) -> str:
        """Build the evaluation prompt for Claude."""

        return f"""You are a security-focused approval system for Claude Code operations.

Your role is to evaluate whether a permission request should be:
- **approve**: Safe operation aligned with current task
- **deny**: Clearly dangerous or out of scope
- **ask_user**: Ambiguous, requires human judgment

**Permission Request:**
- Tool: {tool_name}
- Input: {json.dumps(input_data, indent=2)}

**Project Context:**
- Project: {self.project_name}
- Type: {self.project_type}
- Current Task: {self.current_task}

**Evaluation Guidelines:**

1. **approve** if:
   - Operation is clearly aligned with the current task
   - Risk is minimal or well-contained
   - Operation is reversible or has no side effects
   - Confidence ≥ {self.approval_threshold * 100}%

2. **deny** if:
   - Operation is clearly dangerous or destructive
   - Operation targets production systems without context
   - Operation violates security best practices
   - Operation is completely unrelated to stated task

3. **ask_user** if:
   - Ambiguous whether operation is appropriate
   - Requires domain knowledge to judge safety
   - Confidence < {self.approval_threshold * 100}%
   - High-stakes operation needing explicit approval

**Risk Categories:**
- **benign**: Read-only, no side effects
- **moderate_risk**: Writes to project files, config changes
- **high_risk**: Database operations, deployments, external API calls
- **critical**: Production changes, data deletion, credentials

**Required Response Format (JSON):**
{{
  "decision": "approve" | "deny" | "ask_user",
  "category": "benign" | "moderate_risk" | "high_risk" | "critical",
  "reasoning": "Brief explanation of your decision",
  "confidence": 0.0-1.0,
  "suggested_message": "Message to show user if escalating (optional)"
}}

**Examples:**

Tool: Bash, Command: "git status"
→ {{"decision": "approve", "category": "benign", "reasoning": "Read-only git operation", "confidence": 0.99}}

Tool: Bash, Command: "npm install lodash"
→ {{"decision": "approve", "category": "moderate_risk", "reasoning": "Package installation aligned with development", "confidence": 0.85}}

Tool: Edit, File: "src/services/AuthService.cs", Change: Renaming method
→ {{"decision": "ask_user", "category": "moderate_risk", "reasoning": "Code changes require contextual review", "confidence": 0.65}}

Tool: Bash, Command: "curl -X DELETE https://api.production.com/users/123"
→ {{"decision": "deny", "category": "critical", "reasoning": "DELETE to production API without context", "confidence": 0.95}}

Provide your evaluation now:"""

    def _parse_evaluation(self, response_text: str) -> EvaluationResult:
        """Parse Claude's JSON response into EvaluationResult."""
        import re

        try:
            # Strategy 1: Extract from markdown code blocks
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            elif "```" in response_text:
                json_start = response_text.find("```") + 3
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()

            # Strategy 2: Extract first complete JSON object using regex
            # This handles cases where Claude returns JSON followed by explanation text
            json_pattern = r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}"
            match = re.search(json_pattern, response_text, re.DOTALL)
            if match:
                response_text = match.group(0)

            data = json.loads(response_text)
            return EvaluationResult(**data)

        except (json.JSONDecodeError, ValueError) as e:
            # If parsing fails, return conservative ask_user
            return EvaluationResult(
                decision="ask_user",
                category="moderate_risk",
                reasoning=f"Failed to parse AI response: {str(e)}",
                confidence=0.5,
            )

    def _apply_thresholds(self, evaluation: EvaluationResult) -> str:
        """Apply confidence thresholds to AI decision."""

        # If AI says approve but confidence is low, escalate to human
        if evaluation.decision == "approve" and evaluation.confidence < self.approval_threshold:
            return "ask_user"

        # If AI says deny but confidence is low, escalate to human
        if evaluation.decision == "deny" and evaluation.confidence < self.approval_threshold:
            return "ask_user"

        # For critical operations, always escalate unless very high confidence
        if evaluation.category == "critical" and evaluation.confidence < 0.95:
            return "ask_user"

        return evaluation.decision

    def update_context(self, project_name: str | None = None, current_task: str | None = None):
        """Update project context for better evaluations."""
        if project_name:
            self.project_name = project_name
        if current_task:
            self.current_task = current_task
