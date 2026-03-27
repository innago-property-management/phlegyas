"""
Tests for the phlegyas-trust CLI (trust_cli.py).

Covers all four subcommands (trust, list, revoke, verify),
the argument parser, and the main() entry point.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from phlegyas.tier2_5_trust import ScriptTrustStore
from phlegyas.trust_cli import build_parser, cmd_list, cmd_revoke, cmd_trust, cmd_verify, main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    """Temporary trust store JSON path."""
    return tmp_path / "trusted-scripts.json"


@pytest.fixture
def store(store_path: Path) -> ScriptTrustStore:
    """ScriptTrustStore backed by a temp file with no on_change callback."""
    return ScriptTrustStore(store_path=store_path)


@pytest.fixture
def sample_script(tmp_path: Path) -> Path:
    """A real shell script file on disk."""
    script = tmp_path / "deploy.sh"
    script.write_text("#!/bin/bash\necho 'deploying'\n")
    return script


@pytest.fixture
def another_script(tmp_path: Path) -> Path:
    """A second shell script for multi-entry tests."""
    script = tmp_path / "lint.sh"
    script.write_text("#!/bin/bash\nruff check .\n")
    return script


# ---------------------------------------------------------------------------
# cmd_trust
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCmdTrust:
    """Tests for the trust subcommand."""

    def test_trust_script(self, store: ScriptTrustStore, sample_script: Path, capsys):
        """cmd_trust should add a script to the store and print its details."""
        args = build_parser().parse_args([str(sample_script), "--note", "deploy script"])
        rc = cmd_trust(args, store)

        assert rc == 0
        captured = capsys.readouterr()
        assert "Trusted:" in captured.out
        assert "sha256:" in captured.out
        assert "deploy script" in captured.out

        # Verify actually in store
        entries = store.list_trusted()
        assert str(sample_script.resolve()) in entries

    def test_trust_nonexistent_file(self, store: ScriptTrustStore, tmp_path: Path, capsys):
        """cmd_trust should print an error and return 1 for a missing file."""
        args = build_parser().parse_args([str(tmp_path / "ghost.sh")])
        rc = cmd_trust(args, store)

        assert rc == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

    def test_trust_without_note(self, store: ScriptTrustStore, sample_script: Path, capsys):
        """cmd_trust should work fine without --note."""
        args = build_parser().parse_args([str(sample_script)])
        rc = cmd_trust(args, store)

        assert rc == 0
        captured = capsys.readouterr()
        assert "Trusted:" in captured.out
        # Note line should not appear when note is empty
        assert "Note:" not in captured.out


# ---------------------------------------------------------------------------
# cmd_list
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCmdList:
    """Tests for the list subcommand."""

    def test_list_empty(self, store: ScriptTrustStore, capsys):
        """cmd_list should report no trusted scripts when store is empty."""
        rc = cmd_list(store)

        assert rc == 0
        captured = capsys.readouterr()
        assert "No trusted scripts" in captured.out

    def test_list_populated(
        self,
        store: ScriptTrustStore,
        sample_script: Path,
        another_script: Path,
        capsys,
    ):
        """cmd_list should print all trusted scripts with their metadata."""
        store.trust(str(sample_script), note="deploy")
        store.trust(str(another_script), note="lint")

        rc = cmd_list(store)

        assert rc == 0
        captured = capsys.readouterr()
        assert "Trusted scripts (2):" in captured.out
        assert "deploy" in captured.out
        assert "lint" in captured.out
        assert "sha256:" in captured.out


# ---------------------------------------------------------------------------
# cmd_revoke
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCmdRevoke:
    """Tests for the revoke subcommand."""

    def test_revoke_trusted_script(self, store: ScriptTrustStore, sample_script: Path, capsys):
        """cmd_revoke should remove a trusted script and return 0."""
        store.trust(str(sample_script))
        args = build_parser().parse_args(["--revoke", str(sample_script)])
        rc = cmd_revoke(args, store)

        assert rc == 0
        captured = capsys.readouterr()
        assert "Revoked:" in captured.out
        assert store.list_trusted() == {}

    def test_revoke_non_trusted_script(self, store: ScriptTrustStore, tmp_path: Path, capsys):
        """cmd_revoke should print an error and return 1 for unknown scripts."""
        args = build_parser().parse_args(["--revoke", str(tmp_path / "nope.sh")])
        rc = cmd_revoke(args, store)

        assert rc == 1
        captured = capsys.readouterr()
        assert "Not found" in captured.err


# ---------------------------------------------------------------------------
# cmd_verify
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCmdVerify:
    """Tests for the verify subcommand."""

    def test_verify_all_match(self, store: ScriptTrustStore, sample_script: Path, capsys):
        """cmd_verify should report success when all hashes match."""
        store.trust(str(sample_script))
        rc = cmd_verify(store)

        assert rc == 0
        captured = capsys.readouterr()
        assert "verified successfully" in captured.out

    def test_verify_hash_mismatch(self, store: ScriptTrustStore, sample_script: Path, capsys):
        """cmd_verify should detect a modified script and return 1."""
        store.trust(str(sample_script))
        sample_script.write_text("#!/bin/bash\nrm -rf /\n")  # modify after trust

        rc = cmd_verify(store)

        assert rc == 1
        captured = capsys.readouterr()
        assert "HASH CHANGED" in captured.err

    def test_verify_missing_file(self, store: ScriptTrustStore, sample_script: Path, capsys):
        """cmd_verify should detect a missing file and return 1."""
        store.trust(str(sample_script))
        sample_script.unlink()

        rc = cmd_verify(store)

        assert rc == 1
        captured = capsys.readouterr()
        assert "MISSING" in captured.err


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBuildParser:
    """Tests for the argument parser."""

    def test_parser_accepts_path(self):
        """Parser should accept a positional script path."""
        parser = build_parser()
        args = parser.parse_args(["/some/script.sh"])
        assert args.path == "/some/script.sh"

    def test_parser_accepts_note(self):
        """Parser should accept --note."""
        parser = build_parser()
        args = parser.parse_args(["/some/script.sh", "--note", "test note"])
        assert args.note == "test note"

    def test_parser_accepts_list(self):
        """Parser should accept --list."""
        parser = build_parser()
        args = parser.parse_args(["--list"])
        assert args.list is True

    def test_parser_accepts_revoke(self):
        """Parser should accept --revoke."""
        parser = build_parser()
        args = parser.parse_args(["--revoke", "/some/script.sh"])
        assert args.revoke == "/some/script.sh"

    def test_parser_accepts_verify(self):
        """Parser should accept --verify."""
        parser = build_parser()
        args = parser.parse_args(["--verify"])
        assert args.verify is True

    def test_parser_accepts_store(self):
        """Parser should accept --store for custom store path."""
        parser = build_parser()
        args = parser.parse_args(["--store", "/tmp/store.json", "/some/script.sh"])
        assert args.store == "/tmp/store.json"

    def test_list_and_revoke_mutually_exclusive(self):
        """--list, --revoke, --verify should be mutually exclusive."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--list", "--verify"])


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMain:
    """Tests for the main() CLI entry point."""

    @patch("phlegyas.trust_cli.pieces_checkpoint")
    def test_main_trust(self, mock_checkpoint, store_path: Path, sample_script: Path, capsys):
        """main() should trust a script via positional arg."""
        rc = main([str(sample_script), "--store", str(store_path)])

        assert rc == 0
        captured = capsys.readouterr()
        assert "Trusted:" in captured.out

    @patch("phlegyas.trust_cli.pieces_checkpoint")
    def test_main_list(self, mock_checkpoint, store_path: Path, capsys):
        """main() with --list should list trusted scripts."""
        rc = main(["--list", "--store", str(store_path)])

        assert rc == 0
        captured = capsys.readouterr()
        assert "No trusted scripts" in captured.out

    @patch("phlegyas.trust_cli.pieces_checkpoint")
    def test_main_revoke(self, mock_checkpoint, store_path: Path, sample_script: Path, capsys):
        """main() with --revoke should revoke a trusted script."""
        # First trust, then revoke
        main([str(sample_script), "--store", str(store_path)])
        rc = main(["--revoke", str(sample_script), "--store", str(store_path)])

        assert rc == 0
        captured = capsys.readouterr()
        assert "Revoked:" in captured.out

    @patch("phlegyas.trust_cli.pieces_checkpoint")
    def test_main_verify(self, mock_checkpoint, store_path: Path, sample_script: Path, capsys):
        """main() with --verify should verify all trusted scripts."""
        main([str(sample_script), "--store", str(store_path)])
        rc = main(["--verify", "--store", str(store_path)])

        assert rc == 0
        captured = capsys.readouterr()
        assert "verified successfully" in captured.out

    def test_main_no_args_prints_help(self, store_path: Path, capsys):
        """main() with no arguments should print help and return 0."""
        rc = main(["--store", str(store_path)])

        assert rc == 0
        captured = capsys.readouterr()
        assert "phlegyas-trust" in captured.out
