"""Phlegyas — AI-powered permission approver for Claude Code.

Three-tier intelligent evaluation pipeline:
  Tier 1: Instant denial of dangerous operations (regex pattern matching)
  Tier 2: Instant approval of known-safe operations (read-only, tests, builds)
  Tier 3: Claude AI evaluation for ambiguous cases with confidence thresholds

Named after Phlegyas, the ferryman of the river Styx in Dante's Inferno —
the gatekeeper who decides who may pass.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("phlegyas")
except PackageNotFoundError:
    # Fallback for editable installs or running from source without install.
    # Also serves as the single source of truth for hatch version extraction.
    __version__ = "0.3.0"
