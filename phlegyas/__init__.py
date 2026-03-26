"""Phlegyas — AI-powered permission approver for Claude Code.

Three-tier intelligent evaluation pipeline:
  Tier 1: Instant denial of dangerous operations (regex pattern matching)
  Tier 2: Instant approval of known-safe operations (read-only, tests, builds)
  Tier 3: Claude AI evaluation for ambiguous cases with confidence thresholds

Named after Phlegyas, the ferryman of the river Styx in Dante's Inferno —
the gatekeeper who decides who may pass.
"""

# Single source of truth for hatch version extraction (regex-matched by hatchling).
__version__ = "0.3.0"

# Override with installed package metadata when available (editable/wheel installs).
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("phlegyas")
except PackageNotFoundError:
    pass
