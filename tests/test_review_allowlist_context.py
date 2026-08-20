"""
tests/test_review_allowlist_context.py -- confirms the two
classification branches execute_command's REVIEW message enrichment
relies on, using is_allowlisted() directly (no server, no network).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engines.allowlist import is_allowlisted


class TestAllowlistContextClassification:
    """
    Locks in the two branches execute_command's REVIEW message
    enrichment relies on: is_allowlisted() must correctly say
    "not recognized" for the known evasion pattern (unchanged
    behavior from the Phase 2 tests), and "recognized" for a command
    that IS in the allowlist -- both are prerequisites for the
    message enrichment in devmind_server.py to say the right thing.
    """

    def test_known_evasion_pattern_is_not_recognized(self):
        allowed, reason = is_allowlisted(r"find /tmp -type f -exec rm {} \;")
        assert allowed is False
        # Rejected either as unrecognized or as containing a shell
        # chaining character (";" is part of find's own -exec syntax
        # here) -- either reason is a correct rejection.
        assert reason in ("not in allowlist", "contains shell chaining/substitution -- not eligible for allowlist fast-path")

    def test_known_safe_command_is_recognized_with_category(self):
        allowed, reason = is_allowlisted("kubectl get pods")
        assert allowed is True
        assert reason == "diagnostic_investigation"