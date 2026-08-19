"""
tests/test_audit_engine_selection.py -- unit tests for
_select_audit_engine() in devmind_server.py.

Covers the exact regression found and fixed this week: a first
attempt at wiring a durable audit trail passed
audit_engine=SupabaseAuditEngine() unconditionally, which silently
defeated GovernedSandbox's own fallback to local JSONL --
SupabaseAuditEngine() is never None as an object even when its
internal Supabase client is None (no credentials configured), so a
local dev instance without Supabase would have logged zero audit
records instead of falling back to a file as it always had before.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from devmind_server import _select_audit_engine


class TestSelectAuditEngine:
    def test_candidate_with_live_client_is_selected(self):
        candidate = SimpleNamespace(_client=object())
        result = _select_audit_engine(candidate)
        assert result is candidate

    def test_candidate_with_none_client_falls_back_to_none(self):
        """The exact regression: an object that exists but has no
        real Supabase client underneath must NOT be selected --
        returning it anyway is what silently dropped all audit
        records in the first (buggy) version of this fix."""
        candidate = SimpleNamespace(_client=None)
        result = _select_audit_engine(candidate)
        assert result is None

    def test_candidate_missing_client_attribute_falls_back_to_none(self):
        """Defensive: an object with no _client attribute at all
        (e.g. a different audit engine implementation) should also
        fall back safely rather than raising AttributeError."""
        candidate = object()
        result = _select_audit_engine(candidate)
        assert result is None

    def test_none_candidate_falls_back_to_none(self):
        result = _select_audit_engine(None)
        assert result is None