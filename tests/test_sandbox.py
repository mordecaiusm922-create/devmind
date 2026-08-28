"""
tests/test_sandbox.py -- DevMind Agent Governance
Regression coverage for runtime/sandbox.py::DevMindSandbox.

Point 3 of NEXT STEPS (2026-08-23 snapshot). No dedicated test file for
sandbox.py existed before this one -- flagged explicitly as a follow-up
in commit 33600c2 ("no dedicated test for this helper yet, tracked as
follow-up").

Context: agent_sessions.org_id is a Supabase column typed UUID.
_persist_session used to guard against the sentinel "default" by
comparing the literal string -- but the real default used elsewhere in
the codebase is "devmind-default", a different string the guard never
matched. Every session-persist write failed silently with "invalid
input syntax for type uuid" on every single request. Fixed in 33600c2
by replacing the string comparison with _is_org_id_a_valid_uuid(), which
actually parses the value.

Two layers here, same discipline as the evasion-regression suite:
  1. Unit tests directly on the static helper -- fast, exhaustive on
     edge cases.
  2. An integration-level test against _persist_session itself, using a
     fake Supabase client that records the exact dict passed to
     .upsert(). This is the layer that would have caught the original
     bug: a helper can be unit-correct while the call site still misuses
     it (e.g. inverts the condition, or checks the wrong attribute).
"""
import sys
import uuid as uuid_module
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.types import AgentSession, SessionRiskProfile, SessionState
from runtime.sandbox import DevMindSandbox


# =============================================================================
# Layer 1 -- unit tests on the static helper
# =============================================================================

class TestIsOrgIdAValidUuid:

    def test_real_uuid_returns_true(self) -> None:
        real_uuid = str(uuid_module.uuid4())
        assert DevMindSandbox._is_org_id_a_valid_uuid(real_uuid) is True

    def test_real_uuid_uppercase_returns_true(self) -> None:
        """uuid.UUID() is case-insensitive on hex digits -- confirm the
        helper doesn't reject a validly-formatted but uppercase UUID."""
        real_uuid = str(uuid_module.uuid4()).upper()
        assert DevMindSandbox._is_org_id_a_valid_uuid(real_uuid) is True

    def test_devmind_default_sentinel_returns_false(self) -> None:
        """The exact sentinel that caused the silent production failure:
        devmind_server.py's real default, which the old ' != "default" '
        string comparison never matched."""
        assert DevMindSandbox._is_org_id_a_valid_uuid("devmind-default") is False

    def test_bare_default_sentinel_returns_false(self) -> None:
        """The old sentinel the original (buggy) guard did match --
        confirms the fix didn't regress the case it used to handle."""
        assert DevMindSandbox._is_org_id_a_valid_uuid("default") is False

    def test_empty_string_returns_false(self) -> None:
        assert DevMindSandbox._is_org_id_a_valid_uuid("") is False

    def test_none_returns_false(self) -> None:
        """org_id is typed str, but defensively confirm a None value
        (e.g. from a misconfigured caller) doesn't raise -- it should be
        treated as not-a-valid-uuid, not blow up _persist_session."""
        assert DevMindSandbox._is_org_id_a_valid_uuid(None) is False

    def test_uuid_like_but_wrong_length_returns_false(self) -> None:
        assert DevMindSandbox._is_org_id_a_valid_uuid("12345678-1234-1234-1234") is False

    def test_arbitrary_org_slug_returns_false(self) -> None:
        """A realistic non-UUID org identifier a caller might pass,
        e.g. a human-readable org slug -- must be treated as invalid,
        not accidentally coerced to True."""
        assert DevMindSandbox._is_org_id_a_valid_uuid("acme-corp") is False


# =============================================================================
# Layer 2 -- integration: _persist_session actually calls the helper
# correctly and sends the right thing to Supabase
# =============================================================================

class _FakeUpsertResult:
    def __init__(self, data):
        self.data = data


class _FakeQuery:
    def __init__(self, captured: dict, table_name: str, row: dict) -> None:
        self._captured = captured
        self._table_name = table_name
        self._row = row

    def execute(self):
        self._captured["table"] = self._table_name
        self._captured["row"] = self._row
        return _FakeUpsertResult(data=[self._row])


class _FakeTable:
    def __init__(self, captured: dict, table_name: str) -> None:
        self._captured = captured
        self._table_name = table_name

    def upsert(self, row: dict):
        return _FakeQuery(self._captured, self._table_name, row)


class _FakeSupabaseClient:
    def __init__(self) -> None:
        self.captured: dict = {}

    def table(self, name: str):
        return _FakeTable(self.captured, name)


class _FakeAuditEngine:
    """Minimal stand-in exposing only what _supabase_client() reads."""
    def __init__(self, client) -> None:
        self._client = client


def _make_session(session_id: str = "s1") -> AgentSession:
    return AgentSession(
        session_id=session_id,
        agent="test-agent",
        organization="org-1",
        user=None,
        started_at=datetime.now(timezone.utc),
        state=SessionState.ACTIVE,
        risk_profile=SessionRiskProfile(),
    )


class TestPersistSessionOrgIdHandling:

    def test_invalid_org_id_persists_as_none_not_the_raw_string(self) -> None:
        """REGRESSION (33600c2): this is the exact failure mode. Before
        the fix, org_id="devmind-default" was sent to Supabase as the
        literal string, which the UUID-typed column rejected -- and the
        write failed silently (caught by the bare except Exception,
        never surfaced to the caller)."""
        client = _FakeSupabaseClient()
        sandbox = DevMindSandbox(org_id="devmind-default", audit_engine=_FakeAuditEngine(client))

        sandbox._persist_session(_make_session())

        assert client.captured, "upsert().execute() was never called"
        assert client.captured["table"] == "agent_sessions"
        assert client.captured["row"]["org_id"] is None, (
            f"REGRESSION: non-UUID org_id must be sent as None, got "
            f"{client.captured['row']['org_id']!r}"
        )

    def test_valid_uuid_org_id_is_passed_through_unchanged(self) -> None:
        client = _FakeSupabaseClient()
        real_uuid = str(uuid_module.uuid4())
        sandbox = DevMindSandbox(org_id=real_uuid, audit_engine=_FakeAuditEngine(client))

        sandbox._persist_session(_make_session())

        assert client.captured["row"]["org_id"] == real_uuid

    def test_bare_default_sentinel_also_persists_as_none(self) -> None:
        """The pre-fix guard's one hardcoded case must still work post-fix."""
        client = _FakeSupabaseClient()
        sandbox = DevMindSandbox(org_id="default", audit_engine=_FakeAuditEngine(client))

        sandbox._persist_session(_make_session())

        assert client.captured["row"]["org_id"] is None

    def test_no_supabase_client_is_a_silent_noop(self) -> None:
        """With no Supabase-backed audit engine, _persist_session must
        not raise -- session state simply stays in-memory only (the
        documented behavior, unrelated to the UUID bug but worth
        pinning so a future change doesn't make this path start
        assuming a client is always present)."""
        sandbox = DevMindSandbox(org_id="devmind-default")
        sandbox._persist_session(_make_session())  # must not raise