"""
tests/test_api_auth.py -- unit tests for resolve_org_from_token() in api.py.

This function has been patched twice this week (fail-closed auth,
then resource-binding symmetry) with zero dedicated test coverage
either time -- a regression here would only be caught by someone
manually re-running the same curl commands. These tests mock the
Supabase client entirely (chained .table().select().eq().single()
.execute() calls) so they run in CI with no network dependency,
matching how the rest of this function actually calls Supabase.
"""
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api as api_module


class FakeRequest:
    """Minimal stand-in for fastapi.Request -- only .headers is used."""

    def __init__(self, authorization: str | None = None):
        self.headers = {"authorization": authorization} if authorization else {}


def make_supabase_client(row: dict | None, raise_on_select: Exception | None = None):
    """
    Builds a MagicMock that mimics the exact chain
    client.table(...).select(...).eq(...).single().execute()
    used in resolve_org_from_token(), returning `row` as
    result.data, or raising raise_on_select if given.
    """
    client = MagicMock()
    query = client.table.return_value.select.return_value.eq.return_value.single.return_value
    if raise_on_select is not None:
        query.execute.side_effect = raise_on_select
    else:
        query.execute.return_value = SimpleNamespace(data=row)
    client.table.return_value.update.return_value.eq.return_value.execute.return_value = None
    return client


TOKEN = "dvm_testtoken123"
TOKEN_HASH = hashlib.sha256(TOKEN.encode()).hexdigest()


@pytest.fixture(autouse=True)
def restore_audit_client():
    """Every test sets api_module.audit._client directly; restore after."""
    original = api_module.audit._client
    yield
    api_module.audit._client = original


class TestMissingHeader:
    async def _call(self):
        return await api_module.resolve_org_from_token(FakeRequest())

    @pytest.mark.asyncio
    async def test_no_header_no_supabase_falls_back_to_body(self):
        api_module.audit._client = None
        result = await self._call()
        assert result is None

    @pytest.mark.asyncio
    async def test_no_header_with_supabase_raises_401(self):
        api_module.audit._client = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await self._call()
        assert exc_info.value.status_code == 401


class TestTokenPresentNoSupabase:
    @pytest.mark.asyncio
    async def test_token_sent_but_no_supabase_configured_fails_closed_503(self):
        api_module.audit._client = None
        with pytest.raises(HTTPException) as exc_info:
            await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert exc_info.value.status_code == 503


class TestTokenLookupFailure:
    @pytest.mark.asyncio
    async def test_supabase_query_exception_fails_closed_503(self):
        api_module.audit._client = make_supabase_client(
            row=None, raise_on_select=RuntimeError("connection reset")
        )
        with pytest.raises(HTTPException) as exc_info:
            await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert exc_info.value.status_code == 503


class TestRevokedOrMissingToken:
    @pytest.mark.asyncio
    async def test_no_matching_row_raises_401(self):
        api_module.audit._client = make_supabase_client(row=None)
        with pytest.raises(HTTPException) as exc_info:
            await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_revoked_token_raises_401(self):
        api_module.audit._client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": None, "revoked_at": "2026-01-01T00:00:00Z",
        })
        with pytest.raises(HTTPException) as exc_info:
            await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert exc_info.value.status_code == 401


class TestValidToken:
    @pytest.mark.asyncio
    async def test_unscoped_token_returns_org_and_agent(self):
        api_module.audit._client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": "loom", "resource": None, "revoked_at": None,
        })
        org_id, agent_id = await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert org_id == "org-1"
        assert agent_id == "loom"

    @pytest.mark.asyncio
    async def test_org_wide_token_has_none_agent_id(self):
        api_module.audit._client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None, "resource": None, "revoked_at": None,
        })
        org_id, agent_id = await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert agent_id is None


class TestResourceBindingSymmetry:
    """
    The fix added this week: a token scoped specifically to devmind-mcp
    must be rejected by the REST API, mirroring what
    SupabaseTokenVerifier already enforces in the other direction.
    """

    @pytest.mark.asyncio
    async def test_token_scoped_to_rest_resource_is_accepted(self):
        api_module.audit._client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": api_module.REST_RESOURCE_URL, "revoked_at": None,
        })
        org_id, _ = await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_scoped_to_mcp_resource_is_rejected(self):
        api_module.audit._client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": "https://devmind-mcp.onrender.com", "revoked_at": None,
        })
        with pytest.raises(HTTPException) as exc_info:
            await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert exc_info.value.status_code == 401
        assert "different resource" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_token_scoped_to_unrelated_resource_is_rejected(self):
        api_module.audit._client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": "https://some-other-service.example.com", "revoked_at": None,
        })
        with pytest.raises(HTTPException) as exc_info:
            await api_module.resolve_org_from_token(FakeRequest(f"Bearer {TOKEN}"))
        assert exc_info.value.status_code == 401