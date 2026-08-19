"""
tests/test_mcp_token_verifier.py -- unit tests for
SupabaseTokenVerifier.verify_token() in devmind_server.py.

Mirrors tests/test_api_auth.py for the REST side. Note the interface
difference: verify_token() returns None on any failure (per the MCP
SDK's TokenVerifier contract) rather than raising HTTPException like
resolve_org_from_token() does -- these are two different auth
functions with two different failure conventions, both need their
own coverage.
"""
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import devmind_server


def make_supabase_client(row: dict | None, raise_on_select: Exception | None = None):
    client = MagicMock()
    query = client.table.return_value.select.return_value.eq.return_value.single.return_value
    if raise_on_select is not None:
        query.execute.side_effect = raise_on_select
    else:
        query.execute.return_value = SimpleNamespace(data=row)
    client.table.return_value.update.return_value.eq.return_value.execute.return_value = None
    return client


TOKEN = "dvm_testtoken456"


def make_verifier(client) -> devmind_server.SupabaseTokenVerifier:
    """Build a SupabaseTokenVerifier with its internal Supabase client
    swapped for a mock, without touching real credentials."""
    verifier = devmind_server.SupabaseTokenVerifier()
    verifier._audit._client = client
    return verifier


class TestNoSupabaseConfigured:
    @pytest.mark.asyncio
    async def test_no_client_returns_none(self):
        verifier = make_verifier(None)
        result = await verifier.verify_token(TOKEN)
        assert result is None


class TestLookupFailure:
    @pytest.mark.asyncio
    async def test_query_exception_returns_none(self):
        client = make_supabase_client(row=None, raise_on_select=RuntimeError("timeout"))
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is None


class TestRevokedOrMissingToken:
    @pytest.mark.asyncio
    async def test_no_matching_row_returns_none(self):
        client = make_supabase_client(row=None)
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is None

    @pytest.mark.asyncio
    async def test_revoked_token_returns_none(self):
        client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": None, "revoked_at": "2026-01-01T00:00:00Z",
        })
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is None


class TestValidToken:
    @pytest.mark.asyncio
    async def test_unscoped_token_returns_access_token_with_agent_as_client_id(self):
        client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": "loom", "resource": None, "revoked_at": None,
        })
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is not None
        assert result.token == TOKEN
        assert result.client_id == "loom"
        assert result.scopes == []

    @pytest.mark.asyncio
    async def test_org_wide_token_falls_back_to_org_id_as_client_id(self):
        client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None, "resource": None, "revoked_at": None,
        })
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is not None
        assert result.client_id == "org-1"


class TestResourceBindingSymmetry:
    """
    The other half of the Resource Indicators check tested in
    tests/test_api_auth.py: a token bound to a resource other than
    this MCP server (e.g. scoped specifically to the REST API) must
    be rejected here too.
    """

    @pytest.mark.asyncio
    async def test_token_scoped_to_mcp_resource_is_accepted(self):
        client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": devmind_server.MCP_RESOURCE_URL, "revoked_at": None,
        })
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is not None

    @pytest.mark.asyncio
    async def test_token_scoped_to_rest_resource_is_rejected(self):
        client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": "https://devmind-2cej.onrender.com", "revoked_at": None,
        })
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is None

    @pytest.mark.asyncio
    async def test_token_scoped_to_unrelated_resource_is_rejected(self):
        client = make_supabase_client(row={
            "org_id": "org-1", "agent_id": None,
            "resource": "https://some-other-service.example.com", "revoked_at": None,
        })
        verifier = make_verifier(client)
        result = await verifier.verify_token(TOKEN)
        assert result is None