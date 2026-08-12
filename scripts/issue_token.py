"""
scripts/issue_token.py -- Issue a new per-organization API token for DevMind.

Usage:
    py scripts/issue_token.py <org_id> [label] [--resource <resource_server_url>]

Examples:
    py scripts/issue_token.py my-org "loom-local"
        -> unscoped token, valid against any DevMind backend (legacy behavior)

    py scripts/issue_token.py my-org "loom-mcp" --resource https://devmind-mcp.onrender.com
        -> only valid against the MCP server; rejected by the REST API

The raw token is printed ONCE and is never recoverable afterward --
only its SHA-256 hash is stored in Supabase. Save it somewhere safe
(a password manager, not a plaintext file in the repo).
"""
from __future__ import annotations

import os
import sys
import secrets
import hashlib


def generate_api_token() -> tuple[str, str]:
    raw_token = f"dvm_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def issue_token_for_org(org_id: str, label: str = "", resource: str | None = None) -> str:
    from supabase import create_client

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
    if not url or not key:
        raise SystemExit(
            "SUPABASE_URL and SUPABASE_KEY (or SUPABASE_SERVICE_KEY) "
            "must be set as environment variables."
        )
    client = create_client(url, key)
    raw_token, token_hash = generate_api_token()
    row = {
        "org_id": org_id,
        "token_hash": token_hash,
        "token_prefix": raw_token[:8],
        "label": label,
    }
    if resource:
        row["resource"] = resource
    client.table("api_credentials").insert(row).execute()
    return raw_token


def _parse_args(argv: list[str]) -> tuple[str, str, str | None]:
    if len(argv) < 1:
        print("Usage: py scripts/issue_token.py <org_id> [label] [--resource <resource_server_url>]")
        sys.exit(1)

    resource: str | None = None
    if "--resource" in argv:
        idx = argv.index("--resource")
        try:
            resource = argv[idx + 1]
        except IndexError:
            print("--resource requires a value")
            sys.exit(1)
        del argv[idx:idx + 2]

    org_id = argv[0]
    label = argv[1] if len(argv) > 1 else ""
    return org_id, label, resource


if __name__ == "__main__":
    org_id, label, resource = _parse_args(sys.argv[1:])
    token = issue_token_for_org(org_id, label, resource)
    print("Token issued. Save it now -- it will not be shown again:")
    print(token)
    if resource:
        print(f"Scoped to resource: {resource}")
    else:
        print("Unscoped (valid against any DevMind backend -- legacy behavior)")
