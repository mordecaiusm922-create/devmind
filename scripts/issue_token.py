"""
scripts/issue_token.py -- Issue a new per-organization API token for DevMind.

Usage:
    py scripts/issue_token.py <org_id> [label]

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


def issue_token_for_org(org_id: str, label: str = "") -> str:
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
    client.table("api_credentials").insert({
        "org_id": org_id,
        "token_hash": token_hash,
        "token_prefix": raw_token[:8],
        "label": label,
    }).execute()
    return raw_token


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: py scripts/issue_token.py <org_id> [label]")
        sys.exit(1)
    org_id = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else ""
    token = issue_token_for_org(org_id, label)
    print("Token issued. Save it now -- it will not be shown again:")
    print(token)
