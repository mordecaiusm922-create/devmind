"""
engines/allowlist.py -- Allowlist for the terminal/filesystem surface.

Phase 2 of the terminal/filesystem hardening plan. Where SIGNALS in
policy_engine.py is a blocklist ("deny what looks bad"), this module
is the opposite model: "allow only what is explicitly recognized as
safe, everything else goes to REVIEW." The blocklist approach was
proven to have real gaps (5 confirmed evasions: find -exec, dd,
fork bomb, redirection truncation, reverse shell) because it can
only ever cover patterns someone thought to write a regex for.

Categories are organized around what actually remains of the SRE /
platform engineer role in 2026 as AI agents absorb first-pass
investigation and routine remediation (per industry research: SRE
work is shifting from manual triage to supervising/constraining the
agents that now do the triage) -- not a generic list of "safe-ish"
Linux commands:

  - DIAGNOSTIC_INVESTIGATION: read-only, zero side effects. The
    "log archaeology" and status-checking work agents already do.
  - APPROVED_REMEDIATION: known, bounded-effect operational actions
    (the industry's own term for this pattern -- PagerDuty
    documents agents "running approved remediations").
  - CAPACITY_SLO: read-only capacity/resource inspection.

This module does NOT enforce anything by itself -- it only
classifies. Wiring it into intercept() (in shadow mode first, then
enforce mode) is a separate step.
"""
from __future__ import annotations

import re
import shlex

# Any of these appearing in the raw command string disqualifies it
# from the allowlist fast-path outright, regardless of what command
# comes before or after. None of the categories below need shell
# chaining/substitution to do their job -- if a real use case needs
# it later, it gets added deliberately, not accepted by default.
_CHAIN_OPERATORS = re.compile(r"[;&|`]|\$\(|<\(|>\(")


# --- Diagnostic / investigation: read-only, no side effects ---
DIAGNOSTIC_INVESTIGATION: frozenset[tuple[str, ...]] = frozenset({
    ("ls",), ("cat",), ("grep",), ("head",), ("tail",),
    ("ps",), ("df",), ("du",),
    ("pwd",), ("whoami",), ("uptime",), ("uname",),
    ("systemctl", "status"),
    ("journalctl",),
    ("kubectl", "get"), ("kubectl", "describe"), ("kubectl", "logs"),
    ("git", "status"), ("git", "log"), ("git", "diff"),
    ("git", "show"), ("git", "branch"),
    ("terraform", "plan"), ("terraform", "show"), ("terraform", "state", "list"),
    ("dig",), ("nslookup",), ("ping",), ("traceroute",),
    ("curl", "-I"),
    ("helm", "list"), ("helm", "status"), ("helm", "get"),
    ("docker", "ps"), ("docker", "logs"), ("docker", "inspect"),
    ("aws", "s3", "ls"), ("aws", "ec2", "describe-instances"),
})

# --- Approved remediation: known, bounded-effect operational actions ---
APPROVED_REMEDIATION: frozenset[tuple[str, ...]] = frozenset({
    ("systemctl", "restart"),
    ("kubectl", "rollout", "restart"),
    ("git", "pull"), ("git", "fetch"),
    ("docker", "restart"),
})

# --- Capacity / SLO: read-only resource and capacity inspection ---
CAPACITY_SLO: frozenset[tuple[str, ...]] = frozenset({
    ("free",), ("top",), ("vmstat",), ("iostat",), ("nproc",),
})

_ALL_CATEGORIES: tuple[tuple[str, frozenset[tuple[str, ...]]], ...] = (
    ("diagnostic_investigation", DIAGNOSTIC_INVESTIGATION),
    ("approved_remediation", APPROVED_REMEDIATION),
    ("capacity_slo", CAPACITY_SLO),
)

# Longest prefix we bother checking (covers e.g. "aws s3 ls" = 3 tokens).
_MAX_PREFIX_LEN = 4


def is_allowlisted(command: str) -> tuple[bool, str]:
    """
    Classify a terminal command against the allowlist.

    Returns (allowed, reason). reason is the matched category name
    when allowed=True, or a short explanation when allowed=False.
    This function only classifies -- it does not enforce anything.
    """
    if not command or not command.strip():
        return False, "empty command"

    if _CHAIN_OPERATORS.search(command):
        return False, "contains shell chaining/substitution -- not eligible for allowlist fast-path"

    try:
        tokens = shlex.split(command)
    except ValueError as e:
        return False, f"unparseable command: {e}"

    if not tokens:
        return False, "empty command after parsing"

    for length in range(min(_MAX_PREFIX_LEN, len(tokens)), 0, -1):
        prefix = tuple(tokens[:length])
        for category_name, category_set in _ALL_CATEGORIES:
            if prefix in category_set:
                return True, category_name

    return False, "not in allowlist"