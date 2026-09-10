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
    # Added Sept 2026 -- found via the synthetic SRE-command stress
    # test (scripts/allowlist_stress_test.py): plausible, purely
    # read-only diagnostic commands with no allowlist coverage at all.
    ("crontab", "-l"),
    ("netstat",), ("ss",),
})

# --- Approved remediation: known, bounded-effect operational actions ---
APPROVED_REMEDIATION: frozenset[tuple[str, ...]] = frozenset({
    ("systemctl", "restart"),
    ("kubectl", "rollout", "restart"),
    ("git", "pull"), ("git", "fetch"),
    ("docker", "restart"),
    # Added Sept 2026 -- found via the synthetic SRE-command stress
    # test. Deliberately NOT adding "terraform apply" here even though
    # the same stress test flagged it as plausible-but-unlisted: unlike
    # every entry below (and unlike terraform plan/show, already in
    # DIAGNOSTIC_INVESTIGATION), apply's actual blast radius depends
    # entirely on the plan's contents -- it could be a harmless tag
    # change or a destroy, and the allowlist has no way to tell those
    # apart at the verb-prefix level. It continues to require REVIEW.
    ("kubectl", "scale"),
    ("kubectl", "rollout", "undo"),
    ("kubectl", "cordon"), ("kubectl", "drain"),
    ("nginx", "-s", "reload"),
    ("systemctl", "daemon-reload"),
})

# --- Capacity / SLO: read-only resource and capacity inspection ---
CAPACITY_SLO: frozenset[tuple[str, ...]] = frozenset({
    ("free",), ("top",), ("vmstat",), ("iostat",), ("nproc",),
    # Added Sept 2026 -- same stress test; these are the Kubernetes
    # equivalent of `top`/`free`, purely read-only resource inspection.
    ("kubectl", "top", "pods"), ("kubectl", "top", "nodes"),
})

_ALL_CATEGORIES: tuple[tuple[str, frozenset[tuple[str, ...]]], ...] = (
    ("diagnostic_investigation", DIAGNOSTIC_INVESTIGATION),
    ("approved_remediation", APPROVED_REMEDIATION),
    ("capacity_slo", CAPACITY_SLO),
)

# Longest prefix we bother checking (covers e.g. "aws s3 ls" = 3 tokens).
_MAX_PREFIX_LEN = 4

# --- Prefix-matching normalization (Sept 2026) -----------------------------
# is_allowlisted() only ever produces a fail-safe outcome when it gets this
# wrong: a false negative just falls through to the normal REVIEW path (the
# existing default), never a false ALLOW. That asymmetry is what makes it
# safe to be pragmatic/heuristic here, unlike the blocklist signal patterns
# in policy_engine.py, which need to be precise since a false negative
# there really does mean something dangerous slips through.
#
# Found via a synthetic SRE-command stress test
# (scripts/allowlist_stress_test.py): a `sudo` prefix, a `time`/`watch`
# wrapper, a leading env-var assignment (KUBECONFIG=... kubectl ...), or a
# tool's own flag appearing between the base command and its verb
# (`kubectl -n production get pods`, `git --no-pager log`) all defeated the
# purely-positional prefix match even though the underlying command was
# identical to one already on the list.
_LEADING_WRAPPERS = {"sudo", "nohup", "nice", "ionice", "time"}
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VALUE_TAKING_LONG_FLAGS = {"--namespace", "--context", "--kubeconfig", "--interval", "--tail"}
# Only tools whose OWN category entries actually use a multi-token
# (base command + verb) shape need "skip flags before the verb"
# handling -- and only when that second token is a genuine verb word,
# not itself a flag (nginx's "-s reload" and crontab's "-l" ARE the
# meaningful operation identity, not scaffolding to skip past; curl's
# only entry, "-I", has the same shape). Single-word entries (ls, cat,
# df, ps, ...) have no verb position to find at all, so leaving their
# own flags alone (df -h, ps aux) is both correct and avoids any
# needless transformation of tokens that already match fine.
_SUBCOMMAND_TOOLS = frozenset(
    prefix[0]
    for _, category_set in _ALL_CATEGORIES
    for prefix in category_set
    if len(prefix) > 1 and not prefix[1].startswith("-")
)


def _normalize_tokens(tokens: list[str]) -> list[str]:
    """Strips benign wrapper prefixes and in-between flags that a real
    SRE routinely types but which would otherwise defeat an
    otherwise-exact allowlist match. See the module-level comment
    above for the safety argument (fail-safe by construction)."""
    tokens = list(tokens)

    changed = True
    while changed and tokens:
        changed = False
        if tokens[0] in _LEADING_WRAPPERS:
            tokens.pop(0)
            changed = True
        elif _ENV_ASSIGNMENT.match(tokens[0]):
            tokens.pop(0)
            changed = True

    if tokens and tokens[0] == "watch":
        tokens.pop(0)
        while tokens and tokens[0].startswith("-"):
            flag = tokens.pop(0)
            if flag in ("-n", "--interval") and tokens:
                tokens.pop(0)

    if len(tokens) > 1 and tokens[0] in _SUBCOMMAND_TOOLS:
        i = 1
        while i < len(tokens) and tokens[i].startswith("-"):
            flag = tokens[i]
            i += 1
            is_short_flag = re.fullmatch(r"-[a-zA-Z]", flag) is not None
            takes_value = (is_short_flag or flag in _VALUE_TAKING_LONG_FLAGS) and "=" not in flag
            if takes_value and i < len(tokens) and not tokens[i].startswith("-"):
                i += 1
        if i > 1:
            tokens = [tokens[0]] + tokens[i:]

    return tokens


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

    tokens = _normalize_tokens(tokens)
    if not tokens:
        return False, "empty command after normalization"

    for length in range(min(_MAX_PREFIX_LEN, len(tokens)), 0, -1):
        prefix = tuple(tokens[:length])
        for category_name, category_set in _ALL_CATEGORIES:
            if prefix in category_set:
                return True, category_name

    return False, "not in allowlist"