"""
tests/run_eval.py — DevMind PR Summarizer evaluation suite.

Usage (from devmind/backend/):

    # Full suite
    python tests/run_eval.py

    # Filter by category
    python tests/run_eval.py tiny high-risk

    # Debug mode — prints raw Claude response + parsed JSON + pre_analysis
    python tests/run_eval.py --debug

    # Debug a single category
    python tests/run_eval.py --debug high-risk

    # Run only dampening verification
    python tests/run_eval.py --dampening

Requires GITHUB_TOKEN and ANTHROPIC_API_KEY in backend/.env
Calls the REAL pipeline — no mocks.
"""

import sys
import os
import json
import time
import textwrap
import traceback
from dataclasses import dataclass

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, BACKEND_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(BACKEND_DIR, ".env"))

import summarizer as _summarizer_mod
from github import get_pr_data
from summarizer import summarize_pr
from evaluator import usefulness_check, TRIVIAL_CHURN_THRESHOLD


# ══════════════════════════════════════════════════════════════════════════════
# Test suite
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TestCase:
    repo:        str
    pr:          int
    label:       str
    category:    str
    expect_risk: str
    notes:       str


TEST_SUITE = [
    TestCase("psf/black", 3864,
             "black — single-file typo fix", "tiny", "low",
             "1 file, <10 lines. Tests minimal diff handling."),
    TestCase("django/django", 17379,
             "django — CI config change", "config", "medium",
             "Only .yml/Actions. Should not hallucinate logic changes."),
    TestCase("pallets/flask", 5491,
             "flask — adds tests only", "tests", "low",
             "Only test files. Risk floor stays low."),
    TestCase("tiangolo/fastapi", 11633,
             "fastapi — internal rename/refactor", "refactor", "low",
             "Renames without behaviour change."),
    TestCase("tiangolo/fastapi", 11523,
             "fastapi — feature addition", "medium", "medium",
             "Real feature PR. Should produce high-specificity summary."),
    TestCase("encode/httpx", 3215,
             "httpx — auth/cookie handling", "high-risk", "high",
             "Touches auth code. enforce_risk_floor() must escalate to high."),
    TestCase("django/django", 17363,
             "django — DB / ORM change", "high-risk", "high",
             "ORM-adjacent. Should trigger db-query/db-migration tag."),
    TestCase("facebook/react", 31500,
             "react — large multi-file PR", "large", "medium",
             "20+ files. Tests chunked analysis + synthesis quality."),
]

DAMPENING_CASES = [
    TestCase("psf/requests", 6628,
             "requests — trivial touch of auth.py", "dampening", "medium",
             "auth.py <8 lines changed. Floor should dampen high→medium."),
    TestCase("pallets/flask", 5494,
             "flask — minor doc fix near security code", "dampening", "low",
             "Tiny fix. Even if path matches rule, churn is trivial."),
]


# ══════════════════════════════════════════════════════════════════════════════
# ANSI helpers
# ══════════════════════════════════════════════════════════════════════════════

R="[0m"; BOLD="[1m"; DIM="[2m"
RED="[91m"; YLW="[93m"; GRN="[92m"
CYN="[96m"; BLU="[94m"; WHT="[97m"
GRY="[90m"; MAG="[95m"

def c(text, *codes): return "".join(codes)+str(text)+R

def clvl(lvl):  return {'high':GRN,'medium':YLW,'low':RED}.get(lvl,WHT)
def rlvl(lvl):  return {'low':GRN,'medium':YLW,'high':RED}.get(lvl,WHT)

def wrap(text, width=68, ind="      "):
    return textwrap.fill(str(text), width=width, subsequent_indent=ind)


# ══════════════════════════════════════════════════════════════════════════════
# CaseResult
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CaseResult:
    tc:                 TestCase
    ok:                 bool
    error:              str
    error_tb:           str
    elapsed_s:          float
    summary:            dict
    pre:                object
    risk_level:         str
    risk_escalated:     bool
    risk_dampened:      bool
    confidence:         str
    confidence_score:   float
    specificity_score:  float
    is_flagged:         bool
    flag_reason:        str
    generic_phrases:    list
    usefulness_level:   str
    usefulness_missing: list
    used_chunking:      bool
    changed_files:      int
    risk_tags:          list
    trivially_touched:  list
    debug_calls:        list
    risk_floor_correct: bool


# ══════════════════════════════════════════════════════════════════════════════
# Runner
# ══════════════════════════════════════════════════════════════════════════════

def run_case(tc, debug=False):
    t0 = time.time()
    debug_calls = []
    try:
        if debug:
            _summarizer_mod.debug_capture = debug_calls

        pr_data          = get_pr_data(tc.repo, tc.pr)
        summary, pre, ev = summarize_pr(pr_data)
        uc               = usefulness_check(summary)

        risk_obj = summary.get("risk", {})
        risk_lvl = risk_obj.get("level", "low") if isinstance(risk_obj, dict) else "low"
        risk_esc = "[Risk escalated" in (risk_obj.get("reason","") if isinstance(risk_obj,dict) else "")

        LEVELS = {"low":0,"medium":1,"high":2}
        return CaseResult(
            tc=tc, ok=True, error="", error_tb="",
            elapsed_s=round(time.time()-t0, 1),
            summary=summary, pre=pre,
            risk_level=risk_lvl, risk_escalated=risk_esc,
            risk_dampened=bool(getattr(pre,"trivially_touched",[])),
            confidence=ev.confidence, confidence_score=ev.confidence_score,
            specificity_score=ev.specificity_score,
            is_flagged=ev.is_flagged, flag_reason=ev.flag_reason or "",
            generic_phrases=ev.generic_phrases_found,
            usefulness_level=uc.usefulness_level, usefulness_missing=uc.missing,
            used_chunking=bool(summary.get("analysed_in_chunks")),
            changed_files=pr_data.get("changed_files",0),
            risk_tags=getattr(pre,"risk_tags",[]),
            trivially_touched=getattr(pre,"trivially_touched",[]),
            debug_calls=debug_calls,
            risk_floor_correct=LEVELS.get(risk_lvl,0)>=LEVELS.get(tc.expect_risk,0),
        )
    except Exception as e:
        return CaseResult(
            tc=tc, ok=False, error=str(e), error_tb=traceback.format_exc(),
            elapsed_s=round(time.time()-t0,1),
            summary={}, pre=None, risk_level="", risk_escalated=False,
            risk_dampened=False, confidence="", confidence_score=0.0,
            specificity_score=0.0, is_flagged=False, flag_reason="",
            generic_phrases=[], usefulness_level="", usefulness_missing=[],
            used_chunking=False, changed_files=0, risk_tags=[],
            trivially_touched=[], debug_calls=debug_calls,
            risk_floor_correct=False,
        )
    finally:
        _summarizer_mod.debug_capture = None


# ══════════════════════════════════════════════════════════════════════════════
# Printers
# ══════════════════════════════════════════════════════════════════════════════

SEP  = "─"*72
SEP2 = "═"*72

def pf(name, value):
    if not value: return
    print(c(f"  {name}:", GRY) + f" {wrap(value)}")


def print_case(r, idx, total, debug=False):
    print(f"\n{c(SEP,DIM)}")
    print(c(f"[{idx}/{total}]",DIM) + "  " + c(r.tc.label,BOLD,WHT) +
          c(f"  #{r.tc.pr}",DIM) + c(f"  {r.tc.category.upper()}",CYN))

    if not r.ok:
        print(c(f"\n  ✗  PIPELINE FAILED: {r.error}", RED, BOLD))
        if debug and r.error_tb:
            for line in r.error_tb.splitlines():
                print(c(f"    {line}", DIM))
        return

    conf_str  = c(r.confidence.upper(), clvl(r.confidence), BOLD)
    risk_str  = c(r.risk_level.upper(), rlvl(r.risk_level), BOLD)
    use_str   = c(r.usefulness_level.upper(), clvl(r.usefulness_level), BOLD)
    floor_str = c("✓ floor ok",GRN) if r.risk_floor_correct else c("✗ floor LOW",RED,BOLD)
    esc_str   = c("↑",YLW) if r.risk_escalated else ""
    damp_str  = c("  ↓ dampened",BLU) if r.risk_dampened else ""
    flag_str  = c("  ⚠ FLAGGED",YLW,BOLD) if r.is_flagged else ""
    chunk_str = c("  ⬡ chunked",CYN) if r.used_chunking else ""

    print(f"  conf {conf_str} ({r.confidence_score:.2f})"
          f"  ·  risk {risk_str}{esc_str}"
          f"  ·  useful {use_str}"
          f"  ·  {r.changed_files} files  {r.elapsed_s}s"
          f"  ·  {floor_str}{chunk_str}{flag_str}{damp_str}")

    if r.risk_tags:       print(c(f"  risk tags: {', '.join(r.risk_tags)}", DIM))
    if r.trivially_touched: print(c(f"  trivially touched: {', '.join(r.trivially_touched)}", BLU))
    if r.is_flagged:      print(c(f"  ⚠  {r.flag_reason}", YLW))
    if r.generic_phrases: print(c(f"  generic: {', '.join(repr(p) for p in r.generic_phrases[:4])}", YLW))
    if r.usefulness_missing: print(c(f"  missing: {', '.join(r.usefulness_missing)}", RED))

    s = r.summary
    pf("what",         s.get("what",""))
    pf("why",          s.get("why",""))
    pf("impact",       s.get("impact",""))
    pf("review_focus", s.get("review_focus",""))
    ro = s.get("risk",{})
    pf("risk", ro.get("reason","") if isinstance(ro,dict) else str(ro))
    changes = s.get("key_changes") or []
    if changes:
        print(c("  key_changes:", GRY))
        for ch in changes[:4]:
            print(c(f"    → {wrap(ch)}", DIM))
    print(c(f"  notes: {r.tc.notes}", DIM))

    if debug:
        print_debug(r)


def print_debug(r):
    print(f"\n  {c('── DEBUG ─────────────────────────────────────────', MAG)}")
    pre = r.pre
    if pre:
        print(c("  pre_analysis:", MAG, BOLD))
        for k in ["risk_floor","risk_tags","flagged_files","trivially_touched",
                  "files_with_diff","files_skipped_noise","files_skipped_budget","total_diff_chars"]:
            print(c(f"    {k}: ", MAG) + str(getattr(pre, k, "?")))

    if not r.debug_calls:
        print(c("  No Claude calls captured.", DIM))
        print(f"  {c('── END DEBUG ─────────────────────────────────────', MAG)}\n")
        return

    for i, call in enumerate(r.debug_calls, 1):
        lbl = f"Claude call #{i}" + (" [synthesis]" if i==len(r.debug_calls) and len(r.debug_calls)>1 else "")
        print(f"\n  {c(lbl, MAG, BOLD)}  prompt: {call['prompt_chars']:,} chars")
        print(c("  prompt tail (last 600 chars):", MAG))
        for line in call["prompt_tail"].splitlines()[-20:]:
            print(c(f"    {line}", DIM))

        raw = call.get("raw","")
        print(c(f"\n  raw Claude response ({len(raw)} chars):", MAG))
        lines = raw.splitlines()
        show = lines if len(lines) <= 40 else lines[:20]+[f"... [{len(lines)-40} lines] ..."]+lines[-20:]
        for line in show:
            print(c(f"    {line}", DIM))

        parsed = call.get("parsed",{})
        print(c("\n  parsed JSON:", MAG))
        for line in json.dumps(parsed, indent=4, ensure_ascii=False).splitlines()[:60]:
            print(c(f"    {line}", DIM))

    print(f"  {c('── END DEBUG ─────────────────────────────────────', MAG)}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Dampening report
# ══════════════════════════════════════════════════════════════════════════════

def run_dampening_verification(debug=False):
    print(f"\n{c(SEP2,BOLD,CYN)}")
    print(c("  RISK DAMPENING VERIFICATION", BOLD, CYN))
    print(c(f"  TRIVIAL_CHURN_THRESHOLD = {TRIVIAL_CHURN_THRESHOLD} lines", DIM))
    print(c(SEP2,BOLD,CYN))

    results = []
    for i, tc in enumerate(DAMPENING_CASES, 1):
        print(c(f"\n  [{i}/{len(DAMPENING_CASES)}] {tc.label}...", DIM), end="", flush=True)
        r = run_case(tc, debug=debug)
        print(c(" done",GRN) if r.ok else c(f" FAILED",RED))
        results.append(r)

        if not r.ok:
            print(c(f"    ✗ {r.error}", RED))
            if debug and r.error_tb:
                for line in r.error_tb.splitlines():
                    print(c(f"      {line}", DIM))
            time.sleep(1.5)
            continue

        pre = r.pre
        if pre:
            print(c(f"  pre_analysis:", BLU, BOLD))
            print(c(f"    risk_floor:        {pre.risk_floor}", BLU))
            print(c(f"    risk_tags:         {pre.risk_tags}", BLU))
            print(c(f"    trivially_touched: {pre.trivially_touched}", BLU))
            print(c(f"    flagged_files:     {pre.flagged_files}", BLU))

        damp_ok  = bool(r.trivially_touched)
        floor_ok = r.risk_floor_correct
        print(f"  Dampening applied: {c('YES',GRN,BOLD) if damp_ok else c('NO',YLW)}")
        print(f"  Floor >= expected ({tc.expect_risk}): "
              + (c('✓',GRN,BOLD) if floor_ok else c('✗',RED,BOLD))
              + f"  actual={r.risk_level}")

        if debug:
            print_debug(r)

        time.sleep(1.5)

    passed = sum(1 for r in results if r.ok and r.risk_floor_correct)
    print(f"\n  Dampening passed: {c(f'{passed}/{len(results)}', GRN if passed==len(results) else YLW, BOLD)}")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Aggregate report
# ══════════════════════════════════════════════════════════════════════════════

def print_report(results):
    ok  = [r for r in results if r.ok]
    n   = len(ok)
    tot = len(results)

    print(f"\n{c(SEP2,BOLD)}")
    print(c("  DEVMIND EVALUATION REPORT", BOLD, WHT))
    print(c(SEP2,BOLD))

    if n == 0:
        print(c("  No successful analyses.", RED)); return

    err = tot - n
    print(f"\n  {c('Run',BOLD)}  {n}/{tot} successful"
          + (c(f"  ({err} error{'s' if err>1 else ''})",RED) if err else c("  (all passed)",GRN)))

    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n  {c('Failed cases:',BOLD,RED)}")
        for r in failed:
            print(f"    · {c(r.tc.label,BOLD)}  #{r.tc.pr}")
            print(c(f"      {r.error}", RED))

    # Confidence
    cc = {"high":0,"medium":0,"low":0}
    for r in ok: cc[r.confidence] = cc.get(r.confidence,0)+1
    avg_conf = sum(r.confidence_score for r in ok)/n
    avg_spec = sum(r.specificity_score for r in ok)/n
    print(f"\n  {c('Confidence',BOLD,WHT)}")
    for lvl in ["high","medium","low"]:
        cnt=cc.get(lvl,0); bar="█"*cnt+"░"*(n-cnt)
        print(f"    {c(lvl.upper(),clvl(lvl)):<28} {bar}  {cnt}/{n}  ({cnt/n*100:.0f}%)")
    print(f"    avg conf {c(f'{avg_conf:.3f}',BOLD)}  ·  avg spec {c(f'{avg_spec:.3f}',BOLD)}")

    # Flagging
    flagged  = [r for r in ok if r.is_flagged]
    fpct     = len(flagged)/n*100
    fc       = RED if fpct>30 else YLW if fpct>10 else GRN
    print(f"\n  {c('Flagging',BOLD,WHT)}")
    print(f"    flagged  {c(f'{len(flagged)}/{n}',fc,BOLD)}  ({c(f'{fpct:.0f}%',fc)})")

    all_phrases: dict = {}
    for r in ok:
        for p in r.generic_phrases: all_phrases[p]=all_phrases.get(p,0)+1
    if all_phrases:
        print(f"\n  {c('Common generic phrases',BOLD,WHT)}")
        for phrase,cnt in sorted(all_phrases.items(),key=lambda x:-x[1])[:6]:
            print(f"    {c(repr(phrase),YLW)}  ×{cnt}")

    # Risk
    rc = {"low":0,"medium":0,"high":0}
    for r in ok: rc[r.risk_level or "low"]+=1
    esc  = sum(1 for r in ok if r.risk_escalated)
    damp = sum(1 for r in ok if r.risk_dampened)
    print(f"\n  {c('Risk',BOLD,WHT)}")
    for lvl in ["low","medium","high"]:
        cnt=rc.get(lvl,0); bar="█"*cnt+"░"*(n-cnt)
        print(f"    {c(lvl.upper(),rlvl(lvl)):<28} {bar}  {cnt}/{n}")
    print(f"    escalated {c(str(esc),BOLD)}/{n}  ·  dampened {c(str(damp),BLU,BOLD)}/{n}")
    fok  = sum(1 for r in ok if r.risk_floor_correct)
    fc2  = GRN if fok/n>=0.8 else YLW if fok/n>=0.5 else RED
    print(f"    floor met  {c(f'{fok}/{n}',fc2,BOLD)}  ({fok/n*100:.0f}%)")

    # Usefulness
    uc = {"high":0,"medium":0,"low":0}
    for r in ok: uc[r.usefulness_level or "low"]+=1
    low_u = [r for r in ok if r.usefulness_level=="low"]
    print(f"\n  {c('Developer usefulness',BOLD,WHT)}")
    for lvl in ["high","medium","low"]:
        cnt=uc.get(lvl,0); bar="█"*cnt+"░"*(n-cnt)
        print(f"    {c(lvl.upper(),clvl(lvl)):<28} {bar}  {cnt}/{n}  ({cnt/n*100:.0f}%)")
    if low_u:
        print(f"\n    {c('Low-usefulness:',BOLD,RED)}")
        for r in low_u:
            ms=", ".join(r.usefulness_missing) if r.usefulness_missing else "?"
            print(f"      · {r.tc.label}  —  {c(ms,RED)}")

    # Edge cases
    print(f"\n  {c('Edge case coverage',BOLD,WHT)}")
    by_cat: dict = {}
    for r in ok: by_cat.setdefault(r.tc.category,[]).append(r)
    for cat,cases in sorted(by_cat.items()):
        avg_c   = sum(r.confidence_score for r in cases)/len(cases)
        issues  = []
        if any(r.is_flagged for r in cases):       issues.append(c("flagged",YLW))
        if any(r.usefulness_level=="low" for r in cases): issues.append(c("low-usefulness",RED))
        issue_str = "  "+"  ".join(issues) if issues else c("  clean",GRN)
        print(f"    {c(cat.upper(),BOLD):<23}  conf {avg_c:.2f}{issue_str}")

    # Perf
    avg_t   = sum(r.elapsed_s for r in ok)/n
    total_t = sum(r.elapsed_s for r in results)
    print(f"\n  {c('Performance',BOLD,WHT)}  avg {c(f'{avg_t:.1f}s',BOLD)}  ·  total {c(f'{total_t:.1f}s',BOLD)}")

    # Verdict
    useful_pct  = (uc["high"]+uc["medium"])/n*100
    pass_thresh = useful_pct>=70 and fpct<40 and avg_conf>=0.25
    print(f"\n  {c(SEP,DIM)}")
    if pass_thresh:
        print(c("  ✓  SYSTEM IS USABLE FOR DEVELOPERS", GRN, BOLD))
        print(c(f"  {useful_pct:.0f}% useful  ·  {fpct:.0f}% flagged  ·  avg conf {avg_conf:.2f}", DIM))
    else:
        print(c("  ✗  SYSTEM NEEDS IMPROVEMENT", RED, BOLD))
        print(c(f"  useful {useful_pct:.0f}% (≥70%)  ·  flagged {fpct:.0f}% (<40%)  ·  conf {avg_conf:.2f} (≥0.25)", DIM))
    print(f"  {c(SEP2,BOLD)}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    args      = sys.argv[1:]
    debug     = "--debug" in args
    run_damp  = "--dampening" in args
    cats      = [a for a in args if not a.startswith("--")]

    flags = []
    if debug:    flags.append(c("--debug", MAG))
    if run_damp: flags.append(c("--dampening", BLU))
    if cats:     flags.append(c(f"filter: {cats}", CYN))
    print(c(f"\n  DevMind Eval  {'  '.join(flags)}\n", BOLD, WHT))

    suite = TEST_SUITE
    if cats:
        suite = [tc for tc in TEST_SUITE if tc.category in cats]
        if not suite:
            print(c(f"  No cases match: {cats}", RED))
            print(f"  Available: {sorted({tc.category for tc in TEST_SUITE})}")
            sys.exit(1)

    results = []
    for i, tc in enumerate(suite, 1):
        print(c(f"  [{i}/{len(suite)}] {tc.label}...", DIM), end="", flush=True)
        r = run_case(tc, debug=debug)
        print(c(" done",GRN) if r.ok else c(" FAILED",RED))
        results.append(r)
        print_case(r, i, len(suite), debug=debug)
        if i < len(suite): time.sleep(1.5)

    print_report(results)

    if run_damp or not cats:
        damp = run_dampening_verification(debug=debug)
        results.extend(damp)


if __name__ == "__main__":
    main()
