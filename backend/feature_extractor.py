# -*- coding: utf-8 -*-
CRITICAL_MODULES = ["auth", "payment", "token", "session", "password", "db", "execute", "query", "secret", "key"]

EXTERNAL_PATTERNS = ["request", "fetch", "http", "socket", "redis", "celery", "boto", "s3", "smtp"]

def extract_features(parsed_result: dict, diff_stats: dict) -> dict:
    functions = parsed_result.get("functions_changed", [])
    calls = parsed_result.get("calls", [])
    calls_str = str(calls).lower()

    locs = []
    for f in functions:
        lines = f.get("lines", [0, 0])
        locs.append(lines[1] - lines[0])

    avg_loc = sum(locs) / len(locs) if locs else 0
    max_loc = max(locs) if locs else 0

    touches_critical = int(any(m in calls_str for m in CRITICAL_MODULES))
    external_calls = sum(1 for p in EXTERNAL_PATTERNS if p in calls_str)

    return {
        "num_functions_touched": len(functions),
        "avg_loc": round(avg_loc, 2),
        "max_loc": max_loc,
        "total_calls": len(calls),
        "lines_added": diff_stats.get("additions", 0),
        "lines_deleted": diff_stats.get("deletions", 0),
        "files_changed": diff_stats.get("changed_files", 0),
        "touches_critical": touches_critical,
        "external_calls": external_calls
    }
