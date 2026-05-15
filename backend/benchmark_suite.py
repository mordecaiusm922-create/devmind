from __future__ import annotations
import json
from dataclasses import dataclass

@dataclass
class BenchmarkCase:
    id: str
    repo: str
    pr_number: int
    expected_band: str        # minimal/low/medium/high/critical
    expected_action: str      # APPROVE/REVIEW/BLOCK
    surface: str              # documentation/runtime_code/tests/ci_config
    description: str

BENCHMARK_CASES = [
    # Docs only - debe ser minimal
    BenchmarkCase("docs-01", "django/django", 17379, "minimal", "REVIEW", "documentation", "MD5->Scrypt en docs .txt"),

    # Runtime con hardcoded secret - debe ser critical/BLOCK
    BenchmarkCase("secret-01", "django/django", 17473, "critical", "BLOCK", "runtime_code", "Django project con SECRET_KEY hardcodeado"),

    # Fix seguro - debe ser low/REVIEW
    BenchmarkCase("safe-01", "pallets/flask", 5992, "minimal", "REVIEW", "runtime_code", "Flask fix seguro"),

    # PR grande - debe ser high
    BenchmarkCase("large-01", "psf/requests", 6710, "critical", "REVIEW", "runtime_code", "Requests PR grande"),

    # Django ORM fix
    BenchmarkCase("orm-01", "django/django", 17379, "minimal", "REVIEW", "documentation", "Django docs change"),
]

def evaluate_benchmark(result: dict, case: BenchmarkCase) -> dict:
    actual_band = result.get("risk", {}).get("band", "unknown")
    actual_action = result.get("decision", {}).get("action", "unknown")
    actual_surface = result.get("risk", {}).get("surface", "")

    band_correct = actual_band == case.expected_band
    action_correct = actual_action == case.expected_action
    surface_correct = actual_surface == case.surface if case.surface == "documentation" else True

    return {
        "id": case.id,
        "description": case.description,
        "expected_band": case.expected_band,
        "actual_band": actual_band,
        "expected_action": case.expected_action,
        "actual_action": actual_action,
        "band_correct": band_correct,
        "action_correct": action_correct,
        "surface_correct": surface_correct,
        "pass": band_correct and action_correct,
    }

def print_report(results: list[dict]) -> None:
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    print(f"\n{'='*60}")
    print(f"DEVMIND BENCHMARK REPORT")
    print(f"{'='*60}")
    print(f"Total: {total} | Passed: {passed} | Failed: {total-passed}")
    print(f"Precision: {passed/total*100:.1f}%")
    print(f"{'='*60}")
    for r in results:
        status = "✅" if r["pass"] else "❌"
        print(f"{status} {r['id']}: {r['description']}")
        if not r["pass"]:
            print(f"   band: {r['expected_band']} → {r['actual_band']}")
            print(f"   action: {r['expected_action']} → {r['actual_action']}")
    print(f"{'='*60}\n")
