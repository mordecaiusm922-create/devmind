from __future__ import annotations

import ast
import json
import os
import py_compile
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List


DANGEROUS_PATTERNS = {
    "eval(": "dynamic_eval",
    "exec(": "dynamic_exec",
    "shell=True": "shell_execution",
    "os.system(": "shell_execution",
    "subprocess.Popen(": "subprocess_execution",
}


def _static_analysis(code: str) -> List[Dict[str, Any]]:
    findings = []

    for pattern, label in DANGEROUS_PATTERNS.items():
        if pattern in code:
            findings.append({
                "type": label,
                "severity": "high",
                "pattern": pattern,
            })

    try:
        tree = ast.parse(code)

        for node in ast.walk(tree):

            if isinstance(node, ast.Call):

                if isinstance(node.func, ast.Name):

                    if node.func.id in {"eval", "exec"}:
                        findings.append({
                            "type": "dangerous_builtin",
                            "severity": "high",
                            "function": node.func.id,
                        })

    except Exception as e:
        findings.append({
            "type": "ast_parse_error",
            "severity": "medium",
            "message": str(e),
        })

    return findings


def _run_bandit(temp_file: str) -> List[Dict[str, Any]]:
    if shutil.which("bandit") is None:
        return []

    try:

        result = subprocess.run(
            [
                "bandit",
                "-r",
                temp_file,
                "-f",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        data = json.loads(result.stdout or "{}")

        return data.get("results", [])

    except Exception:
        return []


def _run_pytest(repo_path: str) -> bool:

    if shutil.which("pytest") is None:
        return False

    tests_exist = (
        Path(repo_path, "tests").exists()
        or any("test_" in x.name for x in Path(repo_path).glob("*.py"))
    )

    if not tests_exist:
        return False

    try:

        result = subprocess.run(
            [
                "pytest",
                "--tb=short",
            ],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.returncode == 0

    except Exception:
        return False


def sandbox_candidate(
    code: str,
    repo_path: str | None = None,
) -> Dict[str, Any]:

    evidence = {
        "syntax_valid": False,
        "ast_safe": False,
        "bandit_issues": [],
        "static_findings": [],
        "test_passed": False,
        "evidence_type": "runtime",
    }

    with tempfile.TemporaryDirectory() as tmp:

        temp_file = Path(tmp) / "candidate.py"

        temp_file.write_text(code, encoding="utf-8")

        #
        # Syntax validation
        #
        try:
            py_compile.compile(
                str(temp_file),
                doraise=True,
            )

            evidence["syntax_valid"] = True

        except py_compile.PyCompileError as e:
            evidence["syntax_error"] = str(e)
            return evidence

        #
        # AST + static analysis
        #
        findings = _static_analysis(code)

        evidence["static_findings"] = findings
        evidence["ast_safe"] = len(findings) == 0

        #
        # Bandit scan
        #
        evidence["bandit_issues"] = _run_bandit(str(temp_file))

        #
        # Pytest
        #
        if repo_path:
            evidence["test_passed"] = _run_pytest(repo_path)

    return evidence