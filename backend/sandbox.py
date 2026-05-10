from __future__ import annotations

import ast
import importlib.util
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional


@dataclass
class SandboxEvidence:
    syntax_valid: bool
    syntax_error: str | None = None
    static_issues: list[dict[str, Any]] = field(default_factory=list)
    bandit_issues: list[dict[str, Any]] = field(default_factory=list)
    bandit_available: bool = False
    bandit_ran: bool = False
    test_passed: bool | None = None
    test_ran: bool = False
    test_output: str = ""
    evidence_type: str = "static"
    status: str = "ok"
    temp_file: str | None = None
    workspace: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_str(value: Any, default: str = "") -> str:
    return str(value) if value is not None else default

def _safe_int(value: Any, default: int = 10) -> int:
    try:
        return int(value) if value is not None else default
    except Exception:
        return default

def _clamp_timeout(seconds: int) -> int:
    return max(1, min(10, seconds))

def _extract_candidate_text(candidate: Any) -> str:
    if isinstance(candidate, str):
        return candidate
    if isinstance(candidate, Mapping):
        return _safe_str(candidate.get("code") or candidate.get("diff") or "")
    return _safe_str(candidate)

def _looks_like_unified_diff(text: str) -> bool:
    return "diff --git" in text or text.lstrip().startswith(("---", "+++", "@@"))

def _normalize_source(text: str) -> str:
    text = _safe_str(text)
    if not text:
        return ""
    if not _looks_like_unified_diff(text):
        return text
    lines = []
    for line in text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
        elif line.startswith(" "):
            lines.append(line[1:])
    return "\n".join(lines).strip() or text

def _write_temp_source(source: str, *, target_path: str = "candidate.py"):
    workspace = Path(tempfile.mkdtemp(prefix="devmind_sandbox_"))
    file_path = workspace / target_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(source, encoding="utf-8")
    return workspace, file_path

def _validate_syntax(source_path, source_text: str):
    try:
        ast.parse(source_text)
    except SyntaxError as exc:
        return False, f"{exc.msg} (line {exc.lineno})"
    try:
        py_compile.compile(str(source_path), doraise=True)
    except Exception as exc:
        return False, str(exc)
    return True, None

def _bandit_available() -> bool:
    return importlib.util.find_spec("bandit") is not None

def _static_scan(source: str) -> list[dict[str, Any]]:
    issues = []
    DANGEROUS = {"eval", "exec", "__import__", "os.system", "pickle.loads", "yaml.load"}
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"
                if name in DANGEROUS:
                    issues.append({"type": "dangerous_call", "severity": "critical", "message": f"Dangerous call: {name}", "line": getattr(node, "lineno", None)})
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        issues.append({"type": "shell_true", "severity": "critical", "message": "shell=True detected"})
    except Exception:
        pass
    return issues

def _run_bandit(workspace, timeout_s: int):
    if not _bandit_available():
        return [], False, "not_installed"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", str(workspace), "-f", "json"],
            capture_output=True, text=True, timeout=timeout_s
        )
        payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
        issues = [{"type": "bandit", "severity": i.get("issue_severity","medium").lower(), "message": i.get("issue_text","")} for i in payload.get("results", [])]
        return issues, True, "ok"
    except Exception as exc:
        return [], False, str(exc)

def run_sandbox(candidate: Any, *, repo_root: str | None = None, target_path: str = "candidate.py", tests_dir: str | None = None, timeout_seconds: int = 10) -> dict[str, Any]:
    started = time.perf_counter()
    timeout_seconds = _clamp_timeout(_safe_int(timeout_seconds, 10))
    source = _normalize_source(_extract_candidate_text(candidate))
    workspace, source_path = _write_temp_source(source, target_path=target_path)
    syntax_valid, syntax_error = _validate_syntax(source_path, source)
    static_issues = _static_scan(source)
    bandit_issues, bandit_ran, _ = _run_bandit(workspace, max(1, timeout_seconds - int(time.perf_counter() - started)))
    evidence_type = "runtime" if bandit_ran else "static"
    status = "error" if not syntax_valid else "ok"
    duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
    return SandboxEvidence(
        syntax_valid=syntax_valid,
        syntax_error=syntax_error,
        static_issues=static_issues,
        bandit_issues=bandit_issues,
        bandit_available=_bandit_available(),
        bandit_ran=bandit_ran,
        evidence_type=evidence_type,
        status=status,
        temp_file=str(source_path),
        workspace=str(workspace),
        duration_ms=duration_ms,
    ).to_dict()

def sandbox_from_dict(payload: Mapping[str, Any]) -> dict[str, Any]:
    return run_sandbox(
        payload.get("candidate") or payload.get("code") or payload.get("diff") or "",
        repo_root=payload.get("repo_root"),
        target_path=payload.get("target_path", "candidate.py"),
        tests_dir=payload.get("tests_dir"),
        timeout_seconds=payload.get("timeout_seconds", 10),
    )
