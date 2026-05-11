from __future__ import annotations

import ast
import json
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


_DIFF_FILE_RE = re.compile(r"^diff --git a/\S+ b/(?P<right>\S+)", re.MULTILINE)
_PY_EXTENSIONS = {".py", ".pyi"}
_DANGEROUS_IMPORTS = {"subprocess", "pickle", "marshal", "ctypes", "importlib", "socket"}
_DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__"}


def run_sandbox(candidate: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Real bounded sandbox evidence.

    The candidate is written to a temp file, but never imported or executed.
    The only execution this function can trigger is optional known repo tests
    through pytest when a repo_path is explicitly provided in context.
    """
    context = dict(context or {})
    started = time.monotonic()
    deadline = started + float(context.get("timeout_seconds", 10) or 10)

    filename = _candidate_filename(candidate, context)
    code = _candidate_code(candidate)

    with tempfile.TemporaryDirectory(prefix="devmind-sandbox-") as temp_dir:
        temp_root = Path(temp_dir)
        temp_file = temp_root / Path(filename).name
        if temp_file.suffix.lower() not in _PY_EXTENSIONS:
            temp_file = temp_file.with_suffix(".py")
        temp_file.write_text(code, encoding="utf-8")

        syntax = _validate_python_syntax(temp_file, code)
        static = _static_analysis(code)
        bandit = _run_bandit(temp_file, _remaining(deadline))
        tests = _run_tests_if_available(context, _remaining(deadline))

    bandit_issues = bandit.get("issues", [])
    high_bandit = [
        issue for issue in bandit_issues
        if str(issue.get("issue_severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]
    test_passed = tests.get("passed")

    status = "passed"
    if not syntax["syntax_valid"] or static["unsafe_calls"] or high_bandit or test_passed is False:
        status = "failed"
    elif static["dangerous_imports"] or bandit.get("status") == "unavailable" or test_passed is None:
        status = "warn"

    return {
        "evidence_type": "runtime",
        "mode": "static_plus_known_tests",
        "status": status,
        "filename": filename,
        "syntax_valid": bool(syntax["syntax_valid"]),
        "syntax_error": syntax.get("syntax_error"),
        "py_compile_valid": bool(syntax.get("py_compile_valid")),
        "bandit_available": bool(bandit.get("available")),
        "bandit_status": bandit.get("status"),
        "bandit_issues": bandit_issues,
        "static_analysis": static,
        "test_passed": test_passed,
        "test_status": tests.get("status"),
        "test_output": tests.get("output", ""),
        "timeouts": {
            "max_seconds": 10,
            "elapsed_seconds": round(time.monotonic() - started, 4),
        },
    }


def _candidate_filename(candidate: dict[str, Any], context: dict[str, Any]) -> str:
    diff = str(candidate.get("diff") or "")
    match = _DIFF_FILE_RE.search(diff)
    if match:
        return match.group("right")
    return str(
        context.get("filename")
        or context.get("file")
        or context.get("path")
        or candidate.get("filename")
        or "candidate.py"
    )


def _candidate_code(candidate: dict[str, Any]) -> str:
    for key in ("code", "content", "source"):
        if candidate.get(key):
            return str(candidate[key])

    diff = str(candidate.get("diff") or "")
    added: list[str] = []
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("+"):
            added.append(line[1:])

    if added:
        return "\n".join(added) + "\n"
    return diff


def _validate_python_syntax(path: Path, code: str) -> dict[str, Any]:
    if not code.strip():
        return {"syntax_valid": True, "py_compile_valid": True, "syntax_error": None}

    parse_error: str | None = None
    try:
        ast.parse(code)
        ast_valid = True
    except SyntaxError as exc:
        parse_error = f"{exc.msg} at line {exc.lineno}"
        try:
            ast.parse("if True:\n" + "\n".join(f"    {line}" for line in code.splitlines()))
            ast_valid = True
            parse_error = None
        except SyntaxError as block_exc:
            ast_valid = False
            parse_error = f"{block_exc.msg} at line {block_exc.lineno}"

    try:
        py_compile.compile(str(path), doraise=True)
        py_compile_valid = True
        compile_error = None
    except py_compile.PyCompileError as exc:
        py_compile_valid = ast_valid
        compile_error = str(exc)

    return {
        "syntax_valid": ast_valid,
        "py_compile_valid": py_compile_valid,
        "syntax_error": parse_error or compile_error,
    }


def _static_analysis(code: str) -> dict[str, Any]:
    dangerous_imports: list[str] = []
    unsafe_calls: list[dict[str, Any]] = []
    shell_true = False

    try:
        tree = ast.parse(code)
    except SyntaxError:
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root in _DANGEROUS_IMPORTS and root not in dangerous_imports:
                        dangerous_imports.append(root)
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".", 1)[0]
                if root in _DANGEROUS_IMPORTS and root not in dangerous_imports:
                    dangerous_imports.append(root)
            elif isinstance(node, ast.Call):
                call_name = _call_name(node.func)
                if call_name in _DANGEROUS_CALLS or call_name in {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}:
                    unsafe_calls.append({"call": call_name, "line": getattr(node, "lineno", None)})
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        shell_true = True
                        unsafe_calls.append({"call": f"{call_name}(shell=True)", "line": getattr(node, "lineno", None)})

    regex_hits = []
    for pattern, name in (
        (r"\beval\s*\(", "eval"),
        (r"\bexec\s*\(", "exec"),
        (r"shell\s*=\s*True", "shell=True"),
        (r"os\.system\s*\(", "os.system"),
    ):
        if re.search(pattern, code):
            regex_hits.append(name)

    return {
        "dangerous_imports": sorted(dangerous_imports),
        "unsafe_calls": unsafe_calls,
        "shell_true": shell_true,
        "regex_hits": sorted(set(regex_hits)),
    }


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""


def _run_bandit(path: Path, timeout: float) -> dict[str, Any]:
    bandit = shutil.which("bandit")
    if not bandit:
        return {"available": False, "status": "unavailable", "issues": [], "error": "bandit not found"}

    try:
        completed = subprocess.run(
            [bandit, "-r", str(path), "-f", "json"],
            capture_output=True,
            text=True,
            timeout=max(1.0, min(timeout, 10.0)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "timeout", "issues": [], "error": "bandit timed out"}
    except OSError as exc:
        return {"available": False, "status": "unavailable", "issues": [], "error": str(exc)}

    data: dict[str, Any] = {}
    if completed.stdout.strip():
        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError:
            data = {}

    return {
        "available": True,
        "status": "passed" if completed.returncode == 0 else "issues_found",
        "issues": list(data.get("results") or []),
        "returncode": completed.returncode,
        "stderr": completed.stderr[-1000:],
    }


def _run_tests_if_available(context: dict[str, Any], timeout: float) -> dict[str, Any]:
    repo_path = context.get("repo_path") or context.get("cwd")
    if not repo_path:
        return {"status": "skipped", "passed": None, "output": "repo_path not provided"}

    root = Path(str(repo_path)).resolve()
    if not root.exists() or not root.is_dir():
        return {"status": "skipped", "passed": None, "output": f"repo_path not found: {root}"}

    if context.get("run_tests") is False:
        return {"status": "skipped", "passed": None, "output": "run_tests disabled"}

    if not _has_tests(root):
        return {"status": "skipped", "passed": None, "output": "no tests discovered"}

    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "--tb=short"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(timeout, 10.0)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "passed": False, "output": "pytest timed out"}
    except OSError as exc:
        return {"status": "unavailable", "passed": None, "output": str(exc)}

    output = (completed.stdout + "\n" + completed.stderr).strip()
    return {
        "status": "passed" if completed.returncode == 0 else "failed",
        "passed": completed.returncode == 0,
        "output": output[-4000:],
        "returncode": completed.returncode,
    }


def _has_tests(root: Path) -> bool:
    candidates = [root / "tests", root / "backend" / "tests"]
    if any(path.exists() for path in candidates):
        return True
    return any(root.glob("test_*.py"))


def _remaining(deadline: float) -> float:
    return max(1.0, min(10.0, deadline - time.monotonic()))


def sandbox_candidate(code: str, repo_path: str | None = None) -> dict:
    """Wrapper de compatibilidad para sandbox_candidate."""
    candidate = {"code": code, "diff": code}
    context = {"repo_path": repo_path} if repo_path else {}
    result = run_sandbox(candidate, context)
    # Agrega ast_safe para compatibilidad
    static = result.get("static_analysis", {})
    unsafe_calls = static.get("unsafe_calls", [])
    dangerous_imports = static.get("dangerous_imports", [])
    regex_hits = static.get("regex_hits", [])
    result["ast_safe"] = (
        len(unsafe_calls) == 0
        and len(dangerous_imports) == 0
        and len(regex_hits) == 0
        and not static.get("shell_true", False)
    )
    result["bandit_issues"] = result.get("bandit_issues", [])
    return result


def sandbox_from_dict(payload: dict) -> dict:
    """Wrapper para el endpoint /sandbox."""
    code = (
        payload.get("code")
        or payload.get("candidate")
        or payload.get("diff")
        or ""
    )
    repo = payload.get("repo_path") or payload.get("repo")
    return sandbox_candidate(code=code, repo_path=repo)
