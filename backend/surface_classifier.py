from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any

DOCS_EXTENSIONS = {".txt", ".md", ".rst", ".adoc", ".tex", ".rdoc"}
TEST_PATTERNS = {"test_", "_test", "/tests/", "/test/", "spec_", "_spec"}
EXECUTABLE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".sh", ".php", ".cs"}
CONFIG_EXTENSIONS = {".yml", ".yaml", ".toml", ".json", ".env", ".ini", ".cfg"}
INFRA_EXTENSIONS = {".tf", ".hcl"}
INFRA_NAMES = {"dockerfile", "docker-compose", "makefile", "jenkinsfile"}

@dataclass
class ChangeSurface:
    surface: str
    runtime_reachable: bool
    executes_in_ci: bool
    touches_secrets: bool
    touches_auth: bool
    risk_multiplier: float
    use_lightweight_pipeline: bool
    generate_fixes: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface": self.surface,
            "runtime_reachable": self.runtime_reachable,
            "executes_in_ci": self.executes_in_ci,
            "touches_secrets": self.touches_secrets,
            "touches_auth": self.touches_auth,
            "risk_multiplier": self.risk_multiplier,
            "use_lightweight_pipeline": self.use_lightweight_pipeline,
            "generate_fixes": self.generate_fixes,
            "reason": self.reason,
        }


def _ext(filename: str) -> str:
    filename = filename.lower()
    for ext in [".test.py", "_test.py", ".spec.ts", ".spec.js"]:
        if filename.endswith(ext):
            return ext
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1]
    return ""


def _is_docs(filename: str) -> bool:
    return _ext(filename) in DOCS_EXTENSIONS or "/docs/" in filename.lower()


def _is_test(filename: str) -> bool:
    fl = filename.lower()
    return any(p in fl for p in TEST_PATTERNS)


def _is_executable(filename: str) -> bool:
    return _ext(filename) in EXECUTABLE_EXTENSIONS


def _is_config(filename: str) -> bool:
    return _ext(filename) in CONFIG_EXTENSIONS


def _is_infra(filename: str) -> bool:
    fl = filename.lower()
    return _ext(filename) in INFRA_EXTENSIONS or any(n in fl for n in INFRA_NAMES)


def _touches_secrets(diff: str, prompt: str) -> bool:
    text = (diff + " " + prompt).lower()
    return bool(re.search(r"\b(secret|api_key|token|password|credential|private_key)\b", text))


def _touches_auth(diff: str, prompt: str) -> bool:
    text = (diff + " " + prompt).lower()
    return bool(re.search(r"\b(auth|login|permission|rbac|jwt|oauth|session)\b", text))


def classify_change_surface(
    files: list[dict[str, Any]],
    diff: str = "",
    prompt: str = "",
) -> ChangeSurface:
    if not files:
        filenames = []
    else:
        filenames = [str(f.get("filename") or f.get("path") or "") for f in files]

    secrets = _touches_secrets(diff, prompt)
    auth = _touches_auth(diff, prompt)

    if not filenames:
        return ChangeSurface(
            surface="unknown",
            runtime_reachable=False,
            executes_in_ci=False,
            touches_secrets=secrets,
            touches_auth=auth,
            risk_multiplier=0.5,
            use_lightweight_pipeline=True,
            generate_fixes=False,
            reason="no files provided",
        )

    docs_count = sum(1 for f in filenames if _is_docs(f))
    test_count = sum(1 for f in filenames if _is_test(f))
    exec_count = sum(1 for f in filenames if _is_executable(f))
    config_count = sum(1 for f in filenames if _is_config(f))
    infra_count = sum(1 for f in filenames if _is_infra(f))
    total = len(filenames)

    # Pure documentation
    if docs_count == total:
        return ChangeSurface(
            surface="documentation",
            runtime_reachable=False,
            executes_in_ci=False,
            touches_secrets=secrets,
            touches_auth=auth,
            risk_multiplier=0.10,
            use_lightweight_pipeline=True,
            generate_fixes=False,
            reason="all files are documentation",
        )

    # Pure tests
    if test_count == total:
        return ChangeSurface(
            surface="test",
            runtime_reachable=False,
            executes_in_ci=True,
            touches_secrets=secrets,
            touches_auth=auth,
            risk_multiplier=0.30,
            use_lightweight_pipeline=True,
            generate_fixes=False,
            reason="all files are tests",
        )

    # Pure infra
    if infra_count == total:
        return ChangeSurface(
            surface="infra",
            runtime_reachable=True,
            executes_in_ci=True,
            touches_secrets=secrets,
            touches_auth=auth,
            risk_multiplier=0.85,
            use_lightweight_pipeline=False,
            generate_fixes=True,
            reason="infrastructure files",
        )

    # Pure config
    if config_count == total:
        return ChangeSurface(
            surface="config",
            runtime_reachable=True,
            executes_in_ci=False,
            touches_secrets=secrets,
            touches_auth=auth,
            risk_multiplier=0.65,
            use_lightweight_pipeline=False,
            generate_fixes=secrets or auth,
            reason="configuration files",
        )

    # Runtime executable
    if exec_count > 0:
        return ChangeSurface(
            surface="runtime",
            runtime_reachable=True,
            executes_in_ci=False,
            touches_secrets=secrets,
            touches_auth=auth,
            risk_multiplier=1.0,
            use_lightweight_pipeline=False,
            generate_fixes=True,
            reason="executable source files",
        )

    return ChangeSurface(
        surface="mixed",
        runtime_reachable=True,
        executes_in_ci=False,
        touches_secrets=secrets,
        touches_auth=auth,
        risk_multiplier=0.70,
        use_lightweight_pipeline=False,
        generate_fixes=True,
        reason="mixed file types",
    )
