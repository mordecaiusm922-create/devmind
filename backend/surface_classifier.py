from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any

EXECUTABLE_TYPES = {".py", ".js", ".ts", ".go", ".rb", ".java", ".c", ".cpp", ".sh", ".yml", ".yaml"}
DOC_TYPES = {".txt", ".md", ".rst", ".adoc"}
MANIFEST_RE = re.compile(
    r"(pyproject\.toml|requirements[^/]*\.txt|package\.json|package-lock\.json|"
    r"go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|Gemfile|Gemfile\.lock|"
    r"pom\.xml|build\.gradle|poetry\.lock|setup\.cfg|"
    r"CHANGES\.md|CHANGELOG\.md|HISTORY\.rst)$",
    re.I,
)
TEST_PATTERNS = re.compile(r"(test_|_test\.|spec\.|\.spec\.|/tests/|/test/)", re.I)
CI_PATTERNS = re.compile(r"(\.github/|\.gitlab-ci|jenkinsfile|\.circleci|\.travis)", re.I)

NEGATIVE_SIGNALS = {
    "docs_only_change": 0.15,
    "test_only_change": 0.25,
    "comment_only_change": 0.10,
    "no_runtime_execution": 0.20,
}

@dataclass
class ChangeContext:
    surface: str
    runtime_reachable: bool
    executes_in_ci: bool
    touches_secrets: bool
    touches_auth: bool
    is_docs: bool
    is_test: bool
    is_executable: bool
    risk_multiplier: float
    use_lightweight_pipeline: bool
    disable_fix_generation: bool
    disable_runtime_security: bool
    negative_signals: list[str]

def classify_change_surface(files: list[dict[str, Any]], diff: str = "") -> ChangeContext:
    files = [f for f in files if isinstance(f, dict)]
    has_files = bool(files)
    extensions = set()
    for f in files:
        name = f.get("filename", "") or f.get("path", "")
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        extensions.add(ext)

    is_manifest = has_files and all(MANIFEST_RE.search(f.get('filename','') or '') for f in files)
    is_docs = has_files and all(e in DOC_TYPES for e in extensions if e)
    is_test = any(TEST_PATTERNS.search(f.get("filename", "")) for f in files)
    is_ci = any(CI_PATTERNS.search(f.get("filename", "")) for f in files)
    is_executable = any(e in EXECUTABLE_TYPES for e in extensions if e)

    touches_secrets = bool(re.search(r"(secret|api_key|token|password|credential)", diff, re.I))
    touches_auth = bool(re.search(r"(auth|permission|rbac|login|session|jwt)", diff, re.I))

    negative = []
    risk_multiplier = 1.0

    if is_manifest and not touches_secrets and not touches_auth:
        negative.append("manifest_only_change")
        risk_multiplier *= 0.10

    if is_docs and not touches_secrets and not touches_auth:
        negative.append("docs_only_change")
        risk_multiplier *= NEGATIVE_SIGNALS["docs_only_change"]

    if is_test:
        negative.append("test_only_change")
        risk_multiplier *= NEGATIVE_SIGNALS["test_only_change"]

    if has_files and not is_executable and not is_ci:
        negative.append("no_runtime_execution")
        risk_multiplier *= NEGATIVE_SIGNALS["no_runtime_execution"]

    is_infra = any(
        re.search(r"(k8s|kubernetes|helm|terraform|docker|deploy|pipeline)", 
        f.get("filename",""), re.I) for f in files
    )
    is_auth_surface = bool(re.search(r"(auth|oauth|jwt|session|login|credential|permission|rbac)", diff, re.I))
    is_dataflow = any(
        re.search(r"(migrat|schema|sql|db|orm|model|database)", 
        f.get("filename",""), re.I) for f in files
    )
    is_config = any(
        re.search(r"(settings|config|\.env|secrets|credentials)", 
        f.get("filename",""), re.I) for f in files
    )
    is_payments = bool(re.search(r"(payment|billing|checkout|stripe|invoice|charge)", diff, re.I))

    if is_manifest and not touches_secrets and not touches_auth:
        surface = "manifest"
    elif is_docs:
        surface = "documentation"
    elif is_test:
        surface = "tests"
    elif is_ci:
        surface = "ci_config"
    elif is_payments:
        surface = "payments"
        risk_multiplier = min(risk_multiplier, 1.5)
    elif is_auth_surface:
        surface = "auth"
        risk_multiplier = min(risk_multiplier, 1.3)
    elif is_infra:
        surface = "infra"
        risk_multiplier = min(risk_multiplier, 1.4)
    elif is_dataflow:
        surface = "dataflow"
        risk_multiplier = min(risk_multiplier, 1.2)
    elif is_config:
        surface = "config"
        risk_multiplier = min(risk_multiplier, 1.1)
    elif is_executable:
        surface = "runtime"
    else:
        surface = "unknown"

    use_lightweight = risk_multiplier < 0.5
    disable_fix = not is_executable and not is_ci
    disable_runtime = is_docs or (is_test and not touches_secrets)

    return ChangeContext(
        surface=surface,
        runtime_reachable=is_executable and not is_test,
        executes_in_ci=is_ci,
        touches_secrets=touches_secrets,
        touches_auth=touches_auth,
        is_docs=is_docs,
        is_test=is_test,
        is_executable=is_executable,
        risk_multiplier=risk_multiplier,
        use_lightweight_pipeline=use_lightweight,
        disable_fix_generation=disable_fix,
        disable_runtime_security=disable_runtime,
        negative_signals=negative,
    )
