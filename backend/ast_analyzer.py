from __future__ import annotations
from dataclasses import dataclass, field
from parser import get_ts_parser, detect_language, get_functions, extract_calls, _clean_diff

TAINT_SOURCES = [
    "request.args", "request.form", "request.json", "request.data",
    "request.get_json", "request.values", "request.params",
    "input(", "sys.argv", "os.environ",
    "event[", "event.get(", "params[", "body[",
]

TAINT_SINKS_SQL = [
    ".execute(", ".executemany(", "cursor.execute", "db.execute",
    "engine.execute", "raw(", ".raw(",
]

TAINT_SINKS_CMD = [
    "os.system(", "subprocess.run(", "subprocess.call(",
    "subprocess.Popen(", "eval(", "exec(",
    "os.popen(", "__import__(",
]

TAINT_SINKS_PATH = [
    "open(", "os.path.join(", "os.listdir(",
    "shutil.copy(", "shutil.move(",
]

DANGEROUS_IMPORTS = [
    "pickle", "marshal", "shelve", "yaml.load",
    "subprocess", "ctypes", "cffi",
]

CRYPTO_WEAK = [
    "md5", "sha1", "des", "rc4", "random.random",
    "random.randint", "Math.random",
]

@dataclass
class ASTFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    fix_hint: str = ""

@dataclass
class ASTAnalysisResult:
    findings: list[ASTFinding] = field(default_factory=list)
    risk_score: int = 0
    has_taint_flow: bool = False
    has_dangerous_import: bool = False
    has_weak_crypto: bool = False
    block_merge: bool = False
    functions_analyzed: int = 0

def _check_taint(code: str, filename: str) -> list[ASTFinding]:
    findings = []
    lines = code.splitlines()
    
    # Analisis por bloque de funcion - source y sink pueden estar en lineas distintas
    full_code = code.lower()
    has_source = any(src.lower() in full_code for src in TAINT_SOURCES)
    
    if has_source:
        # Encontrar linea del source
        source_line = 0
        for i, line in enumerate(lines, 1):
            if any(src in line for src in TAINT_SOURCES):
                source_line = i
                break
        
        has_sql_sink = any(sink.lower() in full_code for sink in TAINT_SINKS_SQL)
        has_cmd_sink = any(sink.lower() in full_code for sink in TAINT_SINKS_CMD)
        has_path_sink = any(sink.lower() in full_code for sink in TAINT_SINKS_PATH)
        
        # Encontrar linea del sink
        sink_line = 0
        sink_evidence = ""
        for i, line in enumerate(lines, 1):
            if has_sql_sink and any(sink in line for sink in TAINT_SINKS_SQL):
                sink_line = i
                sink_evidence = line.strip()[:120]
                break
            if has_cmd_sink and any(sink in line for sink in TAINT_SINKS_CMD):
                sink_line = i
                sink_evidence = line.strip()[:120]
                break
            if has_path_sink and any(sink in line for sink in TAINT_SINKS_PATH):
                sink_line = i
                sink_evidence = line.strip()[:120]
                break

        if has_sql_sink:
            findings.append(ASTFinding(
                rule_id="TAINT001",
                severity="critical",
                title="SQL Injection via taint flow",
                description="User input (line " + str(source_line) + ") flows into SQL query without sanitization.",
                file=filename, line=sink_line,
                evidence=sink_evidence,
                fix_hint="Use parameterized queries: cursor.execute(query, (param,))"
            ))
        if has_cmd_sink:
            findings.append(ASTFinding(
                rule_id="TAINT002",
                severity="critical",
                title="Command Injection via taint flow",
                description="User input (line " + str(source_line) + ") flows into shell command without sanitization.",
                file=filename, line=sink_line,
                evidence=sink_evidence,
                fix_hint="Never pass user input to shell commands. Use subprocess with list args."
            ))
        if has_path_sink and not has_sql_sink and not has_cmd_sink:
            findings.append(ASTFinding(
                rule_id="TAINT003",
                severity="high",
                title="Path Traversal via taint flow",
                description="User input (line " + str(source_line) + ") used in file path operation.",
                file=filename, line=sink_line,
                evidence=sink_evidence,
                fix_hint="Validate and sanitize file paths. Use os.path.abspath and check prefix."
            ))
    
    # Analisis linea por linea para imports y crypto
    for i, line in enumerate(lines, 1):
        line_lower = line.lower()

        for imp in DANGEROUS_IMPORTS:
            if "import " + imp in line or "import " + imp.split(".")[0] in line:
                findings.append(ASTFinding(
                    rule_id="AST001",
                    severity="high",
                    title="Dangerous import detected",
                    description=f"Module '{imp}' can be used for unsafe deserialization or code execution.",
                    file=filename, line=i,
                    evidence=line.strip()[:120],
                    fix_hint=f"Avoid '{imp}' in production. Use safer alternatives."
                ))

        for crypto in CRYPTO_WEAK:
            if crypto in line_lower:
                findings.append(ASTFinding(
                    rule_id="AST002",
                    severity="medium",
                    title="Weak cryptography detected",
                    description=f"Use of weak/insecure cryptographic function: {crypto}",
                    file=filename, line=i,
                    evidence=line.strip()[:120],
                    fix_hint="Use SHA-256 or better. Use secrets module for random values."
                ))

    return findings

def analyze_ast(files: list[dict]) -> ASTAnalysisResult:
    all_findings: list[ASTFinding] = []
    functions_analyzed = 0

    for f in files:
        filename = f.get("filename", "") or f.get("path", "")
        content = f.get("content", "") or ""
        if not content:
            patch = f.get("patch", "") or f.get("raw_patch", "") or f.get("diff", "") or ""
            # Extraer solo lineas agregadas del patch
            content = "\n".join(l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++ "))
        if not content or not filename:
            continue

        ext = filename.rsplit(".", 1)[-1].lower()
        if ext not in ("py", "js", "ts"):
            continue

        # Taint analysis en el codigo completo
        all_findings += _check_taint(content, filename)

        # Tree-sitter: analizar funciones
        try:
            lang = detect_language(filename)
            parser = get_ts_parser(lang)
            code_bytes = content.encode("utf-8", errors="replace")
            tree = parser.parse(code_bytes)
            functions = get_functions(tree.root_node, code_bytes)
            functions_analyzed += len(functions)

            for func in functions:
                func_code = func.get("code", "")
                func_findings = _check_taint(func_code, filename)
                # Dedup
                for ff in func_findings:
                    ff.line = func["start"] + ff.line
                    if not any(x.rule_id == ff.rule_id and x.line == ff.line for x in all_findings):
                        all_findings.append(ff)
        except Exception:
            pass

    # Score
    score = 0
    for f in all_findings:
        if f.severity == "critical": score += 40
        elif f.severity == "high": score += 25
        elif f.severity == "medium": score += 10
        elif f.severity == "low": score += 3
    score = min(100, score)

    has_taint = any(f.rule_id.startswith("TAINT") for f in all_findings)
    has_import = any(f.rule_id == "AST001" for f in all_findings)
    has_crypto = any(f.rule_id == "AST002" for f in all_findings)
    block = any(f.severity == "critical" for f in all_findings)

    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.rule_id, f.evidence[:50].strip())
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    all_findings = unique_findings[:8]

    return ASTAnalysisResult(
        findings=all_findings,
        risk_score=score,
        has_taint_flow=has_taint,
        has_dangerous_import=has_import,
        has_weak_crypto=has_crypto,
        block_merge=block,
        functions_analyzed=functions_analyzed,
    )
