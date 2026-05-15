path = r"C:\Users\usuario\Downloads\devmind\devmind\backend\pipeline.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Agrega llamada a semantic_engine despues del sandbox
old = "        # Sandbox evidence scoring"
new = """        # Groq semantic analysis
        _groq_security = None
        _groq_correctness = None
        try:
            from semantic_engine import analyze_diff
            _groq = analyze_diff(candidate.diff[:2000], intent=intent.label if hasattr(intent, "label") else "general_fix")
            _groq_security = _groq.get("security_score")
            _groq_correctness = _groq.get("correctness_score")
            _groq_confidence = _groq.get("confidence", 0.0)
            _groq_missing_deps = _groq.get("missing_dependencies", [])
            if _groq.get("has_sql_injection"):
                security -= 0.30
                catastrophic_risk += 0.20
            if _groq.get("has_hardcoded_secret"):
                security -= 0.25
                catastrophic_risk += 0.15
            if _groq.get("has_unsafe_eval"):
                security -= 0.20
                catastrophic_risk += 0.10
            if _groq_missing_deps:
                correctness -= 0.10 * len(_groq_missing_deps)
                uncertainty += 0.05 * len(_groq_missing_deps)
            if _groq_security is not None:
                security = security * 0.5 + _groq_security * 0.5
            if _groq_correctness is not None:
                correctness = correctness * 0.5 + _groq_correctness * 0.5
        except Exception:
            pass
        # Sandbox evidence scoring"""

if old in content:
    content = content.replace(old, new)
    print("Groq conectado al evaluator")
else:
    print("ERROR: texto no encontrado")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

import subprocess
result = subprocess.run(
    [r"C:\Users\usuario\Downloads\devmind\backend\venv\Scripts\python.exe", "-m", "py_compile", path],
    capture_output=True, text=True
)
print("Exitcode:", result.returncode)
if result.stderr:
    print("Error:", result.stderr)
