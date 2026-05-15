content = open("run_benchmark_v6.py", encoding="utf-8").read()

# Fix 11: agregar "credential" a BLOCK_KEYWORDS
content = content.replace(
    '"expose", "force_destroy",',
    '"expose", "credential", "force_destroy", "db_password", "db_pass",'
)

# Fix 18 y 20: runtime + secure + general_fix con archivos de codigo = REVISE
old = "    # 7. Modo secure con intent de revision\n    if intent in REVISE_INTENTS:\n        return \"REVISE\"\n    dec = data.get(\"decision\", {})\n    if isinstance(dec, dict):\n        action = dec.get(\"action\", \"\").upper()\n        if action in {\"NEEDS_VERIFICATION\", \"NEEDS_REPAIR\", \"REVISE\"}:\n            return \"REVISE\"\n\n    return \"APPROVE\""

new = """    # 7. Modo secure con intent de revision
    if intent in REVISE_INTENTS:
        return "REVISE"
    dec = data.get("decision", {})
    if isinstance(dec, dict):
        action = dec.get("action", "").upper()
        if action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR", "REVISE"}:
            return "REVISE"

    # 8. Runtime secure con archivos de codigo = REVISE por defecto
    if mode == "secure" and surface == "runtime":
        filenames = [f.get("filename","").lower() for f in files]
        code_files = [f for f in filenames if f.endswith((".py",".js",".ts",".java",".go"))]
        if code_files:
            return "REVISE"

    return "APPROVE\""""

content = content.replace(old, new)
content = content.replace("benchmark_results_v6", "benchmark_results_v7")
open("run_benchmark_v7.py", "w", encoding="utf-8").write(content)
print("OK")
